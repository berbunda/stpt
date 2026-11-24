use super::*;
use nix::{dir::Dir, libc};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileExt, MetadataExt, OpenOptionsExt},
    },
};

pub(super) const MOUNT_READY: u64 = 0x4018;
pub(super) const CALL: u64 = 0x4019;
pub(super) const REPLY: u64 = 0x401a;
type FsResult<T> = Result<T, Status>;
type Components = Vec<Vec<u8>>;

pub(crate) fn supported() -> bool {
    use std::sync::OnceLock;
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| root(Path::new("/")).is_ok())
}
pub(super) fn root(path: &Path) -> io::Result<File> {
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    resolve(&file, &[], libc::O_PATH)?;
    Ok(file)
}
fn resolve(root: &File, components: &[Vec<u8>], flags: i32) -> io::Result<File> {
    let path = if components.is_empty() {
        b".".to_vec()
    } else {
        components.join(&b'/')
    };
    let name = CString::new(path)?;
    let how = [
        (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        0,
        0x01 | 0x04 | 0x08,
    ]; // NO_XDEV, NO_SYMLINKS, BENEATH
    // SAFETY: openat2 receives a live directory fd, C string and the three Linux open_how u64 fields.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            how.as_ptr(),
            size_of_val(&how),
        )
    } as i32;
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
fn status(e: io::Error) -> Status {
    match e.raw_os_error() {
        Some(libc::ENOENT) => Status::NotFound,
        Some(libc::ENOTDIR) => Status::NotDirectory,
        Some(libc::EXDEV | libc::ELOOP | libc::EACCES | libc::EPERM) => Status::Access,
        _ => Status::Io,
    }
}
fn components(m: &Message) -> R<Components> {
    let items = m.field(1).and_then(Value::as_array).ok_or_else(invalid)?;
    items
        .iter()
        .map(|v| match v {
            Value::Bytes(b) if p::valid_entry_name(v, 0) => Ok(b.clone()),
            _ => Err(invalid()),
        })
        .collect()
}
fn same(root: &File, path: &[Vec<u8>], obj: &File) -> FsResult<()> {
    let a = resolve(root, path, libc::O_PATH)
        .and_then(|f| f.metadata())
        .map_err(status)?;
    let b = obj.metadata().map_err(status)?;
    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
        return Err(Status::Access);
    }
    Ok(())
}
fn metadata(f: &File) -> FsResult<Value> {
    let m = f.metadata().map_err(status)?;
    let kind = if m.is_file() {
        1
    } else if m.is_dir() {
        2
    } else if m.is_symlink() {
        3
    } else {
        0
    };
    let mut fields = vec![
        (Value::Uint(0), Value::Uint(kind)),
        (Value::Uint(3), Value::Uint(u64::from(m.mode() & 0o777))),
    ];
    if kind == 1 {
        if m.len() > p::MAX_SIZE {
            return Err(Status::Limit);
        }
        fields.push((Value::Uint(1), Value::Uint(m.len())))
    }
    Ok(Value::Map(fields))
}
enum Op {
    Stat(Components),
    List(Components),
    Open(Components),
    Read(u64, u64, usize),
    Close(u64),
    Unknown,
}
fn parse(m: &Message) -> R<Op> {
    if m.kind != CALL {
        return Err(invalid());
    }
    let k = number(m, 0)?;
    let required: &[u64] = match k {
        1..=3 => &[1],
        4 => &[2, 3, 4],
        5 => &[2],
        _ => return Ok(Op::Unknown),
    };
    if (1..=4).any(|i| required.contains(&i) != m.field(i).is_some()) {
        return Err(invalid());
    }
    Ok(match k {
        1 => Op::Stat(components(m)?),
        2 => Op::List(components(m)?),
        3 => Op::Open(components(m)?),
        4 => {
            let offset = number(m, 3)?;
            let n = number(m, 4)?;
            if offset > p::MAX_SIZE || !(1..=p::MAX_CHUNK as u64).contains(&n) {
                return Err(invalid());
            }
            Op::Read(number(m, 2)?, offset, n as usize)
        }
        5 => Op::Close(number(m, 2)?),
        _ => unreachable!(),
    })
}
struct Tree {
    root: File,
    next: u64,
    files: BTreeMap<u64, (Components, File)>,
}
impl Tree {
    fn call(&mut self, op: Op, limit: u64) -> FsResult<Option<(u64, Value)>> {
        match op {
            Op::Stat(path) => {
                let f = resolve(&self.root, &path, libc::O_PATH).map_err(status)?;
                let value = metadata(&f)?;
                same(&self.root, &path, &f)?;
                Ok(Some((1, value)))
            }
            Op::Open(path) => {
                if self.files.len() >= 256 {
                    return Err(Status::Limit);
                }
                let pin = resolve(&self.root, &path, libc::O_PATH).map_err(status)?;
                if !pin.metadata().map_err(status)?.is_file() {
                    return Err(Status::Access);
                }
                // Reopen the verified regular object, never a substituted device at its old name.
                let f = File::open(format!("/proc/self/fd/{}", pin.as_raw_fd())).map_err(status)?;
                same(&self.root, &path, &f)?;
                self.next = self.next.checked_add(1).ok_or(Status::Limit)?;
                self.files.insert(self.next, (path, f));
                Ok(Some((3, Value::Uint(self.next))))
            }
            Op::Read(h, off, n) => {
                let (path, f) = self.files.get(&h).ok_or(Status::NotFound)?;
                same(&self.root, path, f)?;
                let mut b = vec![0; n];
                let n = f.read_at(&mut b, off).map_err(status)?;
                same(&self.root, path, f)?;
                b.truncate(n);
                Ok(Some((4, Value::Bytes(b))))
            }
            Op::Close(h) => {
                self.files.remove(&h).ok_or(Status::NotFound)?;
                Ok(None)
            }
            Op::List(path) => {
                let fd = resolve(&self.root, &path, libc::O_RDONLY | libc::O_DIRECTORY)
                    .map_err(status)?;
                let mut dir = Dir::from_fd(fd.try_clone().map_err(status)?.into())
                    .map_err(|e| status(e.into()))?;
                let mut entries = Vec::new();
                let mut budget = 0;
                for entry in dir.iter() {
                    let entry = entry.map_err(|e| status(e.into()))?;
                    let n = entry.file_name().to_bytes();
                    if n == b"." || n == b".." {
                        continue;
                    }
                    let mut child = path.clone();
                    child.push(n.to_vec());
                    let value = Value::Array(vec![
                        Value::Bytes(n.to_vec()),
                        metadata(&resolve(&self.root, &child, libc::O_PATH).map_err(status)?)?,
                    ]);
                    budget += crate::cbor::encode(&value).len();
                    if budget > limit as usize || entries.len() >= 8192 {
                        return Err(Status::Limit);
                    }
                    entries.push(value);
                }
                same(&self.root, &path, &fd)?;
                Ok(Some((2, Value::Array(entries))))
            }
            Op::Unknown => Err(Status::Unsupported),
        }
    }
}
// A blocking directory or file on the Client must not retain a usable worker
// across revocation. The child gets the pinned descriptor, never a path to reopen.
fn worker(root: &File) -> io::Result<tokio::process::Child> {
    use std::process::Stdio;
    let fd = root.as_raw_fd();
    let parent = std::process::id();
    let mut cmd = tokio::process::Command::new("/proc/self/exe");
    cmd.args(["__stpt-mount-tree", &fd.to_string()])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // SAFETY: async-signal-safe syscalls only, before exec of this binary.
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() as u32 != parent
                || libc::fcntl(fd, libc::F_SETFD, 0) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}
pub(crate) fn helper() -> io::Result<()> {
    let fd: i32 = std::env::args()
        .nth(2)
        .and_then(|v| v.parse().ok())
        .filter(|v| *v >= 3)
        .ok_or(io::ErrorKind::InvalidInput)?;
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    let root = unsafe { File::from_raw_fd(copy) };
    if !root.metadata()?.is_dir() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut tree = Tree {
        root,
        next: 0,
        files: BTreeMap::new(),
    };
    let mut input = io::stdin().lock();
    let mut out = io::stdout().lock();
    out.write_all(&[1])?;
    out.flush()?;
    loop {
        let mut len = [0; 4];
        input.read_exact(&mut len)?;
        let n = u32::from_be_bytes(len) as usize;
        if n > wire::DEFAULT_MESSAGE_LIMIT as usize {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut buf = vec![0; n];
        input.read_exact(&mut buf)?;
        let m = Message::decode(&buf)
            .and_then(|m| parse(&m))
            .map_err(|_| io::ErrorKind::InvalidData)?;
        let reply = match tree.call(m, wire::DEFAULT_MESSAGE_LIMIT) {
            Ok(field) => {
                let mut fields = vec![(0, Value::Uint(0))];
                fields.extend(field);
                Message::new(REPLY, fields)
            }
            Err(s) => nmsg(REPLY, s as u64),
        };
        let mut data = reply.encode();
        if data.len() > wire::DEFAULT_MESSAGE_LIMIT as usize {
            data = nmsg(REPLY, Status::Limit as u64).encode()
        }
        out.write_all(&(data.len() as u32).to_be_bytes())?;
        out.write_all(&data)?;
        out.flush()?;
    }
}
async fn next_call(c: &mut Channel) -> R<Message> {
    let mut first = [0];
    if c.rx.read(&mut first).await.map_err(local)?.is_none() {
        return Err(interrupted());
    }
    deadline(c.timers.progress, async {
        wire::read_started_message(&mut c.rx, wire::DEFAULT_MESSAGE_LIMIT, first[0])
            .await
            .map_err(stream)
    })
    .await
}
pub(super) async fn serve(c: &mut Channel, root: &File) -> R<()> {
    let mut child = match worker(root) {
        Ok(v) => v,
        Err(_) => {
            c.result(Status::Io).await?;
            return c.eof().await;
        }
    };
    let mut input = child.stdin.take().ok_or_else(interrupted)?;
    let mut output = child.stdout.take().ok_or_else(interrupted)?;
    if !matches!(
        timeout(c.timers.progress, output.read_u8())
            .await
            .map_err(|_| Failure::new(Code::Timeout, "mount worker startup timed out"))?,
        Ok(1)
    ) {
        c.result(Status::Io).await?;
        return c.eof().await;
    }
    c.send(nmsg(MOUNT_READY, 0)).await?;
    loop {
        let message = tokio::select! {biased;
            _=child.wait()=>return Err(local("mount worker exited")),
            result=next_call(c)=>result?,
        };
        let end = tokio::time::Instant::now() + c.timers.progress;
        parse(&message)?;
        let work = async {
            let b = message.encode();
            input.write_u32(b.len() as u32).await.map_err(local)?;
            input.write_all(&b).await.map_err(local)?;
            let n = output.read_u32().await.map_err(local)? as usize;
            if n > wire::DEFAULT_MESSAGE_LIMIT as usize {
                return Err(local("invalid mount worker response"));
            }
            let mut data = vec![0; n];
            output.read_exact(&mut data).await.map_err(local)?;
            Message::decode(&data)
        };
        let reply = before_end(
            &mut c.rx,
            deadline(
                end.saturating_duration_since(tokio::time::Instant::now()),
                work,
            ),
        )
        .await?;
        c.send(reply).await?;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn path(name: &str) -> Components {
        vec![name.as_bytes().to_vec()]
    }
    #[test]
    fn pinned_handles_refuse_replacement_escape_and_stale_ids() {
        let folder = std::env::temp_dir().join(format!("stpt-tree-{}", SessionId::generate()));
        let base = folder.join("approved");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("file"), b"original").unwrap();
        let mut t = Tree {
            root: root(&base).unwrap(),
            files: BTreeMap::new(),
            next: 0,
        };
        let handle = |v: Option<(u64, Value)>| v.unwrap().1.as_uint().unwrap();
        let h = handle(t.call(Op::Open(path("file")), 65535).unwrap());
        assert_eq!(
            t.call(Op::Read(h, 1, 3), 65535).unwrap(),
            Some((4, Value::Bytes(b"rig".to_vec())))
        );
        std::fs::rename(base.join("file"), folder.join("outside")).unwrap();
        std::fs::write(base.join("file"), b"replacement").unwrap();
        assert_eq!(t.call(Op::Read(h, 0, 5), 65535), Err(Status::Access));
        std::os::unix::fs::symlink(folder.join("outside"), base.join("link")).unwrap();
        assert!(t.call(Op::Open(path("link")), 65535).is_err());
        assert_eq!(t.call(Op::List(vec![]), 1), Err(Status::Limit));
        t.call(Op::Close(h), 65535).unwrap();
        let second = handle(t.call(Op::Open(path("file")), 65535).unwrap());
        assert!(second > h);
        assert_eq!(t.call(Op::Read(h, 0, 1), 65535), Err(Status::NotFound));
        std::fs::rename(&base, folder.join("moved-root")).unwrap();
        std::fs::create_dir(&base).unwrap();
        assert!(t.call(Op::Read(second, 0, 1), 65535).is_ok());
        assert!(resolve(&root(Path::new("/")).unwrap(), &path("proc"), libc::O_PATH).is_err());
        std::fs::remove_dir_all(folder).unwrap();
    }
    #[tokio::test]
    async fn idle_mount_waits_and_an_incomplete_call_expires() {
        let pair = crate::files::tests::Pair::start().await;
        pair.client.set_max_concurrent_bi_streams(1u32.into());
        let mut server = Channel::new(
            &pair.server,
            pair.server.open_bi().await.unwrap(),
            wire::DEFAULT_MESSAGE_LIMIT,
        );
        server.send(msg(START)).await.unwrap();
        let mut client = Channel::new(
            &pair.client,
            pair.client.accept_bi().await.unwrap(),
            wire::DEFAULT_MESSAGE_LIMIT,
        );
        client.expect(START, OPEN).await.unwrap();
        client.send(nmsg(MOUNT_READY, 0)).await.unwrap();
        server.expect(MOUNT_READY, OPEN).await.unwrap();
        let previous = pair.server.remote_address();
        pair.rebind_client();
        // Exchange a complete call on the existing stream after the Server
        // observes the new UDP port.
        timeout(OPEN, async {
            while pair.server.remote_address() == previous {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        server.send(nmsg(CALL, 99)).await.unwrap();
        assert!(matches!(
            parse(&next_call(&mut client).await.unwrap()),
            Ok(Op::Unknown)
        ));
        client
            .send(nmsg(REPLY, Status::Unsupported as u64))
            .await
            .unwrap();
        assert_eq!(
            number(&server.expect(REPLY, OPEN).await.unwrap(), 0).unwrap(),
            Status::Unsupported as u64
        );
        client.timers.progress = Duration::from_millis(70);
        let receive = next_call(&mut client);
        tokio::pin!(receive);
        assert!(
            timeout(Duration::from_millis(160), &mut receive)
                .await
                .is_err()
        );
        server.tx.write_all(&[0x40]).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), receive)
                .await
                .unwrap()
                .unwrap_err()
                .code,
            Code::Timeout
        );
        assert!(pair.server.close_reason().is_none());
    }
    #[test]
    fn mount_calls_reject_traversal_and_wrong_fields() {
        for name in [b"..".as_slice(), b".", b"/etc", b"a/b", b"x\0y"] {
            assert!(
                parse(&Message::new(
                    CALL,
                    vec![
                        (0, Value::Uint(1)),
                        (1, Value::Array(vec![Value::Bytes(name.into())]))
                    ]
                ))
                .is_err()
            );
        }
        assert!(
            parse(&Message::new(
                CALL,
                vec![
                    (0, Value::Uint(5)),
                    (2, Value::Uint(1)),
                    (3, Value::Uint(0))
                ]
            ))
            .is_err()
        );
        assert!(matches!(parse(&nmsg(CALL, 999)), Ok(Op::Unknown)));
    }
}
