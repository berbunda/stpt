//! Linux FUSE worker. The Server starts a separate, killable instance in the
//! Session mount namespace. No kernel data/attribute cache spans requests.
use crate::{
    cbor::Value,
    file_protocol as p,
    wire::{DEFAULT_MESSAGE_LIMIT, Message},
};
use fuser::*;
use nix::libc;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsStr},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{DirBuilderExt, MetadataExt},
        },
    },
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, OnceLock},
    time::{Duration, UNIX_EPOCH},
};
use tokio::process::{Child, Command};

pub fn available() -> bool {
    static OK: OnceLock<bool> = OnceLock::new();
    *OK.get_or_init(|| {
        nix::unistd::geteuid().is_root()
            && OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/fuse")
                .is_ok()
            && isolated_namespace(true).is_ok()
    })
}
pub fn namespace() -> io::Result<Arc<File>> {
    isolated_namespace(false)
}
fn isolated_namespace(probe: bool) -> io::Result<Arc<File>> {
    // Pin the new namespace while the creating thread is still in it. Both the
    // Session child and its workers receive this same descriptor from the Server.
    std::thread::Builder::new()
        .name("stpt-session-namespace".into())
        .spawn(move || {
            if unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_FS) } != 0
                || unsafe {
                    libc::mount(
                        std::ptr::null(),
                        c"/".as_ptr(),
                        std::ptr::null(),
                        libc::MS_PRIVATE | libc::MS_REC,
                        std::ptr::null(),
                    )
                } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if probe {
                // This thread is the sole owner of a disposable, propagation-private namespace.
                // Both the test mount and its namespace disappear when the thread exits.
                if unsafe {
                    libc::mount(
                        c"none".as_ptr(),
                        c"/tmp".as_ptr(),
                        c"fusectl".as_ptr(),
                        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                        std::ptr::null(),
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            File::open("/proc/thread-self/ns/mnt").map(Arc::new)
        })?
        .join()
        .map_err(|_| io::Error::other("namespace thread failed"))?
}

pub struct Target {
    namespace: Arc<File>,
    leader: i32,
    uid: u32,
}
impl Target {
    pub fn new(namespace: Arc<File>, leader: i32, uid: u32) -> Self {
        Self {
            namespace,
            leader,
            uid,
        }
    }
    pub fn spawn(&self, kind: u64) -> io::Result<Worker> {
        let path = format!("/tmp/stpt-mount-{}", crate::terminal::SessionId::generate());
        let (guard_read, guard_write) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
        let mut cmd = Command::new("/proc/self/exe");
        cmd.args([
            "__stpt-fuse",
            &path,
            &self.leader.to_string(),
            &self.uid.to_string(),
            &kind.to_string(),
            &guard_read.as_raw_fd().to_string(),
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
        let ns = self.namespace.clone();
        let parent = std::process::id();
        // Only syscalls between fork and exec. The worker inherits the exact pinned namespace.
        unsafe {
            cmd.pre_exec(move || {
                if libc::fcntl(guard_read.as_raw_fd(), libc::F_SETFD, 0) != 0
                    || libc::getppid() as u32 != parent
                    || libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNS) != 0
                {
                    return Err(io::Error::other("cannot start isolated FUSE worker"));
                }
                Ok(())
            });
        }
        let tmp = std::fs::metadata("/tmp")?;
        if tmp.uid() != 0 || (tmp.mode() & 0o022 != 0 && tmp.mode() & 0o1000 == 0) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        let control = format!("{path}-control");
        if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(&control) {
            let _ = std::fs::remove_dir(&path);
            return Err(e);
        }
        let child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let _ = std::fs::remove_dir(control);
                let _ = std::fs::remove_dir(path);
                return Err(e);
            }
        };
        Ok(Worker {
            child,
            abort: None,
            _lifetime: guard_write,
            namespace: self.namespace.clone(),
            path,
        })
    }
}
pub struct Worker {
    _lifetime: std::os::fd::OwnedFd,
    abort: Option<File>,
    pub child: Child,
    namespace: Arc<File>,
    pub path: String,
}
impl Worker {
    // Hold the abort control for this exact kernel connection even after lazy unmount.
    pub fn arm(&mut self) -> io::Result<()> {
        let pid = self.child.id().ok_or(io::ErrorKind::BrokenPipe)?;
        let info = std::fs::read_to_string(format!("/proc/{pid}/mountinfo"))?;
        let line = info
            .lines()
            .find(|line| {
                line.split_whitespace().nth(4) == Some(&self.path) && line.contains(" - fuse")
            })
            .ok_or(io::ErrorKind::NotFound)?;
        let minor = line
            .split_whitespace()
            .nth(2)
            .and_then(|v| v.strip_prefix("0:"))
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or(io::ErrorKind::InvalidData)?;
        self.abort = Some(OpenOptions::new().write(true).open(format!(
            "/proc/{pid}/root{}-control/{minor}/abort",
            self.path
        ))?);
        Ok(())
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(f) = self.abort.as_mut() {
            let _ = f.write_all(b"1");
        }
        let _ = self.child.start_kill();
        let ns = self.namespace.clone();
        let path = self.path.clone();
        // A dedicated thread can enter this namespace without changing any executor thread.
        let _ = std::thread::Builder::new()
            .name("stpt-unmount".into())
            .spawn(move || {
                if unsafe {
                    libc::unshare(libc::CLONE_FS) == 0
                        && libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNS) == 0
                } {
                    cleanup(&path);
                }
            });
    }
}
fn cleanup(path: &str) {
    for dir in [path.to_owned(), format!("{path}-control")] {
        let c = CString::new(dir.as_str()).unwrap();
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH | libc::UMOUNT_NOFOLLOW) };
        if std::fs::symlink_metadata(&dir)
            .is_ok_and(|m| m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700)
        {
            let _ = std::fs::remove_dir(dir);
        }
    }
}
struct View {
    sid: i32,
    uid: u32,
    kind: u64,
    next: u64,
    paths: BTreeMap<u64, Vec<Value>>,
}
type Native<T> = Result<T, i32>;
impl View {
    fn allows(&self, r: &Request) -> Native<()> {
        if r.uid() == self.uid && r.pid() > 0 && unsafe { libc::getsid(r.pid() as i32) } == self.sid
        {
            Ok(())
        } else {
            Err(libc::EACCES)
        }
    }
    fn path(&self, ino: u64) -> Native<Vec<Value>> {
        self.paths.get(&ino).cloned().ok_or(libc::ESTALE)
    }
    fn name(&self, name: &OsStr) -> Native<Value> {
        let value = if self.kind == 0 {
            Value::Bytes(name.as_bytes().to_vec())
        } else {
            Value::Text(name.to_str().ok_or(libc::EILSEQ)?.into())
        };
        if p::valid_entry_name(&value, self.kind) {
            Ok(value)
        } else {
            Err(libc::EINVAL)
        }
    }
    fn inode(&mut self, path: Vec<Value>) -> Native<u64> {
        if let Some((id, _)) = self.paths.iter().find(|(_, p)| **p == path) {
            return Ok(*id);
        }
        if self.paths.len() >= 8192 {
            return Err(libc::ENOSPC);
        }
        self.next = self.next.checked_add(1).ok_or(libc::EOVERFLOW)?;
        self.paths.insert(self.next, path);
        Ok(self.next)
    }
    fn rpc(&self, op: u64, fields: Vec<(u64, Value)>) -> Native<Message> {
        let mut all = vec![(0, Value::Uint(op))];
        all.extend(fields);
        let data = Message::new(0x4019, all).encode();
        if data.len() > DEFAULT_MESSAGE_LIMIT as usize {
            return Err(libc::E2BIG);
        }
        let mut out = io::stdout().lock();
        out.write_all(&(data.len() as u32).to_be_bytes())
            .and_then(|_| out.write_all(&data))
            .and_then(|_| out.flush())
            .map_err(|_| libc::EIO)?;
        let mut input = io::stdin().lock();
        let mut len = [0; 4];
        input.read_exact(&mut len).map_err(|_| libc::EIO)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > DEFAULT_MESSAGE_LIMIT as usize {
            return Err(libc::EIO);
        }
        let mut b = vec![0; len];
        input.read_exact(&mut b).map_err(|_| libc::EIO)?;
        let m = Message::decode(&b).map_err(|_| libc::EIO)?;
        match m.field(0).and_then(Value::as_uint) {
            Some(0) => Ok(m),
            Some(1) => Err(libc::ENOENT),
            Some(2) => Err(libc::EACCES),
            Some(4) => Err(libc::ENOTDIR),
            Some(11) => Err(libc::E2BIG),
            _ => Err(libc::EIO),
        }
    }
    fn attr(&self, ino: u64, path: Vec<Value>) -> Native<FileAttr> {
        let m = self.rpc(1, vec![(1, Value::Array(path))])?;
        let meta =
            p::validate_metadata(m.field(1).ok_or(libc::EIO)?, self.kind).map_err(|_| libc::EIO)?;
        let kind = ft(meta.kind)?;
        let size = meta.size.unwrap_or(0);
        let mtime = meta
            .modified
            .and_then(|(s, n)| {
                let d = Duration::from_secs(s.unsigned_abs());
                (if s >= 0 {
                    UNIX_EPOCH.checked_add(d)
                } else {
                    UNIX_EPOCH.checked_sub(d)
                })?
                .checked_add(Duration::from_nanos(n as u64))
            })
            .unwrap_or(UNIX_EPOCH);
        Ok(FileAttr {
            ino,
            size,
            blocks: size.div_ceil(512),
            atime: mtime,
            mtime,
            ctime: mtime,
            crtime: UNIX_EPOCH,
            kind,
            perm: if kind == FileType::Directory {
                0o500
            } else {
                0o400
            },
            nlink: 1,
            uid: self.uid,
            gid: 0,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        })
    }
}
fn ft(kind: u64) -> Native<FileType> {
    match kind {
        1 => Ok(FileType::RegularFile),
        2 => Ok(FileType::Directory),
        3 => Ok(FileType::Symlink),
        _ => Err(libc::EOPNOTSUPP),
    }
}
impl Filesystem for View {
    fn init(&mut self, _: &Request, config: &mut KernelConfig) -> Result<(), i32> {
        let _ = config.set_max_readahead(0);
        let _ = config.set_max_background(1);
        io::stdout()
            .write_all(&[1])
            .and_then(|_| io::stdout().flush())
            .map_err(|_| libc::EIO)
    }
    fn lookup(&mut self, r: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let result = (|| {
            self.allows(r)?;
            let mut path = self.path(parent)?;
            path.push(self.name(name)?);
            let mut a = self.attr(0, path.clone())?;
            a.ino = self.inode(path)?;
            Ok(a)
        })();
        match result {
            Ok(a) => reply.entry(&Duration::ZERO, &a, 0),
            Err(e) => reply.error(e),
        }
    }
    fn getattr(&mut self, r: &Request, ino: u64, _: Option<u64>, reply: ReplyAttr) {
        match self.allows(r).and_then(|_| self.attr(ino, self.path(ino)?)) {
            Ok(a) => reply.attr(&Duration::ZERO, &a),
            Err(e) => reply.error(e),
        }
    }
    fn open(&mut self, r: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let result = (|| {
            self.allows(r)?;
            if flags & (libc::O_ACCMODE | libc::O_TRUNC) != 0 {
                return Err(libc::EROFS);
            }
            let m = self.rpc(3, vec![(1, Value::Array(self.path(ino)?))])?;
            m.field(3).and_then(Value::as_uint).ok_or(libc::EIO)
        })();
        match result {
            Ok(h) => reply.opened(h, fuser::consts::FOPEN_DIRECT_IO),
            Err(e) => reply.error(e),
        }
    }
    fn read(
        &mut self,
        r: &Request,
        _: u64,
        h: u64,
        off: i64,
        size: u32,
        _: i32,
        lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let result = (|| {
            self.allows(r)?;
            // Linux direct user reads identify their lock owner. Folio fills for
            // private mmap and readahead omit it. Never feed the page cache.
            if lock_owner.is_none() {
                return Err(libc::EOPNOTSUPP);
            }
            let off = u64::try_from(off).map_err(|_| libc::EINVAL)?;
            if off > p::MAX_SIZE {
                return Ok(Vec::new());
            }
            let mut out = Vec::new();
            if size > 1048576 {
                return Err(libc::E2BIG);
            }
            while out.len() < size as usize {
                let n = (size as usize - out.len()).min(p::MAX_CHUNK);
                let m = self.rpc(
                    4,
                    vec![
                        (2, Value::Uint(h)),
                        (3, Value::Uint(off + out.len() as u64)),
                        (4, Value::Uint(n as u64)),
                    ],
                )?;
                let Some(Value::Bytes(b)) = m.field(4) else {
                    return Err(libc::EIO);
                };
                if b.len() > n {
                    return Err(libc::EIO);
                }
                out.extend(b);
                if b.len() < n {
                    break;
                }
            }
            Ok(out)
        })();
        match result {
            Ok(b) => reply.data(&b),
            Err(e) => reply.error(e),
        }
    }
    fn release(
        &mut self,
        _: &Request,
        _: u64,
        h: u64,
        _: i32,
        _: Option<u64>,
        _: bool,
        reply: ReplyEmpty,
    ) {
        match self.rpc(5, vec![(2, Value::Uint(h))]) {
            Ok(_) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
    fn opendir(&mut self, r: &Request, _: u64, _: i32, reply: ReplyOpen) {
        match self.allows(r) {
            Ok(()) => reply.opened(0, 0),
            Err(e) => reply.error(e),
        }
    }
    fn readdir(&mut self, r: &Request, ino: u64, _: u64, off: i64, mut reply: ReplyDirectory) {
        let result = (|| {
            self.allows(r)?;
            let start = usize::try_from(off).map_err(|_| libc::EINVAL)?;
            let path = self.path(ino)?;
            let m = self.rpc(2, vec![(1, Value::Array(path.clone()))])?;
            let entries = m.field(2).and_then(Value::as_array).ok_or(libc::EIO)?;
            let mut names = vec![
                (FileType::Directory, b".".to_vec()),
                (FileType::Directory, b"..".to_vec()),
            ];
            let mut seen = BTreeSet::new();
            for entry in entries {
                let pair = entry.as_array().filter(|p| p.len() == 2).ok_or(libc::EIO)?;
                let name = match &pair[0] {
                    Value::Bytes(b) => b.clone(),
                    Value::Text(s) => s.as_bytes().to_vec(),
                    _ => return Err(libc::EILSEQ),
                };
                if !p::valid_entry_name(&pair[0], self.kind) || !seen.insert(name.clone()) {
                    return Err(libc::EILSEQ);
                }
                let meta = p::validate_metadata(&pair[1], self.kind).map_err(|_| libc::EIO)?;
                names.push((ft(meta.kind)?, name));
            }
            for (i, (kind, name)) in names.iter().enumerate().skip(start) {
                let mut child = path.clone();
                if i == 1 {
                    child.pop();
                } else if i > 1 {
                    child.push(self.name(OsStr::from_bytes(name))?);
                }
                let inode = self.inode(child)?;
                if reply.add(inode, (i + 1) as i64, *kind, OsStr::from_bytes(name)) {
                    break;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(e),
        }
    }
}
pub fn helper() -> io::Result<()> {
    let mut a = std::env::args().skip(2);
    let path = PathBuf::from(a.next().ok_or(io::ErrorKind::InvalidInput)?);
    let mut n = || {
        a.next()
            .and_then(|v| v.parse::<u32>().ok())
            .ok_or(io::ErrorKind::InvalidInput)
    };
    let sid = n()? as i32;
    let uid = n()?;
    let kind = u64::from(n()?);
    let guard = i32::try_from(n()?).map_err(io::Error::other)?;
    if path.parent() != Some(Path::new("/tmp"))
        || !path.file_name().is_some_and(|s| {
            s.as_bytes()
                .strip_prefix(b"stpt-mount-")
                .is_some_and(|id| id.len() == 32 && id.iter().all(u8::is_ascii_hexdigit))
        })
        || kind > 1
    {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let tmp = std::fs::metadata("/tmp")?;
    if tmp.uid() != 0 || (tmp.mode() & 0o022 != 0 && tmp.mode() & 0o1000 == 0) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let control = CString::new(format!("{}-control", path.display()))?;
    for dir in [
        path.as_path(),
        Path::new(OsStr::from_bytes(control.as_bytes())),
    ] {
        let meta = std::fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    if guard < 3 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let copy = unsafe { libc::fcntl(guard, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    use std::os::fd::FromRawFd;
    let mut guard = unsafe { File::from_raw_fd(copy) };
    let cleanup_path = path.to_str().ok_or(io::ErrorKind::InvalidInput)?.to_owned();
    std::thread::Builder::new()
        .name("stpt-server-lifetime".into())
        .spawn(move || {
            loop {
                match guard.read(&mut [0]) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    _ => break,
                }
            }
            cleanup(&cleanup_path);
            std::process::exit(0);
        })?;
    // A private fusectl mount also works when the host exposes sysfs read-only.
    if unsafe {
        libc::mount(
            c"none".as_ptr(),
            control.as_ptr(),
            c"fusectl".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let fs = View {
        sid,
        uid,
        kind,
        next: 1,
        paths: BTreeMap::from([(1, Vec::new())]),
    };
    use MountOption::*;
    fuser::mount2(
        fs,
        &path,
        &[
            RO,
            NoDev,
            NoExec,
            NoSuid,
            AllowOther,
            DefaultPermissions,
            FSName("stpt".into()),
        ],
    )
}
