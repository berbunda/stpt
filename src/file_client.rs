//! Explicit Client file operations; peer names are only displayed, never local paths.
use crate::cbor::Value;
use crate::cli::{FsAction, Remote};
use crate::file_protocol::{self as p, Status};
use crate::files::Channel;
use crate::wire::{self, Code, Failure, Message, StreamError};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
pub enum Error {
    Limit,
    Protocol(Failure),
    Stream(StreamError),
    Local(std::io::Error),
    Remote(Status),
    Usage(&'static str),
    Timeout,
}
impl From<Failure> for Error {
    fn from(e: Failure) -> Self {
        Self::Protocol(e)
    }
}
impl From<StreamError> for Error {
    fn from(e: StreamError) -> Self {
        Self::Stream(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Local(e)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit => f.write_str("file exceeds the Client's max_file_size limit"),
            Self::Protocol(e) => write!(f,"invalid file exchange: {e}"),
            Self::Stream(StreamError::Failure(e)) => write!(f,"file Channel: {e}"),
            Self::Stream(_) => f.write_str("file Channel interrupted; a modifying operation may have an unknown outcome and was not retried"),
            Self::Local(e) => write!(f,"local file: {e}"),
            Self::Remote(s) => f.write_str(s.name()),
            Self::Usage(s) => f.write_str(s),
            Self::Timeout => f.write_str("file operation timed out; remote outcome may be unknown; not retried"),
        }
    }
}
impl std::error::Error for Error {}

pub struct Operation {
    pub max_size: u64,
    kind: u64,
    path: String,
    destination: Option<String>,
    local: Option<PathBuf>,
    replace: bool,
    hash: u64,
}
pub fn split(action: FsAction) -> (Remote, Operation) {
    let (remote, kind, path, destination, local, replace, hash) = match action {
        FsAction::Pull {
            target,
            local,
            replace,
            hash,
        } => (
            target.remote,
            1,
            target.path,
            None,
            Some(local),
            replace,
            hash.id(),
        ),
        FsAction::Push {
            remote,
            local,
            path,
            replace,
            hash,
        } => (remote, 2, path, None, Some(local), replace, hash.id()),
        FsAction::Stat(t) => (t.remote, 3, t.path, None, None, false, 1),
        FsAction::List(t) => (t.remote, 4, t.path, None, None, false, 1),
        FsAction::Mkdir(t) => (t.remote, 5, t.path, None, None, false, 1),
        FsAction::Remove(t) => (t.remote, 6, t.path, None, None, false, 1),
        FsAction::Rename {
            target,
            destination,
            replace,
        } => (
            target.remote,
            7,
            target.path,
            Some(destination),
            None,
            replace,
            1,
        ),
    };
    (
        remote,
        Operation {
            max_size: p::DEFAULT_MAX_SIZE,
            kind,
            path,
            destination,
            local,
            replace,
            hash,
        },
    )
}
fn remote_path(path: &str) -> Result<Value, Error> {
    if !path.starts_with('/') {
        return Err(Error::Usage("Server path must be an absolute POSIX path"));
    }
    let mut names = Vec::new();
    for name in path.split('/').skip(1) {
        if name.is_empty() {
            continue;
        }
        if !p::valid_posix_component(name.as_bytes()) {
            return Err(Error::Usage(
                "Server path must not contain '.', '..' or NUL",
            ));
        }
        names.push(Value::Bytes(name.as_bytes().to_vec()));
    }
    Ok(Value::Array(vec![Value::Uint(0), Value::Array(names)]))
}
async fn send(ch: &mut Channel, m: &Message, limit: u64, deadline: Duration) -> Result<(), Error> {
    tokio::time::timeout(deadline, wire::write_message(&mut ch.send, m, limit))
        .await
        .map_err(|_| Error::Timeout)??;
    Ok(())
}
async fn receive(ch: &mut Channel, deadline: Duration) -> Result<Message, Error> {
    tokio::time::timeout(deadline, wire::read_message(&mut ch.recv, 65535))
        .await
        .map_err(|_| Error::Timeout)??
        .ok_or_else(|| Error::Stream(StreamError::Reset(Code::NoError.varint())))
}
fn final_result(m: &Message, kind: u64) -> Result<(), Error> {
    if m.kind != p::RESULT {
        return Err(Failure::violation("expected FILE_RESULT").into());
    }
    p::id(m, 0)?;
    let status = p::status(m)?;
    if status == Status::Ok && kind == 3 {
        p::validate_metadata(
            m.field(2)
                .ok_or_else(|| Failure::violation("stat metadata missing"))?,
        )?;
    } else if m.field(2).is_some() {
        return Err(Failure::violation("unexpected file result metadata").into());
    }
    if status != Status::Ok {
        return Err(Error::Remote(status));
    }
    Ok(())
}
pub async fn run(
    ch: &mut Channel,
    op: Operation,
    limit: u64,
    deadline: Duration,
) -> Result<(), Error> {
    let result = perform(ch, op, limit, deadline).await;
    if matches!(&result, Err(Error::Limit)) {
        ch.abort(Code::LimitExceeded);
    }
    if matches!(&result, Err(Error::Timeout)) {
        ch.abort(Code::Timeout);
    }
    if let Err(Error::Protocol(f)) = &result {
        ch.connection.close(f.code.varint(), b"");
    }
    if let Err(Error::Stream(StreamError::Failure(f))) = &result {
        ch.connection.close(f.code.varint(), b"");
    }
    result
}
async fn perform(
    ch: &mut Channel,
    op: Operation,
    limit: u64,
    deadline: Duration,
) -> Result<(), Error> {
    let mut fields = vec![
        (0, Value::Uint(0)),
        (1, Value::Uint(op.kind)),
        (2, remote_path(&op.path)?),
    ];
    if let Some(dest) = &op.destination {
        fields.push((3, remote_path(dest)?));
    }
    if matches!(op.kind, 2 | 7) {
        fields.push((4, Value::Bool(op.replace)));
    }
    let mut source = None;
    let mut length = 0;
    if op.kind == 2 {
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(nix::libc::O_NONBLOCK);
        let file = options.open(op.local.as_ref().unwrap()).await?;
        let metadata = file.metadata().await?;
        if !metadata.is_file() {
            return Err(Error::Usage("upload source must be a regular file"));
        }
        length = metadata.len();
        if length > op.max_size || length > p::MAX_SIZE {
            return Err(Error::Limit);
        }
        source = Some(file);
        fields.push((5, Value::Uint(length)));
    }
    if matches!(op.kind, 1 | 2) {
        fields.push((6, Value::Uint(op.hash)));
    }
    send(
        ch,
        &Message::new(wire::FILE_REQUEST, fields),
        limit,
        deadline,
    )
    .await?;
    let first = receive(ch, deadline).await?;
    if op.kind == 1 || op.kind == 2 {
        if first.kind == p::RESULT {
            final_result(&first, op.kind)?;
            return Err(Failure::violation("transfer succeeded without acceptance").into());
        }
        if first.kind != p::ACCEPTED {
            return Err(Failure::violation("expected FILE_ACCEPTED").into());
        }
        p::id(&first, 0)?;
        let accepted = p::size(&first, 1)?;
        if p::uint(&first, 2)? != op.hash
            || first.field(3).is_some()
            || (op.kind == 2 && accepted != length)
        {
            return Err(Failure::violation("invalid transfer acceptance").into());
        }
        if accepted > op.max_size {
            return Err(Error::Limit);
        }
        if op.kind == 2 {
            return upload(ch, source.unwrap(), accepted, op.hash, limit, deadline).await;
        }
        return download(
            ch,
            op.local.as_ref().unwrap(),
            op.replace,
            accepted,
            op.hash,
            limit,
            deadline,
        )
        .await;
    }
    let mut message = first;
    while message.kind == p::ENTRIES && op.kind == 4 {
        p::id(&message, 0)?;
        let entries = message
            .field(1)
            .and_then(Value::as_array)
            .filter(|a| !a.is_empty())
            .ok_or_else(|| Failure::violation("empty or invalid FILE_ENTRIES"))?;
        for entry in entries {
            let a = entry
                .as_array()
                .filter(|a| a.len() == 2)
                .ok_or_else(|| Failure::violation("invalid file entry"))?;
            let Value::Bytes(name) = &a[0] else {
                return Err(Failure::violation("POSIX listing name is not bytes").into());
            };
            if !p::valid_posix_component(name) {
                return Err(Failure::violation("invalid listing component").into());
            }
            let (kind, size) = p::validate_metadata(&a[1])?;
            println!(
                "{}\t{}\t{}",
                kind_name(kind),
                size.map_or_else(|| "-".into(), |n| n.to_string()),
                escape(name)
            );
        }
        message = receive(ch, deadline).await?;
    }
    final_result(&message, op.kind)?;
    if op.kind == 3 {
        let (kind, size) = p::validate_metadata(message.field(2).unwrap())?;
        println!(
            "{}\t{}",
            kind_name(kind),
            size.map_or_else(|| "-".into(), |n| n.to_string())
        );
    }
    Ok(())
}
fn kind_name(k: u64) -> &'static str {
    match k {
        1 => "file",
        2 => "directory",
        3 => "symlink",
        _ => "other",
    }
}
fn escape(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|b| std::ascii::escape_default(*b))
        .map(char::from)
        .collect()
}
async fn upload(
    ch: &mut Channel,
    mut file: tokio::fs::File,
    length: u64,
    algorithm: u64,
    limit: u64,
    deadline: Duration,
) -> Result<(), Error> {
    let sender = async {
        let mut count = 0;
        let mut hash = p::Hash::new(algorithm).unwrap();
        let mut buffer = vec![0; p::CHUNK];
        let mut status = Status::Ok;
        while count < length {
            let wanted = ((length - count).min(buffer.len() as u64)) as usize;
            let n = match tokio::time::timeout(deadline, file.read(&mut buffer[..wanted])).await {
                Ok(Ok(n)) if n > 0 => n,
                _ => {
                    status = Status::Io;
                    break;
                }
            };
            hash.update(&buffer[..n]);
            tokio::time::timeout(
                deadline,
                wire::write_message(
                    &mut ch.send,
                    &p::data(0, count, buffer[..n].to_vec()),
                    limit,
                ),
            )
            .await
            .map_err(|_| Error::Timeout)??;
            count += n as u64;
        }
        tokio::time::timeout(
            deadline,
            wire::write_message(
                &mut ch.send,
                &p::end(
                    0,
                    status,
                    count,
                    (status == Status::Ok).then(|| hash.finish()),
                ),
                limit,
            ),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        Ok::<_, Error>(status)
    };
    // Service STOP_SENDING/reset concurrently; never queue the whole upload first.
    let early = wire::read_message(&mut ch.recv, 65535);
    let status = tokio::select! {biased; status=sender=>status?, reply=early=>{return match reply {Err(e)=>Err(e.into()),_=>Err(Failure::violation("upload result before FILE_END").into())};}};
    let result = receive(ch, deadline).await?;
    final_result(&result, 2)?;
    if status != Status::Ok {
        return Err(Failure::violation("Server accepted failed upload").into());
    }
    Ok(())
}
struct Destination {
    path: PathBuf,
    temp: PathBuf,
    file: Option<tokio::fs::File>,
    replace: bool,
}
impl Destination {
    async fn new(path: &Path, replace: bool) -> Result<Self, Error> {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        if path.file_name().is_none() {
            return Err(Error::Usage("local destination must name a file"));
        }
        if !replace && tokio::fs::symlink_metadata(path).await.is_ok() {
            return Err(Error::Local(std::io::ErrorKind::AlreadyExists.into()));
        }
        let mut random = [0; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| Error::Usage("system randomness failed"))?;
        let temp = path.parent().unwrap_or(Path::new(".")).join(format!(
            ".stpt-download-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let path = path.to_owned();
        tokio::task::spawn_blocking(move || {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(&temp)?;
            Ok::<_, Error>(Self {
                path,
                temp,
                file: Some(tokio::fs::File::from_std(file)),
                replace,
            })
        })
        .await
        .map_err(|_| Error::Usage("download staging task failed"))?
    }

    async fn finish_writes(&mut self) -> Result<(), Error> {
        let mut file = self.file.take().unwrap();
        file.flush().await?;
        let file = file.into_std().await;
        #[cfg(unix)]
        nix::unistd::close(file).map_err(std::io::Error::from)?;
        #[cfg(windows)]
        {
            use std::os::windows::io::IntoRawHandle;
            // SAFETY: into_raw_handle transfers our unique file handle to CloseHandle.
            if unsafe { windows_sys::Win32::Foundation::CloseHandle(file.into_raw_handle()) } == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        Ok(())
    }
    async fn publish(&self) -> Result<(), Error> {
        if self.replace {
            tokio::fs::rename(&self.temp, &self.path).await?;
        } else {
            tokio::fs::hard_link(&self.temp, &self.path).await?;
            tokio::fs::remove_file(&self.temp).await?;
        }
        Ok(())
    }
}
impl Drop for Destination {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Err(e) = std::fs::remove_file(&self.temp)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(?e, "local download staging cleanup failed");
        }
    }
}
async fn download(
    ch: &mut Channel,
    path: &Path,
    replace: bool,
    length: u64,
    algorithm: u64,
    limit: u64,
    deadline: Duration,
) -> Result<(), Error> {
    let mut destination = tokio::time::timeout(deadline, Destination::new(path, replace))
        .await
        .map_err(|_| Error::Timeout)??;
    let mut count = 0;
    let mut hash = p::Hash::new(algorithm).unwrap();
    let mut status = loop {
        let m = receive(ch, deadline).await?;
        if m.kind == p::DATA {
            let bytes = p::bytes(&m, 0, count, length)?;
            tokio::time::timeout(
                deadline,
                destination.file.as_mut().unwrap().write_all(bytes),
            )
            .await
            .map_err(|_| Error::Timeout)??;
            hash.update(bytes);
            count += bytes.len() as u64;
        } else {
            break p::verify_end(&m, 0, count, length, hash.finish())?;
        }
    };
    let mut local_error = None;
    if status == Status::Ok
        && let Err(error) = tokio::time::timeout(deadline, destination.finish_writes())
            .await
            .map_err(|_| Error::Timeout)?
    {
        status = Status::Io;
        local_error = Some(error);
    }
    send(ch, &p::receipt(0, status), limit, deadline).await?;
    let final_message = receive(ch, deadline).await?;
    if final_message.kind != p::RESULT {
        return Err(Failure::violation("expected final download result").into());
    }
    if p::status(&final_message)? != status {
        return Err(Failure::violation("download result does not match receipt").into());
    }
    let result = final_result(&final_message, 1);
    if let Some(error) = local_error {
        return Err(error);
    }
    result?;
    destination.publish().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::{Budget, tests::Pair};
    fn directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("stpt-fs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }
    #[tokio::test]
    async fn bad_digest_is_reported_without_publishing_local_file() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let pair = Pair::start().await;
            let server = pair.server.clone();
            let task = tokio::spawn(async move {
                let (mut send, mut recv) = server.accept_bi().await.unwrap();
                wire::read_message(&mut recv, 65535).await.unwrap();
                wire::write_message(&mut send, &Message::new(wire::FILES_READY, vec![]), 65535)
                    .await
                    .unwrap();
                let request = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                assert_eq!(request.kind, wire::FILE_REQUEST);
                for m in [
                    p::accepted(0, 3, 1),
                    p::data(0, 0, b"abc".to_vec()),
                    p::end(0, Status::Ok, 3, Some([0; 32])),
                ] {
                    wire::write_message(&mut send, &m, 65535).await.unwrap();
                }
                let receipt = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                assert_eq!(p::status(&receipt).unwrap(), Status::Integrity);
                wire::write_message(&mut send, &p::result(0, Status::Integrity, None), 65535)
                    .await
                    .unwrap();
                wire::read_message(&mut recv, 65535).await
            });
            let dir = directory("digest");
            let path = dir.join("target");
            let budget = Budget::new(1);
            let mut channel = Channel::open(&pair.client, 65535, &budget, Duration::from_secs(1))
                .await
                .unwrap();
            let op = Operation {
                max_size: p::DEFAULT_MAX_SIZE,
                kind: 1,
                path: "/source".into(),
                destination: None,
                local: Some(path.clone()),
                replace: false,
                hash: 1,
            };
            assert!(matches!(
                run(&mut channel, op, 65535, Duration::from_secs(1)).await,
                Err(Error::Remote(Status::Integrity))
            ));
            assert!(!path.exists());
            assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
            assert!(pair.client.close_reason().is_none());
            drop(channel);
            let _ = task.await.unwrap();
            std::fs::remove_dir_all(dir).unwrap();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn local_publication_does_not_overwrite_a_racing_destination() {
        let dir = directory("collision");
        let path = dir.join("target");
        {
            let mut staging = Destination::new(&path, false).await.unwrap();
            staging
                .file
                .as_mut()
                .unwrap()
                .write_all(b"new")
                .await
                .unwrap();
            staging.finish_writes().await.unwrap();
            std::fs::write(&path, b"existing").unwrap();
            assert!(staging.publish().await.is_err());
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"existing");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn deadline_and_length_limits_abort_only_the_channel() {
        for length in [0, p::DEFAULT_MAX_SIZE + 1] {
            tokio::time::timeout(Duration::from_secs(3),async {
                let pair=Pair::start().await;
                let server=pair.server.clone();
                let expected=if length==0 {Code::Timeout}else{Code::LimitExceeded};
                let task=tokio::spawn(async move {
                    let(mut send,mut recv)=server.accept_bi().await.unwrap();
                    wire::read_message(&mut recv,65535).await.unwrap();
                    wire::write_message(&mut send,&Message::new(wire::FILES_READY,vec![]),65535).await.unwrap();
                    wire::read_message(&mut recv,65535).await.unwrap();
                    wire::write_message(&mut send,&p::accepted(0,length,1),65535).await.unwrap();
                    assert!(matches!(wire::read_message(&mut recv,65535).await,Err(StreamError::Reset(code)) if code==expected.varint()));
                });
                let dir=directory("limits");
                let path=dir.join("target");
                let budget=Budget::new(1);
                let mut channel=Channel::open(&pair.client,65535,&budget,Duration::from_secs(1)).await.unwrap();
                let op=Operation {max_size:p::DEFAULT_MAX_SIZE,kind:1,path:"/source".into(),destination:None,local:Some(path),replace:false,hash:1};
                let result=run(&mut channel,op,65535,Duration::from_millis(100)).await;
                assert!(if length==0 {matches!(result,Err(Error::Timeout))}else{matches!(result,Err(Error::Limit))});
                task.await.unwrap();
                assert_eq!(std::fs::read_dir(&dir).unwrap().count(),0);
                assert!(pair.client.close_reason().is_none());
                drop(channel);
                std::fs::remove_dir_all(dir).unwrap();
            }).await.unwrap();
        }
    }
}
