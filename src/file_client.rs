//! Explicit Client file operations; peer names are only displayed, never local paths.
use crate::cbor::Value;
use crate::cli::{FsAction, Remote};
use crate::file_checkpoint::Checkpoint;
use crate::file_protocol::{self as p, Status};
use crate::files::Channel;
use crate::wire::{self, Code, Failure, Message, StreamError};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

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
    pub server_identity: Vec<u8>,
    pub max_size: u64,
    resume_state: Option<PathBuf>,
    account: String,
    kind: u64,
    path: OsString,
    destination: Option<OsString>,
    metadata: bool,
    local: Option<PathBuf>,
    replace: bool,
    hash: u64,
}
pub fn split(action: FsAction) -> (Remote, Operation) {
    let metadata = matches!(
        &action,
        FsAction::Stat { metadata: true, .. } | FsAction::List { metadata: true, .. }
    );
    let resume_state = match &action {
        FsAction::Pull { resume_state, .. } | FsAction::Push { resume_state, .. } => {
            resume_state.clone()
        }
        _ => None,
    };
    let (remote, kind, path, destination, local, replace, hash) = match action {
        FsAction::Pull {
            target,
            local,
            replace,
            hash,
            ..
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
            ..
        } => (remote, 2, path, None, Some(local), replace, hash.id()),
        FsAction::Stat { target: t, .. } => (t.remote, 3, t.path, None, None, false, 1),
        FsAction::List { target: t, .. } => (t.remote, 4, t.path, None, None, false, 1),
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
    let account = remote.destination.account.clone();
    (
        remote,
        Operation {
            server_identity: Vec::new(),
            metadata,
            resume_state,
            account,
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
fn remote_path(path: &OsStr) -> Result<Value, Error> {
    #[cfg(unix)]
    let bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_bytes()
    };
    #[cfg(windows)]
    let bytes = path
        .to_str()
        .ok_or(Error::Usage(
            "remote paths must be Unicode scalar text on Windows",
        ))?
        .as_bytes();
    if bytes.starts_with(b"//") {
        return Err(Error::Usage("UNC paths are outside the file profile"));
    }
    if bytes.starts_with(b"/") {
        // Preserve POSIX native bytes, including backslashes and non-UTF-8 names.
        let mut names = Vec::new();
        for name in bytes
            .split(|b| *b == b'/')
            .skip(1)
            .filter(|n| !n.is_empty())
        {
            if !p::valid_posix_component(name) {
                return Err(Error::Usage(
                    "Server path must not contain '.', '..' or NUL",
                ));
            }
            names.push(Value::Bytes(name.to_vec()));
        }
        return Ok(Value::Array(vec![Value::Uint(0), Value::Array(names)]));
    }
    let text = path.to_str().ok_or(Error::Usage(
        "Windows remote paths must be Unicode scalar text",
    ))?;
    let a = text.as_bytes();
    if a.len() < 3 || !a[0].is_ascii_alphabetic() || a[1] != b':' || !matches!(a[2], b'\\' | b'/') {
        return Err(Error::Usage(
            "Server path must be absolute POSIX or a Windows drive path; UNC, device and relative paths are unsupported",
        ));
    }
    let mut names = Vec::new();
    if a.len() > 3 {
        for name in text[3..].split(['\\', '/']) {
            if !p::valid_windows_component(name) {
                return Err(Error::Usage(
                    "invalid Windows path component or reserved device name",
                ));
            }
            names.push(Value::Text(name.to_owned()));
        }
    }
    Ok(Value::Array(vec![
        Value::Uint(1),
        Value::Text((a[0] as char).to_ascii_uppercase().to_string()),
        Value::Array(names),
    ]))
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
        if m.field(2).is_none() {
            return Err(Failure::violation("stat metadata missing").into());
        }
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
    let retained_upload = op.kind == 2 && op.resume_state.is_some();
    let result = perform(ch, op, limit, deadline).await;
    if matches!(&result, Err(Error::Limit)) {
        ch.abort(Code::LimitExceeded);
    }
    if matches!(&result, Err(Error::Timeout)) {
        if retained_upload {
            // Give the Server a bounded chance to observe TIMEOUT and checkpoint
            // before the CLI closes its control Connection with NO_ERROR.
            let _ = ch.send.reset(Code::Timeout.varint());
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                wire::read_message(&mut ch.recv, 65535),
            )
            .await;
        }
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
    let path_value = remote_path(&op.path)?;
    let path_kind = path_value.as_array().unwrap()[0].as_uint().unwrap();
    let mut fields = vec![
        (0, Value::Uint(0)),
        (1, Value::Uint(op.kind)),
        (2, path_value.clone()),
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
    let mut checkpoint = if let Some(dir) = &op.resume_state {
        let local = op.local.as_ref().unwrap();
        let absolute = std::path::absolute(local)?;
        let binding = Value::Array(vec![
            Value::Bytes(op.server_identity.clone()),
            Value::Text(op.account.clone()),
            remote_path(&op.path)?,
            Value::Uint(op.kind),
            Value::Uint(op.hash),
            Value::Bool(op.replace),
            crate::file_checkpoint::local_path(&absolute),
        ]);
        Some(Checkpoint::open(dir, binding)?)
    } else {
        None
    };
    let mut prepared = None;
    if let Some(state) = checkpoint.as_mut() {
        if op.kind == 2 {
            if state.existing && (state.length != length || state.token.is_none()) {
                return Err(Error::Usage(
                    "upload source length changed or resume token missing",
                ));
            }
            let mode = if let Some(t) = &state.token {
                vec![Value::Uint(1), Value::Bytes(t.clone())]
            } else {
                vec![Value::Uint(0)]
            };
            fields.push((7, Value::Array(mode)));
        } else {
            if state.existing && state.offset == 0 {
                return Err(Error::Usage(
                    "no nonempty download checkpoint; choose a new resume-state directory for a fresh transfer",
                ));
            }
            if state.existing && state.token.is_some() {
                return Err(Error::Usage("invalid download resume record"));
            }
            let mut destination =
                Destination::retained(op.local.as_ref().unwrap(), op.replace, state).await?;
            let mut hash = p::Hash::new(op.hash).unwrap();
            let offset = if state.existing { state.offset } else { 0 };
            if offset > op.max_size || state.length > op.max_size {
                return Err(Error::Limit);
            }
            let file = destination.file.as_mut().unwrap();
            if file.metadata().await?.len() < offset {
                return Err(Error::Usage(
                    "local partial file is shorter than checkpoint",
                ));
            }
            file.set_len(offset).await?;
            prefix(file, offset, &mut hash, deadline).await?;
            if offset > 0 {
                fields.push((
                    7,
                    Value::Array(vec![
                        Value::Uint(2),
                        Value::Uint(state.length),
                        Value::Uint(offset),
                        Value::Bytes(hash.clone().finish().to_vec()),
                    ]),
                ));
            }
            prepared = Some((destination, hash, offset));
        }
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
        if p::uint(&first, 2)? != op.hash || (op.kind == 2 && accepted != length) {
            return Err(Failure::violation("invalid transfer acceptance").into());
        }
        if accepted > op.max_size {
            return Err(Error::Limit);
        }
        let resume_requested = checkpoint
            .as_ref()
            .is_some_and(|state| op.kind == 2 || state.offset > 0);
        if resume_requested != first.field(3).is_some() {
            return Err(Failure::violation("missing or unexpected resume acceptance").into());
        }
        let result = if op.kind == 2 {
            let mut file = source.unwrap();
            let mut hash = p::Hash::new(op.hash).unwrap();
            let mut offset = 0;
            if let Some(state) = checkpoint.as_mut() {
                let a = first
                    .field(3)
                    .and_then(Value::as_array)
                    .filter(|a| a.len() == 3)
                    .ok_or_else(|| Failure::violation("invalid upload resume acceptance"))?;
                let Value::Bytes(token) = &a[0] else {
                    return Err(Failure::violation("invalid resume token").into());
                };
                offset = a[1]
                    .as_uint()
                    .filter(|n| *n <= accepted)
                    .ok_or_else(|| Failure::violation("invalid upload resume offset"))?;
                if token.len() != 32
                    || state.token.as_ref().is_some_and(|t| t != token)
                    || (state.token.is_none() && offset != 0)
                {
                    return Err(Failure::violation("inconsistent upload resume acceptance").into());
                }
                if !matches!(&a[2],Value::Bytes(d) if d.len()==32) {
                    return Err(Failure::violation("invalid resume prefix digest").into());
                }
                prefix(&mut file, offset, &mut hash, deadline).await?;
                if a[2] != Value::Bytes(hash.clone().finish().to_vec()) {
                    if state.token.is_none() {
                        return Err(Failure::violation(
                            "fresh upload did not confirm empty prefix",
                        )
                        .into());
                    }
                    state.keep = false;
                    ch.abort(Code::NoError);
                    return Err(Error::Usage(
                        "upload source prefix changed; resume cancelled",
                    ));
                }
                state.keep = false;
                state.token = Some(token.clone());
                state.length = length;
                state.offset = offset;
                state.save()?;
            }
            upload(ch, file, accepted, hash, offset, limit, deadline).await
        } else {
            let (destination, hash, offset) = if let Some(prepared) = prepared {
                prepared
            } else {
                (
                    tokio::time::timeout(
                        deadline,
                        Destination::new(op.local.as_ref().unwrap(), op.replace),
                    )
                    .await
                    .map_err(|_| Error::Timeout)??,
                    p::Hash::new(op.hash).unwrap(),
                    0,
                )
            };
            if resume_requested {
                let state = checkpoint.as_ref().unwrap();
                if accepted != state.length
                    || first.field(3) != Some(&Value::Array(vec![Value::Uint(offset)]))
                {
                    return Err(
                        Failure::violation("inconsistent download resume acceptance").into(),
                    );
                }
            }
            if let Some(state) = checkpoint.as_mut() {
                state.keep = false;
                state.length = accepted;
                state.save()?;
            }
            download(
                ch,
                destination,
                accepted,
                hash,
                offset,
                limit,
                deadline,
                &mut checkpoint,
            )
            .await
        };
        if let Some(state) = checkpoint.as_mut() {
            state.keep = result.as_ref().is_err_and(retain_error);
        }
        return result;
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
            if !p::valid_entry_name(&a[0], path_kind) {
                return Err(
                    Failure::violation("invalid listing component or name representation").into(),
                );
            }
            let metadata = p::validate_metadata(&a[1], path_kind)?;
            let name = match &a[0] {
                Value::Bytes(b) => escape(b),
                Value::Text(t) => escape_text(t),
                _ => unreachable!(),
            };
            println!(
                "{}\t{}\t{}{}",
                kind_name(metadata.kind),
                metadata.size.map_or_else(|| "-".into(), |n| n.to_string()),
                name,
                metadata_columns(&metadata, op.metadata)
            );
        }
        message = receive(ch, deadline).await?;
    }
    final_result(&message, op.kind)?;
    if op.kind == 3 {
        let metadata = p::validate_metadata(message.field(2).unwrap(), path_kind)?;
        println!(
            "{}\t{}{}",
            kind_name(metadata.kind),
            metadata.size.map_or_else(|| "-".into(), |n| n.to_string()),
            metadata_columns(&metadata, op.metadata)
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
fn escape_text(text: &str) -> String {
    let mut output = String::new();
    for c in text.chars() {
        if c.is_control()
            || c == '\\'
            || matches!(c,'\u{61c}'|'\u{200e}'|'\u{200f}'|'\u{2028}'|'\u{2029}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
        {
            output.extend(c.escape_default());
        } else {
            output.push(c);
        }
    }
    output
}
fn metadata_columns(m: &p::Metadata, enabled: bool) -> String {
    if !enabled {
        return String::new();
    }
    // Seconds and fractional nanoseconds stay separate for pre-epoch times.
    let time = m
        .modified
        .map_or_else(|| "-".into(), |(s, n)| format!("[{s},{n:09}]"));
    let mode = m.mode.map_or_else(|| "-".into(), |n| format!("{n:03o}"));
    let readonly = m.readonly.map_or_else(|| "-".into(), |b| b.to_string());
    format!("\t{time}\t{mode}\t{readonly}")
}
async fn upload(
    ch: &mut Channel,
    mut file: tokio::fs::File,
    length: u64,
    mut hash: p::Hash,
    mut count: u64,
    limit: u64,
    deadline: Duration,
) -> Result<(), Error> {
    let sender = async {
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
    persistent: bool,
}
impl Destination {
    async fn retained(path: &Path, replace: bool, state: &Checkpoint) -> Result<Self, Error> {
        if !replace && tokio::fs::symlink_metadata(path).await.is_ok() {
            return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists).into());
        }
        let temp = state.dir.join("data");
        let mut options = tokio::fs::OpenOptions::new();
        options.read(true).write(true);
        if !state.existing {
            options.create_new(true);
        }
        #[cfg(unix)]
        {
            options.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
        }
        let file = options.open(&temp).await?;
        if !file.metadata().await?.is_file() {
            return Err(Error::Usage("resume partial is not a regular file"));
        }
        Ok(Self {
            path: path.to_owned(),
            temp,
            file: Some(file),
            replace,
            persistent: true,
        })
    }

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
                persistent: false,
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
        if !self.persistent
            && let Err(e) = std::fs::remove_file(&self.temp)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(?e, "local download staging cleanup failed");
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn download(
    ch: &mut Channel,
    mut destination: Destination,
    length: u64,
    mut hash: p::Hash,
    mut count: u64,
    limit: u64,
    deadline: Duration,
    checkpoint: &mut Option<Checkpoint>,
) -> Result<(), Error> {
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
            if let Some(state) = checkpoint.as_mut() {
                destination.file.as_mut().unwrap().flush().await?;
                state.offset = count;
                state.save()?;
            }
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

fn retain_error(e: &Error) -> bool {
    matches!(e, Error::Timeout | Error::Stream(StreamError::Lost(_)))
        || matches!(e,Error::Stream(StreamError::Reset(c)) if *c==Code::Timeout.varint())
}
async fn prefix(
    file: &mut tokio::fs::File,
    mut length: u64,
    hash: &mut p::Hash,
    deadline: Duration,
) -> Result<(), Error> {
    file.seek(std::io::SeekFrom::Start(0)).await?;
    let mut buffer = vec![0; p::CHUNK];
    while length > 0 {
        let wanted = length.min(buffer.len() as u64) as usize;
        let n = tokio::time::timeout(deadline, file.read(&mut buffer[..wanted]))
            .await
            .map_err(|_| Error::Timeout)??;
        if n == 0 {
            return Err(Error::Usage("resume prefix is shorter than checkpoint"));
        }
        hash.update(&buffer[..n]);
        length -= n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::{Budget, tests::Pair};
    use std::io::Write;
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
                metadata: false,
                server_identity: Vec::new(),
                resume_state: None,
                account: String::new(),
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
                let op=Operation {metadata:false,server_identity:Vec::new(),resume_state:None,account:String::new(),max_size:p::DEFAULT_MAX_SIZE,kind:1,path:"/source".into(),destination:None,local:Some(path),replace:false,hash:1};
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
    fn resume_operation(kind: u64, local: PathBuf, state: PathBuf) -> Operation {
        Operation {
            metadata: false,
            server_identity: vec![11; 44],
            max_size: p::DEFAULT_MAX_SIZE,
            resume_state: Some(state),
            account: "account".into(),
            kind,
            path: "/remote".into(),
            destination: None,
            local: Some(local),
            replace: false,
            hash: 1,
        }
    }
    async fn mock_open(
        server: &quinn::Connection,
    ) -> (quinn::SendStream, quinn::RecvStream, Message) {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        wire::read_message(&mut recv, 65535).await.unwrap();
        wire::write_message(&mut send, &Message::new(wire::FILES_READY, vec![]), 65535)
            .await
            .unwrap();
        let q = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
        (send, recv, q)
    }
    #[tokio::test]
    async fn download_timeout_retains_only_checkpoint_then_resumes_full_hash() {
        tokio::time::timeout(Duration::from_secs(5),async {
            let dir=directory("resume-download");let local=dir.join("destination");let state=dir.join("state");
            for attempt in 0..2 {
                let pair=Pair::start().await;let server=pair.server.clone();
                let task=tokio::spawn(async move {
                    let(mut send,mut recv,q)=mock_open(&server).await;
                    let mut h=p::Hash::new(1).unwrap();h.update(b"abc");
                    let mut accepted=p::accepted(0,6,1);
                    if attempt==0 {assert!(q.field(7).is_none());}else{
                        assert_eq!(q.field(7),Some(&Value::Array(vec![Value::Uint(2),Value::Uint(6),Value::Uint(3),Value::Bytes(h.clone().finish().to_vec())])));
                        accepted.body.push((Value::Uint(3),Value::Array(vec![Value::Uint(3)])));
                    }
                    wire::write_message(&mut send,&accepted,65535).await.unwrap();
                    wire::write_message(&mut send,&p::data(0,if attempt==0{0}else{3},if attempt==0{b"abc".to_vec()}else{b"def".to_vec()}),65535).await.unwrap();
                    if attempt==0 {assert!(matches!(wire::read_message(&mut recv,65535).await,Err(StreamError::Reset(c)) if c==Code::Timeout.varint()));}
                    else {
                        h.update(b"def");wire::write_message(&mut send,&p::end(0,Status::Ok,6,Some(h.finish())),65535).await.unwrap();
                        let m=wire::read_message(&mut recv,65535).await.unwrap().unwrap();assert_eq!(p::status(&m).unwrap(),Status::Ok);
                        wire::write_message(&mut send,&p::result(0,Status::Ok,None),65535).await.unwrap();
                        let _=wire::read_message(&mut recv,65535).await;
                    }
                });
                let budget=Budget::new(1);let mut channel=Channel::open(&pair.client,65535,&budget,Duration::from_secs(1)).await.unwrap();
                let result=run(&mut channel,resume_operation(1,local.clone(),state.clone()),65535,Duration::from_millis(100)).await;
                if attempt==0 {
                    assert!(matches!(result,Err(Error::Timeout)));assert!(!local.exists());assert_eq!(std::fs::read(state.join("data")).unwrap(),b"abc");
                    // Bytes beyond a persisted complete-message checkpoint must be trimmed.
                    std::fs::OpenOptions::new().append(true).open(state.join("data")).unwrap().write_all(b"unconfirmed").unwrap();
                }else{result.unwrap();assert_eq!(std::fs::read(&local).unwrap(),b"abcdef");assert!(!state.join("record").exists());}
                drop(channel);task.await.unwrap();
            }
            std::fs::remove_dir_all(dir).unwrap();
        }).await.unwrap();
    }
    #[tokio::test]
    async fn upload_explicit_resume_uses_server_offset_and_cancels_changed_prefix() {
        for mismatch in [false, true] {
            let dir = directory(if mismatch {
                "resume-upload-mismatch"
            } else {
                "resume-upload"
            });
            let source = dir.join("source");
            let state = dir.join("state");
            std::fs::write(&source, b"abcdef").unwrap();
            for attempt in 0..2 {
                let pair = Pair::start().await;
                let server = pair.server.clone();
                let task = tokio::spawn(async move {
                    let (mut send, mut recv, q) = mock_open(&server).await;
                    let token = Value::Bytes(vec![5; 32]);
                    assert_eq!(
                        q.field(7),
                        Some(&Value::Array(if attempt == 0 {
                            vec![Value::Uint(0)]
                        } else {
                            vec![Value::Uint(1), token.clone()]
                        }))
                    );
                    let mut h = p::Hash::new(1).unwrap();
                    if attempt == 1 {
                        h.update(if mismatch { b"bad" } else { b"abc" });
                    }
                    let mut accepted = p::accepted(0, 6, 1);
                    accepted.body.push((
                        Value::Uint(3),
                        Value::Array(vec![
                            token,
                            Value::Uint(if attempt == 0 { 0 } else { 3 }),
                            Value::Bytes(h.clone().finish().to_vec()),
                        ]),
                    ));
                    wire::write_message(&mut send, &accepted, 65535)
                        .await
                        .unwrap();
                    if attempt == 1 && mismatch {
                        assert!(
                            matches!(wire::read_message(&mut recv,65535).await,Err(StreamError::Reset(c)) if c==Code::NoError.varint())
                        );
                        return;
                    }
                    let mut count = if attempt == 0 { 0 } else { 3 };
                    loop {
                        let m = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
                        if m.kind == p::DATA {
                            let b = p::bytes(&m, 0, count, 6).unwrap();
                            h.update(b);
                            count += b.len() as u64;
                        } else {
                            assert_eq!(
                                p::verify_end(&m, 0, count, 6, h.finish()).unwrap(),
                                Status::Ok
                            );
                            break;
                        }
                    }
                    if attempt == 0 {
                        send.reset(Code::Timeout.varint()).unwrap();
                        let _ = recv.stop(Code::Timeout.varint());
                    } else {
                        wire::write_message(&mut send, &p::result(0, Status::Ok, None), 65535)
                            .await
                            .unwrap();
                        let _ = wire::read_message(&mut recv, 65535).await;
                    }
                });
                let budget = Budget::new(1);
                let mut channel =
                    Channel::open(&pair.client, 65535, &budget, Duration::from_secs(1))
                        .await
                        .unwrap();
                let result = run(
                    &mut channel,
                    resume_operation(2, source.clone(), state.clone()),
                    65535,
                    Duration::from_secs(1),
                )
                .await;
                if attempt == 0 {
                    assert!(result.is_err());
                    assert!(state.join("record").exists());
                } else if mismatch {
                    assert!(matches!(result, Err(Error::Usage(_))));
                    assert!(!state.join("record").exists());
                } else {
                    result.unwrap();
                    assert!(!state.join("record").exists());
                }
                drop(channel);
                task.await.unwrap();
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }
    #[test]
    fn cli_path_encoding_and_metadata_display_are_lossless() {
        let path = remote_path(OsStr::new("c:\\Data\\東京\\é.txt")).unwrap();
        assert_eq!(
            path,
            Value::Array(vec![
                Value::Uint(1),
                Value::Text("C".into()),
                Value::Array(vec![
                    Value::Text("Data".into()),
                    Value::Text("東京".into()),
                    Value::Text("é.txt".into())
                ])
            ])
        );
        assert_eq!(remote_path(OsStr::new("C:/Data/東京/é.txt")).unwrap(), path);
        assert_eq!(
            remote_path(OsStr::new("z:\\")).unwrap(),
            Value::Array(vec![
                Value::Uint(1),
                Value::Text("Z".into()),
                Value::Array(vec![])
            ])
        );
        for bad in [
            "relative",
            "C:file",
            "\\root",
            "\\\\host\\share",
            "//host/share",
            "\\\\?\\C:\\file",
            "\\\\.\\NUL",
            "C:\\NUL.txt",
            "C:\\a:stream",
            "C:\\a.",
            "C:\\a\\..\\b",
            "C:\\a\\\\b",
        ] {
            assert!(remote_path(OsStr::new(bad)).is_err(), "{bad:?}");
        }
        let a = remote_path(OsStr::new("C:\\é")).unwrap();
        let b = remote_path(OsStr::new("C:\\e\u{301}")).unwrap();
        assert_ne!(a, b);
        assert_eq!(escape_text("東京é"), "東京é");
        assert_eq!(
            escape_text("\u{61c}\u{200e}\u{200f}"),
            "\\u{61c}\\u{200e}\\u{200f}"
        );
        assert_eq!(escape_text("x\u{202e}y"), "x\\u{202e}y");
        let m = p::Metadata {
            kind: 1,
            size: Some(3),
            modified: Some((-1, 500000000)),
            mode: Some(0o640),
            readonly: None,
        };
        assert_eq!(metadata_columns(&m, true), "\t[-1,500000000]\t640\t-");
        assert_eq!(metadata_columns(&m, false), "");
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let name = OsString::from_vec(vec![b'/', b't', b'/', 0xff, b'\\']);
            assert_eq!(
                remote_path(&name).unwrap(),
                Value::Array(vec![
                    Value::Uint(0),
                    Value::Array(vec![
                        Value::Bytes(vec![b't']),
                        Value::Bytes(vec![0xff, b'\\'])
                    ])
                ])
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            assert!(remote_path(&OsString::from_wide(&[67, 58, 92, 0xd800])).is_err());
        }
    }
    #[tokio::test]
    async fn windows_listing_accepts_text_metadata_and_rejects_foreign_attributes() {
        for bad in [false, true] {
            let pair = Pair::start().await;
            let server = pair.server.clone();
            let task = tokio::spawn(async move {
                let (mut send, mut recv, q) = mock_open(&server).await;
                assert_eq!(q.field(2).unwrap().as_array().unwrap()[0], Value::Uint(1));
                let meta = Value::Map(vec![
                    (Value::Uint(0), Value::Uint(1)),
                    (Value::Uint(1), Value::Uint(42)),
                    (
                        Value::Uint(if bad { 3 } else { 4 }),
                        if bad {
                            Value::Uint(0o600)
                        } else {
                            Value::Bool(true)
                        },
                    ),
                ]);
                let entry = Value::Array(vec![Value::Text("東京.txt".into()), meta]);
                wire::write_message(
                    &mut send,
                    &Message::new(
                        p::ENTRIES,
                        vec![(0, Value::Uint(0)), (1, Value::Array(vec![entry]))],
                    ),
                    65535,
                )
                .await
                .unwrap();
                if !bad {
                    wire::write_message(&mut send, &p::result(0, Status::Ok, None), 65535)
                        .await
                        .unwrap();
                }
                let _ = wire::read_message(&mut recv, 65535).await;
            });
            let budget = Budget::new(1);
            let mut channel = Channel::open(&pair.client, 65535, &budget, Duration::from_secs(1))
                .await
                .unwrap();
            let op = Operation {
                server_identity: Vec::new(),
                max_size: p::DEFAULT_MAX_SIZE,
                resume_state: None,
                account: "a".into(),
                kind: 4,
                path: "C:\\Data".into(),
                destination: None,
                local: None,
                replace: false,
                hash: 1,
                metadata: true,
            };
            let result = run(&mut channel, op, 65535, Duration::from_secs(1)).await;
            if bad {
                assert!(matches!(result, Err(Error::Protocol(_))));
            } else {
                result.unwrap();
            }
            drop(channel);
            task.await.unwrap();
        }
    }
}
