//! Blocking filesystem worker. The Server execs this binary with Account credentials.
//! All filesystem checks and mutations, including cleanup, use these credentials.
use crate::cbor::Value;
use crate::file_protocol::{self as p, Request, Status};
use crate::wire::{Code, Failure, Message};
use nix::fcntl::{AtFlags, OFlag, openat, renameat};
use nix::sys::stat::{Mode, fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::ExitCode;

enum Error {
    Failure(Failure),
    Status(Status),
}
impl From<Failure> for Error {
    fn from(f: Failure) -> Self {
        Self::Failure(f)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Status(io_status(&e))
    }
}
impl From<nix::errno::Errno> for Error {
    fn from(e: nix::errno::Errno) -> Self {
        std::io::Error::from(e).into()
    }
}
fn io_status(e: &std::io::Error) -> Status {
    use nix::errno::Errno::*;
    match e.raw_os_error().map(nix::errno::Errno::from_raw) {
        Some(ENOENT) => Status::NotFound,
        Some(EACCES | EPERM) => Status::Access,
        Some(EEXIST) => Status::Exists,
        Some(ENOTDIR) => Status::NotDirectory,
        Some(EISDIR) => Status::IsDirectory,
        Some(ENOTEMPTY) => Status::NotEmpty,
        Some(ENOSPC | EDQUOT) => Status::NoSpace,
        Some(EROFS) => Status::ReadOnly,
        Some(ENAMETOOLONG | EINVAL) => Status::InvalidPath,
        Some(ELOOP | ENOSYS | EOPNOTSUPP | EXDEV) => Status::Unsupported,
        _ => Status::Io,
    }
}
fn abort(reason: &str) -> Error {
    Failure::new(Code::InternalError, reason).into()
}

pub fn main() -> ExitCode {
    let args: Vec<_> = std::env::args().collect();
    let Some(peer_limit) = args
        .get(2)
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 65535)
    else {
        return ExitCode::from(255);
    };
    let Some(max_size) = args
        .get(3)
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n <= p::MAX_SIZE)
    else {
        return ExitCode::from(255);
    };
    let (mut input, mut output) = (std::io::stdin().lock(), std::io::stdout().lock());
    let mut last = None;
    let run = (|| -> Result<(), Error> {
        while let Some(message) = p::read_ipc(&mut input)? {
            let request = Request::parse(&message)?;
            if last.is_none() && request.id != 0 || last.is_some_and(|id| request.id <= id) {
                return Err(Failure::violation(
                    "file operation ID not strictly increasing from zero",
                )
                .into());
            }
            last = Some(request.id);
            let id = request.id;
            match handle(
                request,
                &mut input,
                &mut output,
                peer_limit.min(65535),
                max_size,
            ) {
                Ok(()) => {}
                Err(Error::Status(status)) => {
                    send(&mut output, &p::result(id, status, None), peer_limit)?
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    })();
    if let Err(e) = run {
        let failure = match e {
            Error::Failure(f) => f,
            Error::Status(_) => Failure::new(Code::InternalError, "file worker I/O"),
        };
        let _ = p::write_ipc(
            &mut output,
            &Message::new(0, vec![(0, Value::Uint(failure.code as u64))]),
        );
        return ExitCode::from(255);
    }
    ExitCode::SUCCESS
}
fn send(w: &mut impl Write, m: &Message, limit: u64) -> Result<(), Error> {
    if m.encode().len() as u64 > limit {
        return Err(Error::Status(Status::Limit));
    }
    p::write_ipc(w, m).map_err(|_| abort("worker output closed"))
}
fn next(r: &mut impl Read) -> Result<Message, Error> {
    p::read_ipc(r)?.ok_or_else(|| abort("file Channel interrupted"))
}
fn native(value: &Value, root: bool) -> Result<PathBuf, Error> {
    p::validate_path_shape(value)?;
    let a = value.as_array().unwrap();
    if a[0].as_uint() != Some(0) {
        return Err(Error::Status(Status::Unsupported));
    }
    let names = a[1].as_array().unwrap();
    if names.is_empty() && !root {
        return Err(Error::Status(Status::InvalidPath));
    }
    let mut path = PathBuf::from("/");
    for name in names {
        let Value::Bytes(b) = name else {
            unreachable!()
        };
        if !p::valid_posix_component(b) {
            return Err(Error::Status(Status::InvalidPath));
        }
        path.push(OsString::from_vec(b.clone()));
    }
    Ok(path)
}
fn parent(path: &std::path::Path) -> Result<(File, OsString), Error> {
    // O_PATH does not require directory read permission; actual operations still
    // perform native search/write checks with Account credentials.
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(target_os = "linux")]
    let flags = nix::libc::O_PATH | nix::libc::O_DIRECTORY;
    #[cfg(not(target_os = "linux"))]
    let flags = nix::libc::O_DIRECTORY;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(flags)
        .open(path.parent().ok_or(Error::Status(Status::InvalidPath))?)?;
    Ok((
        directory,
        path.file_name()
            .ok_or(Error::Status(Status::InvalidPath))?
            .to_owned(),
    ))
}
fn metadata(m: &std::fs::Metadata) -> Value {
    let kind = if m.file_type().is_symlink() {
        3
    } else if m.is_file() {
        1
    } else if m.is_dir() {
        2
    } else {
        0
    };
    let mut f = vec![(Value::Uint(0), Value::Uint(kind))];
    if kind == 1 {
        f.push((Value::Uint(1), Value::Uint(m.len())));
    }
    Value::Map(f)
}
fn handle(
    q: Request,
    r: &mut impl Read,
    w: &mut impl Write,
    limit: u64,
    max_size: u64,
) -> Result<(), Error> {
    if q.resume || !(1..=7).contains(&q.kind) {
        return Err(Error::Status(Status::Unsupported));
    }
    let path = native(&q.path, matches!(q.kind, 3 | 4))?;
    match q.kind {
        1 => download(&q, &path, r, w, limit, max_size),
        2 => upload(&q, &path, r, w, limit, max_size),
        3 => {
            let m = std::fs::symlink_metadata(path)?;
            send(w, &p::result(q.id, Status::Ok, Some(metadata(&m))), limit)
        }
        4 => {
            // Pin the directory so entry metadata cannot be redirected by a rename.
            let mut directory = nix::dir::Dir::open(
                &path,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?;
            // A separate descriptor remains usable while Dir's iterator borrows it.
            let fd = nix::unistd::dup(&directory)?;
            for entry in directory.iter() {
                let entry = entry?;
                let name = entry.file_name().to_bytes();
                if name == b"." || name == b".." {
                    continue;
                }
                let stat = fstatat(&fd, entry.file_name(), AtFlags::AT_SYMLINK_NOFOLLOW)?;
                let kind = match stat.st_mode & nix::libc::S_IFMT {
                    nix::libc::S_IFREG => 1,
                    nix::libc::S_IFDIR => 2,
                    nix::libc::S_IFLNK => 3,
                    _ => 0,
                };
                let mut fields = vec![(Value::Uint(0), Value::Uint(kind))];
                if kind == 1 {
                    fields.push((Value::Uint(1), Value::Uint(stat.st_size as u64)));
                }
                let message = Message::new(
                    p::ENTRIES,
                    vec![
                        (0, Value::Uint(q.id)),
                        (
                            1,
                            Value::Array(vec![Value::Array(vec![
                                Value::Bytes(name.to_vec()),
                                Value::Map(fields),
                            ])]),
                        ),
                    ],
                );
                send(w, &message, limit)?;
            }
            send(w, &p::result(q.id, Status::Ok, None), limit)
        }
        5 => {
            let (dir, name) = parent(&path)?;
            mkdirat(&dir, name.as_os_str(), Mode::from_bits_truncate(0o777))?;
            send(w, &p::result(q.id, Status::Ok, None), limit)
        }
        6 => {
            let (dir, name) = parent(&path)?;
            let m = fstatat(&dir, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)?;
            let flag = if m.st_mode & nix::libc::S_IFMT == nix::libc::S_IFDIR {
                UnlinkatFlags::RemoveDir
            } else {
                UnlinkatFlags::NoRemoveDir
            };
            unlinkat(&dir, name.as_os_str(), flag)?;
            send(w, &p::result(q.id, Status::Ok, None), limit)
        }
        7 => {
            let dest = native(q.destination.as_ref().unwrap(), false)?;
            let (a, an) = parent(&path)?;
            let (b, bn) = parent(&dest)?;
            if q.replace {
                renameat(&a, an.as_os_str(), &b, bn.as_os_str())?;
            } else {
                no_replace(&a, an.as_os_str(), &b, bn.as_os_str())?;
            }
            send(w, &p::result(q.id, Status::Ok, None), limit)
        }
        _ => unreachable!(),
    }
}
fn no_replace(a: &File, an: &OsStr, b: &File, bn: &OsStr) -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        match nix::fcntl::renameat2(a, an, b, bn, nix::fcntl::RenameFlags::RENAME_NOREPLACE) {
            Ok(()) => {}
            Err(
                nix::errno::Errno::EINVAL
                | nix::errno::Errno::ENOSYS
                | nix::errno::Errno::EOPNOTSUPP
                | nix::errno::Errno::EXDEV,
            ) => return Err(Error::Status(Status::Unsupported)),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (a, an, b, bn);
        Err(Error::Status(Status::Unsupported))
    }
}
struct Staging {
    parent: File,
    name: OsString,
    dir: File,
}
impl Staging {
    fn new(parent: File) -> Result<(Self, File), Error> {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let mut random = [0u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| abort("staging randomness"))?;
        let name = OsString::from(format!(
            ".stpt-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        mkdirat(&parent, name.as_os_str(), Mode::from_bits_truncate(0o700))?;
        let directory = openat(
            &parent,
            name.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        );
        let dir: File = match directory {
            Ok(fd) => fd.into(),
            Err(error) => {
                if let Err(e) = unlinkat(&parent, name.as_os_str(), UnlinkatFlags::RemoveDir) {
                    eprintln!("stpt file worker: staging setup cleanup failed: {e}");
                }
                return Err(error.into());
            }
        };
        let staging = Self { parent, name, dir };
        if staging.dir.metadata()?.mode() & 0o077 != 0 {
            return Err(Error::Status(Status::Unsupported));
        }
        let file: File = openat(
            &staging.dir,
            "data",
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )?
        .into();
        if file.metadata()?.mode() & 0o077 != 0 {
            return Err(Error::Status(Status::Unsupported));
        }
        Ok((staging, file))
    }
}
impl Drop for Staging {
    fn drop(&mut self) {
        if let Err(e) = unlinkat(&self.dir, "data", UnlinkatFlags::NoRemoveDir)
            && e != nix::errno::Errno::ENOENT
        {
            eprintln!("stpt file worker: staging cleanup failed: {e}");
        }
        if let Err(e) = unlinkat(
            &self.parent,
            self.name.as_os_str(),
            UnlinkatFlags::RemoveDir,
        ) {
            eprintln!("stpt file worker: staging directory cleanup failed: {e}");
        }
    }
}
fn upload(
    q: &Request,
    path: &std::path::Path,
    r: &mut impl Read,
    w: &mut impl Write,
    limit: u64,
    max_size: u64,
) -> Result<(), Error> {
    let length = q.length.unwrap();
    if length > max_size {
        return Err(Error::Status(Status::Limit));
    }
    let mut hash = p::Hash::new(q.algorithm).ok_or(Error::Status(Status::Unsupported))?;
    let (dir, name) = parent(path)?;
    if q.replace {
        match fstatat(&dir, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
            // POSIX has no conditional rename that both replaces and requires a
            // regular destination at the mutation. Refuse rather than race it.
            Ok(_) => return Err(Error::Status(Status::Unsupported)),
            Err(nix::errno::Errno::ENOENT) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let (stage, mut file) = Staging::new(dir)?;
    send(w, &p::accepted(q.id, length, q.algorithm), limit)?;
    let mut count = 0;
    let status = loop {
        let m = next(r)?;
        if m.kind == p::DATA {
            let bytes = p::bytes(&m, q.id, count, length)?;
            file.write_all(bytes).map_err(|error| {
                let code = if io_status(&error) == Status::NoSpace {
                    Code::LimitExceeded
                } else {
                    Code::InternalError
                };
                Error::Failure(Failure::new(code, "staging write failed"))
            })?;
            hash.update(bytes);
            count += bytes.len() as u64;
        } else {
            break p::verify_end(&m, q.id, count, length, hash.finish())?;
        }
    };
    if status != Status::Ok {
        return send(w, &p::result(q.id, status, None), limit);
    }
    file.flush()?;
    nix::unistd::close(file)?;
    no_replace(&stage.dir, OsStr::new("data"), &stage.parent, &name)?;
    send(w, &p::result(q.id, Status::Ok, None), limit)
}
fn download(
    q: &Request,
    path: &std::path::Path,
    r: &mut impl Read,
    w: &mut impl Write,
    limit: u64,
    max_size: u64,
) -> Result<(), Error> {
    let mut hash = p::Hash::new(q.algorithm).ok_or(Error::Status(Status::Unsupported))?;
    let (dir, name) = parent(path)?;
    let mut file: File = openat(
        &dir,
        name.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::Status(if metadata.is_dir() {
            Status::IsDirectory
        } else {
            Status::Unsupported
        }));
    }
    let length = metadata.len();
    if length > max_size || length > p::MAX_SIZE {
        return Err(Error::Status(Status::Limit));
    }
    send(w, &p::accepted(q.id, length, q.algorithm), limit)?;
    let mut count = 0;
    let mut buffer = vec![0; p::CHUNK];
    let mut status = Status::Ok;
    while count < length {
        let wanted = ((length - count).min(buffer.len() as u64)) as usize;
        match file.read(&mut buffer[..wanted]) {
            Ok(0) | Err(_) => {
                status = Status::Io;
                break;
            }
            Ok(n) => {
                hash.update(&buffer[..n]);
                send(w, &p::data(q.id, count, buffer[..n].to_vec()), limit)?;
                count += n as u64;
            }
        }
    }
    send(
        w,
        &p::end(
            q.id,
            status,
            count,
            (status == Status::Ok).then(|| hash.finish()),
        ),
        limit,
    )?;
    let receipt = next(r)?;
    if receipt.kind != p::RECEIVED {
        return Err(Failure::violation("expected FILE_RECEIVED").into());
    }
    p::id(&receipt, q.id)?;
    let received = p::status(&receipt)?;
    let status = if received == Status::Integrity {
        received
    } else if status != Status::Ok {
        status
    } else {
        received
    };
    send(w, &p::result(q.id, status, None), limit)
}
