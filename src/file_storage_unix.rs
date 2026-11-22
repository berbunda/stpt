//! Unix storage authority and native publication for the shared file worker.
use crate::cbor::Value;
use crate::file_protocol::{self as p, Status};
use crate::file_worker::{Error, abort};
use nix::fcntl::{AtFlags, OFlag, openat, renameat};
use nix::sys::stat::{Mode, fstatat, mkdirat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use std::os::unix::{ffi::OsStringExt, fs::MetadataExt};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    path::PathBuf,
};
impl From<nix::errno::Errno> for Error {
    fn from(e: nix::errno::Errno) -> Self {
        std::io::Error::from(e).into()
    }
}
pub type Target = PathBuf;
pub fn io_status(e: &std::io::Error) -> Status {
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
pub fn target(value: &Value, root: bool) -> Result<Target, Error> {
    p::validate_path_shape(value)?;
    let a = value.as_array().unwrap();
    if a[0].as_uint() != Some(0) {
        return Err(Error::Status(Status::Unsupported));
    }
    let names = a[1].as_array().unwrap();
    if !p::valid_path_contents(value, root)? {
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
    posix_metadata(kind, m.len(), m.mtime(), m.mtime_nsec(), m.mode())
}
fn posix_metadata(kind: u64, size: u64, seconds: i64, nanos: i64, mode: u32) -> Value {
    let mut f = vec![(Value::Uint(0), Value::Uint(kind))];
    if kind == 1 {
        f.push((Value::Uint(1), Value::Uint(size)));
    }
    if (0..1_000_000_000).contains(&nanos) {
        let sec = if seconds >= 0 {
            Value::Uint(seconds as u64)
        } else {
            Value::Nint((-1 - seconds) as u64)
        };
        f.push((
            Value::Uint(2),
            Value::Array(vec![sec, Value::Uint(nanos as u64)]),
        ));
    }
    f.push((Value::Uint(3), Value::Uint(u64::from(mode & 0o777))));
    Value::Map(f)
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
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
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

pub fn stat(path: &Target) -> Result<Value, Error> {
    Ok(metadata(&std::fs::symlink_metadata(path)?))
}
pub fn list(
    path: &Target,
    mut emit: impl FnMut(Value, Value) -> Result<(), Error>,
) -> Result<(), Error> {
    // Pin the directory so entry metadata cannot be redirected by a rename.
    let mut directory = nix::dir::Dir::open(
        path,
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
        let meta = posix_metadata(
            kind,
            stat.st_size as u64,
            stat.st_mtime,
            stat.st_mtime_nsec,
            stat.st_mode,
        );
        emit(Value::Bytes(name.to_vec()), meta)?;
    }
    Ok(())
}
pub fn mkdir(path: &Target) -> Result<(), Error> {
    let (dir, name) = parent(path)?;
    mkdirat(&dir, name.as_os_str(), Mode::from_bits_truncate(0o777))?;
    Ok(())
}
pub fn remove(path: &Target) -> Result<(), Error> {
    let (dir, name) = parent(path)?;
    let m = fstatat(&dir, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW)?;
    unlinkat(
        &dir,
        name.as_os_str(),
        if m.st_mode & nix::libc::S_IFMT == nix::libc::S_IFDIR {
            UnlinkatFlags::RemoveDir
        } else {
            UnlinkatFlags::NoRemoveDir
        },
    )?;
    Ok(())
}
pub fn rename(path: &Target, dest: &Target, replace: bool) -> Result<(), Error> {
    let (a, an) = parent(path)?;
    let (b, bn) = parent(dest)?;
    if replace {
        renameat(&a, an.as_os_str(), &b, bn.as_os_str())?;
    } else {
        no_replace(&a, an.as_os_str(), &b, bn.as_os_str())?;
    }
    Ok(())
}
pub fn read(path: &Target) -> Result<File, Error> {
    let (dir, name) = parent(path)?;
    let file: File = openat(
        &dir,
        name.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let m = file.metadata()?;
    if !m.is_file() {
        return Err(Error::Status(if m.is_dir() {
            Status::IsDirectory
        } else {
            Status::Unsupported
        }));
    }
    Ok(file)
}
pub struct Upload {
    stage: Staging,
    file: Option<File>,
}
impl Upload {
    pub fn new(path: &Target, replace: bool) -> Result<Self, Error> {
        let (dir, name) = parent(path)?;
        if replace {
            match fstatat(&dir, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW) {
                Ok(_) => return Err(Error::Status(Status::Unsupported)),
                Err(nix::errno::Errno::ENOENT) => {}
                Err(e) => return Err(e.into()),
            }
        }
        let (stage, file) = Staging::new(dir)?;
        Ok(Self {
            stage,
            file: Some(file),
        })
    }
    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().unwrap()
    }
    pub fn verify_parent(&self, path: &Target) -> Result<(), Error> {
        let (dir, _) = parent(path)?;
        let a = dir.metadata()?;
        let b = self.stage.parent.metadata()?;
        if a.dev() != b.dev() || a.ino() != b.ino() {
            return Err(Error::Status(Status::ResumeUnavailable));
        }
        Ok(())
    }
    pub fn publish(&mut self, path: &Target) -> Result<(), Error> {
        use std::io::Write;
        self.file().flush()?;
        nix::unistd::close(self.file.take().unwrap())?;
        self.verify_parent(path)?;
        let (_, name) = parent(path)?;
        no_replace(
            &self.stage.dir,
            OsStr::new("data"),
            &self.stage.parent,
            &name,
        )
    }
}

/// Client publication pins both directories; temporary source names are private.
/// Retained state directories are already private and remain owned by Checkpoint.
pub struct LocalPublication {
    _staging: Option<Staging>,
    source: File,
    target: File,
    name: OsString,
}
impl LocalPublication {
    pub fn new(path: &std::path::Path) -> Result<(Self, File, PathBuf), Error> {
        let absolute = std::path::absolute(path)?;
        let (target, name) = parent(&absolute)?;
        let (stage, file) = Staging::new(target)?;
        let temp = absolute.parent().unwrap().join(&stage.name).join("data");
        let state = Self {
            source: stage.dir.try_clone()?,
            target: stage.parent.try_clone()?,
            name,
            _staging: Some(stage),
        };
        Ok((state, file, temp))
    }
    pub fn retained(
        path: &std::path::Path,
        temp: &std::path::Path,
        existing: bool,
    ) -> Result<(Self, File), Error> {
        let absolute = std::path::absolute(path)?;
        let (target, name) = parent(&absolute)?;
        let (source, source_name) = parent(temp)?;
        let mut flags = OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
        if !existing {
            flags |= OFlag::O_CREAT | OFlag::O_EXCL;
        }
        let file: File = openat(
            &source,
            source_name.as_os_str(),
            flags,
            Mode::from_bits_truncate(0o600),
        )?
        .into();
        let meta = file.metadata()?;
        if !meta.is_file()
            || meta.uid() != nix::unistd::geteuid().as_raw()
            || meta.mode() & 0o077 != 0
        {
            return Err(Error::Status(Status::Access));
        }
        Ok((
            Self {
                source,
                target,
                name,
                _staging: None,
            },
            file,
        ))
    }
    pub fn publish(&mut self, replace: bool) -> Result<(), Error> {
        if replace {
            renameat(&self.source, "data", &self.target, self.name.as_os_str())?;
        } else {
            nix::unistd::linkat(
                &self.source,
                "data",
                &self.target,
                self.name.as_os_str(),
                AtFlags::empty(),
            )?;
            unlinkat(&self.source, "data", UnlinkatFlags::NoRemoveDir)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod review_tests {
    use super::*;
    #[test]
    fn exhaustion_and_permission_errors_have_portable_statuses() {
        for code in [nix::libc::ENOSPC, nix::libc::EDQUOT] {
            assert_eq!(
                io_status(&std::io::Error::from_raw_os_error(code)),
                Status::NoSpace
            );
        }
        assert_eq!(
            io_status(&std::io::Error::from_raw_os_error(nix::libc::EROFS)),
            Status::ReadOnly
        );
        assert_eq!(
            io_status(&std::io::Error::from_raw_os_error(nix::libc::EACCES)),
            Status::Access
        );
    }
}
