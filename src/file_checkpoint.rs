//! Explicit private Client resume directory, locked across concurrent invocations.
use crate::cbor::Value;
use crate::file_client::Error;
use crate::file_protocol as p;
use crate::wire::Message;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub struct Checkpoint {
    pub dir: PathBuf,
    pub length: u64,
    pub offset: u64,
    pub token: Option<Vec<u8>>,
    pub existing: bool,
    pub keep: bool,
    binding: Value,
    _lock: File,
}
fn private_open(path: &Path) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600).custom_flags(nix::libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        if path.try_exists()? {
            protect(path)?;
        }
        o.custom_flags(0x00200000);
    }
    let file = o.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("resume record is not a regular file"));
    }
    Ok(file)
}
/// Restrict resume state to the owner and SYSTEM, with a protected DACL.
/// Apply via an opened non-reparse handle, not a check followed by a path update.
#[cfg(windows)]
fn protect(path: &Path) -> std::io::Result<()> {
    use std::os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            SetKernelObjectSecurity,
        },
    };
    let file = OpenOptions::new()
        .access_mode(0x00060080)
        .custom_flags(0x02200000)
        .open(path)?;
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(std::io::Error::other(
            "resume state cannot use reparse points",
        ));
    }
    let sddl: Vec<u16> = "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: valid NUL-terminated SDDL, initialized output pointer; allocation
    // is owned here until LocalFree after the synchronous kernel call.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let ok = SetKernelObjectSecurity(
            file.as_raw_handle(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        let result = if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        };
        LocalFree(descriptor);
        result
    }
}
pub fn local_path(path: &Path) -> Value {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Value::Bytes(path.as_os_str().as_bytes().to_vec())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        Value::Bytes(
            path.as_os_str()
                .encode_wide()
                .flat_map(u16::to_le_bytes)
                .collect(),
        )
    }
}
impl Checkpoint {
    pub fn open(dir: &Path, binding: Value) -> Result<Self, Error> {
        #[allow(unused_mut)]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
        let meta = std::fs::symlink_metadata(dir)?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err(Error::Usage("resume state must be a private directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.mode() & 0o077 != 0 || meta.uid() != nix::unistd::geteuid().as_raw() {
                return Err(Error::Usage(
                    "resume directory must be owned by this user with mode 0700",
                ));
            }
        }
        #[cfg(windows)]
        protect(dir)?;
        let lock = private_open(&dir.join("lock"))?;
        lock.try_lock()
            .map_err(|_| Error::Usage("resume state is already in use"))?;
        let mut state = Self {
            dir: dir.to_owned(),
            length: 0,
            offset: 0,
            token: None,
            existing: false,
            keep: true,
            binding,
            _lock: lock,
        };
        let record = dir.join("record");
        if record.try_exists()? {
            let mut f = private_open(&record)?;
            if f.metadata()?.len() > 65535 {
                return Err(Error::Usage("invalid resume record"));
            }
            let mut bytes = Vec::new();
            f.read_to_end(&mut bytes)?;
            let m = Message::decode(&bytes).map_err(|_| Error::Usage("invalid resume record"))?;
            if m.kind != 1 || m.field(0) != Some(&state.binding) {
                return Err(Error::Usage(
                    "resume state belongs to different Server Identity, Account, paths or transfer parameters",
                ));
            }
            state.length = p::size(&m, 1)?;
            state.offset = p::size(&m, 2)?;
            if state.offset > state.length {
                return Err(Error::Usage("invalid resume checkpoint"));
            }
            state.token = match m.field(3) {
                None => None,
                Some(Value::Bytes(v)) if v.len() == 32 => Some(v.clone()),
                _ => return Err(Error::Usage("invalid resume record")),
            };
            state.existing = true;
        } else {
            if dir.join("data").try_exists()? || dir.join("record.new").try_exists()? {
                return Err(Error::Usage(
                    "resume directory contains unrecognized state; use a new private directory",
                ));
            }
            state.keep = false;
        }
        Ok(state)
    }
    pub fn save(&mut self) -> Result<(), Error> {
        let mut fields = vec![
            (0, self.binding.clone()),
            (1, Value::Uint(self.length)),
            (2, Value::Uint(self.offset)),
        ];
        if let Some(t) = &self.token {
            fields.push((3, Value::Bytes(t.clone())));
        }
        let path = self.dir.join("record.new");
        let mut f = private_open(&path)?;
        f.set_len(0)?;
        f.write_all(&Message::new(1, fields).encode())?;
        f.flush()?;
        drop(f);
        std::fs::rename(path, self.dir.join("record"))?;
        self.existing = true;
        Ok(())
    }
}
impl Drop for Checkpoint {
    fn drop(&mut self) {
        if !self.keep {
            for name in ["data", "record", "record.new"] {
                if let Err(e) = std::fs::remove_file(self.dir.join(name))
                    && e.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(?e, "resume state cleanup failed");
                }
            }
        }
        // Keep the directory and lock inode: unlinking a lock can split locking
        // between a waiter holding the old inode and a newly arriving process.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binding_lock_and_unknown_data_are_preserved() {
        let dir = std::env::temp_dir().join(format!("stpt-checkpoint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let binding = Value::Text("identity/account/paths/hash".into());
        {
            let mut state = Checkpoint::open(&dir, binding.clone()).unwrap();
            assert!(Checkpoint::open(&dir, binding.clone()).is_err());
            state.length = 10;
            state.offset = 3;
            state.token = Some(vec![7; 32]);
            state.save().unwrap();
            state.keep = true;
        }
        assert!(Checkpoint::open(&dir, Value::Null).is_err());
        {
            let mut state = Checkpoint::open(&dir, binding.clone()).unwrap();
            assert_eq!(state.offset, 3);
            state.keep = false;
        }
        assert!(!dir.join("record").exists());
        std::fs::write(dir.join("data"), b"unrelated").unwrap();
        assert!(Checkpoint::open(&dir, binding).is_err());
        assert_eq!(std::fs::read(dir.join("data")).unwrap(), b"unrelated");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
