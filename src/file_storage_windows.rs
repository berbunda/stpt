//! Windows storage: local volume GUID paths, pinned non-reparse ancestors and
//! private delete-on-close staging. All access uses the inherited Account token.
use crate::{
    cbor::Value,
    file_protocol::{self as p, Status},
    file_worker::{Error, abort},
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, IntoRawHandle},
    },
    path::{Path, PathBuf},
};
use windows_sys::Wdk::Storage::FileSystem as nt;
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::WindowsProgramming::{DRIVE_CDROM, DRIVE_FIXED, DRIVE_RAMDISK, DRIVE_REMOVABLE},
};
fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}
fn os_error() -> Error {
    io::Error::last_os_error().into()
}
pub fn io_status(e: &io::Error) -> Status {
    match e.raw_os_error().map(|n| n as u32) {
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_INVALID_DRIVE) => Status::NotFound,
        Some(
            ERROR_ACCESS_DENIED
            | ERROR_PRIVILEGE_NOT_HELD
            | ERROR_SHARING_VIOLATION
            | ERROR_LOCK_VIOLATION,
        ) => Status::Access,
        Some(ERROR_ALREADY_EXISTS | ERROR_FILE_EXISTS) => Status::Exists,
        Some(ERROR_DIRECTORY) => Status::NotDirectory,
        Some(ERROR_DIR_NOT_EMPTY) => Status::NotEmpty,
        Some(ERROR_DISK_FULL | ERROR_HANDLE_DISK_FULL | ERROR_DISK_QUOTA_EXCEEDED) => {
            Status::NoSpace
        }
        Some(ERROR_WRITE_PROTECT) => Status::ReadOnly,
        Some(ERROR_INVALID_NAME | ERROR_FILENAME_EXCED_RANGE | ERROR_BAD_PATHNAME) => {
            Status::InvalidPath
        }
        Some(
            ERROR_NOT_SUPPORTED
            | ERROR_INVALID_FUNCTION
            | ERROR_NOT_SAME_DEVICE
            | ERROR_CANT_ACCESS_FILE,
        ) => Status::Unsupported,
        _ => Status::Io,
    }
}
fn direct_volume_mapping(mapping: &str) -> bool {
    mapping
        .strip_prefix("\\Device\\")
        .is_some_and(|name| !name.is_empty() && !name.contains('\\'))
}
pub struct Target {
    root: PathBuf,
    names: Vec<String>,
}
pub fn target(value: &Value, root: bool) -> Result<Target, Error> {
    p::validate_path_shape(value)?;
    let a = value.as_array().unwrap();
    if a[0].as_uint() != Some(1) {
        return Err(Error::Status(Status::Unsupported));
    }
    if !p::valid_path_contents(value, root)? {
        return Err(Error::Status(Status::InvalidPath));
    }
    let drive = match &a[1] {
        Value::Text(s) => s,
        _ => unreachable!(),
    };
    // Inspect the existing DOS mapping only. SUBST and directory/device aliases
    // must not turn a profile drive root into another namespace or a subtree.
    let device = wide(std::ffi::OsStr::new(&format!("{drive}:")));
    let mut mapping = vec![0u16; 32768];
    if unsafe { QueryDosDeviceW(device.as_ptr(), mapping.as_mut_ptr(), mapping.len() as u32) } == 0
    {
        return Err(Error::Status(Status::Unsupported));
    }
    let end = mapping.iter().position(|c| *c == 0).unwrap();
    let mapping =
        String::from_utf16(&mapping[..end]).map_err(|_| Error::Status(Status::Unsupported))?;
    if !direct_volume_mapping(&mapping) {
        return Err(Error::Status(Status::Unsupported));
    }
    let mount = wide(std::ffi::OsStr::new(&format!("{drive}:\\")));
    if !matches!(
        unsafe { GetDriveTypeW(mount.as_ptr()) },
        DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_RAMDISK
    ) {
        return Err(Error::Status(Status::Unsupported));
    }
    let mut volume = [0u16; 64];
    if unsafe {
        GetVolumeNameForVolumeMountPointW(mount.as_ptr(), volume.as_mut_ptr(), volume.len() as u32)
    } == 0
    {
        return Err(Error::Status(Status::Unsupported));
    }
    let end = volume.iter().position(|c| *c == 0).unwrap();
    let root = PathBuf::from(
        String::from_utf16(&volume[..end]).map_err(|_| Error::Status(Status::Unsupported))?,
    );
    let names = a[2]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| match v {
            Value::Text(s) => s.clone(),
            _ => unreachable!(),
        })
        .collect();
    Ok(Target { root, names })
}
struct Pinned {
    handles: Vec<File>,
}
fn open(path: &Path, access: u32) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}
fn native_open(
    parent: &File,
    name: &str,
    access: u32,
    disposition: u32,
    options: u32,
    private: bool,
) -> Result<File, Error> {
    use windows_sys::{
        Wdk::{
            Foundation::OBJECT_ATTRIBUTES,
            Storage::FileSystem::{
                FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
            },
        },
        Win32::System::IO::IO_STATUS_BLOCK,
    };
    let mut name: Vec<u16> = name.encode_utf16().collect();
    let length = u16::try_from(name.len() * 2).map_err(|_| Error::Status(Status::InvalidPath))?;
    let mut text = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: name.as_mut_ptr(),
    };
    let sd = if private {
        Some(crate::windows_security::descriptor(false)?)
    } else {
        None
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &mut text,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: sd.as_ref().map_or(std::ptr::null_mut(), |d| d.0.cast()),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut raw = std::ptr::null_mut();
    let mut ios = IO_STATUS_BLOCK::default();
    // SAFETY: one validated component (or our generated staging name), live parent,
    // synchronous buffers. There are no intermediate names to reparse; the final
    // entry is opened itself. RootDirectory pins the actual filesystem directory.
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            access | SYNCHRONIZE,
            &oa,
            &mut ios,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            if private {
                FILE_SHARE_READ
            } else {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            },
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    nt_result(result)?;
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn nt_result(status: i32) -> Result<(), Error> {
    if status < 0 {
        Err(io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into())
    } else {
        Ok(())
    }
}
fn attrs(file: &File) -> Result<FILE_ATTRIBUTE_TAG_INFO, Error> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileAttributeTagInfo,
            (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            std::mem::size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(os_error());
    }
    Ok(info)
}
fn check_directory(f: &File) -> Result<(), Error> {
    let a = attrs(f)?;
    if a.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::Status(Status::Unsupported));
    }
    if a.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(Error::Status(Status::NotDirectory));
    }
    Ok(())
}
impl Target {
    fn pin(&self, all: bool) -> Result<Pinned, Error> {
        let f = open(&self.root, FILE_READ_ATTRIBUTES | FILE_TRAVERSE)?;
        check_directory(&f)?;
        let mut handles = vec![f];
        let n = if all {
            self.names.len()
        } else {
            self.names.len().saturating_sub(1)
        };
        for name in &self.names[..n] {
            let f = native_open(
                handles.last().unwrap(),
                name,
                FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
                nt::FILE_OPEN,
                0,
                false,
            )?;
            check_directory(&f)?;
            handles.push(f);
        }
        Ok(Pinned { handles })
    }
    fn entry(&self, access: u32) -> Result<(Pinned, File), Error> {
        let pin = self.pin(false)?;
        let file = if let Some(name) = self.names.last() {
            native_open(
                pin.handles.last().unwrap(),
                name,
                access,
                nt::FILE_OPEN,
                0,
                false,
            )?
        } else {
            open(&self.root, access)?
        };
        Ok((pin, file))
    }
}
fn metadata(attributes: u32, tag: u32, size: u64, time: u64) -> Value {
    let kind = if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        if matches!(tag, 0xa0000003 | 0xa000000c) {
            3
        } else {
            0
        }
    } else if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        2
    } else {
        1
    };
    let mut fields = vec![(Value::Uint(0), Value::Uint(kind))];
    if kind == 1 {
        fields.push((Value::Uint(1), Value::Uint(size)));
    }
    let ticks = i128::from(time) - 116444736000000000i128;
    let seconds = ticks.div_euclid(10000000);
    let nanos = ticks.rem_euclid(10000000) * 100;
    let sec = if seconds < 0 {
        Value::Nint((-1 - seconds) as u64)
    } else {
        Value::Uint(seconds as u64)
    };
    fields.push((
        Value::Uint(2),
        Value::Array(vec![sec, Value::Uint(nanos as u64)]),
    ));
    fields.push((
        Value::Uint(4),
        Value::Bool(attributes & FILE_ATTRIBUTE_READONLY != 0),
    ));
    Value::Map(fields)
}
fn file_metadata(file: &File) -> Result<Value, Error> {
    let mut m = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut m) } == 0 {
        return Err(os_error());
    }
    let a = attrs(file)?;
    Ok(metadata(
        m.dwFileAttributes,
        a.ReparseTag,
        (u64::from(m.nFileSizeHigh) << 32) | u64::from(m.nFileSizeLow),
        (u64::from(m.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(m.ftLastWriteTime.dwLowDateTime),
    ))
}
pub fn stat(path: &Target) -> Result<Value, Error> {
    let (_pin, file) = path.entry(FILE_READ_ATTRIBUTES)?;
    file_metadata(&file)
}
pub fn read(path: &Target) -> Result<File, Error> {
    let (_pin, f) = path.entry(GENERIC_READ)?;
    let a = attrs(&f)?;
    if a.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::Status(Status::Unsupported));
    }
    if a.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(Error::Status(Status::IsDirectory));
    }
    if unsafe { GetFileType(f.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(Error::Status(Status::Unsupported));
    }
    Ok(f)
}
pub fn list(
    path: &Target,
    mut emit: impl FnMut(Value, Value) -> Result<(), Error>,
) -> Result<(), Error> {
    let (_pin, file) = path.entry(FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES)?;
    check_directory(&file)?;
    let mut buffer = vec![0u64; 8192];
    let capacity = buffer.len() * 8;
    let mut class = FileIdExtdDirectoryRestartInfo;
    loop {
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
            )
        } == 0
        {
            let e = io::Error::last_os_error();
            return if e.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                Ok(())
            } else {
                Err(e.into())
            };
        }
        class = FileIdExtdDirectoryInfo;
        let mut offset = 0;
        loop {
            let header = std::mem::offset_of!(FILE_ID_EXTD_DIR_INFO, FileName);
            if offset + std::mem::size_of::<FILE_ID_EXTD_DIR_INFO>() > capacity {
                return Err(abort("native directory response"));
            }
            // SAFETY: header bounds checked, Windows-filled buffer; read_unaligned also
            // tolerates an entry offset that is not aligned for Rust's structure.
            let data = unsafe {
                std::ptr::read_unaligned(
                    buffer
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .cast::<FILE_ID_EXTD_DIR_INFO>(),
                )
            };
            let size = data.FileNameLength as usize;
            if !size.is_multiple_of(2) || offset + header + size > capacity {
                return Err(abort("native directory name"));
            }
            let names: Vec<u16> = (0..size / 2)
                .map(|n| unsafe {
                    std::ptr::read_unaligned(
                        buffer
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset + header + n * 2)
                            .cast::<u16>(),
                    )
                })
                .collect();
            let name =
                String::from_utf16(&names).map_err(|_| Error::Status(Status::Unsupported))?;
            if name != "." && name != ".." {
                if !p::valid_windows_component(&name) {
                    return Err(Error::Status(Status::Unsupported));
                }
                emit(
                    Value::Text(name),
                    metadata(
                        data.FileAttributes,
                        data.ReparsePointTag,
                        data.EndOfFile as u64,
                        data.LastWriteTime as u64,
                    ),
                )?;
            }
            let next = data.NextEntryOffset as usize;
            if next == 0 {
                break;
            }
            if next < header + size || offset + next >= capacity {
                return Err(abort("native directory offset"));
            }
            offset += next;
        }
    }
}
pub fn mkdir(path: &Target) -> Result<(), Error> {
    let pin = path.pin(false)?;
    let file = native_open(
        pin.handles.last().unwrap(),
        path.names.last().unwrap(),
        FILE_READ_ATTRIBUTES,
        nt::FILE_CREATE,
        nt::FILE_DIRECTORY_FILE,
        false,
    )?;
    checked_close(file)
}
fn checked_close(f: File) -> Result<(), Error> {
    if unsafe { CloseHandle(f.into_raw_handle()) } == 0 {
        return Err(os_error());
    }
    Ok(())
}
pub fn remove(path: &Target) -> Result<(), Error> {
    let (_pin, file) = path.entry(DELETE | FILE_READ_ATTRIBUTES)?;
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of_val(&info) as u32,
        )
    } == 0
    {
        return Err(os_error());
    }
    checked_close(file)
}
pub fn rename(path: &Target, dest: &Target, replace: bool) -> Result<(), Error> {
    let (_a, file) = path.entry(DELETE | FILE_READ_ATTRIBUTES)?;
    let b = dest.pin(false)?;
    rename_entry(
        &file,
        b.handles.last().unwrap(),
        std::ffi::OsStr::new(dest.names.last().unwrap()),
        replace,
    )?;
    checked_close(file)
}
fn rename_entry(
    file: &File,
    parent: &File,
    name: &std::ffi::OsStr,
    replace: bool,
) -> Result<(), Error> {
    use windows_sys::Wdk::Storage::FileSystem::{FileRenameInformation, NtSetInformationFile};
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    let name: Vec<u16> = name.encode_wide().collect();
    let bytes = (std::mem::offset_of!(FILE_RENAME_INFO, FileName) + name.len() * 2)
        .max(std::mem::size_of::<FILE_RENAME_INFO>());
    let mut buffer = vec![0u64; bytes.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: aligned variable-length buffer, synchronous native call, live handles.
    let result = unsafe {
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast(),
            name.len(),
        );
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            info.cast(),
            bytes as u32,
            FileRenameInformation,
        )
    };
    nt_result(result)?;
    Ok(())
}
fn identity(file: &File) -> Result<(u64, [u8; 16]), Error> {
    let mut id = FILE_ID_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            std::mem::size_of_val(&id) as u32,
        )
    } == 0
    {
        return Err(os_error());
    }
    Ok((id.VolumeSerialNumber, id.FileId.Identifier))
}
pub struct Upload {
    pin: Pinned,
    file: Option<File>,
}
impl Upload {
    pub fn new(path: &Target, replace: bool) -> Result<Self, Error> {
        let pin = path.pin(false)?;
        if replace {
            match native_open(
                pin.handles.last().unwrap(),
                path.names.last().unwrap(),
                FILE_READ_ATTRIBUTES,
                nt::FILE_OPEN,
                0,
                false,
            ) {
                Ok(_) => return Err(Error::Status(Status::Unsupported)),
                Err(Error::Status(Status::NotFound)) => {}
                Err(e) => return Err(e),
            }
        }
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let mut random = [0; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| abort("staging randomness"))?;
        let stage = format!(
            ".stpt-upload-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let file = native_open(
            pin.handles.last().unwrap(),
            &stage,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            nt::FILE_CREATE,
            nt::FILE_DELETE_ON_CLOSE | nt::FILE_NON_DIRECTORY_FILE,
            true,
        )?;
        crate::windows_security::check_handle(&file, true)
            .map_err(|_| Error::Status(Status::Unsupported))?;
        Ok(Self {
            pin,
            file: Some(file),
        })
    }
    pub fn file(&mut self) -> &mut File {
        self.file.as_mut().unwrap()
    }
    pub fn verify_parent(&self, path: &Target) -> Result<(), Error> {
        let pin = path.pin(false)?;
        if identity(pin.handles.last().unwrap())? != identity(self.pin.handles.last().unwrap())? {
            return Err(Error::Status(Status::ResumeUnavailable));
        }
        Ok(())
    }
    pub fn publish(&mut self, path: &Target) -> Result<(), Error> {
        self.file().flush()?;
        self.file().sync_all()?;
        self.verify_parent(path)?;
        crate::windows_security::check_handle(self.file(), true)
            .map_err(|_| Error::Status(Status::Unsupported))?;

        link(
            self.file.as_ref().unwrap(),
            self.pin.handles.last().unwrap(),
            std::ffi::OsStr::new(path.names.last().unwrap()),
        )?;
        checked_close(self.file.take().unwrap())
    }
}
fn link(file: &File, parent: &File, name: &std::ffi::OsStr) -> Result<(), Error> {
    use windows_sys::{
        Wdk::Storage::FileSystem::{
            FILE_LINK_INFORMATION, FileLinkInformation, NtSetInformationFile,
        },
        Win32::System::IO::IO_STATUS_BLOCK,
    };
    let name: Vec<u16> = name.encode_wide().collect();
    let bytes = (std::mem::offset_of!(FILE_LINK_INFORMATION, FileName) + name.len() * 2)
        .max(std::mem::size_of::<FILE_LINK_INFORMATION>());
    let mut buffer = vec![0u64; bytes.div_ceil(8)];
    let info = buffer.as_mut_ptr().cast::<FILE_LINK_INFORMATION>();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: aligned, initialized, synchronous buffer and live handles. The native
    // normal access-checking class uses the pinned directory, never a name lookup.
    let result = unsafe {
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast(),
            name.len(),
        );
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            info.cast(),
            bytes as u32,
            FileLinkInformation,
        )
    };
    nt_result(result)
}
/// Client-side native names are local policy, not remote profile components.
pub struct LocalPublication {
    file: File,
    parent: File,
    name: std::ffi::OsString,
    cleanup: bool,
    published: bool,
}
impl LocalPublication {
    fn parent(path: &Path) -> Result<(File, std::ffi::OsString, PathBuf), Error> {
        let absolute = std::path::absolute(path)?;
        let name = absolute
            .file_name()
            .ok_or(Error::Status(Status::InvalidPath))?
            .to_owned();
        let parent = absolute
            .parent()
            .ok_or(Error::Status(Status::InvalidPath))?;
        // Local directory symlinks are an explicit Client choice. Pin their
        // resolved target; none of these native names comes from a peer listing.
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | FILE_TRAVERSE)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(parent)?;
        Ok((file, name, parent.to_owned()))
    }
    pub fn new(path: &Path) -> Result<(Self, File, PathBuf), Error> {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let (parent, name, directory) = Self::parent(path)?;
        let mut random = [0u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| abort("local staging randomness"))?;
        let stage = format!(
            ".stpt-download-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let file = native_open(
            &parent,
            &stage,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            nt::FILE_CREATE,
            nt::FILE_NON_DIRECTORY_FILE,
            true,
        )?;
        let state = Self {
            file,
            parent,
            name,
            cleanup: true,
            published: false,
        };
        crate::windows_security::check_handle(&state.file, true)
            .map_err(|_| Error::Status(Status::Unsupported))?;
        let primary = state.file.try_clone()?;
        Ok((state, primary, directory.join(stage)))
    }
    pub fn retained(path: &Path, temp: &Path, existing: bool) -> Result<(Self, File), Error> {
        let (parent, name, _) = Self::parent(path)?;
        let (source, source_name, _) = Self::parent(temp)?;
        let source_name = source_name
            .to_str()
            .ok_or(Error::Status(Status::InvalidPath))?;
        let file = native_open(
            &source,
            source_name,
            GENERIC_READ | GENERIC_WRITE | DELETE,
            if existing {
                nt::FILE_OPEN
            } else {
                nt::FILE_CREATE
            },
            nt::FILE_NON_DIRECTORY_FILE,
            true,
        )?;
        if attrs(&file)?.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(Error::Status(Status::Unsupported));
        }
        crate::windows_security::check_handle(&file, true)
            .map_err(|_| Error::Status(Status::Access))?;
        let primary = file.try_clone()?;
        Ok((
            Self {
                file,
                parent,
                name,
                cleanup: false,
                published: false,
            },
            primary,
        ))
    }
    fn remove_stage(&self) -> Result<(), Error> {
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        if unsafe {
            SetFileInformationByHandle(
                self.file.as_raw_handle(),
                FileDispositionInfo,
                (&info as *const FILE_DISPOSITION_INFO).cast(),
                std::mem::size_of_val(&info) as u32,
            )
        } == 0
        {
            return Err(os_error());
        }
        Ok(())
    }
    pub fn publish(&mut self, replace: bool) -> Result<(), Error> {
        if replace {
            rename_entry(&self.file, &self.parent, &self.name, true)?;
        } else {
            link(&self.file, &self.parent, &self.name)?;
            self.remove_stage()?;
        }
        self.published = true;
        Ok(())
    }
}
impl Drop for LocalPublication {
    fn drop(&mut self) {
        if self.cleanup
            && !self.published
            && let Err(e) = self.remove_stage()
        {
            eprintln!("stpt: local staging cleanup failed: {e:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exhaustion_and_permission_errors_have_portable_statuses() {
        for code in [
            ERROR_DISK_FULL,
            ERROR_HANDLE_DISK_FULL,
            ERROR_DISK_QUOTA_EXCEEDED,
        ] {
            assert_eq!(
                io_status(&io::Error::from_raw_os_error(code as i32)),
                Status::NoSpace
            );
        }
        assert_eq!(
            io_status(&io::Error::from_raw_os_error(ERROR_WRITE_PROTECT as i32)),
            Status::ReadOnly
        );
        assert_eq!(
            io_status(&io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)),
            Status::Access
        );
    }
    #[test]
    fn dos_mapping_validation_refuses_substituted_paths_and_aliases() {
        for mapping in [r"\Device\HarddiskVolume3", r"\Device\CdRom0"] {
            assert!(direct_volume_mapping(mapping));
        }
        for mapping in [
            r"\??\C:\folder",
            r"\??\Volume{alias}\",
            r"\Device\HarddiskVolume3\folder",
            r"\Device\",
            r"C:\folder",
            "",
        ] {
            assert!(!direct_volume_mapping(mapping));
        }
    }
    #[test]
    fn private_publication_cleans_staging_name() {
        let dir = std::env::temp_dir().join(format!("stpt-g3-upload-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("dest");
        let text = dest.to_str().unwrap();
        let value = Value::Array(vec![
            Value::Uint(1),
            Value::Text(text[..1].into()),
            Value::Array(
                text[3..]
                    .split('\\')
                    .map(|s| Value::Text(s.into()))
                    .collect(),
            ),
        ]);
        let target = target(&value, false).unwrap();
        let mut upload = Upload::new(&target, false).unwrap();
        upload.file().write_all(b"hello").unwrap();
        upload.publish(&target).unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"hello");
        std::fs::remove_file(dest).unwrap();
        drop(upload);
        std::fs::remove_dir(dir).unwrap();
    }
}
