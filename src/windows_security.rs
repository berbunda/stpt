//! Conservative owner/DACL checks for administrator-controlled Server files.
use std::os::windows::{
    fs::{MetadataExt, OpenOptionsExt},
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::{fs::OpenOptions, io, path::Path};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::Threading::*,
};
pub(crate) struct Local(pub(crate) *mut std::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
fn current_sid() -> io::Result<Vec<u8>> {
    unsafe {
        let mut raw = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle::from_raw_handle(raw);
        let mut size = 0;
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut size,
        );
        let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        if GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = &*(buffer.as_ptr().cast::<TOKEN_USER>());
        let length = GetLengthSid(user.User.Sid);
        Ok(std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), length as usize).to_vec())
    }
}
fn known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; 68];
    let mut size = bytes.len() as u32;
    if unsafe {
        CreateWellKnownSid(
            kind,
            std::ptr::null_mut(),
            bytes.as_mut_ptr().cast(),
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(size as usize);
    Ok(bytes)
}
/// Client state must be owned by this user before tightening its DACL; granting
/// OWNER RIGHTS to an unrelated owner would leave that owner access to tokens.
pub(crate) fn check_current_owner(file: &std::fs::File) -> io::Result<()> {
    let own = current_sid()?;
    unsafe {
        let mut owner = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let result = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let _descriptor = Local(descriptor);
        if owner.is_null() || EqualSid(owner, own.as_ptr() as _) == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "resume state must be owned by this user",
            ));
        }
    }
    Ok(())
}
pub fn check(path: &Path) -> io::Result<()> {
    check_access(path, false)
}
#[cfg(test)]
pub fn check_private(path: &Path) -> io::Result<()> {
    check_access(path, true)
}
fn check_access(path: &Path, private: bool) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(0x00020080)
        .custom_flags(0x02200000)
        .open(path)?;
    check_handle(&file, private)
}
pub fn open_read(path: &Path) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(0x00200000)
        .open(path)
}
pub fn check_handle(file: &std::fs::File, private: bool) -> io::Result<()> {
    if file.metadata()?.file_attributes() & 0x400 != 0 {
        return Err(io::Error::other("reparse point in Server configuration"));
    }
    let own = current_sid()?;
    let system = known(WinLocalSystemSid)?;
    let admins = known(WinBuiltinAdministratorsSid)?;
    let rights = known(WinCreatorOwnerRightsSid)?;
    let trusted = |sid: PSID| -> bool {
        [&own, &system, &admins]
            .iter()
            .any(|v| unsafe { EqualSid(sid, v.as_ptr() as _) } != 0)
    };
    unsafe {
        let mut owner = std::ptr::null_mut();
        let mut acl = std::ptr::null_mut();
        let mut descriptor = std::ptr::null_mut();
        let result = GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        );
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let _local = Local(descriptor);
        if owner.is_null() || !trusted(owner) || acl.is_null() {
            return Err(io::Error::other("untrusted owner or unrestricted DACL"));
        }
        // GetSecurityInfo stores the ACL in the descriptor owned by _local.
        if IsValidAcl(acl) == 0 {
            return Err(io::Error::other("invalid Server DACL"));
        }
        for index in 0..(*acl).AceCount as u32 {
            let mut ace = std::ptr::null_mut();
            if GetAce(acl, index, &mut ace) == 0 {
                return Err(io::Error::last_os_error());
            }
            // A successful GetAce returns the indexed entry in that same ACL.
            let header = &*ace.cast::<ACE_HEADER>();
            if header.AceFlags & INHERIT_ONLY_ACE as u8 != 0 {
                continue;
            }
            // WinNT ACCESS_DENIED_ACE_TYPE=1, ACCESS_ALLOWED_ACE_TYPE=0.
            if header.AceType == 1 {
                continue;
            }
            if header.AceType != 0
                || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            {
                return Err(io::Error::other("unsupported Server DACL entry"));
            }
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            // SidStart marks a variable-length SID. Derive the slice from
            // the whole ACE allocation, never from the four-byte field.
            let offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            let tail = std::slice::from_raw_parts(
                ace.cast::<u8>().add(offset),
                usize::from(header.AceSize) - offset,
            );
            let sid = ace_sid(tail)?.as_ptr() as PSID;
            if IsValidSid(sid) == 0 {
                return Err(io::Error::other("invalid SID in Server DACL entry"));
            }
            // Generic write/all, DELETE, WRITE_DAC/OWNER and file/directory
            // mutation bits. Private keys additionally forbid content reads.
            const MUTATE: u32 = 0x500d0156;
            const READ_CONTENTS: u32 = 0x80000001;
            let forbidden = MUTATE | if private { READ_CONTENTS } else { 0 };
            if allowed.Mask & forbidden != 0
                && !trusted(sid)
                && EqualSid(sid, rights.as_ptr() as _) == 0
            {
                return Err(io::Error::other(
                    "Server file writable by an untrusted principal",
                ));
            }
        }
    }
    Ok(())
}

fn ace_sid(bytes: &[u8]) -> io::Result<&[u8]> {
    // GetSidLengthRequired includes the fixed header and all subauthorities.
    bytes
        .get(1)
        .and_then(|&count| bytes.get(..unsafe { GetSidLengthRequired(count) } as usize))
        .ok_or_else(|| io::Error::other("truncated SID in Server DACL entry"))
}

pub(crate) fn descriptor(inherit: bool) -> io::Result<Local> {
    let s = if inherit {
        "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    } else {
        "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)"
    };
    let text: Vec<_> = s.encode_utf16().chain(Some(0)).collect();
    let mut raw = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut raw,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Local(raw))
}
pub fn create_private(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::*;
    let name: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let sd = descriptor(false)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            &sa,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    Ok(std::fs::File::from(unsafe {
        OwnedHandle::from_raw_handle(raw)
    }))
}
/// Atomically create private Client state, or validate an existing object.
/// An inherited DACL followed by a later restriction can leave an already-open
/// reader with access, so the descriptor must participate in CreateFileW.
fn state_descriptor(inherit: bool) -> io::Result<Local> {
    let own = current_sid()?;
    let mut owner = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(own.as_ptr() as _, &mut owner) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _owner = Local(owner.cast());
    let mut length = 0;
    // SAFETY: ConvertSidToStringSidW returns an allocated NUL-terminated string,
    // kept alive by _owner through descriptor conversion.
    while unsafe { *owner.add(length) } != 0 {
        length += 1;
    }
    let owner = String::from_utf16(unsafe { std::slice::from_raw_parts(owner, length) })
        .map_err(|_| io::Error::other("invalid owner SID text"))?;
    let grants = if inherit {
        "D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)"
    } else {
        "D:P(A;;FA;;;OW)(A;;FA;;;SY)"
    };
    let sddl: Vec<u16> = format!("O:{owner}{grants}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut raw_sd = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut raw_sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(Local(raw_sd))
}
pub(crate) fn create_private_state_directory(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
    let sd = state_descriptor(true)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe { CreateDirectoryW(name.as_ptr(), &sa) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) fn open_private_state(path: &Path) -> io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::*;
    let sd = state_descriptor(false)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &sa,
            OPEN_ALWAYS,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(raw) });
    // The creation descriptor is ignored for an existing file. Reject unsafe
    // existing access before any record bytes are read, truncated or written.
    check_current_owner(&file)?;
    check_handle(&file, true)?;
    Ok(file)
}
#[cfg(test)]
pub fn make_private(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(0x00040000)
        .custom_flags(0x02200000)
        .open(path)?;
    let sd = descriptor(true)?;
    if unsafe {
        SetKernelObjectSecurity(
            file.as_raw_handle(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd.0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ace_must_contain_the_entire_sid() {
        let sid = known(WinBuiltinAdministratorsSid).unwrap();
        assert!(ace_sid(&sid).is_ok());
        for length in 0..sid.len() {
            assert!(ace_sid(&sid[..length]).is_err());
        }
    }
    #[test]
    fn private_file_and_owner_dacl_are_enforced() {
        let path = std::env::temp_dir().join(format!("stpt-private-key-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let file = create_private(&path).unwrap();
        drop(file);
        check_private(&path).unwrap();
        make_private(&path).unwrap();
        check_private(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let directory = path.with_extension("state-dir");
        create_private_state_directory(&directory).unwrap();
        check_private(&directory).unwrap();
        let state_path = directory.join("state");
        let state_file = open_private_state(&state_path).unwrap();
        check_current_owner(&state_file).unwrap();
        check_handle(&state_file, true).unwrap();
        drop(state_file);
        std::fs::remove_file(state_path).unwrap();
        std::fs::remove_dir(directory).unwrap();
        let mut file = open_private_state(&path).unwrap();
        check_current_owner(&file).unwrap();
        check_handle(&file, true).unwrap();
        use std::io::{Read, Seek, Write};
        file.write_all(b"state").unwrap();
        file.rewind().unwrap();
        let mut bytes = [0; 5];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"state");
        drop(file);
        std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn writable_or_readable_world_acl_is_not_accepted_for_private_keys() {
        let path = std::env::temp_dir().join(format!("stpt-unsafe-acl-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        drop(create_private(&path).unwrap());
        let set = |sddl: &str| {
            let file = OpenOptions::new()
                .access_mode(0x00040000)
                .open(&path)
                .unwrap();
            let text: Vec<_> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut raw = std::ptr::null_mut();
            assert_ne!(
                unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        text.as_ptr(),
                        1,
                        &mut raw,
                        std::ptr::null_mut(),
                    )
                },
                0
            );
            let sd = Local(raw);
            assert_ne!(
                unsafe {
                    SetKernelObjectSecurity(
                        file.as_raw_handle(),
                        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                        sd.0,
                    )
                },
                0
            );
        };
        set("D:P(A;;FA;;;OW)(A;;FR;;;WD)");
        assert!(open_private_state(&path).is_err());
        assert!(check(&path).is_ok());
        assert!(check_private(&path).is_err());
        set("D:P(A;;FA;;;WD)");
        assert!(check(&path).is_err());
        assert!(check_private(&path).is_err());
        make_private(&path).unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
