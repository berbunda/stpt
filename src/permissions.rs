//! Attachment-local consent state (§17). RF003 supplies the trusted local UI and
//! stream dispatcher. Only that dispatcher should hold mutable access to the owner.
#![allow(dead_code)] // The production terminal owns the scope; RF003 supplies requests.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::path::{Component, Path};
use std::sync::Arc;
use std::time::Instant;

use crate::identity::Fingerprint;
use crate::terminal::SessionId;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ReadFile,
    CreateFile(u64),
    MountReadOnly,
}

/// Constructed by trusted local selection, never deserialized from the peer.
/// The native backend must obtain handles under the user's authority and
/// validate descendant resolution at actual use (§17.2).
pub struct Selection(Object);
enum Object {
    Read(File),
    Create(File, OsString, u64),
    Directory(File),
}
impl Selection {
    pub fn read(file: File) -> io::Result<Self> {
        if !file.metadata()?.is_file() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self(Object::Read(file)))
    }
    pub fn create(parent: File, name: OsString, bytes: u64) -> io::Result<Self> {
        let mut parts = Path::new(&name).components();
        if !matches!(parts.next(), Some(Component::Normal(n)) if n == name)
            || parts.next().is_some()
            || name.as_encoded_bytes().contains(&0)
            || !parent.metadata()?.is_dir()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        #[cfg(windows)]
        if !crate::file_protocol::valid_entry_name(
            &crate::cbor::Value::Text(name.to_str().ok_or(io::ErrorKind::InvalidInput)?.to_owned()),
            1,
        ) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self(Object::Create(parent, name, bytes)))
    }
    pub fn directory(root: File) -> io::Result<Self> {
        if !root.metadata()?.is_dir() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(Self(Object::Directory(root)))
    }
    fn action(&self) -> Action {
        match self.0 {
            Object::Read(_) => Action::ReadFile,
            Object::Create(_, _, bytes) => Action::CreateFile(bytes),
            Object::Directory(_) => Action::MountReadOnly,
        }
    }
}

#[derive(Clone)]
pub struct Ticket {
    scope: Arc<()>,
    serial: u64,
}
struct Request {
    action: Action,
    expires: Option<Instant>,
    phase: Phase,
}
enum Phase {
    Pending,
    Approved(Selection),
    Active(Selection),
}

/// A fresh owner for each authenticated terminal opening, including reattach.
/// Dropping the owner synchronously releases every selection and pending grant.
pub struct Permissions {
    pub server: Fingerprint,
    pub account: String,
    session: SessionId,
    attachment: u64,
    scope: Arc<()>,
    next: u64,
    requests: HashMap<u64, Request>,
}

impl Permissions {
    pub fn clear(&mut self) {
        self.requests.clear();
    }
    pub fn new(server: Fingerprint, account: &str, session: SessionId, attachment: u64) -> Self {
        Self {
            server,
            account: account.into(),
            session,
            attachment,
            scope: Arc::new(()),
            next: 0,
            requests: HashMap::new(),
        }
    }
    /// Caller dispatches only for a live Running Session on this Connection.
    pub fn propose(
        &mut self,
        session: SessionId,
        attachment: u64,
        action: Action,
        expires: Option<Instant>,
    ) -> Option<Ticket> {
        self.expire_at(Instant::now());
        if (session, attachment) != (self.session, self.attachment)
            || self.requests.len() >= 64
            || expires.is_some_and(|end| end <= Instant::now())
        {
            return None;
        }
        self.next = self.next.checked_add(1)?;
        self.requests.insert(
            self.next,
            Request {
                action,
                expires,
                phase: Phase::Pending,
            },
        );
        Some(Ticket {
            scope: self.scope.clone(),
            serial: self.next,
        })
    }
    fn expire_at(&mut self, now: Instant) {
        self.requests
            .retain(|_, r| r.expires.is_none_or(|end| end > now));
    }
    fn get(&mut self, t: &Ticket) -> Option<&mut Request> {
        self.expire_at(Instant::now());
        if !Arc::ptr_eq(&self.scope, &t.scope) {
            return None;
        }
        self.requests.get_mut(&t.serial)
    }
    /// Trusted user's affirmative decision for exactly the displayed proposal.
    pub fn approve(&mut self, t: &Ticket, selected: Selection) -> Option<()> {
        let r = self.get(t)?;
        if !matches!(r.phase, Phase::Pending) || r.action != selected.action() {
            return None;
        }
        r.phase = Phase::Approved(selected);
        Some(())
    }
    /// Admission consumes the approval, even if the admitted operation later fails.
    pub fn start(&mut self, t: &Ticket) -> Option<()> {
        let r = self.get(t)?;
        if !matches!(r.phase, Phase::Approved(_)) {
            return None;
        }
        let Phase::Approved(object) = std::mem::replace(&mut r.phase, Phase::Pending) else {
            unreachable!()
        };
        r.phase = Phase::Active(object);
        Some(())
    }
    fn active(&mut self, t: &Ticket) -> Option<&Object> {
        match &self.get(t)?.phase {
            Phase::Active(s) => Some(&s.0),
            _ => None,
        }
    }
    // Borrowed references are valid only in the serialized owner's current step.
    // Recheck after offloaded I/O and before releasing bytes or publishing.
    pub fn source(&mut self, t: &Ticket) -> Option<&File> {
        match self.active(t)? {
            Object::Read(f) => Some(f),
            _ => None,
        }
    }
    pub fn destination(&mut self, t: &Ticket) -> Option<(&File, &std::ffi::OsStr, u64)> {
        match self.active(t)? {
            Object::Create(p, n, bytes) => Some((p, n, *bytes)),
            _ => None,
        }
    }
    pub fn mount_root(&mut self, t: &Ticket) -> Option<&File> {
        match self.active(t)? {
            Object::Directory(f) => Some(f),
            _ => None,
        }
    }
    /// Used for refusal, cancellation, completion and explicit local revocation.
    pub fn revoke(&mut self, t: &Ticket) {
        if Arc::ptr_eq(&self.scope, &t.scope) {
            self.requests.remove(&t.serial);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const S: SessionId = SessionId([9; 16]);
    fn scope() -> Permissions {
        Permissions::new(
            "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                .parse()
                .unwrap(),
            "alice",
            S,
            1,
        )
    }
    fn file() -> Selection {
        Selection::read(File::open("Cargo.toml").unwrap()).unwrap()
    }

    #[test]
    fn selected_source_survives_path_replacement() {
        use std::io::Read;
        let fixture = std::env::temp_dir().join(format!("stpt-grant-{}", SessionId::generate()));
        std::fs::create_dir(&fixture).unwrap();
        let path = fixture.join("selected");
        std::fs::write(&path, b"original").unwrap();
        let mut a = scope();
        let t = a.propose(S, 1, Action::ReadFile, None).unwrap();
        a.approve(&t, Selection::read(File::open(&path).unwrap()).unwrap())
            .unwrap();
        let moved = fixture.join("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        a.start(&t).unwrap();
        let mut data = Vec::new();
        a.source(&t).unwrap().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"original");
        a.revoke(&t);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(moved).unwrap();
        std::fs::remove_dir(fixture).unwrap();
    }

    #[test]
    fn expiry_invalidates_approval_and_active_access() {
        let mut a = scope();
        let end = Instant::now() + std::time::Duration::from_secs(60);
        let pending = a.propose(S, 1, Action::ReadFile, Some(end)).unwrap();
        let active = a.propose(S, 1, Action::ReadFile, Some(end)).unwrap();
        a.approve(&active, file()).unwrap();
        a.start(&active).unwrap();
        a.expire_at(end);
        assert!(a.source(&active).is_none());
        assert!(a.approve(&pending, file()).is_none());
    }
    fn dir() -> File {
        let mut opts = File::options();
        opts.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            opts.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS);
        }
        opts.open(".").unwrap()
    }
    #[test]
    fn pending_approval_and_start_are_separate_and_single_use() {
        let mut a = scope();
        assert!(a.propose(S, 2, Action::ReadFile, None).is_none());
        assert!(
            a.propose(SessionId([0; 16]), 1, Action::ReadFile, None)
                .is_none()
        );
        let t = a.propose(S, 1, Action::ReadFile, None).unwrap();
        assert!(a.start(&t).is_none());
        assert!(
            a.approve(&t, Selection::directory(dir()).unwrap())
                .is_none()
        );
        a.approve(&t, file()).unwrap();
        assert!(a.source(&t).is_none());
        a.start(&t).unwrap();
        assert!(a.source(&t).is_some());
        assert!(a.mount_root(&t).is_none());
        assert!(a.start(&t).is_none());
        a.revoke(&t);
        assert!(a.source(&t).is_none());
        assert!(a.approve(&t, file()).is_none());
    }
    #[test]
    fn cancellation_and_reattach_never_transfer_consent() {
        let mut a = scope();
        let old = a.propose(S, 1, Action::ReadFile, None).unwrap();
        a.revoke(&old);
        assert!(a.approve(&old, file()).is_none());
        let approved = a.propose(S, 1, Action::ReadFile, None).unwrap();
        a.approve(&approved, file()).unwrap();
        a.revoke(&approved);
        assert!(a.start(&approved).is_none());
        drop(a);
        let mut b = scope();
        let new = b.propose(S, 1, Action::ReadFile, None).unwrap();
        b.approve(&new, file()).unwrap();
        b.revoke(&old);
        assert!(b.start(&old).is_none());
        b.start(&new).unwrap();
    }
    #[test]
    fn create_pins_parent_basename_and_exact_approved_size() {
        let mut a = scope();
        let t = a.propose(S, 1, Action::CreateFile(8), None).unwrap();
        assert!(Selection::create(dir(), "../x".into(), 8).is_err());
        assert!(
            a.approve(&t, Selection::create(dir(), "x".into(), 9).unwrap())
                .is_none()
        );
        a.approve(&t, Selection::create(dir(), "x".into(), 8).unwrap())
            .unwrap();
        a.start(&t).unwrap();
        let (_, name, bytes) = a.destination(&t).unwrap();
        assert_eq!((name, bytes), (std::ffi::OsStr::new("x"), 8));
        assert!(a.source(&t).is_none());
    }
    #[test]
    fn mount_rechecks_after_io_and_discarded_instance_cannot_deliver() {
        let mut a = scope();
        let old = a.propose(S, 1, Action::MountReadOnly, None).unwrap();
        a.approve(&old, Selection::directory(dir()).unwrap())
            .unwrap();
        a.start(&old).unwrap();
        assert!(a.mount_root(&old).is_some());
        a.revoke(&old);
        let new = a.propose(S, 1, Action::MountReadOnly, None).unwrap();
        a.approve(&new, Selection::directory(dir()).unwrap())
            .unwrap();
        a.start(&new).unwrap();
        assert!(a.mount_root(&old).is_none());
        assert!(a.mount_root(&new).is_some());
        assert!(a.destination(&new).is_none());
    }
}
