//! Authorization of user keys on the Server (PROTOCOL.md §12.4).
//!
//! The keys of the Account NAME are in the file NAME of the authorized keys directory
//! (default `/etc/stpt/authorized_keys`), kept by the administrator. One key per line:
//! the base64 of its SubjectPublicKeyInfo, as the second line of
//! `openssl pkey -in KEY -pubout` shows it, optionally followed by a label of 1–64
//! bytes. Empty lines and lines starting with `#` are ignored. Directory and file
//! must be owned by root (or by the user the Server runs as) and must not be writable
//! by group or others.

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::auth::{AuthRequest, ed25519_raw, ed25519_spki};
use crate::identity::{Fingerprint, PublicKey};

/// Default authorized keys directory.
pub const AUTHORIZED_KEYS_DIR: &str = "/etc/stpt/authorized_keys";

/// Maximum length of a key label in bytes (§15.10).
const MAX_LABEL_LEN: usize = 64;

/// Operating system Accounts.
pub trait Accounts: Send + Sync {
    fn exists(&self, name: &str) -> bool;
}

/// Accounts of the system user database (`getpwnam`).
pub struct SystemAccounts;

impl Accounts for SystemAccounts {
    #[cfg(unix)]
    fn exists(&self, name: &str) -> bool {
        matches!(nix::unistd::User::from_name(name), Ok(Some(_)))
    }

    /// Server mode is Unix only for now (gate G2).
    #[cfg(not(unix))]
    fn exists(&self, _name: &str) -> bool {
        false
    }
}

/// Result of a successful user authentication: the Authentication Context (§1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub account: String,
    /// The raw Ed25519 public key that authenticated.
    pub key: [u8; 32],
    pub fingerprint: Fingerprint,
    pub label: Option<String>,
}

/// A user key as the Session list shows it (§15.10): the raw key and its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub key: [u8; 32],
    pub label: Option<String>,
}

pub struct Authorizer {
    dir: PathBuf,
    accounts: Box<dyn Accounts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizedKey {
    key: [u8; 32],
    label: Option<String>,
}

impl Authorizer {
    pub fn new(dir: PathBuf, accounts: Box<dyn Accounts>) -> Self {
        Self { dir, accounts }
    }

    /// Decides on an AUTH_REQUEST. Every check runs, whichever of them fails, and the
    /// decision is made once after all of them (§12.4). `Err` holds the exact reason
    /// for the Server log; the Client learns nothing of it.
    pub fn decide(&self, request: &AuthRequest, exporter: &[u8; 32]) -> Result<Accepted, String> {
        let signature = request.signature_valid(exporter);
        let account = self.accounts.exists(&request.account);
        let keys = self.keys(&request.account);
        let entry = keys
            .as_ref()
            .ok()
            .and_then(|keys| keys.iter().find(|k| k.key == request.key));
        match (signature, account, &keys, entry) {
            (true, true, Ok(_), Some(entry)) => Ok(Accepted {
                account: request.account.clone(),
                key: request.key,
                fingerprint: ed25519_spki(&request.key).fingerprint(),
                label: entry.label.clone(),
            }),
            (false, ..) => Err("invalid signature".to_owned()),
            (_, false, ..) => Err("no such Account".to_owned()),
            (.., Err(e), _) => Err(e.to_string()),
            _ => Err("key not authorized for the Account".to_owned()),
        }
    }

    /// Authorized keys of `account`.
    fn keys(&self, account: &str) -> Result<Vec<AuthorizedKey>, KeysError> {
        if !valid_file_name(account) {
            return Err(KeysError::InvalidName);
        }
        let dir_meta = fs::metadata(&self.dir).map_err(|e| KeysError::io(&self.dir, e))?;
        check_owner_and_mode(&dir_meta, &self.dir)?;
        let path = self.dir.join(account);
        let mut file = File::open(&path).map_err(|e| KeysError::io(&path, e))?;
        let meta = file.metadata().map_err(|e| KeysError::io(&path, e))?;
        if !meta.is_file() {
            return Err(KeysError::Unsafe {
                path,
                what: "not a regular file",
            });
        }
        check_owner_and_mode(&meta, &path)?;
        let mut text = String::new();
        file.read_to_string(&mut text)
            .map_err(|e| KeysError::io(&path, e))?;
        parse(&text).map_err(|(line, reason)| KeysError::Syntax { path, line, reason })
    }
}

#[derive(Debug)]
enum KeysError {
    InvalidName,
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Unsafe {
        path: PathBuf,
        what: &'static str,
    },
    Syntax {
        path: PathBuf,
        line: usize,
        reason: &'static str,
    },
}

impl KeysError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_owned(),
            source,
        }
    }
}

impl fmt::Display for KeysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => f.write_str("Account name not usable as a file name"),
            Self::Io { path, source } if source.kind() == io::ErrorKind::NotFound => {
                write!(f, "no authorized keys file {}", path.display())
            }
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Unsafe { path, what } => {
                write!(f, "{}: {what}, ignored", path.display())
            }
            Self::Syntax { path, line, reason } => {
                write!(f, "{}:{line}: {reason}, file ignored", path.display())
            }
        }
    }
}

/// An Account name that names a file inside the directory and nothing else.
fn valid_file_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

/// Only the administrator may change authorized keys: owner root or the Server's
/// own user, not writable by group or others.
#[cfg(unix)]
fn check_owner_and_mode(meta: &fs::Metadata, path: &Path) -> Result<(), KeysError> {
    use std::os::unix::fs::MetadataExt;
    let unsafe_because = |what| {
        Err(KeysError::Unsafe {
            path: path.to_owned(),
            what,
        })
    };
    let owner = meta.uid();
    if owner != 0 && owner != nix::unistd::geteuid().as_raw() {
        return unsafe_because("not owned by root");
    }
    if meta.mode() & 0o022 != 0 {
        return unsafe_because("writable by group or others");
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_owner_and_mode(_meta: &fs::Metadata, _path: &Path) -> Result<(), KeysError> {
    Ok(())
}

/// Parses an authorized keys file; an invalid line invalidates the whole file.
fn parse(text: &str) -> Result<Vec<AuthorizedKey>, (usize, &'static str)> {
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let error = |reason| (n + 1, reason);
        let (encoded, label) = match line.split_once(char::is_whitespace) {
            Some((key, label)) => (key, label.trim()),
            None => (line, ""),
        };
        let key = PublicKey::from_base64(encoded)
            .as_ref()
            .and_then(ed25519_raw)
            .ok_or_else(|| error("not the base64 of an Ed25519 public key"))?;
        let label = match label {
            "" => None,
            l if l.len() > MAX_LABEL_LEN => return Err(error("label longer than 64 bytes")),
            l if l.chars().any(char::is_control) => {
                return Err(error("label contains a control character"));
            }
            l => Some(l.to_owned()),
        };
        keys.push(AuthorizedKey { key, label });
    }
    Ok(keys)
}

/// Authorized keys files for tests of other modules.
#[cfg(test)]
pub mod test_support {
    use std::fs;
    use std::path::Path;

    /// Creates `dir` and writes its keys file `name` with the modes an administrator
    /// gives them (0755, 0644), whatever the umask.
    pub fn keys_file(dir: &Path, name: &str, text: &str) {
        fs::create_dir_all(dir).unwrap();
        let path = dir.join(name);
        fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::keys_file;
    use super::*;
    use crate::auth::UserKey;

    struct These(&'static [&'static str]);

    impl Accounts for These {
        fn exists(&self, name: &str) -> bool {
            self.0.contains(&name)
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("stpt-authorized-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn line(key: &UserKey, label: &str) -> String {
        format!("{} {label}\n", key.public_key().to_base64())
    }

    #[test]
    fn parse_entries() {
        let a = UserKey::generate();
        let b = UserKey::generate();
        let text = format!("# keys\n\n{}{}", line(&a, "laptop work"), line(&b, ""));
        let keys = parse(&text).unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].key, a.raw_public());
        assert_eq!(keys[0].label.as_deref(), Some("laptop work"));
        assert_eq!(keys[1].label, None);

        let server_key = crate::identity::ServerKey::generate().public_key();
        assert!(parse(&format!("{} srv", server_key.to_base64())).is_ok());
        for (text, n) in [
            ("AAAA".to_owned(), 1),
            ("# c\nnot-base64!".to_owned(), 2),
            (format!("{}x{}", line(&a, ""), "y".repeat(65)), 2),
            (line(&a, &"y".repeat(65)), 1),
            (line(&a, "a\u{7}b"), 1),
        ] {
            assert_eq!(parse(&text).unwrap_err().0, n, "{text}");
        }
        assert!(parse(&line(&a, &"y".repeat(64))).is_ok());
    }

    #[test]
    fn file_names() {
        for good in ["alice", "a.b", "..x", "user@domain", "-x"] {
            assert!(valid_file_name(good), "{good}");
        }
        for bad in [
            "",
            ".",
            "..",
            "../etc/shadow",
            "a/b",
            "a\\b",
            "a\nb",
            "a\0b",
        ] {
            assert!(!valid_file_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn decisions() {
        let dir = temp_dir("decide");
        let user = UserKey::generate();
        let other = UserKey::generate();
        keys_file(&dir, "alice", &line(&user, "laptop"));
        keys_file(&dir, "ghost", &line(&user, ""));
        let authorizer = Authorizer::new(dir.clone(), Box::new(These(&["alice", "bob"])));
        let exporter = [3u8; 32];
        let decide = |key: &UserKey, account: &str| {
            authorizer.decide(&key.request(&exporter, account), &exporter)
        };

        let accepted = decide(&user, "alice").unwrap();
        assert_eq!(accepted.account, "alice");
        assert_eq!(accepted.label.as_deref(), Some("laptop"));
        assert_eq!(accepted.fingerprint, user.public_key().fingerprint());

        assert_eq!(
            decide(&other, "alice").unwrap_err(),
            "key not authorized for the Account"
        );
        assert_eq!(decide(&user, "ghost").unwrap_err(), "no such Account");
        assert!(
            decide(&user, "bob")
                .unwrap_err()
                .starts_with("no authorized keys file")
        );
        assert_eq!(decide(&user, "../alice").unwrap_err(), "no such Account");
        let mut forged = user.request(&exporter, "alice");
        forged.signature[0] ^= 1;
        assert_eq!(
            authorizer.decide(&forged, &exporter).unwrap_err(),
            "invalid signature"
        );
        // Signed for another Connection.
        let relayed = user.request(&[4u8; 32], "alice");
        assert_eq!(
            authorizer.decide(&relayed, &exporter).unwrap_err(),
            "invalid signature"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn writable_files_are_ignored() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("modes");
        let user = UserKey::generate();
        let path = dir.join("alice");
        fs::write(&path, line(&user, "")).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let authorizer = Authorizer::new(dir.clone(), Box::new(These(&["alice"])));
        let exporter = [0u8; 32];
        let decide = || authorizer.decide(&user.request(&exporter, "alice"), &exporter);
        assert!(decide().is_ok());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(
            decide()
                .unwrap_err()
                .contains("writable by group or others")
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(
            decide()
                .unwrap_err()
                .contains("writable by group or others")
        );
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
