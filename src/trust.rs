//! Trust store of the Client (PROTOCOL.md §9.3): Server address → trusted key.
//!
//! Text file `known_servers` next to the Client configuration, one entry per line:
//! `HOST:PORT KEY`, KEY being the base64 of the key's SubjectPublicKeyInfo. Empty
//! lines and lines starting with `#` are ignored and kept. Entries change only by
//! explicit user action: confirmation at first contact, a verified `--fingerprint`
//! or `stpt trust remove`.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::destination::Address;
use crate::identity::PublicKey;

/// File name of the trust store in the Client configuration directory.
pub const FILE_NAME: &str = "known_servers";

const HEADER: &str = "# STPT trust store: Server address and key (base64 of its SubjectPublicKeyInfo).\n\
                      # Remove an entry with `stpt trust remove HOST[:PORT]`.\n";

#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    lines: Vec<Line>,
}

#[derive(Debug)]
struct Line {
    text: String,
    entry: Option<(Address, PublicKey)>,
}

#[derive(Debug)]
pub enum Error {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Syntax {
        path: PathBuf,
        line: usize,
        reason: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Syntax { path, line, reason } => {
                write!(f, "{}:{line}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for Error {}

impl TrustStore {
    /// Reads the trust store; a missing file is an empty store.
    pub fn load(path: PathBuf) -> Result<Self, Error> {
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
            Err(source) => return Err(Error::Io { path, source }),
        };
        let mut store = Self {
            path,
            lines: Vec::new(),
        };
        for (n, text) in text.lines().enumerate() {
            let syntax = |reason: String| Error::Syntax {
                path: store.path.clone(),
                line: n + 1,
                reason,
            };
            let entry = parse_line(text).map_err(|r| syntax(r.to_owned()))?;
            if let Some((address, key)) = &entry
                && let Some(known) = store.get(address)
                && known != key
            {
                // Two different keys for one address: neither can be trusted.
                return Err(syntax(format!("second, different key for {address}")));
            }
            store.lines.push(Line {
                text: text.to_owned(),
                entry,
            });
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, address: &Address) -> Option<&PublicKey> {
        self.entries().find(|(a, _)| *a == address).map(|(_, k)| k)
    }

    pub fn entries(&self) -> impl Iterator<Item = (&Address, &PublicKey)> {
        self.lines
            .iter()
            .filter_map(|l| l.entry.as_ref().map(|(a, k)| (a, k)))
    }

    /// Adds an entry for an address that has none.
    pub fn add(&mut self, address: Address, key: PublicKey) -> Result<(), Error> {
        debug_assert!(self.get(&address).is_none());
        self.lines.push(Line {
            text: format!("{address} {}", key.to_base64()),
            entry: Some((address, key)),
        });
        self.save()
    }

    /// Removes the entry of `address`; returns whether there was one.
    pub fn remove(&mut self, address: &Address) -> Result<bool, Error> {
        let before = self.lines.len();
        self.lines
            .retain(|l| l.entry.as_ref().is_none_or(|(a, _)| a != address));
        if self.lines.len() == before {
            return Ok(false);
        }
        self.save().map(|()| true)
    }

    /// Writes the whole file to a temporary file and renames it over the old one, so
    /// a crash never leaves a truncated trust store.
    fn save(&self) -> Result<(), Error> {
        let io_error = |source| Error::Io {
            path: self.path.clone(),
            source,
        };
        let mut text = String::new();
        if self.lines.is_empty() || !self.lines[0].text.starts_with('#') {
            text.push_str(HEADER);
        }
        for line in &self.lines {
            text.push_str(&line.text);
            text.push('\n');
        }
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir).map_err(io_error)?;
        }
        let mut temp = self.path.clone().into_os_string();
        temp.push(format!(".tmp-{}", std::process::id()));
        let temp = PathBuf::from(temp);
        fs::write(&temp, text).map_err(io_error)?;
        fs::rename(&temp, &self.path).map_err(|e| {
            let _ = fs::remove_file(&temp);
            io_error(e)
        })
    }
}

/// Parses one line: `None` for an empty line or a comment.
fn parse_line(text: &str) -> Result<Option<(Address, PublicKey)>, &'static str> {
    let text = text.trim();
    if text.is_empty() || text.starts_with('#') {
        return Ok(None);
    }
    let mut fields = text.split_whitespace();
    let (Some(address), Some(key), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err("expected HOST:PORT KEY");
    };
    let address = address.parse().map_err(|_| "invalid Server address")?;
    let key = PublicKey::from_base64(key).ok_or("invalid key: expected base64")?;
    Ok(Some((address, key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ServerKey;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stpt-trust-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("sub").join(FILE_NAME)
    }

    fn address(s: &str) -> Address {
        s.parse().unwrap()
    }

    #[test]
    fn add_get_remove_persist() {
        let path = temp_path("persist");
        let mut store = TrustStore::load(path.clone()).unwrap();
        assert_eq!(store.entries().count(), 0);

        let a = ServerKey::generate().public_key();
        let b = ServerKey::generate().public_key();
        store.add(address("Example.org"), a.clone()).unwrap();
        store.add(address("[::1]:900"), b.clone()).unwrap();

        let store = TrustStore::load(path.clone()).unwrap();
        assert_eq!(store.get(&address("example.org:843")), Some(&a));
        assert_eq!(store.get(&address("[0::1]:900")), Some(&b));
        assert_eq!(store.get(&address("example.org:844")), None);

        let mut store = store;
        assert!(store.remove(&address("example.org")).unwrap());
        assert!(!store.remove(&address("example.org")).unwrap());
        let store = TrustStore::load(path.clone()).unwrap();
        assert_eq!(store.entries().count(), 1);
        assert_eq!(store.get(&address("example.org")), None);

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# STPT trust store"), "{text}");
        assert!(
            text.contains(&format!("[::1]:900 {}\n", b.to_base64())),
            "{text}"
        );
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn comments_are_kept() {
        let path = temp_path("comments");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let key = ServerKey::generate().public_key();
        fs::write(&path, format!("# mine\n\nhost:1 {}\n", key.to_base64())).unwrap();
        let mut store = TrustStore::load(path.clone()).unwrap();
        store.add(address("other"), key.clone()).unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# mine\n\nhost:1 "), "{text}");
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }

    #[test]
    fn invalid_files_are_errors() {
        let path = temp_path("invalid");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let a = ServerKey::generate().public_key().to_base64();
        let b = ServerKey::generate().public_key().to_base64();
        for (text, line) in [
            ("host".to_owned(), 1),
            (format!("# c\nhost {a} extra"), 2),
            ("host:0 AAAA".to_owned(), 1),
            ("host not-base64!".to_owned(), 1),
            (format!("host {a}\nHOST:843 {b}"), 2),
        ] {
            fs::write(&path, &text).unwrap();
            match TrustStore::load(path.clone()) {
                Err(Error::Syntax { line: l, .. }) => assert_eq!(l, line, "{text}"),
                other => panic!("{text}: {other:?}"),
            }
        }
        // The same entry twice is harmless.
        fs::write(&path, format!("host {a}\nhost:843 {a}\n")).unwrap();
        assert!(TrustStore::load(path.clone()).is_ok());
        fs::remove_dir_all(path.parent().unwrap().parent().unwrap()).unwrap();
    }
}
