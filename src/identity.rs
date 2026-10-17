//! Server Identity (PROTOCOL.md §9): key pair, public key, fingerprint, key file.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use aws_lc_rs::digest::{SHA256, SHA256_OUTPUT_LEN, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use rustls::SignatureAlgorithm;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

/// Public key of a Server Identity: DER-encoded SubjectPublicKeyInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    pub fn from_spki(der: &[u8]) -> Self {
        Self(der.to_vec())
    }

    /// SHA-256 over the SubjectPublicKeyInfo (§9.2).
    pub fn fingerprint(&self) -> Fingerprint {
        let hash = digest(&SHA256, &self.0);
        Fingerprint(hash.as_ref().try_into().expect("SHA-256 output length"))
    }

    /// Base64 of the SubjectPublicKeyInfo, with padding (trust store).
    pub fn to_base64(&self) -> String {
        STANDARD.encode(&self.0)
    }

    pub fn from_base64(text: &str) -> Option<Self> {
        STANDARD.decode(text).ok().map(Self)
    }
}

/// Fingerprint of a public key; text form `SHA256:<base64 without padding>` (§9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint([u8; SHA256_OUTPUT_LEN]);

const FINGERPRINT_PREFIX: &str = "SHA256:";

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{FINGERPRINT_PREFIX}{}", STANDARD_NO_PAD.encode(self.0))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintError;

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected the full fingerprint SHA256:<43 base64 characters>")
    }
}

impl std::error::Error for FingerprintError {}

impl FromStr for Fingerprint {
    type Err = FingerprintError;

    /// Accepts only the full text form: a prefix of a fingerprint is never enough (§9.2).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let encoded = s.strip_prefix(FINGERPRINT_PREFIX).ok_or(FingerprintError)?;
        let hash = STANDARD_NO_PAD
            .decode(encoded)
            .map_err(|_| FingerprintError)?;
        Ok(Self(hash.try_into().map_err(|_| FingerprintError)?))
    }
}

/// Default path of the Server key file.
pub const SERVER_KEY_PATH: &str = "/etc/stpt/server_key";

/// Key pair of a Server Identity (§9.1): Ed25519.
pub struct ServerKey {
    certified: Arc<CertifiedKey>,
}

#[derive(Debug)]
pub enum KeyFileError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    /// Readable by group or others (Unix).
    #[cfg_attr(not(unix), expect(dead_code, reason = "checked on Unix only"))]
    Permissions {
        path: PathBuf,
        mode: u32,
    },
    Format {
        path: PathBuf,
        reason: String,
    },
}

impl fmt::Display for KeyFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Permissions { path, mode } => write!(
                f,
                "{}: permissions {mode:03o} are too open, the key must be accessible \
                 by its owner only (chmod 600)",
                path.display()
            ),
            Self::Format { path, reason } => write!(f, "{}: {reason}", path.display()),
        }
    }
}

impl std::error::Error for KeyFileError {}

impl ServerKey {
    /// Generates a new Ed25519 key pair, held in memory only.
    #[cfg(test)]
    pub fn generate() -> Self {
        Self::from_pkcs8(generate_pkcs8()).expect("generated Ed25519 key is valid")
    }

    /// Reads the key file at `path`, or creates it with a new key if it does not
    /// exist. Returns the key and whether it was created.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool), KeyFileError> {
        match load(path) {
            Err(KeyFileError::Io { source, .. }) if source.kind() == io::ErrorKind::NotFound => {
                match create(path) {
                    Ok(key) => Ok((key, true)),
                    // Another Server process created it meanwhile.
                    Err(KeyFileError::Io { source, .. })
                        if source.kind() == io::ErrorKind::AlreadyExists =>
                    {
                        Ok((load(path)?, false))
                    }
                    Err(e) => Err(e),
                }
            }
            other => other.map(|key| (key, false)),
        }
    }

    fn from_pkcs8(der: PrivatePkcs8KeyDer<'static>) -> Result<Self, String> {
        let signing = crate::tls::crypto_provider()
            .key_provider
            .load_private_key(der.into())
            .map_err(|e| format!("invalid private key: {e}"))?;
        if signing.algorithm() != SignatureAlgorithm::ED25519 {
            return Err("not an Ed25519 key".to_owned());
        }
        let spki = signing.public_key().expect("Ed25519 key has a public key");
        let certified = CertifiedKey::new(vec![CertificateDer::from(spki.to_vec())], signing);
        Ok(Self {
            certified: Arc::new(certified),
        })
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.certified.end_entity_cert().expect("one key").to_vec())
    }

    pub(crate) fn certified(&self) -> Arc<CertifiedKey> {
        self.certified.clone()
    }
}

fn generate_pkcs8() -> PrivatePkcs8KeyDer<'static> {
    let pkcs8 =
        Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("Ed25519 key generation");
    PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec())
}

/// Reads a PEM PKCS#8 key file; on Unix it must not be accessible by group or others.
fn load(path: &Path) -> Result<ServerKey, KeyFileError> {
    let io_error = |source| KeyFileError::Io {
        path: path.to_owned(),
        source,
    };
    let mut file = File::open(path).map_err(io_error)?;
    check_permissions(&file, path)?;
    let mut pem = Vec::new();
    file.read_to_end(&mut pem).map_err(io_error)?;
    let format = |reason| KeyFileError::Format {
        path: path.to_owned(),
        reason,
    };
    let der = PrivatePkcs8KeyDer::from_pem_slice(&pem)
        .map_err(|e| format(format!("expected a PEM PKCS#8 private key: {e}")))?;
    ServerKey::from_pkcs8(der).map_err(format)
}

#[cfg(unix)]
fn check_permissions(file: &File, path: &Path) -> Result<(), KeyFileError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = file
        .metadata()
        .map_err(|source| KeyFileError::Io {
            path: path.to_owned(),
            source,
        })?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(KeyFileError::Permissions {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_file: &File, _path: &Path) -> Result<(), KeyFileError> {
    Ok(())
}

/// Creates the key file with a new key, readable by its owner only; never replaces
/// an existing file.
fn create(path: &Path) -> Result<ServerKey, KeyFileError> {
    let io_error = |source| KeyFileError::Io {
        path: path.to_owned(),
        source,
    };
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir).map_err(io_error)?;
    }
    let der = generate_pkcs8();
    let pem = to_pem(der.secret_pkcs8_der());
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).map_err(io_error)?;
    file.write_all(pem.as_bytes()).map_err(io_error)?;
    file.sync_all().map_err(io_error)?;
    Ok(ServerKey::from_pkcs8(der).expect("generated Ed25519 key is valid"))
}

/// PEM encoding of a PKCS#8 private key (RFC 7468).
fn to_pem(der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN PRIVATE KEY-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END PRIVATE KEY-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stpt-identity-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn fingerprint_text_form() {
        // §9.2 example: SHA-256 of the empty input.
        let empty = PublicKey::from_spki(b"");
        assert_eq!(
            empty.fingerprint().to_string(),
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
        );
        let fp = empty.fingerprint();
        assert_eq!(fp.to_string().parse(), Ok(fp));
    }

    #[test]
    fn fingerprint_must_be_complete() {
        let full = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        for bad in [
            "",
            "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
            "SHA256:47DEQpj8HBSa",
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFUA",
            "sha256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU",
            "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFV",
        ] {
            assert_eq!(bad.parse::<Fingerprint>(), Err(FingerprintError), "{bad}");
        }
        assert!(full.parse::<Fingerprint>().is_ok());
    }

    #[test]
    fn public_key_base64_round_trip() {
        let key = ServerKey::generate().public_key();
        assert_eq!(PublicKey::from_base64(&key.to_base64()), Some(key));
        assert_eq!(PublicKey::from_base64("not base64!"), None);
    }

    #[test]
    fn key_file_is_created_once_and_reused() {
        let dir = temp_dir("create");
        let path = dir.join("sub").join("server_key");
        let (first, created) = ServerKey::load_or_create(&path).unwrap();
        assert!(created);
        let (second, created) = ServerKey::load_or_create(&path).unwrap();
        assert!(!created);
        assert_eq!(first.public_key(), second.public_key());
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("-----BEGIN PRIVATE KEY-----\n"), "{text}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn invalid_key_files_are_errors() {
        let dir = temp_dir("invalid");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server_key");
        fs::write(&path, "garbage").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            ServerKey::load_or_create(&path),
            Err(KeyFileError::Format { .. })
        ));
        // A PKCS#8 key of another algorithm: ECDSA P-256.
        let ecdsa = aws_lc_rs::signature::EcdsaKeyPair::generate_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &SystemRandom::new(),
        )
        .unwrap();
        fs::write(&path, to_pem(ecdsa.as_ref())).unwrap();
        let err = ServerKey::load_or_create(&path).err().unwrap();
        assert!(err.to_string().ends_with("not an Ed25519 key"), "{err}");
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn key_file_readable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perm");
        let path = dir.join("server_key");
        ServerKey::load_or_create(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = ServerKey::load_or_create(&path).err().unwrap();
        assert!(matches!(err, KeyFileError::Permissions { mode: 0o644, .. }));
        fs::remove_dir_all(dir).unwrap();
    }
}
