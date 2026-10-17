//! User authentication messages, channel binding and the user key
//! (PROTOCOL.md §12).

use std::path::Path;

use aws_lc_rs::signature::{self, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::cbor::{self, Value};
use crate::hello::AUTH_PUBLICKEY_ED25519;
use crate::identity::{self, KeyFileError, PublicKey};
use crate::wire::{AUTH_REQUEST, AUTH_RESULT, Code, Failure, Message};

/// Maximum length of an Account name in bytes (§13.4).
pub const MAX_ACCOUNT_LEN: usize = 256;

/// Context string of the signed data (§12.3).
const CONTEXT: &str = "STPT user authentication";

/// TLS exporter label of the channel binding (§12.3).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-STPT-user-auth";

/// DER prefix of the SubjectPublicKeyInfo of an Ed25519 key (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// SubjectPublicKeyInfo of a raw Ed25519 public key.
pub fn ed25519_spki(raw: &[u8; 32]) -> PublicKey {
    let mut der = ED25519_SPKI_PREFIX.to_vec();
    der.extend_from_slice(raw);
    PublicKey::from_spki(&der)
}

/// The raw Ed25519 key of a SubjectPublicKeyInfo; `None` for any other key.
pub fn ed25519_raw(key: &PublicKey) -> Option<[u8; 32]> {
    key.as_spki()
        .strip_prefix(&ED25519_SPKI_PREFIX[..])?
        .try_into()
        .ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub method: u64,
    pub account: String,
    pub key: [u8; 32],
    pub signature: [u8; 64],
}

impl AuthRequest {
    pub fn to_message(&self) -> Message {
        Message::new(
            AUTH_REQUEST,
            vec![
                (0, Value::Uint(self.method)),
                (1, Value::Text(self.account.clone())),
                (2, Value::Bytes(self.key.to_vec())),
                (3, Value::Bytes(self.signature.to_vec())),
            ],
        )
    }

    /// Checks the CDDL of §12.2 and the Account name limit of §13.4.
    pub fn from_message(message: &Message) -> Result<Self, Failure> {
        debug_assert_eq!(message.kind, AUTH_REQUEST);
        let method = message
            .field(0)
            .and_then(Value::as_uint)
            .ok_or_else(|| Failure::violation("AUTH_REQUEST: method missing or not a uint"))?;
        let Some(Value::Text(account)) = message.field(1) else {
            return Err(Failure::violation(
                "AUTH_REQUEST: Account missing or not a text string",
            ));
        };
        if account.len() > MAX_ACCOUNT_LEN {
            return Err(Failure::new(
                Code::LimitExceeded,
                format!("Account name of {} bytes", account.len()),
            ));
        }
        let bytes = |key, what: &str| match message.field(key) {
            Some(Value::Bytes(b)) => Ok(b.as_slice()),
            _ => Err(Failure::violation(format!(
                "AUTH_REQUEST: {what} missing or not a byte string"
            ))),
        };
        let key = bytes(2, "public key")?
            .try_into()
            .map_err(|_| Failure::violation("AUTH_REQUEST: public key is not 32 bytes"))?;
        let signature = bytes(3, "signature")?
            .try_into()
            .map_err(|_| Failure::violation("AUTH_REQUEST: signature is not 64 bytes"))?;
        Ok(Self {
            method,
            account: account.clone(),
            key,
            signature,
        })
    }

    /// Whether the signature is valid for the signed data rebuilt from this request
    /// and the own exporter value (§12.3; RFC 8032 §5.1.7).
    pub fn signature_valid(&self, exporter: &[u8; 32]) -> bool {
        let data = signed_data(exporter, self.method, &self.account, &self.key);
        UnparsedPublicKey::new(&signature::ED25519, &self.key)
            .verify(&data, &self.signature)
            .is_ok()
    }
}

pub fn result_message(success: bool) -> Message {
    Message::new(AUTH_RESULT, vec![(0, Value::Bool(success))])
}

/// Success of an AUTH_RESULT.
pub fn result_from_message(message: &Message) -> Result<bool, Failure> {
    if message.kind != AUTH_RESULT {
        return Err(Failure::violation(format!(
            "message type {} instead of AUTH_RESULT",
            message.kind
        )));
    }
    match message.field(0) {
        Some(Value::Bool(success)) => Ok(*success),
        _ => Err(Failure::violation(
            "AUTH_RESULT: success missing or not a bool",
        )),
    }
}

/// Deterministic CBOR of `auth-signed-data` (§12.3).
pub fn signed_data(exporter: &[u8; 32], method: u64, account: &str, key: &[u8; 32]) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Text(CONTEXT.to_owned()),
        Value::Bytes(exporter.to_vec()),
        Value::Uint(method),
        Value::Text(account.to_owned()),
        Value::Bytes(key.to_vec()),
    ]))
}

/// The TLS exporter value of the Connection for user authentication (§12.3).
pub fn exporter(connection: &quinn::Connection) -> Result<[u8; 32], Failure> {
    let mut value = [0u8; 32];
    connection
        .export_keying_material(&mut value, EXPORTER_LABEL, b"")
        .map_err(|e| Failure::new(Code::InternalError, format!("TLS exporter: {e:?}")))?;
    Ok(value)
}

/// Ed25519 key of a user, for `publickey-ed25519`.
pub struct UserKey {
    pair: Ed25519KeyPair,
}

impl UserKey {
    /// Reads a PEM PKCS#8 Ed25519 private key, e.g. one written by
    /// `openssl genpkey -algorithm ed25519`; on Unix accessible by its owner only.
    pub fn load(path: &Path) -> Result<Self, KeyFileError> {
        let der = identity::read_private_key(path)?;
        let pair =
            Ed25519KeyPair::from_pkcs8_maybe_unchecked(der.secret_pkcs8_der()).map_err(|_| {
                KeyFileError::Format {
                    path: path.to_owned(),
                    reason: "not an Ed25519 private key".to_owned(),
                }
            })?;
        Ok(Self { pair })
    }

    #[cfg(test)]
    pub fn generate() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new()).unwrap();
        Self {
            pair: Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap(),
        }
    }

    pub fn raw_public(&self) -> [u8; 32] {
        self.pair
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key is 32 bytes")
    }

    pub fn public_key(&self) -> PublicKey {
        ed25519_spki(&self.raw_public())
    }

    /// AUTH_REQUEST for `account`, bound to the Connection by `exporter`.
    pub fn request(&self, exporter: &[u8; 32], account: &str) -> AuthRequest {
        let key = self.raw_public();
        let data = signed_data(exporter, AUTH_PUBLICKEY_ED25519, account, &key);
        let signature = self
            .pair
            .sign(&data)
            .as_ref()
            .try_into()
            .expect("Ed25519 signature is 64 bytes");
        AuthRequest {
            method: AUTH_PUBLICKEY_ED25519,
            account: account.to_owned(),
            key,
            signature,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_binds_every_field() {
        let user = UserKey::generate();
        let exporter = [7u8; 32];
        let request = user.request(&exporter, "alice");
        assert!(request.signature_valid(&exporter));
        // Another Connection, Account, method, key or signature: invalid.
        assert!(!request.signature_valid(&[8u8; 32]));
        let changed = |f: fn(&mut AuthRequest)| {
            let mut r = request.clone();
            f(&mut r);
            r.signature_valid(&exporter)
        };
        assert!(!changed(|r| r.account = "bob".into()));
        assert!(!changed(|r| r.method = 2));
        assert!(!changed(|r| r.key = UserKey::generate().raw_public()));
        assert!(!changed(|r| r.signature[0] ^= 1));
    }

    #[test]
    fn signed_data_layout() {
        let data = signed_data(&[0u8; 32], 1, "a", &[1u8; 32]);
        let Value::Array(items) = cbor::decode(&data).unwrap() else {
            panic!()
        };
        assert_eq!(items[0], Value::Text("STPT user authentication".into()));
        assert_eq!(items[1], Value::Bytes(vec![0; 32]));
        assert_eq!(items[2], Value::Uint(1));
        assert_eq!(items[3], Value::Text("a".into()));
        assert_eq!(items[4], Value::Bytes(vec![1; 32]));
    }

    #[test]
    fn request_message() {
        let request = UserKey::generate().request(&[0u8; 32], "alice");
        let message = Message::decode(&request.to_message().encode()).unwrap();
        assert_eq!(AuthRequest::from_message(&message).unwrap(), request);

        let mut fields = vec![
            (0, Value::Uint(1)),
            (1, Value::Text("alice".into())),
            (2, Value::Bytes(vec![0; 32])),
            (3, Value::Bytes(vec![0; 64])),
        ];
        let parse = |fields: &Vec<(u64, Value)>| {
            AuthRequest::from_message(&Message::new(AUTH_REQUEST, fields.clone()))
        };
        assert!(parse(&fields).is_ok());
        for (i, bad) in [
            (0, Value::Nint(0)),
            (1, Value::Bytes(b"alice".to_vec())),
            (2, Value::Bytes(vec![0; 31])),
            (3, Value::Bytes(vec![0; 65])),
            (3, Value::Text("x".into())),
        ] {
            let mut f = fields.clone();
            f[i].1 = bad;
            assert_eq!(
                parse(&f).unwrap_err().code,
                Code::ProtocolViolation,
                "{f:?}"
            );
        }
        fields[1].1 = Value::Text("a".repeat(MAX_ACCOUNT_LEN + 1));
        assert_eq!(parse(&fields).unwrap_err().code, Code::LimitExceeded);
        fields[1].1 = Value::Text("a".repeat(MAX_ACCOUNT_LEN));
        assert!(parse(&fields).is_ok());
    }

    #[test]
    fn result_messages() {
        for success in [true, false] {
            let message = Message::decode(&result_message(success).encode()).unwrap();
            assert_eq!(result_from_message(&message), Ok(success));
        }
        let bad = Message::new(AUTH_RESULT, vec![(0, Value::Uint(1))]);
        assert!(result_from_message(&bad).is_err());
        assert!(result_from_message(&Message::new(AUTH_REQUEST, vec![])).is_err());
    }

    #[test]
    fn spki_conversion() {
        let user = UserKey::generate();
        let spki = user.public_key();
        assert_eq!(spki.as_spki().len(), 44);
        assert_eq!(ed25519_raw(&spki), Some(user.raw_public()));
        assert_eq!(ed25519_raw(&PublicKey::from_spki(&[0; 44])), None);
        // The same encoding as a Server key, which rustls produces.
        let server = crate::identity::ServerKey::generate().public_key();
        assert!(ed25519_raw(&server).is_some());
    }
}
