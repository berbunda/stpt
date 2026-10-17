//! HELLO exchange and negotiation (PROTOCOL.md §10, §11, §13.4).

use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use crate::cbor::Value;
use crate::wire::{CLIENT_HELLO, Code, DEFAULT_MESSAGE_LIMIT, Failure, Message, SERVER_HELLO};

/// Current draft wire version (§11.1).
pub const WIRE_VERSION: u64 = 0xFF00_0001;

/// Wire versions this implementation supports.
const SUPPORTED_VERSIONS: &[u64] = &[WIRE_VERSION];

/// User authentication method `publickey-ed25519` (§12.1).
pub const AUTH_PUBLICKEY_ED25519: u64 = 1;

/// Receiver limits announced in HELLO (§13.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum message size in bytes.
    pub max_message: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_message: DEFAULT_MESSAGE_LIMIT,
        }
    }
}

impl Limits {
    /// `None` when every limit is the default, so the field is left out.
    fn to_value(self) -> Option<Value> {
        (self != Self::default())
            .then(|| Value::Map(vec![(Value::Uint(0), Value::Uint(self.max_message))]))
    }

    fn from_value(value: Option<&Value>) -> Result<Self, Failure> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let entries = value
            .as_map()
            .ok_or_else(|| Failure::violation("limits is not a map"))?;
        if !entries.iter().all(|(k, _)| k.is_int()) {
            return Err(Failure::violation("limits key is not an integer"));
        }
        let max_message = match entries.iter().find(|(k, _)| *k == Value::Uint(0)) {
            None => DEFAULT_MESSAGE_LIMIT,
            Some((_, v)) => v
                .as_uint()
                .ok_or_else(|| Failure::violation("message size limit is not a uint"))?,
        };
        if max_message < DEFAULT_MESSAGE_LIMIT {
            return Err(Failure::violation(format!(
                "message size limit {max_message} below the minimum {DEFAULT_MESSAGE_LIMIT}"
            )));
        }
        Ok(Self { max_message })
    }
}

/// Capability id => parameters (§11.2).
pub type Capabilities = Vec<(u64, Value)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub versions: Vec<u64>,
    pub capabilities: Capabilities,
    pub limits: Limits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u64,
    pub capabilities: Capabilities,
    pub limits: Limits,
    pub auth_methods: Vec<u64>,
}

impl ClientHello {
    /// CLIENT_HELLO of this implementation: its versions, no capabilities, and one
    /// random GREASE version and capability (§11.5) to keep Servers tolerant.
    pub fn ours() -> Self {
        let mut nibble = [0u8; 1];
        SystemRandom::new()
            .fill(&mut nibble)
            .expect("system random generator");
        let digit = u64::from(nibble[0] & 0x0F);
        let mut versions = SUPPORTED_VERSIONS.to_vec();
        versions.push(digit * 0x1010_1010 + 0x0A0A_0A0A);
        Self {
            versions,
            capabilities: vec![(digit * 0x1010 + 0x0A0A, Value::Null)],
            limits: Limits::default(),
        }
    }

    pub fn to_message(&self) -> Message {
        let mut fields = vec![(
            0,
            Value::Array(self.versions.iter().map(|v| Value::Uint(*v)).collect()),
        )];
        if !self.capabilities.is_empty() {
            fields.push((1, capabilities_value(&self.capabilities)));
        }
        if let Some(limits) = self.limits.to_value() {
            fields.push((2, limits));
        }
        Message::new(CLIENT_HELLO, fields)
    }

    pub fn from_message(message: &Message) -> Result<Self, Failure> {
        if message.kind != CLIENT_HELLO {
            return Err(Failure::violation(format!(
                "message type {} instead of CLIENT_HELLO",
                message.kind
            )));
        }
        Ok(Self {
            versions: uint_list(message.field(0), "wire versions")?,
            capabilities: capabilities(message.field(1))?,
            limits: Limits::from_value(message.field(2))?,
        })
    }
}

impl ServerHello {
    /// The Server's answer: the selected version, no capabilities (none is defined
    /// yet, so every offered one is unknown and ignored), its limits and methods.
    pub fn answer(hello: &ClientHello) -> Result<Self, Failure> {
        let version = select_version(&hello.versions, SUPPORTED_VERSIONS).ok_or_else(|| {
            Failure::new(
                Code::VersionNegotiationFailed,
                format!("no common wire version in {:x?}", hello.versions),
            )
        })?;
        Ok(Self {
            version,
            capabilities: Vec::new(),
            limits: Limits::default(),
            auth_methods: vec![AUTH_PUBLICKEY_ED25519],
        })
    }

    pub fn to_message(&self) -> Message {
        let mut fields = vec![(0, Value::Uint(self.version))];
        if !self.capabilities.is_empty() {
            fields.push((1, capabilities_value(&self.capabilities)));
        }
        if let Some(limits) = self.limits.to_value() {
            fields.push((2, limits));
        }
        fields.push((
            3,
            Value::Array(self.auth_methods.iter().map(|m| Value::Uint(*m)).collect()),
        ));
        Message::new(SERVER_HELLO, fields)
    }

    pub fn from_message(message: &Message) -> Result<Self, Failure> {
        if message.kind != SERVER_HELLO {
            return Err(Failure::violation(format!(
                "message type {} instead of SERVER_HELLO",
                message.kind
            )));
        }
        let version = message
            .field(0)
            .and_then(Value::as_uint)
            .ok_or_else(|| Failure::violation("selected wire version missing or not a uint"))?;
        Ok(Self {
            version,
            capabilities: capabilities(message.field(1))?,
            limits: Limits::from_value(message.field(2))?,
            auth_methods: uint_list(message.field(3), "authentication methods")?,
        })
    }

    /// Client check of the answer against its CLIENT_HELLO (§10.2, §11.1, §11.2).
    pub fn check(&self, offered: &ClientHello) -> Result<(), Failure> {
        if !offered.versions.contains(&self.version) || is_grease_version(self.version) {
            return Err(Failure::violation(format!(
                "selected wire version {:#x} was not offered",
                self.version
            )));
        }
        for (id, _) in &self.capabilities {
            if !offered.capabilities.iter().any(|(o, _)| o == id) || is_grease_capability(*id) {
                return Err(Failure::violation(format!(
                    "selected capability {id:#x} was not offered"
                )));
            }
        }
        Ok(())
    }
}

/// The version the Server selects: the highest final version both support, else
/// the highest common draft version; GREASE values never (§11.1).
pub fn select_version(offered: &[u64], supported: &[u64]) -> Option<u64> {
    let common = || {
        offered
            .iter()
            .copied()
            .filter(|v| supported.contains(v) && !is_grease_version(*v))
    };
    common()
        .filter(|v| (1..=0x7FFF_FFFF).contains(v))
        .max()
        .or_else(|| {
            common()
                .filter(|v| (0xFF00_0000..=0xFFFF_FFFF).contains(v))
                .max()
        })
}

/// GREASE wire versions 0x0A0A0A0A, 0x1A1A1A1A, …, 0xFAFAFAFA (§11.5).
fn is_grease_version(v: u64) -> bool {
    let high = (v >> 4) & 0x0F0F_0F0F;
    v <= 0xFFFF_FFFF && v & 0x0F0F_0F0F == 0x0A0A_0A0A && high == (high & 0x0F) * 0x0101_0101
}

/// GREASE capability ids 0x0A0A, 0x1A1A, …, 0xFAFA (§11.5).
fn is_grease_capability(id: u64) -> bool {
    let high = (id >> 4) & 0x0F0F;
    id <= 0xFFFF && id & 0x0F0F == 0x0A0A && high == (high & 0x0F) * 0x0101
}

fn uint_list(value: Option<&Value>, what: &str) -> Result<Vec<u64>, Failure> {
    let items = value
        .and_then(Value::as_array)
        .ok_or_else(|| Failure::violation(format!("{what} missing or not an array")))?;
    if items.is_empty() {
        return Err(Failure::violation(format!("{what} empty")));
    }
    items
        .iter()
        .map(|v| {
            v.as_uint()
                .ok_or_else(|| Failure::violation(format!("{what}: not a uint")))
        })
        .collect()
}

fn capabilities(value: Option<&Value>) -> Result<Capabilities, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_map()
        .ok_or_else(|| Failure::violation("capabilities is not a map"))?;
    entries
        .iter()
        .map(|(k, v)| {
            k.as_uint()
                .map(|id| (id, v.clone()))
                .ok_or_else(|| Failure::violation("capability id is not a uint"))
        })
        .collect()
}

fn capabilities_value(capabilities: &Capabilities) -> Value {
    Value::Map(
        capabilities
            .iter()
            .map(|(id, v)| (Value::Uint(*id), v.clone()))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(message: &Message) -> Message {
        Message::decode(&message.encode()).unwrap()
    }

    #[test]
    fn grease_values() {
        for digit in 0..16u64 {
            assert!(is_grease_version(digit * 0x1010_1010 + 0x0A0A_0A0A));
            assert!(is_grease_capability(digit * 0x1010 + 0x0A0A));
        }
        for v in [
            WIRE_VERSION,
            1,
            0x0A0A,
            0x1A2A_3A4A,
            0x0A_0A0A_0A0A,
            0x0A0A_0A1A,
        ] {
            assert!(!is_grease_version(v), "{v:#x}");
        }
        for id in [1, 0x1A2A, 0x0A0A0A, 0x0A1A] {
            assert!(!is_grease_capability(id), "{id:#x}");
        }
    }

    #[test]
    fn our_hello_carries_grease() {
        let hello = ClientHello::ours();
        assert_eq!(hello.versions[0], WIRE_VERSION);
        assert_eq!(hello.versions.len(), 2);
        assert!(is_grease_version(hello.versions[1]));
        assert_eq!(hello.capabilities.len(), 1);
        assert!(is_grease_capability(hello.capabilities[0].0));
        let decoded = ClientHello::from_message(&decode(&hello.to_message())).unwrap();
        assert_eq!(decoded, hello);
    }

    #[test]
    fn version_selection() {
        let draft = |n: u64| 0xFF00_0000 + n;
        let supported = [1, 2, draft(1), draft(2)];
        assert_eq!(
            select_version(&[draft(1), draft(2)], &supported),
            Some(draft(2))
        );
        assert_eq!(select_version(&[draft(2), 1], &supported), Some(1));
        assert_eq!(select_version(&[1, 2, draft(9)], &supported), Some(2));
        assert_eq!(select_version(&[3, draft(3)], &supported), None);
        assert_eq!(select_version(&[0x0A0A_0A0A], &[0x0A0A_0A0A]), None);
        assert_eq!(select_version(&[0], &[0]), None);
    }

    #[test]
    fn server_answer() {
        let hello = ClientHello::ours();
        let answer = ServerHello::answer(&hello).unwrap();
        assert_eq!(answer.version, WIRE_VERSION);
        assert!(answer.capabilities.is_empty());
        assert_eq!(answer.auth_methods, [AUTH_PUBLICKEY_ED25519]);
        let decoded = ServerHello::from_message(&decode(&answer.to_message())).unwrap();
        assert_eq!(decoded, answer);
        decoded.check(&hello).unwrap();

        let unknown = ClientHello {
            versions: vec![0xFF00_0009, 0x2A2A_2A2A],
            ..hello
        };
        let err = ServerHello::answer(&unknown).unwrap_err();
        assert_eq!(err.code, Code::VersionNegotiationFailed);
    }

    #[test]
    fn client_checks_the_answer() {
        let hello = ClientHello::ours();
        let good = ServerHello::answer(&hello).unwrap();
        let grease_version = hello.versions[1];
        let grease_capability = hello.capabilities[0].0;
        let bad = [
            ServerHello {
                version: 0xFF00_0002,
                ..good.clone()
            },
            ServerHello {
                version: grease_version,
                ..good.clone()
            },
            ServerHello {
                capabilities: vec![(7, Value::Null)],
                ..good.clone()
            },
            ServerHello {
                capabilities: vec![(grease_capability, Value::Null)],
                ..good.clone()
            },
        ];
        for answer in bad {
            let err = answer.check(&hello).unwrap_err();
            assert_eq!(err.code, Code::ProtocolViolation, "{answer:?}");
        }
    }

    #[test]
    fn invalid_hellos() {
        let client = |fields: Vec<(u64, Value)>| {
            ClientHello::from_message(&Message::new(CLIENT_HELLO, fields))
        };
        let versions = Value::Array(vec![Value::Uint(WIRE_VERSION)]);
        assert!(client(vec![(0, versions.clone())]).is_ok());
        // Unknown keys are ignored.
        assert!(client(vec![(0, versions.clone()), (99, Value::Null)]).is_ok());
        let bad: [Vec<(u64, Value)>; 7] = [
            vec![],
            vec![(0, Value::Array(vec![]))],
            vec![(0, Value::Uint(WIRE_VERSION))],
            vec![(0, Value::Array(vec![Value::Nint(1)]))],
            vec![
                (0, versions.clone()),
                (1, Value::Map(vec![(Value::Nint(0), Value::Null)])),
            ],
            vec![
                (0, versions.clone()),
                (2, Value::Map(vec![(Value::Uint(0), Value::Uint(1024))])),
            ],
            vec![(0, versions.clone()), (2, Value::Uint(0))],
        ];
        for fields in bad {
            assert_eq!(
                client(fields.clone()).unwrap_err().code,
                Code::ProtocolViolation,
                "{fields:?}"
            );
        }
        let limits = client(vec![
            (0, versions.clone()),
            (2, Value::Map(vec![(Value::Uint(0), Value::Uint(1 << 20))])),
        ])
        .unwrap()
        .limits;
        assert_eq!(limits.max_message, 1 << 20);

        let wrong_type = Message::new(SERVER_HELLO, vec![(0, versions)]);
        assert!(ClientHello::from_message(&wrong_type).is_err());

        let server = |fields| ServerHello::from_message(&Message::new(SERVER_HELLO, fields));
        let methods = Value::Array(vec![Value::Uint(1)]);
        assert!(server(vec![(0, Value::Uint(WIRE_VERSION)), (3, methods.clone())]).is_ok());
        assert!(server(vec![(0, Value::Uint(WIRE_VERSION))]).is_err());
        assert!(server(vec![(3, methods.clone())]).is_err());
        assert!(
            server(vec![
                (0, Value::Uint(WIRE_VERSION)),
                (3, Value::Array(vec![]))
            ])
            .is_err()
        );
    }
}
