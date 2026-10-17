//! Frames and messages on STPT streams (PROTOCOL.md §7), message types (§11.3),
//! error codes (§13.2).

use std::fmt;

use quinn::{ReadError, ReadExactError, RecvStream, SendStream, VarInt, WriteError};

use crate::cbor::{self, Value};

/// Message size every Endpoint accepts, and the limit unless the peer announces a
/// larger one (§7.2, §13.4).
pub const DEFAULT_MESSAGE_LIMIT: u64 = 65535;

pub const CLIENT_HELLO: u64 = 1;
pub const SERVER_HELLO: u64 = 2;

/// Error codes (§13.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    NoError = 0,
    ProtocolViolation = 1,
    InternalError = 2,
    VersionNegotiationFailed = 3,
    AuthFailed = 4,
    Timeout = 5,
    LimitExceeded = 6,
    ChannelRejected = 7,
    ServerShutdown = 8,
    SessionNotFound = 9,
    SessionNameInUse = 10,
    AttachmentNotFound = 11,
}

impl Code {
    const ALL: [Code; 12] = [
        Self::NoError,
        Self::ProtocolViolation,
        Self::InternalError,
        Self::VersionNegotiationFailed,
        Self::AuthFailed,
        Self::Timeout,
        Self::LimitExceeded,
        Self::ChannelRejected,
        Self::ServerShutdown,
        Self::SessionNotFound,
        Self::SessionNameInUse,
        Self::AttachmentNotFound,
    ];

    /// The code of a value; `None` for an unknown one, which a receiver treats as
    /// INTERNAL_ERROR.
    pub fn from_value(value: u64) -> Option<Self> {
        Self::ALL.into_iter().find(|c| *c as u64 == value)
    }

    pub fn varint(self) -> VarInt {
        VarInt::from_u32(self as u32)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::NoError => "NO_ERROR",
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
            Self::InternalError => "INTERNAL_ERROR",
            Self::VersionNegotiationFailed => "VERSION_NEGOTIATION_FAILED",
            Self::AuthFailed => "AUTH_FAILED",
            Self::Timeout => "TIMEOUT",
            Self::LimitExceeded => "LIMIT_EXCEEDED",
            Self::ChannelRejected => "CHANNEL_REJECTED",
            Self::ServerShutdown => "SERVER_SHUTDOWN",
            Self::SessionNotFound => "SESSION_NOT_FOUND",
            Self::SessionNameInUse => "SESSION_NAME_IN_USE",
            Self::AttachmentNotFound => "ATTACHMENT_NOT_FOUND",
        }
    }
}

/// A reason to close the Connection, found locally. The reason text goes to the
/// local log or message only; the peer receives the code alone (§13.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub code: Code,
    pub reason: String,
}

impl Failure {
    pub fn new(code: Code, reason: impl Into<String>) -> Self {
        Self {
            code,
            reason: reason.into(),
        }
    }

    pub fn violation(reason: impl Into<String>) -> Self {
        Self::new(Code::ProtocolViolation, reason)
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.reason, self.code.name())
    }
}

/// A message: type and body with integer keys (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: u64,
    pub body: Vec<(Value, Value)>,
}

impl Message {
    pub fn new(kind: u64, fields: Vec<(u64, Value)>) -> Self {
        Self {
            kind,
            body: fields
                .into_iter()
                .map(|(k, v)| (Value::Uint(k), v))
                .collect(),
        }
    }

    /// The field with key `key`; unknown keys are simply never asked for (§7.3).
    pub fn field(&self, key: u64) -> Option<&Value> {
        self.body
            .iter()
            .find(|(k, _)| *k == Value::Uint(key))
            .map(|(_, v)| v)
    }

    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Uint(self.kind),
            Value::Map(self.body.clone()),
        ]))
    }

    /// Decodes a frame payload: strict CBOR (§7.4) of the form `[type, {* int => any}]`.
    pub fn decode(payload: &[u8]) -> Result<Self, Failure> {
        let value =
            cbor::decode(payload).map_err(|e| Failure::violation(format!("invalid CBOR: {e}")))?;
        let invalid = || Failure::violation("message is not [type, {* int => any}]");
        let Value::Array(mut items) = value else {
            return Err(invalid());
        };
        if items.len() != 2 {
            return Err(invalid());
        }
        let (Value::Map(body), Value::Uint(kind)) = (items.pop().unwrap(), items.pop().unwrap())
        else {
            return Err(invalid());
        };
        if !body.iter().all(|(k, _)| k.is_int()) {
            return Err(invalid());
        }
        Ok(Self { kind, body })
    }
}

/// End of reading a message other than a message.
#[derive(Debug)]
pub enum StreamError {
    /// The peer violated the protocol or a limit; the Connection is to be closed.
    Failure(Failure),
    /// The peer reset the stream (RESET_STREAM) or stopped it (STOP_SENDING).
    Reset(VarInt),
    /// The Connection is gone.
    Lost(quinn::ConnectionError),
}

impl From<Failure> for StreamError {
    fn from(f: Failure) -> Self {
        Self::Failure(f)
    }
}

impl From<ReadError> for StreamError {
    fn from(e: ReadError) -> Self {
        match e {
            ReadError::Reset(code) => Self::Reset(code),
            ReadError::ConnectionLost(e) => Self::Lost(e),
            other => Self::Failure(Failure::new(
                Code::InternalError,
                format!("reading: {other}"),
            )),
        }
    }
}

impl From<ReadExactError> for StreamError {
    fn from(e: ReadExactError) -> Self {
        match e {
            ReadExactError::FinishedEarly(_) => {
                Self::Failure(Failure::violation("stream ended inside a frame"))
            }
            ReadExactError::ReadError(e) => e.into(),
        }
    }
}

impl From<WriteError> for StreamError {
    fn from(e: WriteError) -> Self {
        match e {
            WriteError::Stopped(code) => Self::Reset(code),
            WriteError::ConnectionLost(e) => Self::Lost(e),
            other => Self::Failure(Failure::new(
                Code::InternalError,
                format!("writing: {other}"),
            )),
        }
    }
}

/// Reads the next message; `None` at the end of the stream between frames. A frame
/// longer than `limit` is refused before its payload is read (§7.2).
pub async fn read_message(
    recv: &mut RecvStream,
    limit: u64,
) -> Result<Option<Message>, StreamError> {
    let mut first = [0u8; 1];
    match recv.read_exact(&mut first).await {
        Ok(()) => {}
        Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let mut length = [0u8; 8];
    let size = varint_size(first[0]);
    length[0] = first[0];
    recv.read_exact(&mut length[1..size]).await?;
    let length = decode_varint(&length[..size]);
    if length == 0 {
        return Err(Failure::violation("frame of length 0").into());
    }
    if length > limit {
        return Err(Failure::new(
            Code::LimitExceeded,
            format!("message of {length} bytes, limit {limit}"),
        )
        .into());
    }
    let mut payload = vec![0u8; length as usize];
    recv.read_exact(&mut payload).await?;
    Ok(Some(Message::decode(&payload)?))
}

/// Writes `message` as one frame; `limit` is the peer's message size limit.
pub async fn write_message(
    send: &mut SendStream,
    message: &Message,
    limit: u64,
) -> Result<(), StreamError> {
    let payload = message.encode();
    if payload.len() as u64 > limit {
        return Err(Failure::new(
            Code::InternalError,
            format!(
                "own message of {} bytes over the peer limit {limit}",
                payload.len()
            ),
        )
        .into());
    }
    send.write_all(&frame(&payload)).await?;
    Ok(())
}

/// Frame of `payload`: QUIC variable-length integer length, then the payload (§7.2).
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = encode_varint(payload.len() as u64);
    out.extend_from_slice(payload);
    out
}

/// QUIC variable-length integer (RFC 9000 §16) in its shortest form.
fn encode_varint(n: u64) -> Vec<u8> {
    match n {
        0..=0x3F => vec![n as u8],
        0x40..=0x3FFF => (0x4000 | n as u16).to_be_bytes().to_vec(),
        0x4000..=0x3FFF_FFFF => (0x8000_0000 | n as u32).to_be_bytes().to_vec(),
        _ => {
            assert!(n < 1 << 62, "varint out of range");
            (0xC000_0000_0000_0000 | n).to_be_bytes().to_vec()
        }
    }
}

/// Size of a variable-length integer from its first byte.
fn varint_size(first: u8) -> usize {
    1 << (first >> 6)
}

fn decode_varint(bytes: &[u8]) -> u64 {
    let mut n = u64::from(bytes[0] & 0x3F);
    for b in &bytes[1..] {
        n = n << 8 | u64::from(*b);
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints() {
        // RFC 9000 Appendix A.1 examples.
        for (n, encoded) in [
            (37, &[0x25][..]),
            (15293, &[0x7b, 0xbd]),
            (494_878_333, &[0x9d, 0x7f, 0x3e, 0x7d]),
            (
                151_288_809_941_952_652,
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
            ),
        ] {
            assert_eq!(encode_varint(n), encoded);
            assert_eq!(varint_size(encoded[0]), encoded.len());
            assert_eq!(decode_varint(encoded), n);
        }
        // A longer form than needed is valid in QUIC (RFC 9000 §16).
        assert_eq!(decode_varint(&[0x40, 0x25]), 37);
    }

    #[test]
    fn message_round_trip_and_fields() {
        let m = Message::new(7, vec![(2, Value::Bool(true)), (0, Value::Uint(5))]);
        let decoded = Message::decode(&m.encode()).unwrap();
        assert_eq!(decoded.kind, 7);
        assert_eq!(decoded.field(0), Some(&Value::Uint(5)));
        assert_eq!(decoded.field(2), Some(&Value::Bool(true)));
        assert_eq!(decoded.field(1), None);
    }

    #[test]
    fn invalid_messages() {
        let cases: [Value; 6] = [
            Value::Uint(1),
            Value::Array(vec![Value::Uint(1)]),
            Value::Array(vec![Value::Uint(1), Value::Map(vec![]), Value::Null]),
            Value::Array(vec![Value::Nint(0), Value::Map(vec![])]),
            Value::Array(vec![Value::Uint(1), Value::Array(vec![])]),
            Value::Array(vec![
                Value::Uint(1),
                Value::Map(vec![(Value::Text("a".into()), Value::Null)]),
            ]),
        ];
        for value in cases {
            let err = Message::decode(&cbor::encode(&value)).unwrap_err();
            assert_eq!(err.code, Code::ProtocolViolation, "{value:?}");
        }
        let err = Message::decode(&[0x9f, 0xff]).unwrap_err();
        assert_eq!(err.reason, "invalid CBOR: indefinite length");
        // Negative keys are integers and allowed.
        let value = Value::Array(vec![
            Value::Uint(1),
            Value::Map(vec![(Value::Nint(3), Value::Null)]),
        ]);
        assert!(Message::decode(&cbor::encode(&value)).is_ok());
    }

    #[test]
    fn codes() {
        for code in Code::ALL {
            assert_eq!(Code::from_value(code as u64), Some(code));
        }
        assert_eq!(Code::from_value(12), None);
        assert_eq!(
            Code::VersionNegotiationFailed.name(),
            "VERSION_NEGOTIATION_FAILED"
        );
    }
}
