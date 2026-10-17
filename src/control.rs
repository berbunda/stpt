//! Control Channel rules (PROTOCOL.md §3.1, §8, §11.4): which messages the control
//! stream carries in which Connection state, requests and Channel opening.

use std::fmt;

use crate::cbor::Value;
use crate::wire::{
    AUTH_REQUEST, AUTH_RESULT, CHANNEL_OPEN, CLIENT_HELLO, Code, Failure, Message, REQUEST_RESULT,
    SERVER_HELLO, SESSION_DETACH, SESSION_LIST, SESSION_TERMINATE, TERMINAL_ATTACHED,
    TERMINAL_DATA, TERMINAL_EOF, TERMINAL_EXIT, TERMINAL_RESIZE, TERMINAL_SIGNAL, TERMINAL_STDERR,
};

/// Connection state of an Endpoint (§3.1), as far as the control stream is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Handshaking,
    Established,
    Authenticated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sender {
    Client,
    Server,
}

impl fmt::Display for Sender {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Client => "Client",
            Self::Server => "Server",
        })
    }
}

/// Channel kind of the terminal Channel (§14.1).
pub const TERMINAL: u64 = 1;

/// Send priority of the control stream on both sides; Channel streams keep the
/// default 0, so control messages go first (§8.1).
pub const CONTROL_PRIORITY: i32 = 1;

/// Who may send a control message, and in which state (§8.1, §8.4, §10, §12).
fn control_message(kind: u64) -> Option<(Sender, State)> {
    use {Sender::*, State::*};
    Some(match kind {
        CLIENT_HELLO => (Client, Handshaking),
        SERVER_HELLO => (Server, Handshaking),
        AUTH_REQUEST => (Client, Established),
        AUTH_RESULT => (Server, Established),
        SESSION_TERMINATE | SESSION_DETACH | SESSION_LIST => (Client, Authenticated),
        REQUEST_RESULT => (Server, Authenticated),
        _ => return None,
    })
}

/// Core types carried on Channel streams, never on the control stream.
fn channel_message(kind: u64) -> bool {
    matches!(
        kind,
        CHANNEL_OPEN
            | TERMINAL_ATTACHED
            | TERMINAL_DATA
            | TERMINAL_STDERR
            | TERMINAL_EOF
            | TERMINAL_RESIZE
            | TERMINAL_SIGNAL
            | TERMINAL_EXIT
    )
}

/// Checks a message received on the control stream: a type that is unknown, belongs
/// to a Channel, or is not permitted from `sender` in `state` is a protocol
/// violation (§8.1, §11.4).
pub fn check(kind: u64, sender: Sender, state: State) -> Result<(), Failure> {
    match control_message(kind) {
        Some(allowed) if allowed == (sender, state) => Ok(()),
        Some(_) => Err(Failure::violation(format!(
            "message type {kind} not permitted from the {sender} in state {state:?}"
        ))),
        None if channel_message(kind) => Err(Failure::violation(format!(
            "message type {kind} on the control stream"
        ))),
        None => Err(Failure::violation(format!("unknown message type {kind}"))),
    }
}

/// Whether a permitted Client message in the Authenticated state is a request (§8.4).
pub fn is_request(kind: u64) -> bool {
    matches!(kind, SESSION_TERMINATE | SESSION_DETACH | SESSION_LIST)
}

/// Request ID of a request (§8.4).
pub fn request_id(message: &Message) -> Result<u64, Failure> {
    message.field(0).and_then(Value::as_uint).ok_or_else(|| {
        Failure::violation(format!(
            "request type {}: request ID missing or not a uint",
            message.kind
        ))
    })
}

/// REQUEST_RESULT for `id` with error code `code` (NO_ERROR: success) (§8.4).
pub fn request_result(id: u64, code: Code) -> Message {
    Message::new(
        REQUEST_RESULT,
        vec![(0, Value::Uint(id)), (1, Value::Uint(code as u64))],
    )
}

/// Channel kind of the first message on a Channel stream, which must be
/// CHANNEL_OPEN (§8.3).
pub fn channel_kind(message: &Message) -> Result<u64, Failure> {
    if message.kind != CHANNEL_OPEN {
        return Err(Failure::violation(format!(
            "first message on a Channel stream has type {}, not CHANNEL_OPEN",
            message.kind
        )));
    }
    message
        .field(0)
        .and_then(Value::as_uint)
        .ok_or_else(|| Failure::violation("CHANNEL_OPEN: channel kind missing or not a uint"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Sender::*;
    use State::*;

    #[test]
    fn permitted_messages() {
        let ok = [
            (CLIENT_HELLO, Client, Handshaking),
            (SERVER_HELLO, Server, Handshaking),
            (AUTH_REQUEST, Client, Established),
            (AUTH_RESULT, Server, Established),
            (SESSION_LIST, Client, Authenticated),
            (SESSION_TERMINATE, Client, Authenticated),
            (SESSION_DETACH, Client, Authenticated),
            (REQUEST_RESULT, Server, Authenticated),
        ];
        for (kind, sender, state) in ok {
            assert_eq!(check(kind, sender, state), Ok(()), "{kind}");
        }
        let refused = [
            (CLIENT_HELLO, Client, Established, "not permitted"),
            (AUTH_REQUEST, Client, Authenticated, "not permitted"),
            (AUTH_REQUEST, Client, Handshaking, "not permitted"),
            (SESSION_LIST, Client, Established, "not permitted"),
            (REQUEST_RESULT, Client, Authenticated, "not permitted"),
            (AUTH_RESULT, Client, Established, "not permitted"),
            (CHANNEL_OPEN, Client, Authenticated, "on the control stream"),
            (
                TERMINAL_DATA,
                Client,
                Authenticated,
                "on the control stream",
            ),
            (
                TERMINAL_EXIT,
                Server,
                Authenticated,
                "on the control stream",
            ),
            (0, Client, Authenticated, "unknown message type 0"),
            (9, Client, Authenticated, "unknown message type 9"),
            (0x4000, Client, Authenticated, "unknown message type"),
        ];
        for (kind, sender, state, reason) in refused {
            let failure = check(kind, sender, state).unwrap_err();
            assert_eq!(failure.code, Code::ProtocolViolation);
            assert!(
                failure.reason.contains(reason),
                "{kind}: {}",
                failure.reason
            );
        }
    }

    #[test]
    fn requests() {
        assert!(is_request(SESSION_LIST));
        assert!(!is_request(REQUEST_RESULT));
        let list = Message::new(SESSION_LIST, vec![(0, Value::Uint(7))]);
        assert_eq!(request_id(&list), Ok(7));
        assert!(request_id(&Message::new(SESSION_LIST, vec![])).is_err());
        let wrong = Message::new(SESSION_LIST, vec![(0, Value::Nint(1))]);
        assert!(request_id(&wrong).is_err());
        let result = request_result(7, Code::InternalError);
        assert_eq!(result.kind, REQUEST_RESULT);
        assert_eq!(result.field(0), Some(&Value::Uint(7)));
        assert_eq!(result.field(1), Some(&Value::Uint(2)));
    }

    #[test]
    fn channel_open() {
        let open = Message::new(CHANNEL_OPEN, vec![(0, Value::Uint(TERMINAL))]);
        assert_eq!(channel_kind(&open), Ok(TERMINAL));
        assert!(channel_kind(&Message::new(CHANNEL_OPEN, vec![])).is_err());
        let data = Message::new(TERMINAL_DATA, vec![(0, Value::Uint(1))]);
        assert!(channel_kind(&data).is_err());
    }
}
