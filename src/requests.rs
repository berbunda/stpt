//! Session requests on the Server (Unix; PROTOCOL.md §8.4, §15.6, §15.9, §15.10).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor::Value;
use crate::control;
use crate::listing::{self, EXITED, Listed, ListedAttachment, RUNNING, TERMINATING};
use crate::session::{Session, State, Store};
use crate::terminal::SessionId;
use crate::wire::{Code, Failure, Message, SESSION_DETACH, SESSION_LIST, SESSION_TERMINATE};

/// A request read from the control stream, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    List {
        only: Option<SessionId>,
        after: Option<SessionId>,
    },
    Terminate {
        session: SessionId,
        force: bool,
    },
    Detach {
        session: SessionId,
        attachment: Option<u64>,
    },
}

/// Parses a request whose type and ID were checked; a malformed one is a protocol
/// violation (§0.2).
pub fn parse(message: &Message) -> Result<Request, Failure> {
    let invalid = || Failure::violation(format!("request type {}: invalid body", message.kind));
    let optional_id = |key| match message.field(key) {
        None => Ok(None),
        Some(value) => listing::session_id(value).map(Some).ok_or_else(invalid),
    };
    let session = || optional_id(1)?.ok_or_else(invalid);
    match message.kind {
        SESSION_LIST => Ok(Request::List {
            only: optional_id(1)?,
            after: optional_id(2)?,
        }),
        SESSION_TERMINATE => Ok(Request::Terminate {
            session: session()?,
            force: match message.field(2) {
                None => false,
                Some(Value::Bool(force)) => *force,
                Some(_) => return Err(invalid()),
            },
        }),
        SESSION_DETACH => Ok(Request::Detach {
            session: session()?,
            attachment: match message.field(2) {
                None => None,
                Some(Value::Uint(id)) => Some(*id),
                Some(_) => return Err(invalid()),
            },
        }),
        kind => Err(Failure::violation(format!("request type {kind} unknown"))),
    }
}

/// What a request runs against: the Sessions of the Connection's Account.
pub struct Context {
    pub store: Arc<Store>,
    pub account: String,
    /// Message size limit of the Client, for paging the list.
    pub peer_limit: u64,
}

/// Runs a request; returns its REQUEST_RESULT.
pub async fn handle(id: u64, request: Request, context: &Context) -> Message {
    let failed = |code| control::request_result(id, code);
    let session = |session| context.store.get(&context.account, session);
    match request {
        Request::List {
            only: Some(only), ..
        } => match session(only) {
            Some(session) => listing::list_result(id, vec![listed(&session).to_value()], false),
            None => failed(Code::SessionNotFound),
        },
        Request::List { only: None, after } => list(id, after, context),
        Request::Terminate {
            session: target,
            force,
        } => match session(target) {
            Some(session) => {
                tracing::info!(session = %target, force, "termination requested");
                session.terminate(&context.store, force).await;
                failed(Code::NoError)
            }
            None => failed(Code::SessionNotFound),
        },
        Request::Detach {
            session: target,
            attachment,
        } => match session(target) {
            None => failed(Code::SessionNotFound),
            Some(session) => match attachment {
                Some(attachment) if !session.end_attachment(attachment, Code::NoError) => {
                    failed(Code::AttachmentNotFound)
                }
                Some(_) => failed(Code::NoError),
                None => {
                    session.end_all_attachments();
                    failed(Code::NoError)
                }
            },
        },
    }
}

/// One page of the list: as many Sessions after `after` as fit the Client's
/// message size limit (§15.10).
fn list(id: u64, after: Option<SessionId>, context: &Context) -> Message {
    let mut entries = Vec::new();
    let mut more = false;
    let sessions = context.store.list(&context.account);
    for session in sessions.iter().filter(|s| after.is_none_or(|a| s.id > a)) {
        if session.state() == State::Terminated {
            continue;
        }
        entries.push(listed(session).to_value());
        let size = listing::list_result(id, entries.clone(), true)
            .encode()
            .len();
        if size as u64 > context.peer_limit {
            entries.pop();
            more = true;
            break;
        }
    }
    listing::list_result(id, entries, more)
}

fn unix_time(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// The list entry of a Session (§15.10).
fn listed(session: &Session) -> Listed {
    let (state, exit) = match session.state() {
        State::Running => (RUNNING, None),
        State::Exited(exit) => (EXITED, Some(exit)),
        State::Terminating | State::Terminated => (TERMINATING, None),
    };
    let attachments = session.attachments().into_iter().map(|a| ListedAttachment {
        id: a.id,
        attached: unix_time(a.info.attached),
        key: a.info.key.key,
        label: a.info.key.label,
        read_only: a.read_only,
        active: a.active,
        address: Some(a.info.connection.remote_address()),
    });
    Listed {
        id: session.id,
        name: session.name.clone(),
        state,
        created: unix_time(session.created),
        key: session.creator.key,
        label: session.creator.label.clone(),
        pty: session.pty(),
        command: session.command.clone(),
        exit,
        removal: session.removal().map(unix_time),
        attachments: attachments.collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_parsed() {
        let id = SessionId([4; 16]);
        let cases = [
            (
                listing::list_request(1, None, Some(id)),
                Request::List {
                    only: None,
                    after: Some(id),
                },
            ),
            (
                listing::terminate_request(2, id, true),
                Request::Terminate {
                    session: id,
                    force: true,
                },
            ),
            (
                listing::detach_request(3, id, Some(7)),
                Request::Detach {
                    session: id,
                    attachment: Some(7),
                },
            ),
        ];
        for (message, request) in cases {
            assert_eq!(parse(&message), Ok(request));
        }
        let no_session = Message::new(SESSION_TERMINATE, vec![(0, Value::Uint(1))]);
        assert!(parse(&no_session).is_err());
        let short_id = Message::new(
            SESSION_DETACH,
            vec![(0, Value::Uint(1)), (1, Value::Bytes(vec![1; 15]))],
        );
        assert!(parse(&short_id).is_err());
    }
}
