//! Session requests on the control Channel (PROTOCOL.md §15.6, §15.9, §15.10): the
//! request messages, and the Session list entries both roles encode or read.

// The Server parts are unused where Server mode is not available (gate G2).
#![cfg_attr(not(unix), allow(dead_code))]

use std::net::{IpAddr, SocketAddr};

use crate::cbor::Value;
use crate::terminal::{Exit, SessionId};
use crate::wire::{
    Failure, Message, REQUEST_RESULT, SESSION_DETACH, SESSION_LIST, SESSION_TERMINATE,
    TERMINAL_EXIT,
};

/// Session states in the list (§15.10).
pub const RUNNING: u64 = 1;
pub const EXITED: u64 = 2;
pub const TERMINATING: u64 = 3;

/// One Session in the list (§15.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub id: SessionId,
    pub name: Option<String>,
    pub state: u64,
    /// Unix time in seconds.
    pub created: u64,
    pub key: [u8; 32],
    pub label: Option<String>,
    pub pty: bool,
    pub command: Option<String>,
    pub exit: Option<Exit>,
    pub removal: Option<u64>,
    pub attachments: Vec<ListedAttachment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedAttachment {
    pub id: u64,
    pub attached: u64,
    pub key: [u8; 32],
    pub label: Option<String>,
    pub read_only: bool,
    pub active: bool,
    pub address: Option<SocketAddr>,
}

fn uint_map(fields: Vec<(u64, Option<Value>)>) -> Value {
    let entries = fields
        .into_iter()
        .filter_map(|(k, v)| Some((Value::Uint(k), v?)))
        .collect();
    Value::Map(entries)
}

fn text(value: &Option<String>) -> Option<Value> {
    value.clone().map(Value::Text)
}

impl Listed {
    pub fn to_value(&self) -> Value {
        let exit = self.exit.map(|exit| Value::Map(exit.to_message().body));
        let attachments = self
            .attachments
            .iter()
            .map(ListedAttachment::to_value)
            .collect();
        uint_map(vec![
            (0, Some(Value::Bytes(self.id.0.to_vec()))),
            (1, text(&self.name)),
            (2, Some(Value::Uint(self.state))),
            (3, Some(Value::Uint(self.created))),
            (4, Some(Value::Bytes(self.key.to_vec()))),
            (5, text(&self.label)),
            (6, Some(Value::Bool(self.pty))),
            (7, text(&self.command)),
            (8, exit),
            (9, self.removal.map(Value::Uint)),
            (10, Some(Value::Array(attachments))),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Self, Failure> {
        let invalid = || Failure::violation("invalid session-info");
        let fields = Fields(value.as_map().ok_or_else(invalid)?);
        let attachments = fields
            .get(10)
            .and_then(Value::as_array)
            .ok_or_else(invalid)?;
        let exit = match fields.get(8) {
            None => None,
            Some(Value::Map(body)) => {
                let message = Message {
                    kind: TERMINAL_EXIT,
                    body: body.clone(),
                };
                Some(Exit::from_message(&message)?)
            }
            Some(_) => return Err(invalid()),
        };
        Ok(Self {
            id: fields.session_id(0).ok_or_else(invalid)?,
            name: fields.optional_text(1).map_err(|()| invalid())?,
            state: fields.uint(2).ok_or_else(invalid)?,
            created: fields.uint(3).ok_or_else(invalid)?,
            key: fields.key(4).ok_or_else(invalid)?,
            label: fields.optional_text(5).map_err(|()| invalid())?,
            pty: fields.bool(6).ok_or_else(invalid)?,
            command: fields.optional_text(7).map_err(|()| invalid())?,
            exit,
            removal: fields.optional_uint(9).map_err(|()| invalid())?,
            attachments: attachments
                .iter()
                .map(ListedAttachment::from_value)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl ListedAttachment {
    fn to_value(&self) -> Value {
        let address = self.address.map(|address| {
            let ip = match address.ip() {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                    Some(v4) => v4.octets().to_vec(),
                    None => ip.octets().to_vec(),
                },
            };
            Value::Array(vec![Value::Bytes(ip), Value::Uint(address.port().into())])
        });
        uint_map(vec![
            (0, Some(Value::Uint(self.id))),
            (1, Some(Value::Uint(self.attached))),
            (2, Some(Value::Bytes(self.key.to_vec()))),
            (3, text(&self.label)),
            (4, Some(Value::Bool(self.read_only))),
            (5, Some(Value::Bool(self.active))),
            (6, address),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, Failure> {
        let invalid = || Failure::violation("invalid attachment-info");
        let fields = Fields(value.as_map().ok_or_else(invalid)?);
        let address = match fields.get(6) {
            None => None,
            Some(Value::Array(items)) => match items.as_slice() {
                [Value::Bytes(ip), Value::Uint(port)] => {
                    let ip: IpAddr = match ip.len() {
                        4 => <[u8; 4]>::try_from(ip.as_slice()).unwrap().into(),
                        16 => <[u8; 16]>::try_from(ip.as_slice()).unwrap().into(),
                        _ => return Err(invalid()),
                    };
                    let port = u16::try_from(*port).map_err(|_| invalid())?;
                    Some(SocketAddr::new(ip, port))
                }
                _ => return Err(invalid()),
            },
            Some(_) => return Err(invalid()),
        };
        Ok(Self {
            id: fields.uint(0).ok_or_else(invalid)?,
            attached: fields.uint(1).ok_or_else(invalid)?,
            key: fields.key(2).ok_or_else(invalid)?,
            label: fields.optional_text(3).map_err(|()| invalid())?,
            read_only: fields.bool(4).ok_or_else(invalid)?,
            active: fields.bool(5).ok_or_else(invalid)?,
            address,
        })
    }
}

/// Fields of a map with integer keys.
struct Fields<'a>(&'a [(Value, Value)]);

impl Fields<'_> {
    fn get(&self, key: u64) -> Option<&Value> {
        self.0
            .iter()
            .find(|(k, _)| *k == Value::Uint(key))
            .map(|(_, v)| v)
    }

    fn uint(&self, key: u64) -> Option<u64> {
        self.get(key).and_then(Value::as_uint)
    }

    fn bool(&self, key: u64) -> Option<bool> {
        match self.get(key) {
            Some(Value::Bool(b)) => Some(*b),
            _ => None,
        }
    }

    fn key(&self, key: u64) -> Option<[u8; 32]> {
        match self.get(key) {
            Some(Value::Bytes(b)) => b.as_slice().try_into().ok(),
            _ => None,
        }
    }

    fn session_id(&self, key: u64) -> Option<SessionId> {
        session_id(self.get(key)?)
    }

    fn optional_text(&self, key: u64) -> Result<Option<String>, ()> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Text(t)) => Ok(Some(t.clone())),
            Some(_) => Err(()),
        }
    }

    fn optional_uint(&self, key: u64) -> Result<Option<u64>, ()> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Uint(n)) => Ok(Some(*n)),
            Some(_) => Err(()),
        }
    }
}

pub fn session_id(value: &Value) -> Option<SessionId> {
    match value {
        Value::Bytes(b) => b.as_slice().try_into().ok().map(SessionId),
        _ => None,
    }
}

fn id_value(id: SessionId) -> Value {
    Value::Bytes(id.0.to_vec())
}

/// SESSION_LIST (§15.10): only one Session, or the page after a Session ID.
pub fn list_request(request: u64, only: Option<SessionId>, after: Option<SessionId>) -> Message {
    let mut body = vec![(0, Value::Uint(request))];
    body.extend(only.map(|id| (1, id_value(id))));
    body.extend(after.map(|id| (2, id_value(id))));
    Message::new(SESSION_LIST, body)
}

/// SESSION_TERMINATE (§15.6).
pub fn terminate_request(request: u64, session: SessionId, force: bool) -> Message {
    let mut body = vec![(0, Value::Uint(request)), (1, id_value(session))];
    if force {
        body.push((2, Value::Bool(true)));
    }
    Message::new(SESSION_TERMINATE, body)
}

/// SESSION_DETACH (§15.9): one Attachment, or all of them.
pub fn detach_request(request: u64, session: SessionId, attachment: Option<u64>) -> Message {
    let mut body = vec![(0, Value::Uint(request)), (1, id_value(session))];
    body.extend(attachment.map(|id| (2, Value::Uint(id))));
    Message::new(SESSION_DETACH, body)
}

/// The REQUEST_RESULT of a successful SESSION_LIST.
pub fn list_result(request: u64, sessions: Vec<Value>, more: bool) -> Message {
    let mut body = vec![
        (0, Value::Uint(request)),
        (1, Value::Uint(0)),
        (2, Value::Array(sessions)),
    ];
    if more {
        body.push((3, Value::Bool(true)));
    }
    Message::new(REQUEST_RESULT, body)
}

/// The Sessions of a successful SESSION_LIST result and whether more follow.
pub fn list_of(result: &Message) -> Result<(Vec<Listed>, bool), Failure> {
    let invalid = || Failure::violation("invalid Session list");
    let sessions = result
        .field(2)
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let more = match result.field(3) {
        None => false,
        Some(Value::Bool(more)) => *more,
        Some(_) => return Err(invalid()),
    };
    let sessions = sessions
        .iter()
        .map(Listed::from_value)
        .collect::<Result<_, _>>()?;
    Ok((sessions, more))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listed() -> Listed {
        Listed {
            id: SessionId([3; 16]),
            name: Some("work".into()),
            state: EXITED,
            created: 1_700_000_000,
            key: [7; 32],
            label: Some("laptop".into()),
            pty: true,
            command: None,
            exit: Some(Exit::Code(3)),
            removal: Some(1_700_086_400),
            attachments: vec![
                ListedAttachment {
                    id: 2,
                    attached: 1_700_000_100,
                    key: [9; 32],
                    label: None,
                    read_only: false,
                    active: true,
                    address: Some("192.0.2.1:50000".parse().unwrap()),
                },
                ListedAttachment {
                    id: 3,
                    attached: 1_700_000_200,
                    key: [9; 32],
                    label: None,
                    read_only: true,
                    active: false,
                    address: Some("[2001:db8::1]:843".parse().unwrap()),
                },
            ],
        }
    }

    #[test]
    fn session_info_round_trip() {
        let entry = listed();
        let result = list_result(5, vec![entry.to_value()], true);
        let decoded = Message::decode(&result.encode()).unwrap();
        assert_eq!(list_of(&decoded).unwrap(), (vec![entry], true));
    }

    #[test]
    fn ipv4_mapped_addresses_are_sent_as_ipv4() {
        let mut entry = listed();
        entry.attachments.truncate(1);
        entry.attachments[0].address = Some("[::ffff:192.0.2.1]:50000".parse().unwrap());
        let decoded = Listed::from_value(&entry.to_value()).unwrap();
        assert_eq!(
            decoded.attachments[0].address,
            Some("192.0.2.1:50000".parse().unwrap())
        );
    }

    #[test]
    fn invalid_entries() {
        let mut value = listed().to_value();
        if let Value::Map(entries) = &mut value {
            entries.retain(|(k, _)| *k != Value::Uint(10));
        }
        assert!(Listed::from_value(&value).is_err());
        assert!(Listed::from_value(&Value::Uint(1)).is_err());
    }
}
