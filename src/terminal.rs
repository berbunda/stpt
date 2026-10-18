//! Terminal Channel messages (PROTOCOL.md §14, §15.1): opening parameters and their
//! validation, TERMINAL_ATTACHED, terminal data, exit status and signal ids. Shared
//! by Client and Server.

// The Server parts are unused where Server mode is not available (gate G2).
#![cfg_attr(not(unix), allow(dead_code))]

use std::fmt;

use crate::cbor::Value;
use crate::control::TERMINAL;
use crate::wire::{
    CHANNEL_OPEN, Code, Failure, Message, TERMINAL_ATTACHED, TERMINAL_DATA, TERMINAL_EOF,
    TERMINAL_EXIT, TERMINAL_RESIZE, TERMINAL_STDERR,
};

/// Length of a Session ID in bytes (§15.1).
pub const SESSION_ID_LEN: usize = 16;

/// Limits of the environment field (§14.6).
const MAX_ENV_VARS: usize = 64;
const MAX_ENV_LEN: usize = 4096;

/// Session ID (§15.1); shown as 32 lowercase hexadecimal digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionId(pub [u8; SESSION_ID_LEN]);

impl SessionId {
    /// A new random Session ID.
    pub fn generate() -> Self {
        use aws_lc_rs::rand::{SecureRandom, SystemRandom};
        let mut id = [0; SESSION_ID_LEN];
        SystemRandom::new().fill(&mut id).expect("system random");
        Self(id)
    }

    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Bytes(b) => b.as_slice().try_into().ok().map(Self),
            _ => None,
        }
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Window size of a terminal: columns and rows 1–65535, pixel sizes 0 when unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Size {
    pub columns: u16,
    pub rows: u16,
    pub width: u16,
    pub height: u16,
}

impl Size {
    fn fields(self) -> Vec<(u64, Value)> {
        let mut fields = vec![
            (1, Value::Uint(self.columns.into())),
            (2, Value::Uint(self.rows.into())),
        ];
        for (key, pixels) in [(3, self.width), (4, self.height)] {
            if pixels != 0 {
                fields.push((key, Value::Uint(pixels.into())));
            }
        }
        fields
    }

    /// TERMINAL_RESIZE with this size (§14.8).
    pub fn resize_message(self) -> Message {
        Message::new(TERMINAL_RESIZE, self.fields())
    }

    /// The size of a TERMINAL_RESIZE; an invalid one is a protocol violation.
    pub fn from_resize(message: &Message) -> Result<Self, Failure> {
        Self::from_fields(|key| message.field(key).cloned())
            .map_err(|reason| Failure::violation(format!("TERMINAL_RESIZE: {reason}")))
    }

    /// Keys 1–4 of pty-params or TERMINAL_RESIZE (§14.6, §14.8).
    fn from_fields(field: impl Fn(u64) -> Option<Value>) -> Result<Self, &'static str> {
        let cells = |key| match field(key) {
            Some(Value::Uint(n @ 1..=65535)) => Ok(n as u16),
            Some(_) => Err("columns and rows must be 1–65535"),
            None => Err("columns or rows missing"),
        };
        let pixels = |key| match field(key) {
            None => Ok(0),
            Some(Value::Uint(n @ 0..=65535)) => Ok(n as u16),
            Some(_) => Err("pixel sizes must be 0–65535"),
        };
        Ok(Self {
            columns: cells(1)?,
            rows: cells(2)?,
            width: pixels(3)?,
            height: pixels(4)?,
        })
    }
}

/// What a new Session runs (§14.6); `None` in [`Open`] is the login shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// A command line for the Account's shell.
    Line(String),
    /// An argument vector, passed unchanged.
    Argv(Vec<String>),
}

/// CHANNEL_OPEN of a terminal Channel (§14.3, §14.6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Open {
    /// `None`: create a new Session; else attach to it.
    pub session: Option<SessionId>,
    /// Terminal type; present with `size` when a PTY is requested on create.
    pub term: Option<String>,
    pub size: Option<Size>,
    pub command: Option<Command>,
    pub env: Vec<(String, String)>,
    pub name: Option<String>,
    pub detach_timeout: Option<u64>,
    pub takeover: Option<bool>,
    pub read_only: Option<bool>,
    pub resume: Option<u64>,
}

impl Open {
    pub fn to_message(&self) -> Message {
        let mut body = vec![
            (0, Value::Uint(TERMINAL)),
            (
                1,
                self.session
                    .map_or(Value::Null, |id| Value::Bytes(id.0.to_vec())),
            ),
        ];
        if let Some(size) = self.size {
            let mut pty = size.fields();
            if let Some(term) = &self.term {
                pty.push((0, Value::Text(term.clone())));
            }
            body.push((2, uint_map(pty)));
        }
        match &self.command {
            Some(Command::Line(line)) => body.push((3, Value::Text(line.clone()))),
            Some(Command::Argv(argv)) => body.push((
                3,
                Value::Array(argv.iter().cloned().map(Value::Text).collect()),
            )),
            None => {}
        }
        if !self.env.is_empty() {
            let env = self.env.iter().cloned();
            let env = env.map(|(n, v)| (Value::Text(n), Value::Text(v))).collect();
            body.push((4, Value::Map(env)));
        }
        if let Some(name) = &self.name {
            body.push((5, Value::Text(name.clone())));
        }
        if let Some(timeout) = self.detach_timeout {
            body.push((6, Value::Uint(timeout)));
        }
        if let Some(takeover) = self.takeover {
            body.push((7, Value::Uint(takeover.into())));
        }
        if let Some(read_only) = self.read_only {
            body.push((8, Value::Bool(read_only)));
        }
        if let Some(offset) = self.resume {
            body.push((9, Value::Uint(offset)));
        }
        Message::new(CHANNEL_OPEN, body)
    }

    /// Parses and validates the parameters of a terminal CHANNEL_OPEN whose kind was
    /// checked already. A failure carries the code to reject the Channel with:
    /// CHANNEL_REJECTED, or LIMIT_EXCEEDED for environment limits (§14.6).
    pub fn from_message(message: &Message) -> Result<Self, Failure> {
        let rejected = |reason: &str| Failure::new(Code::ChannelRejected, reason);
        let mut open = Open::default();
        match message.field(1) {
            Some(Value::Null) => {}
            Some(value) => {
                let id = SessionId::from_value(value)
                    .ok_or_else(|| rejected("Session ID is not 16 bytes"))?;
                open.session = Some(id);
            }
            None => return Err(rejected("Session ID or null missing")),
        }
        if let Some(pty) = message.field(2) {
            let entries = pty
                .as_map()
                .ok_or_else(|| rejected("pty-params is not a map"))?;
            let field = |key| {
                entries
                    .iter()
                    .find(|(k, _)| *k == Value::Uint(key))
                    .map(|(_, v)| v.clone())
            };
            open.size = Some(Size::from_fields(field).map_err(rejected)?);
            open.term = match field(0) {
                Some(Value::Text(term)) if valid_term(&term) => Some(term),
                Some(_) => return Err(rejected("invalid terminal type")),
                None => None,
            };
        }
        open.command = match message.field(3) {
            None => None,
            Some(Value::Text(line)) if !line.is_empty() && !line.contains('\0') => {
                Some(Command::Line(line.clone()))
            }
            Some(Value::Array(items)) if !items.is_empty() => {
                let argv = items.iter().map(|item| match item {
                    Value::Text(arg) if !arg.contains('\0') => Some(arg.clone()),
                    _ => None,
                });
                let argv = argv.collect::<Option<Vec<_>>>();
                Some(Command::Argv(
                    argv.ok_or_else(|| rejected("invalid command"))?,
                ))
            }
            Some(_) => return Err(rejected("invalid command")),
        };
        if let Some(env) = message.field(4) {
            open.env = environment(env)?;
        }
        open.name = match message.field(5) {
            None => None,
            Some(Value::Text(name)) if valid_name(name) => Some(name.clone()),
            Some(_) => return Err(rejected("invalid Session name")),
        };
        open.detach_timeout = match message.field(6) {
            None => None,
            Some(Value::Uint(seconds)) => Some(*seconds),
            Some(_) => return Err(rejected("detach timeout is not a uint")),
        };
        open.takeover = match message.field(7) {
            None => None,
            Some(Value::Uint(mode @ 0..=1)) => Some(*mode == 1),
            Some(_) => return Err(rejected("invalid attach mode")),
        };
        open.read_only = match message.field(8) {
            None => None,
            Some(Value::Bool(read_only)) => Some(*read_only),
            Some(_) => return Err(rejected("read-only is not a bool")),
        };
        open.resume = match message.field(9) {
            None => None,
            Some(Value::Uint(offset)) => Some(*offset),
            Some(_) => return Err(rejected("resume offset is not a uint")),
        };

        let creating = open.session.is_none();
        if creating {
            if open.size.is_some() && open.term.is_none() {
                return Err(rejected("terminal type missing"));
            }
            if open.takeover.is_some() || open.read_only.is_some() || open.resume.is_some() {
                return Err(rejected("attach parameters when creating a Session"));
            }
        } else if open.term.is_some()
            || open.command.is_some()
            || !open.env.is_empty()
            || message.field(4).is_some()
            || open.name.is_some()
            || open.detach_timeout.is_some()
        {
            return Err(rejected("creation parameters when attaching"));
        }
        Ok(open)
    }
}

fn uint_map(fields: Vec<(u64, Value)>) -> Value {
    Value::Map(
        fields
            .into_iter()
            .map(|(k, v)| (Value::Uint(k), v))
            .collect(),
    )
}

/// Terminal type: 1–64 bytes `[A-Za-z0-9][A-Za-z0-9._+-]*` (§14.6).
pub fn valid_term(term: &str) -> bool {
    valid_word(term, "._+-")
}

/// Session name: 1–64 bytes `[A-Za-z0-9][A-Za-z0-9._-]*` (§15.3).
pub fn valid_name(name: &str) -> bool {
    valid_word(name, "._-")
}

fn valid_word(word: &str, punctuation: &str) -> bool {
    let bytes = word.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || punctuation.as_bytes().contains(b))
}

/// The environment field (§14.6): names non-empty without `=` and NUL, values
/// without NUL; at most 64 variables of at most 4096 bytes each.
fn environment(value: &Value) -> Result<Vec<(String, String)>, Failure> {
    let rejected = |reason| Failure::new(Code::ChannelRejected, reason);
    let entries = value
        .as_map()
        .ok_or_else(|| rejected("environment is not a map"))?;
    if entries.len() > MAX_ENV_VARS {
        return Err(Failure::new(
            Code::LimitExceeded,
            format!("{} environment variables", entries.len()),
        ));
    }
    let mut env = Vec::new();
    for (name, value) in entries {
        let (Value::Text(name), Value::Text(value)) = (name, value) else {
            return Err(rejected("environment entry is not text"));
        };
        if name.len() > MAX_ENV_LEN || value.len() > MAX_ENV_LEN {
            return Err(Failure::new(
                Code::LimitExceeded,
                "environment variable longer than 4096 bytes",
            ));
        }
        if name.is_empty() || name.contains(['=', '\0']) || value.contains('\0') {
            return Err(rejected("invalid environment variable"));
        }
        env.push((name.clone(), value.clone()));
    }
    Ok(env)
}

/// TERMINAL_ATTACHED (§14.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attached {
    pub session: SessionId,
    pub attachment: u64,
    /// Output offset of the first output byte that follows (§15.11).
    pub offset: u64,
}

impl Attached {
    pub fn to_message(self) -> Message {
        Message::new(
            TERMINAL_ATTACHED,
            vec![
                (0, Value::Bytes(self.session.0.to_vec())),
                (1, Value::Uint(self.attachment)),
                (2, Value::Uint(self.offset)),
            ],
        )
    }

    pub fn from_message(message: &Message) -> Result<Self, Failure> {
        let invalid = || Failure::violation("invalid TERMINAL_ATTACHED");
        if message.kind != TERMINAL_ATTACHED {
            return Err(Failure::violation(format!(
                "message type {} before TERMINAL_ATTACHED",
                message.kind
            )));
        }
        let uint = |key| {
            message
                .field(key)
                .and_then(Value::as_uint)
                .ok_or_else(invalid)
        };
        Ok(Self {
            session: message
                .field(0)
                .and_then(SessionId::from_value)
                .ok_or_else(invalid)?,
            attachment: uint(1)?,
            offset: uint(2)?,
        })
    }
}

/// TERMINAL_DATA (input or output) or TERMINAL_STDERR with `data`, not empty (§14.7).
pub fn data(kind: u64, data: &[u8]) -> Message {
    debug_assert!(matches!(kind, TERMINAL_DATA | TERMINAL_STDERR) && !data.is_empty());
    Message::new(kind, vec![(0, Value::Bytes(data.to_vec()))])
}

/// The data of TERMINAL_DATA or TERMINAL_STDERR: a non-empty byte string.
pub fn data_of(message: &Message) -> Result<&[u8], Failure> {
    match message.field(0) {
        Some(Value::Bytes(data)) if !data.is_empty() => Ok(data),
        _ => Err(Failure::violation(format!(
            "message type {}: data missing or empty",
            message.kind
        ))),
    }
}

pub fn eof() -> Message {
    Message::new(TERMINAL_EOF, vec![])
}

/// Signal ids (§14.9); index = id.
const SIGNALS: [&str; 15] = [
    "", "INT", "QUIT", "HUP", "TERM", "KILL", "USR1", "USR2", "ABRT", "SEGV", "PIPE", "BUS", "FPE",
    "ILL", "ALRM",
];

/// Name of a signal id; `None` for id 0 and unknown ids.
pub fn signal_name(id: u64) -> Option<&'static str> {
    SIGNALS.get(id as usize).copied().filter(|n| !n.is_empty())
}

/// Signal id of a platform signal number; 0 for a signal not in §14.9.
#[cfg(unix)]
pub fn signal_id(number: i32) -> u64 {
    use nix::libc::*;
    let table = [
        SIGINT, SIGQUIT, SIGHUP, SIGTERM, SIGKILL, SIGUSR1, SIGUSR2, SIGABRT, SIGSEGV, SIGPIPE,
        SIGBUS, SIGFPE, SIGILL, SIGALRM,
    ];
    table
        .iter()
        .position(|s| *s == number)
        .map_or(0, |i| i as u64 + 1)
}

/// Exit status of the primary process (§14.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(u32),
    Signal { id: u64, core_dumped: bool },
}

impl Exit {
    pub fn to_message(self) -> Message {
        let fields = match self {
            Self::Code(code) => vec![(0, Value::Uint(code.into()))],
            Self::Signal { id, core_dumped } => {
                let mut fields = vec![(1, Value::Uint(id))];
                if core_dumped {
                    fields.push((2, Value::Bool(true)));
                }
                fields
            }
        };
        Message::new(TERMINAL_EXIT, fields)
    }

    /// Exactly one of exit code and signal id; an unknown signal id becomes 0.
    pub fn from_message(message: &Message) -> Result<Self, Failure> {
        let invalid = || Failure::violation("invalid TERMINAL_EXIT");
        let core_dumped = match message.field(2) {
            None => false,
            Some(Value::Bool(core)) => *core,
            Some(_) => return Err(invalid()),
        };
        match (message.field(0), message.field(1)) {
            (Some(Value::Uint(code)), None) => {
                Ok(Self::Code(u32::try_from(*code).map_err(|_| invalid())?))
            }
            (None, Some(Value::Uint(id))) => Ok(Self::Signal {
                id: if signal_name(*id).is_some() { *id } else { 0 },
                core_dumped,
            }),
            _ => Err(invalid()),
        }
    }

    #[cfg(unix)]
    pub fn from_status(status: std::process::ExitStatus) -> Self {
        use std::os::unix::process::ExitStatusExt;
        match (status.code(), status.signal()) {
            (Some(code), _) => Self::Code(code as u32),
            (None, Some(signal)) => Self::Signal {
                id: signal_id(signal),
                core_dumped: status.core_dumped(),
            },
            (None, None) => Self::Code(u32::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(fields: Vec<(u64, Value)>) -> Result<Open, Failure> {
        let mut body = vec![(0, Value::Uint(TERMINAL))];
        body.extend(fields);
        Open::from_message(&Message::new(CHANNEL_OPEN, body))
    }

    fn code(result: Result<Open, Failure>) -> Code {
        result.unwrap_err().code
    }

    fn pty(fields: Vec<(u64, Value)>) -> (u64, Value) {
        (2, uint_map(fields))
    }

    fn term(t: &str) -> (u64, Value) {
        (0, Value::Text(t.into()))
    }

    const SIZE: Size = Size {
        columns: 80,
        rows: 24,
        width: 0,
        height: 0,
    };

    #[test]
    fn round_trip() {
        let opens = [
            Open::default(),
            Open {
                term: Some("xterm-256color".into()),
                size: Some(Size { width: 800, ..SIZE }),
                command: Some(Command::Argv(vec!["ls".into(), "".into()])),
                env: vec![("LANG".into(), "C.UTF-8".into())],
                name: Some("build.1".into()),
                detach_timeout: Some(0),
                ..Open::default()
            },
            Open {
                command: Some(Command::Line("make -j4".into())),
                ..Open::default()
            },
            Open {
                session: Some(SessionId([7; 16])),
                size: Some(SIZE),
                takeover: Some(true),
                read_only: Some(false),
                resume: Some(12),
                ..Open::default()
            },
        ];
        for open in opens {
            let message = Message::decode(&open.to_message().encode()).unwrap();
            assert_eq!(Open::from_message(&message).unwrap(), open);
        }
    }

    #[test]
    fn invalid_parameters_reject_the_channel() {
        let rejected = Code::ChannelRejected;
        let size = |c: u64, r: u64| vec![term("xterm"), (1, Value::Uint(c)), (2, Value::Uint(r))];
        assert_eq!(code(open(vec![])), rejected);
        assert_eq!(code(open(vec![(1, Value::Bytes(vec![1; 15]))])), rejected);
        let null = (1, Value::Null);
        let with = |field| open(vec![null.clone(), field]);
        assert!(with(pty(size(80, 24))).is_ok());
        assert!(with(pty(size(65535, 1))).is_ok());
        for bad in [
            size(0, 24),
            size(80, 65536),
            vec![term("xterm"), (1, Value::Uint(80))],
        ] {
            assert_eq!(code(with(pty(bad))), rejected);
        }
        let mut no_term = size(80, 24);
        no_term.remove(0);
        assert_eq!(code(with(pty(no_term))), rejected);
        for t in ["", "-x", "xterm 256", "xterm;", &"x".repeat(65)] {
            let mut fields = size(80, 24);
            fields[0] = term(t);
            assert_eq!(code(with(pty(fields))), rejected, "{t:?}");
        }
        let mut pixels = size(80, 24);
        pixels.push((3, Value::Uint(65536)));
        assert_eq!(code(with(pty(pixels))), rejected);
        for command in [
            Value::Text("".into()),
            Value::Text("a\0b".into()),
            Value::Array(vec![]),
            Value::Array(vec![Value::Uint(1)]),
            Value::Uint(1),
        ] {
            assert_eq!(code(with((3, command))), rejected);
        }
        for name in ["", ".x", "a b", &"n".repeat(65)] {
            assert_eq!(code(with((5, Value::Text(name.into())))), rejected);
        }
        assert_eq!(code(with((7, Value::Uint(1)))), rejected);
        assert_eq!(code(with((8, Value::Bool(true)))), rejected);
        assert_eq!(code(with((9, Value::Uint(0)))), rejected);
        let attach = (1, Value::Bytes(vec![1; 16]));
        let attaching = |field| open(vec![attach.clone(), field]);
        assert!(attaching((7, Value::Uint(1))).is_ok());
        assert_eq!(code(attaching((7, Value::Uint(2)))), rejected);
        assert_eq!(code(attaching((3, Value::Text("ls".into())))), rejected);
        assert_eq!(code(attaching(pty(size(80, 24)))), rejected);
        assert_eq!(code(attaching((6, Value::Uint(5)))), rejected);
    }

    fn env(entries: Vec<(&str, &str)>) -> Result<Open, Failure> {
        let map = entries
            .into_iter()
            .map(|(n, v)| (Value::Text(n.into()), Value::Text(v.into())))
            .collect();
        open(vec![(1, Value::Null), (4, Value::Map(map))])
    }

    #[test]
    fn environment_rules() {
        assert!(env(vec![("LANG", "C"), ("X", "")]).is_ok());
        for bad in [("", "x"), ("A=B", "x"), ("A\0", "x"), ("A", "x\0")] {
            assert_eq!(code(env(vec![bad])), Code::ChannelRejected, "{bad:?}");
        }
        let long = "x".repeat(4097);
        assert_eq!(code(env(vec![("A", &long)])), Code::LimitExceeded);
        let names: Vec<String> = (0..65).map(|i| format!("V{i:02}")).collect();
        let many = names.iter().map(|n| (n.as_str(), "")).collect();
        assert_eq!(code(env(many)), Code::LimitExceeded);
    }

    #[test]
    fn attached_round_trip() {
        let attached = Attached {
            session: SessionId::generate(),
            attachment: 1,
            offset: 0,
        };
        assert_eq!(Attached::from_message(&attached.to_message()), Ok(attached));
        let data = data(TERMINAL_DATA, b"x");
        assert!(Attached::from_message(&data).is_err());
    }

    #[test]
    fn session_id_text() {
        let mut id = [0; 16];
        id[0] = 0x3f;
        id[15] = 0xa5;
        assert_eq!(
            SessionId(id).to_string(),
            "3f0000000000000000000000000000a5"
        );
        assert_ne!(SessionId::generate(), SessionId::generate());
    }

    #[test]
    fn data_must_not_be_empty() {
        assert_eq!(data_of(&data(TERMINAL_DATA, b"ab")), Ok(&b"ab"[..]));
        let empty = Message::new(TERMINAL_DATA, vec![(0, Value::Bytes(vec![]))]);
        assert!(data_of(&empty).is_err());
        assert!(data_of(&Message::new(TERMINAL_DATA, vec![])).is_err());
    }

    #[test]
    fn exit_status() {
        for exit in [
            Exit::Code(0),
            Exit::Code(u32::MAX),
            Exit::Signal {
                id: 9,
                core_dumped: true,
            },
            Exit::Signal {
                id: 1,
                core_dumped: false,
            },
        ] {
            assert_eq!(Exit::from_message(&exit.to_message()), Ok(exit));
        }
        let both = Message::new(
            TERMINAL_EXIT,
            vec![(0, Value::Uint(1)), (1, Value::Uint(1))],
        );
        assert!(Exit::from_message(&both).is_err());
        assert!(Exit::from_message(&Message::new(TERMINAL_EXIT, vec![])).is_err());
        let big = Message::new(TERMINAL_EXIT, vec![(0, Value::Uint(1 << 32))]);
        assert!(Exit::from_message(&big).is_err());
        let unknown = Message::new(TERMINAL_EXIT, vec![(1, Value::Uint(99))]);
        assert_eq!(
            Exit::from_message(&unknown),
            Ok(Exit::Signal {
                id: 0,
                core_dumped: false
            })
        );
    }

    #[test]
    fn signals() {
        assert_eq!(signal_name(1), Some("INT"));
        assert_eq!(signal_name(14), Some("ALRM"));
        assert_eq!(signal_name(0), None);
        assert_eq!(signal_name(15), None);
    }

    #[cfg(unix)]
    #[test]
    fn platform_signals() {
        use nix::libc::*;
        assert_eq!(signal_id(SIGINT), 1);
        assert_eq!(signal_id(SIGKILL), 5);
        assert_eq!(signal_id(SIGALRM), 14);
        assert_eq!(signal_id(SIGWINCH), 0);
    }
}
