//! Errors that end the program. `main` reports them as `stpt: <error>` and
//! exits with [`Error::exit_code`]; command line errors are reported by clap (exit 2).

use std::fmt;
use std::io;
use std::path::PathBuf;

use crate::config;
use crate::destination::Address;
use crate::identity::{self, Fingerprint};
use crate::quic;
use crate::trust;
use crate::wire;

/// Exit code for STPT and Connection errors, as ssh.
pub const EXIT_STPT_ERROR: u8 = 255;

#[derive(Debug)]
pub enum Error {
    Config(config::Error),
    Transport(quic::Error),
    /// Server mode on a platform without it (gate G2).
    ServerUnavailable,
    /// Key file of the Server Identity.
    ServerKey(identity::KeyFileError),
    /// Trust store file of the Client.
    Trust(trust::Error),
    /// No directory for the trust store: the user's directory is unknown.
    NoTrustStore,
    NoTrustEntry(Address),
    Resolve {
        address: Address,
        source: io::Error,
    },
    /// First contact without a fingerprint, and no terminal to ask the user.
    KeyNotKnown {
        address: Address,
        presented: Fingerprint,
    },
    /// First contact: the user did not confirm the key.
    KeyNotTrusted(Address),
    KeyChanged {
        address: Address,
        stored: Fingerprint,
        presented: Fingerprint,
    },
    FingerprintMismatch {
        address: Address,
        expected: Fingerprint,
        presented: Fingerprint,
    },
    Terminal(io::Error),
    /// The Server violated the protocol or a deadline expired; the Connection was
    /// closed with the code of the failure.
    Protocol(wire::Failure),
    /// No user key file at the path.
    NoUserKey(PathBuf),
    UserKey(identity::KeyFileError),
    /// The Server did not accept the user key for the Account.
    AuthRejected {
        account: String,
        fingerprint: Fingerprint,
        /// The key as an authorized keys line: base64 of its SubjectPublicKeyInfo.
        key_line: String,
    },
    /// The Server rejected or reset the terminal Channel with this error code.
    ChannelRejected(u64),
    ChannelReset(u64),
    /// The Server ended the terminal Channel without an exit status.
    TerminalEnded,
    /// The user pressed Ctrl+C repeatedly while a remote command ran without a PTY.
    Interrupted,
    /// The Client was told to end (window closed, logoff, TERM): it detached and
    /// closed the Connection.
    Terminated(&'static str),
    /// Signal handlers could not be set up.
    Signals(io::Error),
    /// A request failed with this error code (§8.4); the command names it.
    Request(&'static str, u64),
    /// No Session matches the argument.
    NoSuchSession(String),
    /// Several Sessions start with the prefix.
    AmbiguousSession(String, usize),
    NoSuchAttachment(String, u64),
    /// The Connection ended while attached; the Session keeps running.
    SessionContinues {
        error: Box<Error>,
        session: crate::terminal::SessionId,
    },
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        EXIT_STPT_ERROR
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config: {e}"),
            Self::Transport(e) => write!(f, "transport: {e}"),
            Self::ServerUnavailable => {
                f.write_str("server: Server mode is not available on this platform")
            }
            Self::ServerKey(e) => write!(f, "server key: {e}"),
            Self::Trust(e) => write!(f, "trust store: {e}"),
            Self::NoTrustStore => f.write_str(if cfg!(windows) {
                "trust store: APPDATA is not set"
            } else {
                "trust store: neither XDG_CONFIG_HOME nor HOME is set"
            }),
            Self::NoTrustEntry(address) => write!(f, "trust store: no entry for {address}"),
            Self::Resolve { address, source } => write!(f, "{}: {source}", address.host),
            Self::KeyNotKnown { address, presented } => write!(
                f,
                "the key of the Server {address} is not known\n  \
                 fingerprint: {presented}\n\
                 Compare it in full with the output of `stpt server --fingerprint` on the \
                 Server, then pass it with --fingerprint or confirm it in a terminal."
            ),
            Self::KeyNotTrusted(address) => {
                write!(f, "the key of the Server {address} was not trusted")
            }
            Self::KeyChanged {
                address,
                stored,
                presented,
            } => write!(
                f,
                "the key of the Server {address} has changed\n  \
                 stored:    {stored}\n  \
                 presented: {presented}\n\
                 Someone may be intercepting the Connection, or the Server has a new key.\n\
                 Only if the Server administrator confirms the new key, remove the old one: \
                 stpt trust remove {address}"
            ),
            Self::FingerprintMismatch {
                address,
                expected,
                presented,
            } => write!(
                f,
                "the key of the Server {address} does not match --fingerprint\n  \
                 expected:  {expected}\n  \
                 presented: {presented}"
            ),
            Self::Terminal(e) => write!(f, "terminal: {e}"),
            Self::Protocol(failure) => write!(f, "protocol: {failure}"),
            Self::NoUserKey(path) => write!(
                f,
                "no user key at {path}\n\
                 Create one with: openssl genpkey -algorithm ed25519 -out {path}{chmod}",
                path = path.display(),
                chmod = if cfg!(unix) {
                    format!(" && chmod 600 {}", path.display())
                } else {
                    String::new()
                }
            ),
            Self::UserKey(e) => write!(f, "user key: {e}"),
            Self::AuthRejected {
                account,
                fingerprint,
                key_line,
            } => write!(
                f,
                "the Server did not accept the key {fingerprint} for the Account {account}\n\
                 If it should, the Server administrator adds this line to the authorized \
                 keys of the Account (by default /etc/stpt/authorized_keys/{account}):\n  \
                 {key_line}"
            ),
            Self::ChannelRejected(code) => {
                write!(f, "terminal: rejected by the Server: {}", code_name(*code))
            }
            Self::ChannelReset(code) => {
                write!(f, "terminal: reset by the Server: {}", code_name(*code))
            }
            Self::TerminalEnded => f.write_str("terminal: ended by the Server"),
            Self::Interrupted => f.write_str("interrupted"),
            Self::Terminated(by) => write!(f, "terminated by {by}"),
            Self::Signals(e) => write!(f, "signal handling: {e}"),
            Self::Request(command, code) => write!(f, "{command}: {}", code_name(*code)),
            Self::NoSuchSession(text) => write!(f, "no Session {text}"),
            Self::AmbiguousSession(text, n) => {
                write!(f, "{n} Sessions start with {text}; give more of the ID")
            }
            Self::NoSuchAttachment(session, id) => {
                write!(f, "no Attachment {id} in the Session {session}")
            }
            Self::SessionContinues { error, session } => write!(
                f,
                "{error}\nThe Session keeps running; attach again with: stpt connect --attach {session}"
            ),
        }
    }
}

/// Name of an error code received from the Server; its number if unknown.
fn code_name(code: u64) -> String {
    wire::Code::from_value(code).map_or_else(|| format!("error {code}"), |c| c.name().to_owned())
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(e) => Some(e),
            Self::Transport(e) => Some(e),
            Self::ServerKey(e) => Some(e),
            Self::Trust(e) => Some(e),
            Self::Resolve { source, .. } => Some(source),
            Self::Terminal(e) => Some(e),
            Self::UserKey(e) => Some(e),
            Self::Signals(e) => Some(e),
            _ => None,
        }
    }
}

impl From<config::Error> for Error {
    fn from(e: config::Error) -> Self {
        Self::Config(e)
    }
}

impl From<quic::Error> for Error {
    fn from(e: quic::Error) -> Self {
        Self::Transport(e)
    }
}

impl From<identity::KeyFileError> for Error {
    fn from(e: identity::KeyFileError) -> Self {
        Self::ServerKey(e)
    }
}

impl From<trust::Error> for Error {
    fn from(e: trust::Error) -> Self {
        Self::Trust(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_and_exit_codes() {
        let e = Error::Request("terminate", 9);
        assert_eq!(e.to_string(), "terminate: SESSION_NOT_FOUND");
        assert_eq!(e.exit_code(), 255);
        assert_eq!(Error::Request("x", 99).to_string(), "x: error 99");
        assert_eq!(
            Error::ServerUnavailable.to_string(),
            "server: Server mode is not available on this platform"
        );
    }

    #[test]
    fn changed_key_shows_both_fingerprints_in_full() {
        let a: Fingerprint = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"
            .parse()
            .unwrap();
        let b = identity::ServerKey::generate().public_key().fingerprint();
        let e = Error::KeyChanged {
            address: "host".parse().unwrap(),
            stored: a,
            presented: b,
        };
        let text = e.to_string();
        assert!(text.contains(&format!("stored:    {a}\n")), "{text}");
        assert!(text.contains(&format!("presented: {b}\n")), "{text}");
        assert!(text.ends_with("stpt trust remove host:843"), "{text}");
    }
}
