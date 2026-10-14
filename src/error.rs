//! Errors that end the program. `main` reports them as `stpt: <error>` and
//! exits with [`Error::exit_code`]; command line errors are reported by clap (exit 2).

use std::fmt;

use crate::config;

/// Exit code for STPT and Connection errors, as ssh.
pub const EXIT_STPT_ERROR: u8 = 255;

#[derive(Debug)]
pub enum Error {
    Config(config::Error),
    /// Server mode on a platform without it (gate G2).
    ServerUnavailable,
    /// Subcommand that is recognised but not implemented yet.
    NotImplemented(&'static str),
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Config(_) | Self::ServerUnavailable | Self::NotImplemented(_) => EXIT_STPT_ERROR,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "config: {e}"),
            Self::ServerUnavailable => {
                f.write_str("server: Server mode is not available on this platform")
            }
            Self::NotImplemented(command) => write!(f, "{command}: not implemented yet"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(e) => Some(e),
            Self::ServerUnavailable | Self::NotImplemented(_) => None,
        }
    }
}

impl From<config::Error> for Error {
    fn from(e: config::Error) -> Self {
        Self::Config(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_and_exit_codes() {
        let e = Error::NotImplemented("connect");
        assert_eq!(e.to_string(), "connect: not implemented yet");
        assert_eq!(e.exit_code(), 255);
        assert_eq!(
            Error::ServerUnavailable.to_string(),
            "server: Server mode is not available on this platform"
        );
    }
}
