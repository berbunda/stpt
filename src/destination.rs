//! Destination of a Connection: `account@host[:port]`.

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;

/// Default STPT port (PROTOCOL.md §6.6).
pub const DEFAULT_PORT: u16 = 843;

/// Maximum length of an Account name in bytes (PROTOCOL.md §13.4).
const MAX_ACCOUNT_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    pub account: String,
    /// DNS name or IP address as given by the user, without brackets.
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    MissingAccount,
    AccountTooLong,
    AccountControlChar,
    MissingHost,
    UnclosedBracket,
    InvalidIpv6,
    UnbracketedIpv6,
    InvalidPort,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingAccount => "expected account@host[:port]",
            Self::AccountTooLong => "account name is longer than 256 bytes",
            Self::AccountControlChar => "account name contains a control character",
            Self::MissingHost => "host is empty",
            Self::UnclosedBracket => "IPv6 address is missing its closing bracket",
            Self::InvalidIpv6 => "invalid IPv6 address in brackets",
            Self::UnbracketedIpv6 => "IPv6 address must be in brackets: account@[addr]:port",
            Self::InvalidPort => "port must be a number from 1 to 65535",
        })
    }
}

impl std::error::Error for ParseError {}

impl FromStr for Destination {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // The last '@' separates the account, so an account such as a Windows
        // `user@domain` stays intact; a host never contains '@'.
        let (account, rest) = s.rsplit_once('@').ok_or(ParseError::MissingAccount)?;
        if account.is_empty() {
            return Err(ParseError::MissingAccount);
        }
        if account.len() > MAX_ACCOUNT_LEN {
            return Err(ParseError::AccountTooLong);
        }
        if account.chars().any(char::is_control) {
            return Err(ParseError::AccountControlChar);
        }

        let (host, port) = if let Some(bracketed) = rest.strip_prefix('[') {
            let (addr, after) = bracketed
                .split_once(']')
                .ok_or(ParseError::UnclosedBracket)?;
            addr.parse::<Ipv6Addr>()
                .map_err(|_| ParseError::InvalidIpv6)?;
            let port = match after {
                "" => None,
                _ => Some(after.strip_prefix(':').ok_or(ParseError::InvalidPort)?),
            };
            (addr, port)
        } else {
            match rest.split_once(':') {
                Some((_, p)) if p.contains(':') => return Err(ParseError::UnbracketedIpv6),
                Some((h, p)) => (h, Some(p)),
                None => (rest, None),
            }
        };

        if host.is_empty() {
            return Err(ParseError::MissingHost);
        }
        let port = match port {
            None => DEFAULT_PORT,
            Some(p) => match p.parse::<u16>() {
                Ok(n) if n != 0 => n,
                _ => return Err(ParseError::InvalidPort),
            },
        };

        Ok(Self {
            account: account.to_owned(),
            host: host.to_owned(),
            port,
        })
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(f, "{}@[{}]:{}", self.account, self.host, self.port)
        } else {
            write!(f, "{}@{}:{}", self.account, self.host, self.port)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dest(account: &str, host: &str, port: u16) -> Destination {
        Destination {
            account: account.into(),
            host: host.into(),
            port,
        }
    }

    #[test]
    fn host_with_default_port() {
        assert_eq!(
            "alice@example.org".parse(),
            Ok(dest("alice", "example.org", DEFAULT_PORT))
        );
    }

    #[test]
    fn host_with_port() {
        assert_eq!(
            "alice@10.0.0.1:2222".parse(),
            Ok(dest("alice", "10.0.0.1", 2222))
        );
    }

    #[test]
    fn ipv6_in_brackets() {
        assert_eq!(
            "alice@[::1]".parse(),
            Ok(dest("alice", "::1", DEFAULT_PORT))
        );
        assert_eq!(
            "alice@[fe80::1]:900".parse(),
            Ok(dest("alice", "fe80::1", 900))
        );
    }

    #[test]
    fn account_with_at_sign() {
        assert_eq!(
            "bob@corp@host".parse(),
            Ok(dest("bob@corp", "host", DEFAULT_PORT))
        );
    }

    #[test]
    fn errors() {
        let cases = [
            ("host", ParseError::MissingAccount),
            ("@host", ParseError::MissingAccount),
            ("alice@", ParseError::MissingHost),
            ("alice@:843", ParseError::MissingHost),
            ("alice@[::1", ParseError::UnclosedBracket),
            ("alice@[zz]", ParseError::InvalidIpv6),
            ("alice@[::1]843", ParseError::InvalidPort),
            ("alice@::1", ParseError::UnbracketedIpv6),
            ("alice@host:0", ParseError::InvalidPort),
            ("alice@host:65536", ParseError::InvalidPort),
            ("alice@host:", ParseError::InvalidPort),
            ("al\nice@host", ParseError::AccountControlChar),
        ];
        for (input, err) in cases {
            assert_eq!(input.parse::<Destination>(), Err(err), "{input}");
        }
    }

    #[test]
    fn account_length_limit() {
        let ok = format!("{}@h", "a".repeat(MAX_ACCOUNT_LEN));
        let long = format!("{}@h", "a".repeat(MAX_ACCOUNT_LEN + 1));
        assert!(ok.parse::<Destination>().is_ok());
        assert_eq!(long.parse::<Destination>(), Err(ParseError::AccountTooLong));
    }

    #[test]
    fn display_round_trip() {
        for s in ["alice@example.org:843", "alice@[::1]:2222"] {
            assert_eq!(s.parse::<Destination>().unwrap().to_string(), s);
        }
    }
}
