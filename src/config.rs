//! Configuration files (TOML): one for the Client, one for the Server.
//!
//! Precedence: command line, then configuration file, then built-in default.
//! Unknown keys are errors, so a misspelt key never falls back to a default silently.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use std::time::Duration;

use serde::de::{DeserializeOwned, Error as _};
use serde::{Deserialize, Deserializer};

use crate::logging;

/// Default path of the Server configuration.
pub const SERVER_PATH: &str = "/etc/stpt/server.toml";

/// Client configuration. It has no settings yet; the first one comes with RD009.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Address and UDP port to listen on.
    pub listen: Option<SocketAddr>,
    /// Log level when neither `-v` nor `-q` is given.
    pub log_level: Option<logging::Level>,
    /// Key file of the Server Identity, created if missing.
    pub identity_key: Option<PathBuf>,
    /// Directory with one file of authorized user keys per Account.
    pub authorized_keys: Option<PathBuf>,
    /// Output still sent after the primary process of a Session exited: 0–60 seconds,
    /// fractions allowed (PROTOCOL.md §14.10).
    #[serde(default, deserialize_with = "exit_grace")]
    pub exit_grace: Option<Duration>,
}

/// Longest exit grace period accepted, in seconds.
const MAX_EXIT_GRACE: f64 = 60.0;

fn exit_grace<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
    let seconds = f64::deserialize(d)?;
    if !(0.0..=MAX_EXIT_GRACE).contains(&seconds) {
        return Err(D::Error::custom("exit_grace must be 0 to 60 seconds"));
    }
    Ok(Some(Duration::from_secs_f64(seconds)))
}

#[derive(Debug)]
pub enum Error {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Parse { path, source } => write!(f, "{}: {source}", path.display()),
        }
    }
}

impl std::error::Error for Error {}

/// Loads a configuration file; returns it with the path of the file read, if any.
///
/// A file given explicitly (`--config`) must exist. A missing file at the default
/// path, or no default path at all, means built-in defaults; any other read error
/// at the default path is an error.
pub fn load<T: DeserializeOwned + Default>(
    explicit: Option<&Path>,
    default: Option<PathBuf>,
) -> Result<(T, Option<PathBuf>), Error> {
    let (path, required) = match (explicit, default) {
        (Some(path), _) => (path.to_owned(), true),
        (None, Some(path)) => (path, false),
        (None, None) => return Ok((T::default(), None)),
    };
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if !required && e.kind() == io::ErrorKind::NotFound => {
            return Ok((T::default(), None));
        }
        Err(source) => return Err(Error::Read { path, source }),
    };
    match toml::from_str(&text) {
        Ok(config) => Ok((config, Some(path))),
        Err(source) => Err(Error::Parse { path, source }),
    }
}

/// Logs which configuration is used; called once logging is initialised.
pub fn log_source(path: Option<&Path>) {
    match path {
        Some(path) => tracing::debug!(path = %path.display(), "configuration file read"),
        None => tracing::debug!("no configuration file, built-in defaults"),
    }
}

/// Default path of the Client configuration; `None` if the user's directory is unknown.
pub fn client_path() -> Option<PathBuf> {
    client_dir().map(|dir| dir.join("config.toml"))
}

/// Directory of the Client configuration and trust store; `None` if the user's
/// directory is unknown.
pub fn client_dir() -> Option<PathBuf> {
    client_dir_from(|name| std::env::var_os(name))
}

fn client_dir_from(var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let dir = |name: &str| var(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = if cfg!(windows) {
        dir("APPDATA")?
    } else {
        // XDG Base Directory: a relative XDG_CONFIG_HOME is invalid and ignored.
        match dir("XDG_CONFIG_HOME").filter(|p| p.is_absolute()) {
            Some(p) => p,
            None => dir("HOME")?.join(".config"),
        }
    };
    Some(base.join("stpt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse<T: DeserializeOwned>(text: &str) -> Result<T, toml::de::Error> {
        toml::from_str(text)
    }

    #[test]
    fn server_listen() {
        let config: ServerConfig = parse(r#"listen = "[::1]:900""#).unwrap();
        assert_eq!(config.listen, Some("[::1]:900".parse().unwrap()));
        assert_eq!(parse::<ServerConfig>("").unwrap().listen, None);
        let config: ServerConfig = parse(r#"log_level = "debug""#).unwrap();
        assert_eq!(config.log_level, Some(logging::Level::Debug));
        let config: ServerConfig = parse(r#"identity_key = "/srv/key""#).unwrap();
        assert_eq!(config.identity_key, Some(PathBuf::from("/srv/key")));
    }

    #[test]
    fn invalid_values_and_unknown_keys_are_errors() {
        assert!(parse::<ServerConfig>(r#"listen = "host""#).is_err());
        assert!(parse::<ServerConfig>("listen = 843").is_err());
        assert!(parse::<ServerConfig>(r#"lisen = "[::]:843""#).is_err());
        assert!(parse::<ClientConfig>("detach_timeout = 60").is_err());
        assert!(parse::<ClientConfig>("").is_ok());
    }

    #[test]
    fn exit_grace() {
        let grace = |text: &str| parse::<ServerConfig>(text).map(|c| c.exit_grace).ok();
        assert_eq!(grace(""), Some(None));
        assert_eq!(grace("exit_grace = 2"), Some(Some(Duration::from_secs(2))));
        assert_eq!(
            grace("exit_grace = 0.25"),
            Some(Some(Duration::from_millis(250)))
        );
        assert_eq!(grace("exit_grace = 0"), Some(Some(Duration::ZERO)));
        for bad in [
            "exit_grace = -1",
            "exit_grace = 60.5",
            "exit_grace = nan",
            "exit_grace = \"1\"",
        ] {
            assert!(grace(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn missing_file() {
        let missing = Path::new("/nonexistent/stpt/config.toml");
        assert!(matches!(
            load::<ServerConfig>(None, Some(missing.to_owned())),
            Ok((_, None))
        ));
        assert!(matches!(load::<ServerConfig>(None, None), Ok((_, None))));
        assert!(matches!(
            load::<ServerConfig>(Some(missing), None),
            Err(Error::Read { .. })
        ));
    }

    #[test]
    fn explicit_path_replaces_default() {
        let dir = std::env::temp_dir().join(format!("stpt-config-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("server.toml");
        fs::write(&file, r#"listen = "127.0.0.1:2222""#).unwrap();
        let bad = dir.join("bad.toml");
        fs::write(&bad, "listen = [").unwrap();

        let (config, read) = load::<ServerConfig>(Some(&file), Some(bad.clone())).unwrap();
        assert_eq!(config.listen.unwrap().port(), 2222);
        assert_eq!(read, Some(file));
        assert!(matches!(
            load::<ServerConfig>(None, Some(bad)),
            Err(Error::Parse { .. })
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    fn env<'a>(vars: &'a [(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            vars.iter()
                .find(|(n, _)| *n == name)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[cfg(windows)]
    #[test]
    fn client_dir_windows() {
        assert_eq!(
            client_dir_from(env(&[("APPDATA", r"C:\Users\a\AppData\Roaming")])),
            Some(PathBuf::from(r"C:\Users\a\AppData\Roaming\stpt"))
        );
        assert_eq!(client_dir_from(env(&[("APPDATA", "")])), None);
    }

    #[cfg(unix)]
    #[test]
    fn client_dir_unix() {
        let path = |vars| client_dir_from(env(vars));
        assert_eq!(
            path(&[("HOME", "/home/a")]),
            Some(PathBuf::from("/home/a/.config/stpt"))
        );
        assert_eq!(
            path(&[("HOME", "/home/a"), ("XDG_CONFIG_HOME", "/cfg")]),
            Some(PathBuf::from("/cfg/stpt"))
        );
        assert_eq!(
            path(&[("HOME", "/home/a"), ("XDG_CONFIG_HOME", "rel")]),
            Some(PathBuf::from("/home/a/.config/stpt"))
        );
        assert_eq!(path(&[]), None);
    }
}
