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

/// Platform directory for Server configuration, identity and authorization.
#[cfg(unix)]
pub fn server_directory() -> PathBuf {
    PathBuf::from("/etc/stpt")
}
#[cfg(windows)]
pub fn server_directory() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("stpt")
}
pub fn server_path() -> PathBuf {
    server_directory().join("server.toml")
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Maximum logical file size (default 8 GiB).
    #[serde(default, deserialize_with = "file_size_limit")]
    pub max_file_size: Option<u64>,
    /// No-progress file operation deadline in seconds (default 60).
    #[serde(default, deserialize_with = "file_deadline")]
    pub file_timeout: Option<u64>,
    /// Seconds a new Session may stay without an Attachment (PROTOCOL.md §15.8).
    pub detach_timeout: Option<u64>,
    /// Seconds automatic reattach keeps trying after the loss of a Connection (§15.12);
    /// 0 turns it off.
    pub reattach_timeout: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Maximum logical size of one file transfer (default 8 GiB).
    #[serde(default, deserialize_with = "file_size_limit")]
    pub max_file_size: Option<u64>,
    /// No-progress deadline for file operations in seconds (default 60).
    #[serde(default, deserialize_with = "file_deadline")]
    pub file_timeout: Option<u64>,
    /// Per-Connection file Channel cap; default 8, 0 disables negotiation.
    pub max_file_channels: Option<u32>,
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
    // Server mode is Unix only for now (gate G2).
    #[cfg_attr(not(unix), allow(dead_code))]
    #[serde(default, deserialize_with = "exit_grace")]
    pub exit_grace: Option<Duration>,
}

fn file_size_limit<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    let value = u64::deserialize(d)?;
    if value > crate::file_protocol::MAX_SIZE {
        return Err(D::Error::custom("max_file_size exceeds wire size bound"));
    }
    Ok(Some(value))
}
fn file_deadline<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    let value = u64::deserialize(d)?;
    if !(1..=86400).contains(&value) {
        return Err(D::Error::custom("file_timeout must be 1 to 86400 seconds"));
    }
    Ok(Some(value))
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
    load_inner(explicit, default, false)
}
pub fn load_server(explicit: Option<&Path>) -> Result<(ServerConfig, Option<PathBuf>), Error> {
    load_inner(explicit, Some(server_path()), true)
}
fn load_inner<T: DeserializeOwned + Default>(
    explicit: Option<&Path>,
    default: Option<PathBuf>,
    secure: bool,
) -> Result<(T, Option<PathBuf>), Error> {
    let (path, required) = match (explicit, default) {
        (Some(path), _) => (path.to_owned(), true),
        (None, Some(path)) => (path, false),
        (None, None) => return Ok((T::default(), None)),
    };
    let read = || -> io::Result<String> {
        #[cfg(windows)]
        if secure {
            use std::io::Read;
            let mut file = crate::windows_security::open_read(&path)?;
            crate::windows_security::check_handle(&file, false)?;
            let mut text = String::new();
            file.read_to_string(&mut text)?;
            return Ok(text);
        }
        let _ = secure;
        fs::read_to_string(&path)
    };
    let text = match read() {
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
        assert!(parse::<ClientConfig>("detach_timout = 60").is_err());
        assert!(parse::<ClientConfig>("").is_ok());
    }

    #[test]
    fn file_channel_policy() {
        assert_eq!(parse::<ServerConfig>("").unwrap().max_file_channels, None);
        for cap in [0, 1, 8, u32::MAX] {
            let text = format!("max_file_channels = {cap}");
            assert_eq!(
                parse::<ServerConfig>(&text).unwrap().max_file_channels,
                Some(cap)
            );
        }
        for value in ["-1", "4294967296", "1.5", "\"8\""] {
            assert!(parse::<ServerConfig>(&format!("max_file_channels = {value}")).is_err());
        }
        assert!(parse::<ClientConfig>("max_file_channels = 2").is_err());
    }

    #[test]
    fn file_limits_and_deadlines_are_validated() {
        assert_eq!(
            parse::<ServerConfig>("max_file_size = 8589934592\nfile_timeout = 120")
                .unwrap()
                .file_timeout,
            Some(120)
        );
        assert!(parse::<ServerConfig>("max_file_size = 2305843009213693952").is_err());
        for bad in ["0", "86401", "-1", "1.5", "\"60\""] {
            let t = format!("file_timeout = {bad}");
            assert!(parse::<ClientConfig>(&t).is_err());
            assert!(parse::<ServerConfig>(&t).is_err());
        }
        assert_eq!(
            parse::<ClientConfig>("file_timeout = 30")
                .unwrap()
                .file_timeout,
            Some(30)
        );
    }

    #[test]
    fn detach_timeout() {
        let timeout = |text: &str| parse::<ClientConfig>(text).map(|c| c.detach_timeout).ok();
        assert_eq!(timeout(""), Some(None));
        assert_eq!(timeout("detach_timeout = 3600"), Some(Some(3600)));
        assert_eq!(timeout("detach_timeout = 0"), Some(Some(0)));
        for bad in [
            "detach_timeout = -1",
            "detach_timeout = 1.5",
            "detach_timeout = \"1h\"",
        ] {
            assert!(timeout(bad).is_none(), "{bad}");
        }
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
