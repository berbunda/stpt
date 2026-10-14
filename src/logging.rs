//! Log messages: `tracing` events written to standard error.
//!
//! Under systemd the Server's standard error goes to the journal. Values that come
//! from a peer are logged only as `?` fields (Debug), which escapes line breaks and
//! control characters, so a peer can neither forge log lines nor send terminal
//! sequences to whoever reads the log. Secrets are never logged.

use serde::Deserialize;
use tracing::level_filters::LevelFilter;

/// Log level; the configuration uses the lowercase names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl From<Level> for LevelFilter {
    fn from(level: Level) -> Self {
        match level {
            Level::Error => Self::ERROR,
            Level::Warn => Self::WARN,
            Level::Info => Self::INFO,
            Level::Debug => Self::DEBUG,
            Level::Trace => Self::TRACE,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// `-q` or `-v` from the command line, else the configuration, else the role default
/// (Client warn, Server info).
pub fn level(role: Role, verbose: u8, quiet: bool, config: Option<Level>) -> Level {
    if quiet {
        return Level::Error;
    }
    match verbose {
        0 => config.unwrap_or(match role {
            Role::Client => Level::Warn,
            Role::Server => Level::Info,
        }),
        1 => Level::Info,
        2 => Level::Debug,
        _ => Level::Trace,
    }
}

/// Installs the global log subscriber; called once, after the configuration is read.
/// Client lines are `LEVEL message`; Server lines also carry the UTC time and the module.
pub fn init(role: Role, level: Level) {
    let builder = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(LevelFilter::from(level))
        .with_ansi(false);
    match role {
        Role::Client => builder.without_time().with_target(false).init(),
        Role::Server => builder.init(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn precedence() {
        use Level::*;
        assert_eq!(level(Role::Client, 0, false, None), Warn);
        assert_eq!(level(Role::Server, 0, false, None), Info);
        assert_eq!(level(Role::Server, 0, false, Some(Debug)), Debug);
        assert_eq!(level(Role::Server, 1, false, Some(Error)), Info);
        assert_eq!(level(Role::Client, 2, false, None), Debug);
        assert_eq!(level(Role::Client, 9, false, None), Trace);
        assert_eq!(level(Role::Server, 0, true, Some(Trace)), Error);
    }

    #[test]
    fn config_names() {
        #[derive(Debug, Deserialize)]
        struct T {
            level: Level,
        }
        let parse = |s: &str| toml::from_str::<T>(s).map(|t| t.level);
        assert_eq!(parse(r#"level = "debug""#).unwrap(), Level::Debug);
        assert!(parse(r#"level = "DEBUG""#).is_err());
        assert!(parse(r#"level = "off""#).is_err());
    }
}
