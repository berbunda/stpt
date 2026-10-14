//! Server role: `stpt server`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::EXIT_STPT_ERROR;
use crate::config::{self, ServerConfig};
use crate::destination::DEFAULT_PORT;

/// Server mode needs a Unix PTY; Windows Server mode (ConPTY) comes with RK006 (gate G2).
pub const AVAILABLE: bool = cfg!(unix);

/// Listen address without `--listen` and configuration: all addresses, port 843.
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT);

pub fn run(listen: Option<SocketAddr>, config_path: Option<&Path>) -> ExitCode {
    if !AVAILABLE {
        eprintln!("stpt: server: Server mode is not available on this platform");
        return ExitCode::from(EXIT_STPT_ERROR);
    }
    let config: ServerConfig =
        match config::load(config_path, Some(PathBuf::from(config::SERVER_PATH))) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("stpt: config: {e}");
                return ExitCode::from(EXIT_STPT_ERROR);
            }
        };
    let _listen = listen_address(listen, &config);
    eprintln!("stpt: server: not implemented yet");
    ExitCode::from(EXIT_STPT_ERROR)
}

/// `--listen`, else the configuration, else [`DEFAULT_LISTEN`].
fn listen_address(cli: Option<SocketAddr>, config: &ServerConfig) -> SocketAddr {
    cli.or(config.listen).unwrap_or(DEFAULT_LISTEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_listen_is_all_addresses_on_default_port() {
        assert!(DEFAULT_LISTEN.ip().is_unspecified());
        assert_eq!(DEFAULT_LISTEN.port(), 843);
    }

    #[test]
    fn listen_precedence() {
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.1:2".parse().unwrap();
        let config = ServerConfig { listen: Some(b) };
        assert_eq!(listen_address(Some(a), &config), a);
        assert_eq!(listen_address(None, &config), b);
        assert_eq!(
            listen_address(None, &ServerConfig::default()),
            DEFAULT_LISTEN
        );
    }

    #[test]
    fn available_on_unix_only() {
        assert_eq!(AVAILABLE, cfg!(unix));
    }
}
