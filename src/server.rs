//! Server role: `stpt server`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::process::ExitCode;

use crate::cli::EXIT_STPT_ERROR;
use crate::destination::DEFAULT_PORT;

/// Server mode needs a Unix PTY; Windows Server mode (ConPTY) comes with RK006 (gate G2).
pub const AVAILABLE: bool = cfg!(unix);

/// Listen address without `--listen`: all addresses, port 843.
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT);

pub fn run(listen: Option<SocketAddr>) -> ExitCode {
    if !AVAILABLE {
        eprintln!("stpt: server: Server mode is not available on this platform");
        return ExitCode::from(EXIT_STPT_ERROR);
    }
    let _listen = listen.unwrap_or(DEFAULT_LISTEN);
    eprintln!("stpt: server: not implemented yet");
    ExitCode::from(EXIT_STPT_ERROR)
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
    fn available_on_unix_only() {
        assert_eq!(AVAILABLE, cfg!(unix));
    }
}
