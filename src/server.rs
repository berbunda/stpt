//! Server role: `stpt server`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;

use quinn::{Endpoint, Incoming};

use crate::cli::Common;
use crate::config::{self, ServerConfig};
use crate::destination::DEFAULT_PORT;
use crate::error::Error;
use crate::identity::{self, ServerKey};
use crate::logging::{self, Role};
use crate::quic;

/// Server mode needs a Unix PTY; Windows Server mode (ConPTY) comes with RC008 (gate G2).
pub const AVAILABLE: bool = cfg!(unix);

/// Listen address without `--listen` and configuration: all addresses, port 843.
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT);

/// Runs the Server; with `print_fingerprint` only prints the fingerprint of its key.
pub fn run(
    listen: Option<SocketAddr>,
    print_fingerprint: bool,
    common: &Common,
) -> Result<ExitCode, Error> {
    if !AVAILABLE {
        return Err(Error::ServerUnavailable);
    }
    let (config, path) = config::load::<ServerConfig>(
        common.config.as_deref(),
        Some(PathBuf::from(config::SERVER_PATH)),
    )?;
    logging::init(
        Role::Server,
        logging::level(Role::Server, common.verbose, common.quiet, config.log_level),
    );
    config::log_source(path.as_deref());

    let key = server_key(&config)?;
    if print_fingerprint {
        println!("{}", key.public_key().fingerprint());
        return Ok(ExitCode::SUCCESS);
    }

    let listen = listen_address(listen, &config);
    quic::runtime()?.block_on(async {
        let endpoint = quic::listen(listen, &key)?;
        let local = endpoint.local_addr().map_err(|source| quic::Error::Bind {
            addr: listen,
            source,
        })?;
        tracing::info!(listen = %local, "listening");
        serve(endpoint).await;
        Ok(ExitCode::SUCCESS)
    })
}

async fn serve(endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(connection(incoming));
    }
}

/// One Connection. Until HELLO (RB004) the Server only keeps it open until the
/// Client closes it or the idle timeout expires.
async fn connection(incoming: Incoming) {
    let remote = incoming.remote_address();
    match quic::accept(incoming).await {
        Ok(connection) => {
            tracing::info!(%remote, "Connection established");
            let reason = connection.closed().await;
            tracing::info!(%remote, ?reason, "Connection closed");
        }
        Err(error) => tracing::info!(%remote, ?error, "handshake failed"),
    }
}

/// Loads the Server Identity key, creating it at the first start (§9.1).
fn server_key(config: &ServerConfig) -> Result<ServerKey, Error> {
    let path = config
        .identity_key
        .clone()
        .unwrap_or_else(|| PathBuf::from(identity::SERVER_KEY_PATH));
    let (key, created) = ServerKey::load_or_create(&path)?;
    let fingerprint = key.public_key().fingerprint();
    if created {
        tracing::info!(path = %path.display(), %fingerprint, "Server key created");
    } else {
        tracing::info!(path = %path.display(), %fingerprint, "Server key");
    }
    Ok(key)
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
        let config = ServerConfig {
            listen: Some(b),
            ..Default::default()
        };
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
