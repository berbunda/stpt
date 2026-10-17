//! QUIC transport of a Connection (PROTOCOL.md §6.1, §7.1, §8.2, §13.3); TLS: `tls`.

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, EndpointConfig, Incoming, TransportConfig, VarInt};
use socket2::{Domain, Protocol, Socket, Type};

use crate::tls::{self, PublicKey, ServerKey};

/// QUIC version 1 (RFC 9000); no other version is offered or accepted.
const QUIC_V1: u32 = 1;

/// QUIC idle timeout (§13.3).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// The Client sends PING after this idle time, so an idle terminal keeps its Connection.
pub const KEEP_ALIVE: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub enum Error {
    Runtime(io::Error),
    Bind { addr: SocketAddr, source: io::Error },
    Connect(quinn::ConnectError),
    Connection(quinn::ConnectionError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(e) => write!(f, "async runtime: {e}"),
            Self::Bind { addr, source } => write!(f, "{addr}: {source}"),
            Self::Connect(e) => e.fmt(f),
            Self::Connection(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

/// Async runtime that drives the QUIC Endpoints.
pub fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Error::Runtime)
}

/// Server Endpoint on `addr`; `[::]` also accepts IPv4 (dual-stack). Needs the runtime.
pub fn listen(addr: SocketAddr, key: &ServerKey) -> Result<Endpoint, Error> {
    let tls = QuicServerConfig::try_from(tls::server_config(key)).expect("suites usable for QUIC");
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(tls));
    config.transport_config(Arc::new(transport(1)));
    // §6.1: a Server MUST NOT disable active migration.
    config.migration(true);
    endpoint(addr, Some(config))
}

/// Completes the handshake of an incoming Connection.
pub async fn accept(incoming: Incoming) -> Result<Connection, Error> {
    incoming.await.map_err(Error::Connection)
}

/// Connects to the Server at `addr`, which must present `expected`. `server_name` is
/// the host as the user gave it: a DNS name is sent as SNI, an IP address is not (§6.4).
#[cfg_attr(not(test), expect(dead_code, reason = "Client connects from RB003 on"))]
pub async fn connect(
    addr: SocketAddr,
    server_name: &str,
    expected: PublicKey,
) -> Result<Connection, Error> {
    connect_tls(addr, server_name, tls::client_config(expected)).await
}

async fn connect_tls(
    addr: SocketAddr,
    server_name: &str,
    tls: rustls::ClientConfig,
) -> Result<Connection, Error> {
    let tls = QuicClientConfig::try_from(tls).expect("suites usable for QUIC");
    let mut config = quinn::ClientConfig::new(Arc::new(tls));
    let mut transport = transport(0);
    transport.keep_alive_interval(Some(KEEP_ALIVE));
    config.transport_config(Arc::new(transport));
    config.version(QUIC_V1);

    let local = match addr {
        SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    };
    let endpoint = endpoint(local, None)?;
    endpoint
        .connect_with(config, addr, server_name)
        .map_err(Error::Connect)?
        .await
        .map_err(Error::Connection)
}

/// Transport parameters; `bidi_streams` is the initial stream limit for the peer.
fn transport(bidi_streams: u32) -> TransportConfig {
    let mut transport = TransportConfig::default();
    // §7.1: bidirectional streams only.
    transport.max_concurrent_uni_streams(VarInt::from_u32(0));
    // §8.2: until authentication the Client may open only the control stream,
    // the Server none. Raised after authentication (RB006).
    transport.max_concurrent_bidi_streams(VarInt::from_u32(bidi_streams));
    transport.max_idle_timeout(Some(
        IDLE_TIMEOUT.try_into().expect("idle timeout in range"),
    ));
    // §6.1: no unreliable datagrams.
    transport.datagram_receive_buffer_size(None);
    transport
}

fn endpoint(addr: SocketAddr, server: Option<quinn::ServerConfig>) -> Result<Endpoint, Error> {
    let error = |source| Error::Bind { addr, source };
    let mut config = EndpointConfig::default();
    config.supported_versions(vec![QUIC_V1]);
    let socket = bind(addr).map_err(error)?;
    Endpoint::new(config, server, socket, Arc::new(quinn::TokioRuntime)).map_err(error)
}

/// UDP socket on `addr`. An unspecified IPv6 address is dual-stack explicitly, so it
/// does not depend on the system default (Linux `net.ipv6.bindv6only`, Windows).
fn bind(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        socket.set_only_v6(false)?;
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::crypto::rustls::HandshakeData;
    use std::future::Future;

    /// Runs `test` with a Server Endpoint on `addr` and its public key.
    fn with_server<F: Future<Output = ()>>(
        addr: &str,
        test: impl FnOnce(Endpoint, PublicKey) -> F,
    ) {
        runtime().unwrap().block_on(async {
            let key = ServerKey::generate();
            let server = listen(addr.parse().unwrap(), &key).unwrap();
            test(server, key.public_key()).await;
        });
    }

    async fn accept_one(server: &Endpoint) -> Result<Connection, Error> {
        accept(server.accept().await.unwrap()).await
    }

    fn port(server: &Endpoint) -> u16 {
        server.local_addr().unwrap().port()
    }

    fn handshake(connection: &Connection) -> Box<HandshakeData> {
        connection.handshake_data().unwrap().downcast().unwrap()
    }

    /// Whether `future` is still pending after a short time.
    async fn blocks<F: Future>(future: F) -> bool {
        tokio::time::timeout(Duration::from_millis(200), future)
            .await
            .is_err()
    }

    #[test]
    fn connection_and_stream_limits() {
        with_server("127.0.0.1:0", |server, key| async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], port(&server)));
            let (client, accepted) =
                tokio::join!(connect(addr, "localhost", key), accept_one(&server));
            let (client, accepted) = (client.unwrap(), accepted.unwrap());

            assert_eq!(handshake(&client).protocol.as_deref(), Some(tls::ALPN));
            assert_eq!(
                handshake(&accepted).server_name.as_deref(),
                Some("localhost")
            );
            assert_eq!(client.max_datagram_size(), None);
            assert_eq!(accepted.max_datagram_size(), None);

            // §8.2: one bidirectional stream for the Client, none for the Server, no uni.
            let (mut send, _recv) = client.open_bi().await.unwrap();
            send.write_all(b"x").await.unwrap();
            assert!(blocks(client.open_bi()).await);
            assert!(blocks(client.open_uni()).await);
            assert!(blocks(accepted.open_bi()).await);
            assert!(blocks(accepted.open_uni()).await);

            client.close(VarInt::from_u32(0), b"");
            assert!(matches!(
                accepted.closed().await,
                quinn::ConnectionError::ApplicationClosed(_)
            ));
        });
    }

    #[test]
    fn ip_address_is_not_sent_as_sni() {
        with_server("127.0.0.1:0", |server, key| async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], port(&server)));
            let (_client, accepted) =
                tokio::join!(connect(addr, "127.0.0.1", key), accept_one(&server));
            assert_eq!(handshake(&accepted.unwrap()).server_name, None);
        });
    }

    #[test]
    fn dual_stack() {
        with_server("[::]:0", |server, key| async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], port(&server)));
            let (client, accepted) =
                tokio::join!(connect(addr, "127.0.0.1", key), accept_one(&server));
            client.unwrap();
            accepted.unwrap();
        });
    }

    #[test]
    fn wrong_key_is_rejected() {
        with_server("127.0.0.1:0", |server, _key| async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], port(&server)));
            let other = ServerKey::generate().public_key();
            let (client, accepted) =
                tokio::join!(connect(addr, "localhost", other), accept_one(&server));
            assert!(matches!(client, Err(Error::Connection(_))));
            assert!(accepted.is_err());
        });
    }

    #[test]
    fn client_without_alpn_is_rejected() {
        with_server("127.0.0.1:0", |server, key| async move {
            let addr = SocketAddr::from(([127, 0, 0, 1], port(&server)));
            let mut tls = tls::client_config(key);
            tls.alpn_protocols.clear();
            let (client, accepted) =
                tokio::join!(connect_tls(addr, "localhost", tls), accept_one(&server));
            assert!(client.is_err(), "{client:?}");
            assert!(accepted.is_err(), "{accepted:?}");
        });
    }
}
