//! Server role: `stpt server`.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use quinn::{Connection, Endpoint, Incoming};
use tokio::time::{Instant, timeout, timeout_at};

use crate::cli::Common;
use crate::config::{self, ServerConfig};
use crate::destination::DEFAULT_PORT;
use crate::error::Error;
use crate::hello::{ClientHello, ServerHello};
use crate::identity::{self, ServerKey};
use crate::logging::{self, Role};
use crate::quic;
use crate::wire::{self, CLIENT_HELLO, DEFAULT_MESSAGE_LIMIT, Failure, StreamError};

/// Server mode needs a Unix PTY; Windows Server mode (ConPTY) comes with RC008 (gate G2).
pub const AVAILABLE: bool = cfg!(unix);

/// Listen address without `--listen` and configuration: all addresses, port 843.
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT);

/// Deadlines of a Connection (§13.3).
#[derive(Debug, Clone, Copy)]
pub struct Deadlines {
    /// CLIENT_HELLO received after the TLS handshake.
    pub hello: Duration,
    /// Connection Authenticated after it became Established.
    pub auth: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Self {
            hello: Duration::from_secs(10),
            auth: Duration::from_secs(60),
        }
    }
}

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
        tokio::spawn(connection(incoming, Deadlines::default()));
    }
}

/// One Connection: TLS handshake, HELLO, then the wait for user authentication.
/// Every rejection is logged with its exact reason; the Client gets the code only.
async fn connection(incoming: Incoming, deadlines: Deadlines) {
    let remote = incoming.remote_address();
    let connection = match quic::accept(incoming).await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::info!(%remote, ?error, "handshake failed");
            return;
        }
    };
    tracing::debug!(%remote, "TLS handshake completed");
    match serve_connection(&connection, deadlines).await {
        Ok(reason) => tracing::info!(%remote, ?reason, "Connection closed"),
        Err(failure) => {
            connection.close(failure.code.varint(), b"");
            tracing::info!(
                %remote,
                code = failure.code.name(),
                reason = %failure.reason,
                "Connection closed by the Server"
            );
        }
    }
}

/// Runs a Connection until it is lost (`Ok` with the reason) or the Server must
/// close it (`Err`).
async fn serve_connection(
    connection: &Connection,
    deadlines: Deadlines,
) -> Result<quinn::ConnectionError, Failure> {
    let hello = timeout(deadlines.hello, async {
        let (send, mut recv) = connection.accept_bi().await.map_err(StreamError::Lost)?;
        let message = control_message(&mut recv).await?;
        Ok::<_, StreamError>((send, recv, message))
    })
    .await
    .map_err(|_| {
        Failure::new(
            wire::Code::Timeout,
            format!("no CLIENT_HELLO within {} s", deadlines.hello.as_secs_f32()),
        )
    })?;
    let (mut send, mut recv, message) = match hello {
        Ok(hello) => hello,
        Err(StreamError::Lost(reason)) => return Ok(reason),
        Err(e) => return Err(control_failure(e)),
    };
    // §10.1: nothing but CLIENT_HELLO may come first.
    let hello = ClientHello::from_message(&message)?;
    let answer = ServerHello::answer(&hello)?;
    match wire::write_message(&mut send, &answer.to_message(), hello.limits.max_message).await {
        Ok(()) => {}
        Err(StreamError::Lost(reason)) => return Ok(reason),
        Err(e) => return Err(control_failure(e)),
    }
    let established = Instant::now();
    tracing::info!(
        remote = %connection.remote_address(),
        version = format_args!("{:#x}", answer.version),
        "Connection established"
    );

    // User authentication comes with RB006: until then every further message is
    // refused, and the authentication deadline ends the Connection.
    let next = timeout_at(established + deadlines.auth, control_message(&mut recv))
        .await
        .map_err(|_| {
            Failure::new(
                wire::Code::Timeout,
                format!(
                    "not authenticated within {} s",
                    deadlines.auth.as_secs_f32()
                ),
            )
        })?;
    match next {
        Ok(message) if message.kind == CLIENT_HELLO => {
            Err(Failure::violation("second CLIENT_HELLO"))
        }
        Ok(message) => Err(Failure::violation(format!(
            "message type {} before authentication (user authentication is not implemented yet)",
            message.kind
        ))),
        Err(StreamError::Lost(reason)) => Ok(reason),
        Err(e) => Err(control_failure(e)),
    }
}

/// The next message on the control stream; its end is an error (§8.1).
async fn control_message(recv: &mut quinn::RecvStream) -> Result<wire::Message, StreamError> {
    wire::read_message(recv, DEFAULT_MESSAGE_LIMIT)
        .await?
        .ok_or_else(|| Failure::violation("control stream ended").into())
}

/// Failure for a stream error other than a lost Connection.
fn control_failure(error: StreamError) -> Failure {
    match error {
        StreamError::Failure(failure) => failure,
        StreamError::Reset(code) => Failure::violation(format!("control stream reset ({code})")),
        StreamError::Lost(reason) => Failure::new(
            wire::Code::InternalError,
            format!("Connection lost: {reason}"),
        ),
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
    use crate::hello::WIRE_VERSION;
    use crate::tls::{Expected, ServerKeyCheck};
    use crate::wire::{Code, Message, SERVER_HELLO, frame};

    const SHORT: Deadlines = Deadlines {
        hello: Duration::from_millis(300),
        auth: Duration::from_millis(300),
    };

    /// A Client Connection to a Server that serves exactly this Connection.
    struct Peer {
        _endpoint: Endpoint,
        connection: Connection,
    }

    impl Peer {
        async fn start(deadlines: Deadlines) -> Self {
            let key = ServerKey::generate();
            let server = quic::listen("127.0.0.1:0".parse().unwrap(), &key).unwrap();
            let addr = server.local_addr().unwrap();
            tokio::spawn(async move {
                let incoming = server.accept().await.unwrap();
                connection(incoming, deadlines).await;
            });
            let endpoint = quic::client(addr).unwrap();
            let check = ServerKeyCheck::new(Expected {
                stored: Some(key.public_key()),
                fingerprint: None,
            });
            let connection = quic::connect(&endpoint, addr, "localhost", check)
                .await
                .unwrap();
            Self {
                _endpoint: endpoint,
                connection,
            }
        }

        /// The error code the Server closed the Connection with.
        async fn closed_with(&self) -> Option<Code> {
            match self.connection.closed().await {
                quinn::ConnectionError::ApplicationClosed(close) => {
                    Code::from_value(close.error_code.into_inner())
                }
                other => panic!("{other:?}"),
            }
        }
    }

    fn hello_frame(hello: &ClientHello) -> Vec<u8> {
        frame(&hello.to_message().encode())
    }

    #[tokio::test]
    async fn hello_then_authentication_deadline() {
        let peer = Peer::start(SHORT).await;
        let (mut send, mut recv) = peer.connection.open_bi().await.unwrap();
        let offer = ClientHello::ours();
        send.write_all(&hello_frame(&offer)).await.unwrap();
        let message = wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        let answer = ServerHello::from_message(&message).unwrap();
        answer.check(&offer).unwrap();
        assert_eq!(answer.version, WIRE_VERSION);
        assert_eq!(answer.auth_methods, [1]);
        assert_eq!(peer.closed_with().await, Some(Code::Timeout));
    }

    #[tokio::test]
    async fn no_hello_times_out() {
        let peer = Peer::start(SHORT).await;
        assert_eq!(peer.closed_with().await, Some(Code::Timeout));
    }

    /// Sends `bytes` as the first data on the control stream; returns the close code.
    async fn first_bytes(bytes: &[u8]) -> Option<Code> {
        let peer = Peer::start(Deadlines::default()).await;
        let (mut send, _recv) = peer.connection.open_bi().await.unwrap();
        send.write_all(bytes).await.unwrap();
        peer.closed_with().await
    }

    #[tokio::test]
    async fn invalid_first_messages() {
        let violation = Some(Code::ProtocolViolation);
        let server_hello = Message::new(SERVER_HELLO, vec![(0, crate::cbor::Value::Uint(1))]);
        assert_eq!(first_bytes(&frame(&server_hello.encode())).await, violation);
        assert_eq!(first_bytes(&frame(&[0x9f, 0x01, 0xff])).await, violation);
        assert_eq!(first_bytes(&[0x00]).await, violation);
        // Length 65536 announced: refused before the payload arrives.
        assert_eq!(
            first_bytes(&[0x80, 0x01, 0x00, 0x00]).await,
            Some(Code::LimitExceeded)
        );
        let unknown = ClientHello {
            versions: vec![0xFF00_0009, 0x2A2A_2A2A],
            ..ClientHello::ours()
        };
        assert_eq!(
            first_bytes(&hello_frame(&unknown)).await,
            Some(Code::VersionNegotiationFailed)
        );
    }

    /// HELLO exchange, then `after` on the control stream; returns the close code.
    async fn after_hello(after: impl AsyncFnOnce(&mut quinn::SendStream)) -> Option<Code> {
        let peer = Peer::start(Deadlines::default()).await;
        let (mut send, mut recv) = peer.connection.open_bi().await.unwrap();
        send.write_all(&hello_frame(&ClientHello::ours()))
            .await
            .unwrap();
        wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        after(&mut send).await;
        peer.closed_with().await
    }

    #[tokio::test]
    async fn control_stream_violations_after_hello() {
        let violation = Some(Code::ProtocolViolation);
        let second = async |send: &mut quinn::SendStream| {
            send.write_all(&hello_frame(&ClientHello::ours()))
                .await
                .unwrap();
        };
        assert_eq!(after_hello(second).await, violation);
        let finish = async |send: &mut quinn::SendStream| send.finish().unwrap();
        assert_eq!(after_hello(finish).await, violation);
        let reset = async |send: &mut quinn::SendStream| {
            send.reset(quinn::VarInt::from_u32(0)).unwrap();
        };
        assert_eq!(after_hello(reset).await, violation);
    }

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
