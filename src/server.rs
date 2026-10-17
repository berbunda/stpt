//! Server role: `stpt server`.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint, Incoming, VarInt};
use tokio::time::{Instant, sleep_until, timeout, timeout_at};

use crate::auth::{self, AUTH_REQUEST, AuthRequest};
use crate::authorized::{self, Accepted, Authorizer, SystemAccounts};
use crate::cli::Common;
use crate::config::{self, ServerConfig};
use crate::destination::DEFAULT_PORT;
use crate::error::Error;
use crate::hello::{AUTH_PUBLICKEY_ED25519, ClientHello, ServerHello};
use crate::identity::{self, ServerKey};
use crate::logging::{self, Role};
use crate::quic;
use crate::wire::{self, CLIENT_HELLO, Code, DEFAULT_MESSAGE_LIMIT, Failure, StreamError};

/// Server mode needs a Unix PTY; Windows Server mode (ConPTY) comes with RC008 (gate G2).
pub const AVAILABLE: bool = cfg!(unix);

/// Listen address without `--listen` and configuration: all addresses, port 843.
pub const DEFAULT_LISTEN: SocketAddr =
    SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), DEFAULT_PORT);

/// Failed authentication attempts per Connection (§13.4).
const MAX_FAILED_ATTEMPTS: u32 = 6;

/// Concurrent Channels per Connection besides the control Channel (§14.5).
const MAX_CHANNELS: u32 = 10;

/// Deadlines of a Connection (§13.3).
#[derive(Debug, Clone, Copy)]
pub struct Deadlines {
    /// CLIENT_HELLO received after the TLS handshake.
    pub hello: Duration,
    /// Connection Authenticated after it became Established.
    pub auth: Duration,
    /// A failed attempt is answered no earlier than this after its AUTH_REQUEST, so
    /// the response time does not depend on the reason of the failure (§12.4).
    pub failure_delay: Duration,
}

impl Deadlines {
    pub const DEFAULT: Self = Self {
        hello: Duration::from_secs(10),
        auth: Duration::from_secs(60),
        failure_delay: Duration::from_millis(300),
    };
}

impl Default for Deadlines {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What the Connections of a Server share.
pub struct Shared {
    pub deadlines: Deadlines,
    pub authorizer: Authorizer,
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

    let keys_dir = config
        .authorized_keys
        .clone()
        .unwrap_or_else(|| PathBuf::from(authorized::AUTHORIZED_KEYS_DIR));
    tracing::info!(path = %keys_dir.display(), "authorized keys directory");
    let shared = Arc::new(Shared {
        deadlines: Deadlines::default(),
        authorizer: Authorizer::new(keys_dir, Box::new(SystemAccounts)),
    });

    let listen = listen_address(listen, &config);
    quic::runtime()?.block_on(async {
        let endpoint = quic::listen(listen, &key)?;
        let local = endpoint.local_addr().map_err(|source| quic::Error::Bind {
            addr: listen,
            source,
        })?;
        tracing::info!(listen = %local, "listening");
        serve(endpoint, shared).await;
        Ok(ExitCode::SUCCESS)
    })
}

async fn serve(endpoint: Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(connection(incoming, shared.clone()));
    }
}

/// One Connection: TLS handshake, HELLO, user authentication, then the
/// Authenticated Connection. Every rejection is logged with its exact reason; the
/// Client gets the code only.
async fn connection(incoming: Incoming, shared: Arc<Shared>) {
    let remote = incoming.remote_address();
    let connection = match quic::accept(incoming).await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::info!(%remote, ?error, "handshake failed");
            return;
        }
    };
    tracing::debug!(%remote, "TLS handshake completed");
    let Err(end) = serve_connection(&connection, &shared).await;
    match end {
        End::Lost(reason) => tracing::info!(%remote, ?reason, "Connection closed"),
        End::Close(failure) => {
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

/// How a Connection ends on the Server.
enum End {
    /// Closed by the Client or lost.
    Lost(quinn::ConnectionError),
    /// The Server closes it.
    Close(Failure),
}

impl From<Failure> for End {
    fn from(failure: Failure) -> Self {
        Self::Close(failure)
    }
}

impl From<StreamError> for End {
    fn from(error: StreamError) -> Self {
        match error {
            StreamError::Lost(reason) => Self::Lost(reason),
            other => Self::Close(control_failure(other)),
        }
    }
}

/// Runs a Connection until it ends.
async fn serve_connection(
    connection: &Connection,
    shared: &Arc<Shared>,
) -> Result<Infallible, End> {
    let deadlines = shared.deadlines;
    let (mut send, mut recv, message) = timeout(deadlines.hello, async {
        let (send, mut recv) = connection.accept_bi().await.map_err(StreamError::Lost)?;
        let message = control_message(&mut recv).await?;
        Ok::<_, End>((send, recv, message))
    })
    .await
    .map_err(|_| {
        Failure::new(
            Code::Timeout,
            format!("no CLIENT_HELLO within {} s", deadlines.hello.as_secs_f32()),
        )
    })??;
    // §10.1: nothing but CLIENT_HELLO may come first.
    let hello = ClientHello::from_message(&message)?;
    let answer = ServerHello::answer(&hello)?;
    let peer_limit = hello.limits.max_message;
    wire::write_message(&mut send, &answer.to_message(), peer_limit).await?;
    let established = Instant::now();
    tracing::info!(
        remote = %connection.remote_address(),
        version = format_args!("{:#x}", answer.version),
        "Connection established"
    );

    let control = Control {
        connection,
        send: &mut send,
        recv: &mut recv,
        peer_limit,
    };
    let accepted = authenticate(control, shared, established + deadlines.auth).await?;
    tracing::info!(
        remote = %connection.remote_address(),
        account = ?accepted.account,
        key = %accepted.fingerprint,
        label = ?accepted.label,
        "Connection authenticated"
    );
    // §8.2, §14.5: Channels become available.
    connection.set_max_concurrent_bi_streams(VarInt::from_u32(1 + MAX_CHANNELS));
    tokio::spawn(reject_channels(connection.clone()));

    // Session requests come with RB007 and Tier RD.
    let message = control_message(&mut recv).await?;
    Err(match message.kind {
        AUTH_REQUEST => Failure::violation("AUTH_REQUEST on an Authenticated Connection"),
        CLIENT_HELLO => Failure::violation("second CLIENT_HELLO"),
        kind => Failure::new(
            Code::InternalError,
            format!("message type {kind}: not implemented yet"),
        ),
    }
    .into())
}

/// The control stream of an Established Connection.
struct Control<'a> {
    connection: &'a Connection,
    send: &'a mut quinn::SendStream,
    recv: &'a mut quinn::RecvStream,
    peer_limit: u64,
}

/// User authentication (§12) until `deadline`: AUTH_REQUEST after AUTH_REQUEST, each
/// decided by the Authorizer; failures are answered after the failure delay, and the
/// last allowed failure closes the Connection with AUTH_FAILED.
async fn authenticate(
    control: Control<'_>,
    shared: &Arc<Shared>,
    deadline: Instant,
) -> Result<Accepted, End> {
    let deadlines = shared.deadlines;
    let remote = control.connection.remote_address();
    let exporter = auth::exporter(control.connection)?;
    let mut failures = 0;
    loop {
        let message = timeout_at(deadline, control_message(control.recv))
            .await
            .map_err(|_| {
                Failure::new(
                    Code::Timeout,
                    format!(
                        "not authenticated within {} s",
                        deadlines.auth.as_secs_f32()
                    ),
                )
            })??;
        match message.kind {
            AUTH_REQUEST => {}
            CLIENT_HELLO => return Err(Failure::violation("second CLIENT_HELLO").into()),
            kind => {
                return Err(Failure::violation(format!(
                    "message type {kind} before authentication"
                ))
                .into());
            }
        }
        let received = Instant::now();
        let request = AuthRequest::from_message(&message)?;
        if request.method != AUTH_PUBLICKEY_ED25519 {
            return Err(Failure::violation(format!(
                "authentication method {} was not offered",
                request.method
            ))
            .into());
        }
        let (worker, deciding) = (shared.clone(), request.clone());
        let decision =
            tokio::task::spawn_blocking(move || worker.authorizer.decide(&deciding, &exporter))
                .await
                .map_err(|e| Failure::new(Code::InternalError, format!("authorization: {e}")))?;
        let success = match decision {
            Ok(accepted) => Some(accepted),
            Err(reason) => {
                failures += 1;
                tracing::info!(
                    %remote,
                    account = ?request.account,
                    key = %auth::ed25519_spki(&request.key).fingerprint(),
                    %reason,
                    attempt = failures,
                    "authentication failed"
                );
                sleep_until(received + deadlines.failure_delay).await;
                if failures >= MAX_FAILED_ATTEMPTS {
                    return Err(Failure::new(Code::AuthFailed, "too many failed attempts").into());
                }
                None
            }
        };
        let result = auth::result_message(success.is_some());
        wire::write_message(control.send, &result, control.peer_limit).await?;
        if let Some(accepted) = success {
            return Ok(accepted);
        }
    }
}

/// Channels come with Tier RC: every stream the Client opens is rejected with
/// CHANNEL_REJECTED (§8.3).
async fn reject_channels(connection: Connection) {
    let code = Code::ChannelRejected.varint();
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let _ = send.reset(code);
        let _ = recv.stop(code);
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
        StreamError::Lost(reason) => {
            Failure::new(Code::InternalError, format!("Connection lost: {reason}"))
        }
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
    use crate::auth::UserKey;
    use crate::authorized::Accounts;
    use crate::hello::WIRE_VERSION;
    use crate::tls::{Expected, ServerKeyCheck};
    use crate::wire::{Message, SERVER_HELLO, frame};

    const SHORT: Deadlines = Deadlines {
        hello: Duration::from_millis(300),
        auth: Duration::from_millis(300),
        failure_delay: Duration::from_millis(50),
    };

    const FAST_FAILURES: Deadlines = Deadlines {
        failure_delay: Duration::from_millis(50),
        ..Deadlines::DEFAULT
    };

    struct Alice;

    impl Accounts for Alice {
        fn exists(&self, name: &str) -> bool {
            name == "alice"
        }
    }

    /// A Client Connection to a Server that serves exactly this Connection; the
    /// Server authorizes `user` for the Account `alice`.
    struct Peer {
        _endpoint: Endpoint,
        connection: Connection,
        user: UserKey,
    }

    impl Peer {
        async fn start(deadlines: Deadlines) -> Self {
            let key = ServerKey::generate();
            let server = quic::listen("127.0.0.1:0".parse().unwrap(), &key).unwrap();
            let addr = server.local_addr().unwrap();
            let user = UserKey::generate();
            let dir = std::env::temp_dir().join(format!(
                "stpt-server-keys-{}-{}",
                std::process::id(),
                addr.port()
            ));
            crate::authorized::test_support::keys_file(
                &dir,
                "alice",
                &format!("{} test\n", user.public_key().to_base64()),
            );
            let shared = Arc::new(Shared {
                deadlines,
                authorizer: Authorizer::new(dir, Box::new(Alice)),
            });
            tokio::spawn(async move {
                let incoming = server.accept().await.unwrap();
                connection(incoming, shared).await;
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
                user,
            }
        }

        /// Opens the control stream and exchanges HELLO.
        async fn hello(&self) -> (quinn::SendStream, quinn::RecvStream) {
            let (mut send, mut recv) = self.connection.open_bi().await.unwrap();
            send.write_all(&hello_frame(&ClientHello::ours()))
                .await
                .unwrap();
            wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            (send, recv)
        }

        /// AUTH_REQUEST of `key` for `account`, signed for this Connection.
        fn request(&self, key: &UserKey, account: &str) -> Vec<u8> {
            let exporter = auth::exporter(&self.connection).unwrap();
            frame(&key.request(&exporter, account).to_message().encode())
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

    async fn auth_result(recv: &mut quinn::RecvStream) -> bool {
        let message = wire::read_message(recv, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        auth::result_from_message(&message).unwrap()
    }

    #[tokio::test]
    async fn authentication_then_channels_rejected() {
        let peer = Peer::start(Deadlines::default()).await;
        let (mut send, mut recv) = peer.hello().await;
        send.write_all(&peer.request(&peer.user, "alice"))
            .await
            .unwrap();
        assert!(auth_result(&mut recv).await);

        // §8.2: the Client may open Channels now; there are none yet, so each is
        // rejected with CHANNEL_REJECTED (§8.3).
        let (mut channel, mut channel_recv) = peer.connection.open_bi().await.unwrap();
        channel.write_all(b"\x01").await.unwrap();
        let mut buf = [0u8; 1];
        match channel_recv.read(&mut buf).await {
            Err(quinn::ReadError::Reset(code)) => {
                assert_eq!(code, Code::ChannelRejected.varint());
            }
            other => panic!("{other:?}"),
        }

        // The Account of a Connection never changes (§12.4).
        send.write_all(&peer.request(&peer.user, "alice"))
            .await
            .unwrap();
        assert_eq!(peer.closed_with().await, Some(Code::ProtocolViolation));
    }

    #[tokio::test]
    async fn failed_attempts_are_uniform_and_limited() {
        let peer = Peer::start(FAST_FAILURES).await;
        let (mut send, mut recv) = peer.hello().await;
        let stranger = UserKey::generate();
        let exporter = auth::exporter(&peer.connection).unwrap();
        let mut relayed = peer.user.request(&[0u8; 32], "alice");
        relayed.signature = peer.user.request(&[1u8; 32], "alice").signature;
        let attempts = [
            peer.request(&stranger, "alice"),
            peer.request(&peer.user, "bob"),
            peer.request(&peer.user, "../alice"),
            frame(&relayed.to_message().encode()),
            frame(
                &stranger
                    .request(&exporter, &"x".repeat(256))
                    .to_message()
                    .encode(),
            ),
        ];
        for attempt in attempts {
            let start = Instant::now();
            send.write_all(&attempt).await.unwrap();
            assert!(!auth_result(&mut recv).await);
            assert!(start.elapsed() >= FAST_FAILURES.failure_delay);
        }
        send.write_all(&peer.request(&stranger, "alice"))
            .await
            .unwrap();
        assert_eq!(peer.closed_with().await, Some(Code::AuthFailed));
    }

    #[tokio::test]
    async fn invalid_authentication_requests() {
        let violation = Some(Code::ProtocolViolation);
        let after = async |bytes: Vec<u8>| {
            let peer = Peer::start(Deadlines::default()).await;
            let (mut send, _recv) = peer.hello().await;
            send.write_all(&bytes).await.unwrap();
            peer.closed_with().await
        };
        let user = UserKey::generate();
        let mut other_method = user.request(&[0u8; 32], "alice");
        other_method.method = 2;
        assert_eq!(
            after(frame(&other_method.to_message().encode())).await,
            violation
        );
        let session_list = Message::new(31, vec![]);
        assert_eq!(after(frame(&session_list.encode())).await, violation);
        let long = user.request(&[0u8; 32], &"x".repeat(257));
        assert_eq!(
            after(frame(&long.to_message().encode())).await,
            Some(Code::LimitExceeded)
        );
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
