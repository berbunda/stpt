//! Client role: every subcommand except `server`.

use std::io::{self, IsTerminal, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

use tokio::time::timeout;

use crate::auth::{self, UserKey};
use crate::cli::{ClientCommand, Common, Remote, TrustAction};
use crate::config::{self, ClientConfig};
use crate::destination::Address;
use crate::error::Error;
use crate::hello::{AUTH_PUBLICKEY_ED25519, ClientHello, ServerHello};
use crate::identity::Fingerprint;
use crate::logging::{self, Role};
use crate::quic;
use crate::tls::{Expected, ServerKeyCheck, Verdict};
use crate::trust::{self, TrustStore};
use crate::wire::{self, DEFAULT_MESSAGE_LIMIT, Failure, StreamError};

/// SERVER_HELLO received after CLIENT_HELLO was sent (§13.3).
pub const SERVER_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// AUTH_RESULT received after AUTH_REQUEST was sent (§13.3).
pub const AUTH_RESULT_TIMEOUT: Duration = Duration::from_secs(10);

/// File name of the user key in the Client configuration directory.
pub const USER_KEY_FILE: &str = "id_ed25519";

pub fn run(command: ClientCommand, common: &Common) -> Result<ExitCode, Error> {
    let (_config, path) =
        config::load::<ClientConfig>(common.config.as_deref(), config::client_path())?;
    logging::init(
        Role::Client,
        logging::level(Role::Client, common.verbose, common.quiet, None),
    );
    config::log_source(path.as_deref());

    let (name, remote) = match command {
        ClientCommand::Trust { action } => return trust_command(action),
        ClientCommand::Connect { remote, .. } => ("connect", remote),
        ClientCommand::Exec { remote, .. } => ("exec", remote),
        ClientCommand::Sessions { remote } => ("sessions", remote),
        ClientCommand::Detach { remote, .. } => ("detach", remote),
        ClientCommand::Terminate { remote, .. } => ("terminate", remote),
    };
    let mut store = trust_store()?;
    let key_path = match &remote.identity {
        Some(path) => path.clone(),
        None => config::client_dir()
            .ok_or(Error::NoTrustStore)?
            .join(USER_KEY_FILE),
    };
    let key = load_user_key(&key_path)?;
    let runtime = quic::runtime()?;
    let _guard = runtime.enter();
    let addr = resolve(&remote.destination.address)?;
    let mut connection = runtime.block_on(connect(&remote, addr, &mut store, ask_user))?;
    let hello = runtime.block_on(connection.hello(SERVER_HELLO_TIMEOUT))?;
    tracing::info!(
        version = format_args!("{:#x}", hello.version),
        "Connection established"
    );
    let account = &remote.destination.account;
    let accepted = runtime.block_on(connection.authenticate(account, &key, AUTH_RESULT_TIMEOUT))?;
    runtime.block_on(connection.close());
    if !accepted {
        return Err(Error::AuthRejected {
            account: account.clone(),
            fingerprint: key.public_key().fingerprint(),
            key_line: key.public_key().to_base64(),
        });
    }
    tracing::info!(%account, key = %key.public_key().fingerprint(), "Connection authenticated");
    // Sessions and terminals come with Tiers RC and RD.
    Err(Error::NotImplemented(name))
}

fn load_user_key(path: &Path) -> Result<UserKey, Error> {
    UserKey::load(path).map_err(|e| match e {
        crate::identity::KeyFileError::Io { source, .. }
            if source.kind() == io::ErrorKind::NotFound =>
        {
            Error::NoUserKey(path.to_owned())
        }
        other => Error::UserKey(other),
    })
}

fn trust_store() -> Result<TrustStore, Error> {
    let dir = config::client_dir().ok_or(Error::NoTrustStore)?;
    Ok(TrustStore::load(dir.join(trust::FILE_NAME))?)
}

fn trust_command(action: TrustAction) -> Result<ExitCode, Error> {
    let mut store = trust_store()?;
    match action {
        TrustAction::List => {
            for (address, key) in store.entries() {
                println!("{address} {}", key.fingerprint());
            }
        }
        TrustAction::Remove { address } => {
            if !store.remove(&address)? {
                return Err(Error::NoTrustEntry(address));
            }
            tracing::info!(path = %store.path().display(), %address, "entry removed");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// First address of the host; addresses of a DNS name are tried in later versions.
fn resolve(address: &Address) -> Result<SocketAddr, Error> {
    (address.host.as_str(), address.port)
        .to_socket_addrs()
        .and_then(|mut addrs| {
            addrs
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))
        })
        .map_err(|source| Error::Resolve {
            address: address.clone(),
            source,
        })
}

/// Connection with a trusted Server key.
pub struct Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    /// Control stream once opened; kept until the Connection is closed, as dropping
    /// it would end the stream, which the Server treats as an error (§8.1).
    control: Option<(quinn::SendStream, quinn::RecvStream)>,
    /// Message size limit of the Server, from SERVER_HELLO.
    peer_limit: u64,
}

impl Connection {
    /// Closes the Connection regularly and waits until the peer is told.
    async fn close(self) {
        self.connection.close(quic::NO_ERROR, b"");
        self.endpoint.wait_idle().await;
    }

    /// HELLO exchange (§10): CLIENT_HELLO on the new control stream, SERVER_HELLO
    /// within `deadline`, checked against the offer. A violation by the Server
    /// closes the Connection with its code; the reason is reported locally only.
    async fn hello(&mut self, deadline: Duration) -> Result<ServerHello, Error> {
        match self.exchange_hello(deadline).await {
            Ok(hello) => Ok(hello),
            Err(error) => Err(self.failed(error).await),
        }
    }

    /// User authentication (§12) with `key` for `account`: AUTH_REQUEST bound to this
    /// Connection, AUTH_RESULT within `deadline`. `Ok(false)`: the key was not accepted.
    async fn authenticate(
        &mut self,
        account: &str,
        key: &UserKey,
        deadline: Duration,
    ) -> Result<bool, Error> {
        match self.exchange_auth(account, key, deadline).await {
            Ok(accepted) => Ok(accepted),
            Err(error) => Err(self.failed(error).await),
        }
    }

    /// Error of a failed step on the control stream. A violation by the Server or an
    /// expired deadline closes the Connection with its code; the reason is reported
    /// locally only.
    async fn failed(&self, error: StreamError) -> Error {
        let failure = match error {
            StreamError::Lost(reason) => return quic::Error::Connection(reason).into(),
            StreamError::Failure(failure) => failure,
            StreamError::Reset(code) => {
                Failure::violation(format!("the Server reset the control stream ({code})"))
            }
        };
        self.connection.close(failure.code.varint(), b"");
        self.endpoint.wait_idle().await;
        Error::Protocol(failure)
    }

    async fn exchange_hello(&mut self, deadline: Duration) -> Result<ServerHello, StreamError> {
        let (send, recv) = self
            .control
            .insert(self.connection.open_bi().await.map_err(StreamError::Lost)?);
        let offer = ClientHello::ours();
        wire::write_message(send, &offer.to_message(), DEFAULT_MESSAGE_LIMIT).await?;
        let message = reply(recv, deadline, "SERVER_HELLO").await?;
        let hello = ServerHello::from_message(&message)?;
        hello.check(&offer)?;
        if !hello.auth_methods.contains(&AUTH_PUBLICKEY_ED25519) {
            return Err(Failure::violation("the Server does not offer publickey-ed25519").into());
        }
        self.peer_limit = hello.limits.max_message;
        Ok(hello)
    }

    async fn exchange_auth(
        &mut self,
        account: &str,
        key: &UserKey,
        deadline: Duration,
    ) -> Result<bool, StreamError> {
        let exporter = auth::exporter(&self.connection)?;
        let (send, recv) = self
            .control
            .as_mut()
            .expect("HELLO opened the control stream");
        let request = key.request(&exporter, account);
        wire::write_message(send, &request.to_message(), self.peer_limit).await?;
        let message = reply(recv, deadline, "AUTH_RESULT").await?;
        Ok(auth::result_from_message(&message)?)
    }
}

/// The next message from the Server within `deadline`; `what` names the expected one.
async fn reply(
    recv: &mut quinn::RecvStream,
    deadline: Duration,
    what: &str,
) -> Result<wire::Message, StreamError> {
    Ok(
        timeout(deadline, wire::read_message(recv, DEFAULT_MESSAGE_LIMIT))
            .await
            .map_err(|_| {
                Failure::new(
                    wire::Code::Timeout,
                    format!("no {what} within {} s", deadline.as_secs_f32()),
                )
            })??
            .ok_or_else(|| Failure::violation("the Server ended the control stream"))?,
    )
}

/// Connects to the Server at `addr` and verifies its key against the trust store
/// and `--fingerprint` (§9.3). At first contact without a fingerprint the handshake
/// is aborted, `confirm` asks the user, and after a confirmation the Client connects
/// again expecting the confirmed key; so no deadline of the Server runs while the
/// user decides. A key confirmed or verified by fingerprint is added to the store.
async fn connect(
    remote: &Remote,
    addr: SocketAddr,
    store: &mut TrustStore,
    confirm: impl Fn(&Address, &Fingerprint) -> Result<bool, Error>,
) -> Result<Connection, Error> {
    let address = &remote.destination.address;
    let endpoint = quic::client(addr)?;
    loop {
        let check = ServerKeyCheck::new(Expected {
            stored: store.get(address).cloned(),
            fingerprint: remote.fingerprint,
        });
        let result = quic::connect(&endpoint, addr, &address.host, check.clone()).await;
        let outcome = check.outcome();
        let error = match result {
            Ok(connection) => {
                let (key, _) = outcome.expect("a Connection is established with a trusted key");
                if store.get(address).is_none() {
                    store.add(address.clone(), key)?;
                    tracing::info!(%address, "Server key verified by fingerprint and stored");
                }
                tracing::debug!(%address, "TLS handshake completed, Server key trusted");
                return Ok(Connection {
                    endpoint,
                    connection,
                    control: None,
                    peer_limit: DEFAULT_MESSAGE_LIMIT,
                });
            }
            Err(error) => error,
        };
        let address = address.clone();
        match outcome {
            Some((key, Verdict::Unknown)) => {
                if !confirm(&address, &key.fingerprint())? {
                    return Err(Error::KeyNotTrusted(address));
                }
                store.add(address, key)?;
            }
            Some((key, Verdict::Changed { stored })) => {
                return Err(Error::KeyChanged {
                    address,
                    stored: stored.fingerprint(),
                    presented: key.fingerprint(),
                });
            }
            Some((key, Verdict::Mismatch { expected })) => {
                return Err(Error::FingerprintMismatch {
                    address,
                    expected,
                    presented: key.fingerprint(),
                });
            }
            Some((_, Verdict::Trusted)) | None => return Err(error.into()),
        }
    }
}

/// Shows the fingerprint of an unknown Server key and asks the user to trust it;
/// only `yes` confirms. Without a terminal there is nobody to ask (§9.3).
fn ask_user(address: &Address, fingerprint: &Fingerprint) -> Result<bool, Error> {
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        return Err(Error::KeyNotKnown {
            address: address.clone(),
            presented: *fingerprint,
        });
    }
    let mut stderr = io::stderr().lock();
    write!(
        stderr,
        "The key of the Server {address} is not known.\n  \
         fingerprint: {fingerprint}\n\
         Compare it in full with the output of `stpt server --fingerprint` on the Server.\n\
         Trust this key? Type yes to confirm: "
    )
    .and_then(|()| stderr.flush())
    .map_err(Error::Terminal)?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(Error::Terminal)?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::Destination;
    use crate::identity::{PublicKey, ServerKey};
    use std::cell::Cell;
    use std::path::{Path, PathBuf};

    struct Server {
        endpoint: quinn::Endpoint,
        key: PublicKey,
    }

    impl Server {
        fn start(key: &ServerKey) -> Self {
            let endpoint = quic::listen("127.0.0.1:0".parse().unwrap(), key).unwrap();
            let accepting = endpoint.clone();
            tokio::spawn(async move {
                while let Some(incoming) = accepting.accept().await {
                    tokio::spawn(async move {
                        if let Ok(c) = quic::accept(incoming).await {
                            c.closed().await;
                        }
                    });
                }
            });
            Self {
                endpoint,
                key: key.public_key(),
            }
        }

        fn addr(&self) -> SocketAddr {
            self.endpoint.local_addr().unwrap()
        }

        fn remote(&self, fingerprint: Option<Fingerprint>) -> Remote {
            Remote {
                destination: format!("alice@127.0.0.1:{}", self.addr().port())
                    .parse::<Destination>()
                    .unwrap(),
                fingerprint,
                identity: None,
            }
        }
    }

    fn store_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stpt-client-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(trust::FILE_NAME)
    }

    fn answer(yes: bool) -> impl Fn(&Address, &Fingerprint) -> Result<bool, Error> {
        move |_, _| Ok(yes)
    }

    fn never_asked(_: &Address, _: &Fingerprint) -> Result<bool, Error> {
        panic!("the user must not be asked")
    }

    async fn run(
        server: &Server,
        fingerprint: Option<Fingerprint>,
        path: &Path,
        confirm: impl Fn(&Address, &Fingerprint) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let mut store = TrustStore::load(path.to_owned()).unwrap();
        let remote = server.remote(fingerprint);
        let connection = connect(&remote, server.addr(), &mut store, confirm).await?;
        connection.close().await;
        Ok(())
    }

    fn stored(path: &Path, server: &Server) -> Option<PublicKey> {
        let store = TrustStore::load(path.to_owned()).unwrap();
        let address = server.remote(None).destination.address;
        store.get(&address).cloned()
    }

    #[tokio::test]
    async fn first_contact_confirmed_then_known() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("confirmed");
        let asked = Cell::new(0);
        let confirm = |_: &Address, fp: &Fingerprint| {
            assert_eq!(*fp, server.key.fingerprint());
            asked.set(asked.get() + 1);
            Ok(true)
        };
        run(&server, None, &path, confirm).await.unwrap();
        assert_eq!(asked.get(), 1);
        assert_eq!(stored(&path, &server), Some(server.key.clone()));
        run(&server, None, &path, never_asked).await.unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn first_contact_declined() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("declined");
        let err = run(&server, None, &path, answer(false)).await.unwrap_err();
        assert!(matches!(err, Error::KeyNotTrusted(_)), "{err}");
        assert_eq!(stored(&path, &server), None);
    }

    #[tokio::test]
    async fn fingerprint_verifies_and_stores() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("fingerprint");
        let fp = Some(server.key.fingerprint());
        run(&server, fp, &path, never_asked).await.unwrap();
        assert_eq!(stored(&path, &server), Some(server.key.clone()));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn wrong_fingerprint_is_refused() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("mismatch");
        let other = ServerKey::generate().public_key().fingerprint();
        let err = run(&server, Some(other), &path, never_asked)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::FingerprintMismatch { expected, .. } if expected == other),
            "{err}"
        );
        assert_eq!(stored(&path, &server), None);
    }

    #[tokio::test]
    async fn changed_key_is_refused_and_kept() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("changed");
        let old = ServerKey::generate().public_key();
        let mut store = TrustStore::load(path.to_owned()).unwrap();
        store
            .add(server.remote(None).destination.address, old.clone())
            .unwrap();
        let err = run(&server, None, &path, never_asked).await.unwrap_err();
        let Error::KeyChanged {
            stored: s,
            presented,
            ..
        } = err
        else {
            panic!("{err}")
        };
        assert_eq!(s, old.fingerprint());
        assert_eq!(presented, server.key.fingerprint());
        assert_eq!(stored(&path, &server), Some(old));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    /// What a fake Server does after it received CLIENT_HELLO.
    enum Reply {
        Bytes(Vec<u8>),
        Nothing,
        Close(wire::Code),
    }

    /// Runs a fake Server for one Connection and the Client HELLO against it.
    /// Returns the result of the Client and the code the Client closed with.
    async fn hello_against(
        reply: impl FnOnce(&ClientHello) -> Reply + Send + 'static,
    ) -> (Result<ServerHello, Error>, Option<wire::Code>) {
        let key = ServerKey::generate();
        let endpoint = quic::listen("127.0.0.1:0".parse().unwrap(), &key).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let connection = quic::accept(endpoint.accept().await.unwrap())
                .await
                .unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let message = wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            match reply(&ClientHello::from_message(&message).unwrap()) {
                Reply::Bytes(bytes) => send.write_all(&bytes).await.unwrap(),
                Reply::Nothing => {}
                Reply::Close(code) => connection.close(code.varint(), b""),
            }
            match connection.closed().await {
                quinn::ConnectionError::ApplicationClosed(close) => {
                    wire::Code::from_value(close.error_code.into_inner())
                }
                _ => None,
            }
        });
        let path = store_path(&format!("hello-{}", addr.port()));
        let mut store = TrustStore::load(path.clone()).unwrap();
        let remote = Remote {
            destination: format!("alice@{addr}").parse().unwrap(),
            fingerprint: Some(key.public_key().fingerprint()),
            identity: None,
        };
        let mut connection = connect(&remote, addr, &mut store, never_asked)
            .await
            .unwrap();
        let result = connection.hello(Duration::from_millis(300)).await;
        if result.is_ok() {
            connection.close().await;
        }
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        (result, server.await.unwrap())
    }

    fn answer_frame(answer: &ServerHello) -> Reply {
        Reply::Bytes(wire::frame(&answer.to_message().encode()))
    }

    #[tokio::test]
    async fn hello_succeeds() {
        let (result, closed) =
            hello_against(|offer| answer_frame(&ServerHello::answer(offer).unwrap())).await;
        assert_eq!(result.unwrap().version, crate::hello::WIRE_VERSION);
        assert_eq!(closed, Some(wire::Code::NoError));
    }

    fn protocol_code(result: Result<ServerHello, Error>) -> wire::Code {
        match result {
            Err(Error::Protocol(failure)) => failure.code,
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn invalid_answers_close_with_violation() {
        let violation = Some(wire::Code::ProtocolViolation);
        let not_offered = |offer: &ClientHello| {
            let mut answer = ServerHello::answer(offer).unwrap();
            answer.version = 0xFF00_0002;
            answer_frame(&answer)
        };
        let grease = |offer: &ClientHello| {
            let mut answer = ServerHello::answer(offer).unwrap();
            answer.version = offer.versions[1];
            answer_frame(&answer)
        };
        let garbage = |_: &ClientHello| Reply::Bytes(wire::frame(&[0xf9, 0x3c, 0x00]));
        let client_hello =
            |offer: &ClientHello| Reply::Bytes(wire::frame(&offer.to_message().encode()));
        for (result, closed) in [
            hello_against(not_offered).await,
            hello_against(grease).await,
            hello_against(garbage).await,
            hello_against(client_hello).await,
        ] {
            assert_eq!(protocol_code(result), wire::Code::ProtocolViolation);
            assert_eq!(closed, violation);
        }
    }

    #[tokio::test]
    async fn missing_answer_times_out() {
        let (result, closed) = hello_against(|_| Reply::Nothing).await;
        assert_eq!(protocol_code(result), wire::Code::Timeout);
        assert_eq!(closed, Some(wire::Code::Timeout));
    }

    #[tokio::test]
    async fn server_close_is_reported_by_name() {
        let (result, _) =
            hello_against(|_| Reply::Close(wire::Code::VersionNegotiationFailed)).await;
        assert_eq!(
            result.unwrap_err().to_string(),
            "transport: closed by the peer: VERSION_NEGOTIATION_FAILED"
        );
    }

    /// Runs a fake Server that exchanges HELLO, checks the channel binding of the
    /// AUTH_REQUEST with its own exporter value, then replies with `reply`.
    /// Returns the result of the Client's authentication.
    async fn authenticate_against(
        reply: impl FnOnce() -> Reply + Send + 'static,
    ) -> Result<bool, Error> {
        let key = ServerKey::generate();
        let endpoint = quic::listen("127.0.0.1:0".parse().unwrap(), &key).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let user = UserKey::generate();
        let user_public = user.raw_public();
        let server = tokio::spawn(async move {
            let connection = quic::accept(endpoint.accept().await.unwrap())
                .await
                .unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let read = async |recv: &mut quinn::RecvStream| {
                wire::read_message(recv, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap()
                    .unwrap()
            };
            let hello = ClientHello::from_message(&read(&mut recv).await).unwrap();
            let answer = ServerHello::answer(&hello).unwrap().to_message();
            send.write_all(&wire::frame(&answer.encode()))
                .await
                .unwrap();
            let request = auth::AuthRequest::from_message(&read(&mut recv).await).unwrap();
            assert_eq!(request.account, "alice");
            assert_eq!(request.key, user_public);
            let exporter = auth::exporter(&connection).unwrap();
            assert!(request.signature_valid(&exporter), "channel binding");
            match reply() {
                Reply::Bytes(bytes) => send.write_all(&bytes).await.unwrap(),
                Reply::Nothing => {}
                Reply::Close(code) => connection.close(code.varint(), b""),
            }
            connection.closed().await;
        });
        let path = store_path(&format!("auth-{}", addr.port()));
        let mut store = TrustStore::load(path.clone()).unwrap();
        let remote = Remote {
            destination: format!("alice@{addr}").parse().unwrap(),
            fingerprint: Some(key.public_key().fingerprint()),
            identity: None,
        };
        let mut connection = connect(&remote, addr, &mut store, never_asked)
            .await
            .unwrap();
        connection.hello(Duration::from_secs(5)).await.unwrap();
        let result = connection
            .authenticate("alice", &user, Duration::from_millis(300))
            .await;
        if result.is_ok() {
            connection.close().await;
        }
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
        result
    }

    fn result_frame(success: bool) -> Reply {
        Reply::Bytes(wire::frame(&auth::result_message(success).encode()))
    }

    #[tokio::test]
    async fn authentication_results() {
        assert!(authenticate_against(|| result_frame(true)).await.unwrap());
        assert!(!authenticate_against(|| result_frame(false)).await.unwrap());
        let garbage = || Reply::Bytes(wire::frame(&wire::Message::new(2, vec![]).encode()));
        assert_eq!(
            protocol_code(authenticate_against(garbage).await.map(|_| unreachable!())),
            wire::Code::ProtocolViolation
        );
        assert_eq!(
            protocol_code(
                authenticate_against(|| Reply::Nothing)
                    .await
                    .map(|_| unreachable!())
            ),
            wire::Code::Timeout
        );
    }

    #[test]
    fn missing_user_key_tells_how_to_create_one() {
        let path = store_path("no-key").with_file_name("id_ed25519");
        let err = load_user_key(&path).err().unwrap();
        assert!(matches!(err, Error::NoUserKey(_)));
        let text = err.to_string();
        assert!(
            text.contains(&format!(
                "openssl genpkey -algorithm ed25519 -out {}",
                path.display()
            )),
            "{text}"
        );
    }
}
