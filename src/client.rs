//! Client role: every subcommand except `server`.

use std::io::{self, IsTerminal, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::auth::{self, UserKey};
use crate::cbor::Value;
use crate::cli::{ClientCommand, Common, Remote, TrustAction};
use crate::commands;
use crate::config::{self, ClientConfig};
use crate::console::{self, Console};
use crate::control::{self, Sender, State};
use crate::destination::Address;
use crate::error::Error;
use crate::hello::{AUTH_PUBLICKEY_ED25519, ClientHello, ServerHello};
use crate::identity::Fingerprint;
use crate::listing;
use crate::logging::{self, Role};
use crate::modes::Modes;
use crate::quic;
use crate::terminal::{self, Attached, Command, Exit, Open, SessionId, Size};
use crate::tls::{Expected, ServerKeyCheck, Verdict};
use crate::trust::{self, TrustStore};
use crate::wire::{
    self, Code, DEFAULT_MESSAGE_LIMIT, Failure, Message, StreamError, TERMINAL_DATA, TERMINAL_EXIT,
    TERMINAL_STDERR,
};

/// SERVER_HELLO received after CLIENT_HELLO was sent (§13.3).
pub const SERVER_HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// AUTH_RESULT received after AUTH_REQUEST was sent (§13.3).
pub const AUTH_RESULT_TIMEOUT: Duration = Duration::from_secs(10);

/// File name of the user key in the Client configuration directory.
pub const USER_KEY_FILE: &str = "id_ed25519";

pub fn run(command: ClientCommand, common: &Common) -> Result<ExitCode, Error> {
    let (config, path) =
        config::load::<ClientConfig>(common.config.as_deref(), config::client_path())?;
    logging::init(
        Role::Client,
        logging::level(Role::Client, common.verbose, common.quiet, None),
    );
    config::log_source(path.as_deref());

    let (remote, action) = match command {
        ClientCommand::Fs { action } => {
            let (remote, mut operation) = crate::file_client::split(action);
            operation.max_size = config
                .max_file_size
                .unwrap_or(crate::file_protocol::DEFAULT_MAX_SIZE);
            (
                remote,
                Action::Files(
                    operation,
                    Duration::from_secs(config.file_timeout.unwrap_or(60)),
                ),
            )
        }
        ClientCommand::Trust { action } => return trust_command(action),
        ClientCommand::Connect {
            remote,
            attach: Some(session),
            takeover,
            read_only,
            ..
        } => (
            remote,
            Action::Attach {
                session,
                takeover,
                read_only,
            },
        ),
        ClientCommand::Connect { remote, name, .. } => {
            let open = Open {
                detach_timeout: config.detach_timeout,
                ..interactive(name)
            };
            (remote, Action::Terminal(open, true))
        }
        ClientCommand::Exec {
            remote,
            no_shell,
            command,
        } => {
            let open = Open {
                detach_timeout: config.detach_timeout,
                ..exec(command, no_shell)
            };
            (remote, Action::Terminal(open, false))
        }
        ClientCommand::Sessions { remote } => (remote, Action::List),
        ClientCommand::Detach {
            remote,
            session,
            target,
        } => (
            remote,
            Action::Detach {
                session,
                attachment: target.id,
            },
        ),
        ClientCommand::Terminate {
            remote,
            session,
            force,
        } => (remote, Action::Terminate { session, force }),
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
    let mut connection = runtime.block_on(login_to_offer(
        &remote,
        addr,
        &mut store,
        &key,
        ask_user,
        matches!(&action, Action::Files(..)),
    ))?;
    let mut login = Login {
        remote: &remote,
        store: &mut store,
        key: &key,
        reattach: Duration::from_secs(config.reattach_timeout.unwrap_or(REATTACH_TIMEOUT)),
    };
    let result = runtime.block_on(perform(&mut connection, action, &mut login));
    runtime.block_on(connection.close());
    result
}

/// How long automatic reattach keeps trying by default, in seconds.
const REATTACH_TIMEOUT: u64 = 60 * 60;

/// One attempt of automatic reattach: a QUIC handshake alone would wait for the idle
/// timeout, while a new attempt may already find the network back.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

/// The longest pause between attempts of automatic reattach.
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// A Connection with a trusted Server key, HELLO exchanged and authenticated (§10, §12).
async fn login_to(
    remote: &Remote,
    addr: SocketAddr,
    store: &mut TrustStore,
    key: &UserKey,
    confirm: impl Fn(&Address, &Fingerprint) -> Result<bool, Error>,
) -> Result<Connection, Error> {
    login_to_offer(remote, addr, store, key, confirm, false).await
}

async fn login_to_offer(
    remote: &Remote,
    addr: SocketAddr,
    store: &mut TrustStore,
    key: &UserKey,
    confirm: impl Fn(&Address, &Fingerprint) -> Result<bool, Error>,
    files: bool,
) -> Result<Connection, Error> {
    let mut connection = connect(remote, addr, store, confirm).await?;
    let hello = if files {
        match connection
            .exchange_hello_offer(SERVER_HELLO_TIMEOUT, ClientHello::with_files(1))
            .await
        {
            Ok(hello) => hello,
            Err(error) => return Err(connection.failed(error).await),
        }
    } else {
        connection.hello(SERVER_HELLO_TIMEOUT).await?
    };
    tracing::info!(
        version = format_args!("{:#x}", hello.version),
        "Connection established"
    );
    let account = &remote.destination.account;
    let accepted = connection
        .authenticate(account, key, AUTH_RESULT_TIMEOUT)
        .await?;
    if !accepted {
        connection.close().await;
        return Err(Error::AuthRejected {
            account: account.clone(),
            fingerprint: key.public_key().fingerprint(),
            key_line: key.public_key().to_base64(),
        });
    }
    tracing::info!(%account, key = %key.public_key().fingerprint(), "Connection authenticated");
    Ok(connection)
}

/// What a Client command does once the Connection is Authenticated.
enum Action {
    Files(crate::file_client::Operation, Duration),
    /// A new Session: its terminal Channel, and whether it has a PTY.
    Terminal(Open, bool),
    Attach {
        session: String,
        takeover: bool,
        read_only: bool,
    },
    List,
    Terminate {
        session: String,
        force: bool,
    },
    Detach {
        session: String,
        attachment: Option<u64>,
    },
}

async fn perform(
    connection: &mut Connection,
    action: Action,
    login: &mut Login<'_>,
) -> Result<ExitCode, Error> {
    match action {
        Action::Files(mut operation, deadline) => {
            operation.server_identity = connection.server_identity.as_spki().to_vec();
            let mut channel = connection
                .open_files()
                .await
                .map_err(|e| Error::Files(e.into()))?;
            let result = tokio::select! {
                result=crate::file_client::run(&mut channel,operation,connection.peer_limit,deadline)=>result.map_err(Error::Files),
                _=tokio::signal::ctrl_c()=>Err(Error::Interrupted),
                ()=follow_network(connection.endpoint.clone(),connection.connection.remote_address())=>unreachable!(),
            };
            if result.is_ok()
                && let Err(error) = channel.close().await
            {
                match error {
                    StreamError::Failure(f) => {
                        return Err(Error::Files(crate::file_client::Error::Protocol(f)));
                    }
                    _ => tracing::debug!(
                        ?error,
                        "file operation completed before Channel teardown failed"
                    ),
                }
            }
            result.map(|()| ExitCode::SUCCESS)
        }
        Action::Terminal(open, pty) => terminal(connection, open, pty, login)
            .await
            .map(outcome_code),
        Action::Attach {
            session,
            takeover,
            read_only,
        } => {
            let session = commands::resolve(connection, &session).await?;
            let open = Open {
                session: Some(session.id),
                size: session.pty.then(|| console::size().unwrap_or(DEFAULT_SIZE)),
                takeover: takeover.then_some(true),
                read_only: read_only.then_some(true),
                ..Open::default()
            };
            terminal(connection, open, session.pty, login)
                .await
                .map(outcome_code)
        }
        Action::List => commands::sessions(connection).await,
        Action::Terminate { session, force } => {
            commands::terminate(connection, &session, force).await
        }
        Action::Detach {
            session,
            attachment,
        } => commands::detach(connection, &session, attachment).await,
    }
}

/// Exit code and message for the end of a terminal Channel.
fn outcome_code(outcome: Outcome) -> ExitCode {
    let note = |text: String| {
        let _ = writeln!(io::stderr(), "stpt: {text}");
    };
    match outcome {
        Outcome::Exited(exit) => exit_code(exit),
        Outcome::Detached(session) => {
            note(format!("detached; Session {session} keeps running"));
            ExitCode::SUCCESS
        }
        Outcome::DetachedByServer(session) => {
            note(format!(
                "detached by the Server; Session {session} keeps running"
            ));
            ExitCode::SUCCESS
        }
    }
}

/// Window size when standard output is not a terminal.
const DEFAULT_SIZE: Size = Size {
    columns: 80,
    rows: 24,
    width: 0,
    height: 0,
};

/// Terminal type when TERM is not set or not valid (e.g. on Windows).
const DEFAULT_TERM: &str = "xterm-256color";

/// `connect`: a new Session with a PTY running the login shell.
fn interactive(name: Option<String>) -> Open {
    let term = std::env::var("TERM")
        .ok()
        .filter(|t| terminal::valid_term(t))
        .unwrap_or_else(|| DEFAULT_TERM.to_owned());
    Open {
        term: Some(term),
        size: Some(console::size().unwrap_or(DEFAULT_SIZE)),
        env: locale(),
        name,
        ..Open::default()
    }
}

/// `exec`: a new Session without a PTY running the command; as ssh, the arguments
/// form one command line unless `no_shell`.
fn exec(command: Vec<String>, no_shell: bool) -> Open {
    let command = if no_shell {
        Command::Argv(command)
    } else {
        Command::Line(command.join(" "))
    };
    Open {
        command: Some(command),
        env: locale(),
        ..Open::default()
    }
}

/// The locale variables the Client passes on: `LANG` and `LC_*`, never the whole
/// environment (§14.6).
fn locale() -> Vec<(String, String)> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .filter(|(name, value)| {
            (name == "LANG" || name.starts_with("LC_")) && name.len() <= 4096 && value.len() <= 4096
        })
        .take(64)
        .collect()
}

/// Exit code of the Client for the remote exit status: the exit code (255 if it does
/// not fit), or 255 after a signal, as ssh.
fn exit_code(exit: Exit) -> ExitCode {
    match exit {
        Exit::Code(code) => ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX)),
        Exit::Signal { id, core_dumped } => {
            let _ = writeln!(
                io::stderr(),
                "stpt: the remote program was killed by signal {}{}",
                terminal::signal_name(id).unwrap_or("(unknown)"),
                if core_dumped { " (core dumped)" } else { "" }
            );
            ExitCode::from(u8::MAX)
        }
    }
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
    server_identity: crate::identity::PublicKey,
    files: Option<crate::files::Budget>,
    authenticated: bool,
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    /// Control stream once opened; kept until the Connection is closed, as dropping
    /// it would end the stream, which the Server treats as an error (§8.1).
    control: Option<(quinn::SendStream, quinn::RecvStream)>,
    /// Message size limit of the Server, from SERVER_HELLO.
    peer_limit: u64,
    /// The last request ID used (§8.4).
    next_request: u64,
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
    pub async fn failed(&self, error: StreamError) -> Error {
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
        self.exchange_hello_offer(deadline, ClientHello::ours())
            .await
    }

    /// File commands supply `ClientHello::with_files`; terminal commands do not offer it.
    async fn exchange_hello_offer(
        &mut self,
        deadline: Duration,
        offer: ClientHello,
    ) -> Result<ServerHello, StreamError> {
        let (send, recv) = self
            .control
            .insert(self.connection.open_bi().await.map_err(StreamError::Lost)?);
        let _ = send.set_priority(control::CONTROL_PRIORITY);
        wire::write_message(send, &offer.to_message(), DEFAULT_MESSAGE_LIMIT).await?;
        let message = reply(recv, deadline, "SERVER_HELLO", State::Handshaking).await?;
        let hello = ServerHello::from_message(&message)?;
        hello.check(&offer)?;
        if !hello.auth_methods.contains(&AUTH_PUBLICKEY_ED25519) {
            return Err(Failure::violation("the Server does not offer publickey-ed25519").into());
        }
        self.peer_limit = hello.limits.max_message;
        self.files = crate::files::selected(&hello.capabilities)
            .map(|max| crate::files::Budget::new(max.min(u64::from(u32::MAX)) as u32));
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
        let message = reply(recv, deadline, "AUTH_RESULT", State::Established).await?;
        let accepted = auth::result_from_message(&message)?;
        self.authenticated = accepted;
        Ok(accepted)
    }

    /// Opens an authenticated, negotiated file Channel for `fs`.
    pub async fn open_files(&self) -> Result<crate::files::Channel, StreamError> {
        if !self.authenticated {
            return Err(Failure::new(
                Code::ChannelRejected,
                "file Channel requires authentication",
            )
            .into());
        }
        let budget = self.files.as_ref().ok_or_else(|| {
            Failure::new(Code::ChannelRejected, "file capability was not selected")
        })?;
        crate::files::Channel::open(
            &self.connection,
            self.peer_limit,
            budget,
            crate::files::OPEN_TIMEOUT,
        )
        .await
    }
}

/// How a terminal Channel ended for the Client.
pub enum Outcome {
    /// The remote program exited.
    Exited(Exit),
    /// The user detached (`Enter ~ .`); the Session keeps running.
    Detached(SessionId),
    /// The Server ended the Attachment (takeover, detach request).
    DetachedByServer(SessionId),
}

/// A terminal Channel the Server has accepted.
struct Channel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    attached: Attached,
}

impl Connection {
    /// Opens a terminal Channel (§14.3) and waits for TERMINAL_ATTACHED.
    async fn open_terminal(&mut self, open: &Open) -> Result<Channel, Error> {
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(quic::Error::Connection)?;
        if let Err(error) =
            wire::write_message(&mut send, &open.to_message(), self.peer_limit).await
        {
            return Err(self.failed(error).await);
        }
        let attached = match wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await {
            Ok(Some(message)) => Attached::from_message(&message).map_err(StreamError::from),
            Ok(None) => {
                Err(Failure::violation("terminal Channel ended before TERMINAL_ATTACHED").into())
            }
            Err(StreamError::Reset(code)) => return Err(Error::ChannelRejected(code.into_inner())),
            Err(error) => Err(error),
        };
        let attached = match attached {
            Ok(attached) => attached,
            Err(error) => return Err(self.failed(error).await),
        };
        tracing::info!(session = %attached.session, attachment = attached.attachment, "attached");
        Ok(Channel {
            send,
            recv,
            attached,
        })
    }

    /// Ends an Attachment of a lost Connection (§15.12). The result is not awaited: it
    /// comes only when that Attachment has ended, and nothing depends on it.
    async fn forget_attachment(&mut self, session: SessionId, attachment: u64) {
        self.next_request += 1;
        let request = listing::detach_request(self.next_request, session, Some(attachment));
        let (send, _) = self.control.as_mut().expect("authenticated");
        let _ = wire::write_message(send, &request, self.peer_limit).await;
    }

    /// Sends the request `build` makes with a new request ID and returns its
    /// REQUEST_RESULT (§8.4). Requests are sent one at a time.
    pub async fn request(&mut self, build: impl FnOnce(u64) -> Message) -> Result<Message, Error> {
        self.next_request += 1;
        let id = self.next_request;
        match self.exchange_request(id, build(id)).await {
            Ok(result) => Ok(result),
            Err(error) => Err(self.failed(error).await),
        }
    }

    async fn exchange_request(
        &mut self,
        id: u64,
        request: Message,
    ) -> Result<Message, StreamError> {
        let (send, recv) = self.control.as_mut().expect("authenticated");
        wire::write_message(send, &request, self.peer_limit).await?;
        let result = reply(
            recv,
            REQUEST_TIMEOUT,
            "REQUEST_RESULT",
            State::Authenticated,
        )
        .await?;
        if result.field(0).and_then(Value::as_uint) != Some(id) {
            return Err(Failure::violation("REQUEST_RESULT for an unknown request ID").into());
        }
        Ok(result)
    }

    /// The error code of a REQUEST_RESULT, `None` for success; a result without a
    /// code closes the Connection.
    pub async fn failed_result(&self, result: &Message) -> Result<Option<u64>, Error> {
        match result.field(1).and_then(Value::as_uint) {
            Some(0) => Ok(None),
            Some(code) => Ok(Some(code)),
            None => Err(self
                .failed(Failure::violation("REQUEST_RESULT without error code").into())
                .await),
        }
    }
}

fn shutting_down(reason: &quinn::ConnectionError) -> bool {
    matches!(reason, quinn::ConnectionError::ApplicationClosed(close)
        if close.error_code == wire::Code::ServerShutdown.varint())
}

/// What a new Connection to the same Server takes (§15.12).
struct Login<'a> {
    remote: &'a Remote,
    store: &'a mut TrustStore,
    key: &'a UserKey,
    /// How long automatic reattach keeps trying; zero: it is off.
    reattach: Duration,
}

/// Input that outlives the Attachments of a terminal Channel: it is read only once,
/// and the escape continues.
struct LocalInput {
    inputs: mpsc::Receiver<Input>,
    escape: Escape,
}

/// The local side of a terminal Channel: it outlives the Connection (§15.12).
struct Terminal<F> {
    session: SessionId,
    mode: InputMode,
    input: mpsc::Sender<Input>,
    /// The terminal modes the Session's programs set (§15.11).
    modes: Modes,
    /// Offset of the first output byte not yet received (§15.11).
    offset: u64,
    terminated: std::pin::Pin<Box<F>>,
}

/// How one Attachment ended.
struct Relayed {
    result: Result<Outcome, Received>,
    sender: tokio::task::JoinHandle<LocalInput>,
    stop: tokio::sync::oneshot::Sender<()>,
    detached: tokio::sync::oneshot::Receiver<()>,
}

impl<F: Future<Output = &'static str>> Terminal<F> {
    /// Relays local input and remote output until the remote program exits or the
    /// Attachment ends.
    async fn relay(&mut self, channel: Channel, local: LocalInput, over: &Connection) -> Relayed {
        let Channel { send, mut recv, .. } = channel;
        let session = self.session;
        let (pty, read_only) = (self.mode.pty, self.mode.read_only);
        let (detach, mut detached) = tokio::sync::oneshot::channel();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let limit = over.peer_limit;
        let sender = tokio::spawn(send_input(send, local, self.mode, limit, detach, stopped));
        let network = tokio::spawn(follow_network(
            over.endpoint.clone(),
            over.connection.remote_address(),
        ));
        // A read-only Attachment sends no input at all, not even its size (§15.9).
        let watcher = match (pty, console::size()) {
            (true, Some(size)) if !read_only => {
                Some(tokio::spawn(watch_size(self.input.clone(), size)))
            }
            _ => None,
        };
        let input = self.input.clone();
        let interrupted = async {
            match (pty, read_only) {
                // Ctrl+C is input for the remote PTY (dropped when read-only).
                (true, _) => std::future::pending().await,
                (false, true) => {
                    let _ = tokio::signal::ctrl_c().await;
                    Ok(Outcome::Detached(session))
                }
                (false, false) => {
                    interrupts(input).await;
                    Err(Received::Local(Error::Interrupted))
                }
            }
        };
        let result = tokio::select! {
            biased;
            Ok(()) = &mut detached => Ok(Outcome::Detached(session)),
            result = receive_output(&mut recv, pty, &mut self.modes, &mut self.offset) => {
                result.map(Outcome::Exited)
            }
            result = interrupted => result,
            by = self.terminated.as_mut() => Err(Received::Local(Error::Terminated(by))),
        };
        network.abort();
        if let Some(watcher) = watcher {
            watcher.abort();
        }
        Relayed {
            result,
            sender,
            stop,
            detached,
        }
    }

    /// After the loss of a Connection: new Connections, each authenticated in full,
    /// until one attaches with resume (§15.12). What is typed meanwhile is dropped,
    /// only the escape counts: `Enter ~ .` gives up, and so does the end of the time.
    async fn reattach(
        &mut self,
        login: &mut Login<'_>,
        local: &mut LocalInput,
        lost_attachment: u64,
        reason: quinn::ConnectionError,
    ) -> Result<(Connection, Channel), Error> {
        let session = self.session;
        self.tell(&format!(
            "connection lost: {}; reconnecting, Enter ~ . gives up",
            quic::Error::Connection(reason.clone())
        ));
        let lost = || Error::SessionContinues {
            error: Box::new(quic::Error::Connection(reason.clone()).into()),
            session,
        };
        let deadline = Instant::now().checked_add(login.reattach);
        let mut attempts = 0;
        loop {
            let delay = retry_delay(attempts);
            attempts += 1;
            if deadline.is_some_and(|d| Instant::now() + delay >= d) {
                return Err(lost());
            }
            let open = Open {
                session: Some(session),
                size: Some(console::size().unwrap_or(DEFAULT_SIZE)),
                read_only: self.mode.read_only.then_some(true),
                resume: Some(self.offset),
                ..Open::default()
            };
            let attempt = async {
                tokio::time::sleep(delay).await;
                timeout(ATTEMPT_TIMEOUT, attach_again(login, &open)).await
            };
            let result = tokio::select! {
                biased;
                by = self.terminated.as_mut() => return Err(Error::Terminated(by)),
                () = local.escaped() => return Err(lost()),
                result = attempt => result,
            };
            match result {
                Ok(Ok((mut connection, channel))) => {
                    connection.forget_attachment(session, lost_attachment).await;
                    self.attached_again(&channel.attached)?;
                    return Ok((connection, channel));
                }
                Ok(Err(error)) if !worth_retrying(&error) => return Err(error),
                Ok(Err(error)) => tracing::debug!(%error, "reattach failed"),
                Err(_) => tracing::debug!("reattach timed out"),
            }
        }
    }

    /// Continues from where the new Attachment starts (§15.11). Without lost output the
    /// terminal stays as it was; else its modes belong to output it has not seen.
    fn attached_again(&mut self, attached: &Attached) -> Result<(), Error> {
        let lost = attached.offset.saturating_sub(self.offset);
        self.offset = attached.offset;
        if lost == 0 {
            self.tell("attached again");
            // A full-screen program does not know about the messages on its screen, and
            // the Server does not redraw on a resume without loss. A read-only
            // Attachment may not change the size (§15.9).
            if self.modes.alternate_screen() && !self.mode.read_only {
                self.redraw();
            }
            return Ok(());
        }
        let mut sequence = self.modes.reset();
        self.modes = Modes::new();
        self.modes.feed(&attached.modes);
        sequence.extend_from_slice(&attached.modes);
        console::write_out(&sequence).map_err(Error::Terminal)?;
        self.tell(&format!("attached again; {lost} bytes of output were lost"));
        Ok(())
    }

    /// A message to the user while the terminal is in raw mode. On the screen of a
    /// full-screen program it goes to the last row: a line feed would scroll the screen
    /// behind the program's back, which repaints only what it knows has changed.
    fn tell(&self, text: &str) {
        let _ = match console::size() {
            Some(size) if self.modes.alternate_screen() => {
                console::write_out(on_last_row(text, size).as_bytes())
            }
            _ => console::write_err(format!("\r\nstpt: {text}\r\n").as_bytes()),
        };
    }

    /// Makes a full-screen program repaint: curses programs do that in full only on a
    /// real change of the size. The size is restored after a pause, as both changes
    /// arriving together would look like none.
    fn redraw(&self) {
        let Some(size) = console::size().filter(|s| s.rows > 1) else {
            return;
        };
        let input = self.input.clone();
        tokio::spawn(async move {
            let smaller = Size {
                rows: size.rows - 1,
                ..size
            };
            let _ = input.send(Input::Resize(smaller)).await;
            tokio::time::sleep(REDRAW_PAUSE).await;
            let size = console::size().unwrap_or(size);
            let _ = input.send(Input::Resize(size)).await;
        });
    }
}

/// How long `Terminal::redraw` keeps the smaller size.
const REDRAW_PAUSE: Duration = Duration::from_millis(200);

/// `text` on the last row of the terminal, in reverse video, leaving the cursor and
/// its attributes as they were. It is cut to fit: wrapping on the last row would scroll.
fn on_last_row(text: &str, size: Size) -> String {
    let width = usize::from(size.columns).saturating_sub(1);
    let text: String = format!("stpt: {text}").chars().take(width).collect();
    format!(
        "\x1b7\x1b[{};1H\x1b[0;7m{text}\x1b[0m\x1b[K\x1b8",
        size.rows
    )
}

/// How often the Client looks whether its address towards the Server has changed.
const NETWORK_POLL: Duration = Duration::from_secs(1);

/// Migrates the Connection when the address of this computer towards the Server changes
/// (§15.12). The system would use the new address by itself, but only with the next
/// packet: at an idle Client that is the keep-alive up to 15 s later, and the Server
/// keeps sending to the old address until then. Without a route it waits; the same
/// address coming back needs nothing.
async fn follow_network(endpoint: quinn::Endpoint, server: SocketAddr) {
    let mut last = quic::route_source(server).ok();
    let mut tick = tokio::time::interval(NETWORK_POLL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        let Ok(source) = quic::route_source(server) else {
            continue;
        };
        if last == Some(source) {
            continue;
        }
        match quic::rebind(&endpoint, server) {
            Ok(()) => {
                tracing::info!(%source, "network changed, Connection migrated");
                last = Some(source);
            }
            Err(error) => tracing::debug!(%error, "migration failed"),
        }
    }
}

/// One attempt of automatic reattach.
async fn attach_again(login: &mut Login<'_>, open: &Open) -> Result<(Connection, Channel), Error> {
    let address = login.remote.destination.address.clone();
    let addr = tokio::task::spawn_blocking(move || resolve(&address))
        .await
        .expect("resolving does not panic")?;
    // Nobody can be asked now: a key not known by now is an error.
    let mut connection =
        login_to(login.remote, addr, login.store, login.key, refuse_unknown).await?;
    let channel = connection.open_terminal(open).await?;
    Ok((connection, channel))
}

/// A first contact during reattach: the trust store has lost the key of the Server.
fn refuse_unknown(address: &Address, fingerprint: &Fingerprint) -> Result<bool, Error> {
    Err(Error::KeyNotKnown {
        address: address.clone(),
        presented: *fingerprint,
    })
}

/// Whether the loss of a Connection is one a new Connection may help with: silence,
/// or a Server that has forgotten it. A close by the Server is its decision.
fn lost_in_transit(reason: &quinn::ConnectionError) -> bool {
    matches!(
        reason,
        quinn::ConnectionError::TimedOut | quinn::ConnectionError::Reset
    )
}

/// Whether a failed attempt of reattach may succeed later: not when the Server key
/// changed, the user key is refused or the Session is gone.
fn worth_retrying(error: &Error) -> bool {
    match error {
        Error::Resolve { .. } | Error::Transport(_) => true,
        Error::Protocol(failure) => failure.code == wire::Code::Timeout,
        // The Attachment of the lost Connection may still count against the limit.
        Error::ChannelRejected(code) => *code == wire::Code::LimitExceeded as u64,
        _ => false,
    }
}

/// How long automatic reattach waits before attempt `attempt`, counted from 0.
fn retry_delay(attempt: u32) -> Duration {
    match attempt {
        0 => Duration::ZERO,
        n => Duration::from_secs(1 << (n - 1).min(8)).min(MAX_RETRY_DELAY),
    }
}

impl LocalInput {
    /// Follows the input without an Attachment: completes on the escape `Enter ~ .`.
    async fn escaped(&mut self) {
        loop {
            match self.inputs.recv().await {
                Some(Input::Data(data)) if self.escape.filter(&data).1 => return,
                Some(_) => {}
                None => std::future::pending().await,
            }
        }
    }
}

/// Runs a terminal Channel until the remote program exits or the Attachment ends and,
/// with a PTY, attaches again after the loss of the Connection (§15.12). With a PTY the
/// local terminal is in raw mode meanwhile, and `Enter ~ .` detaches.
async fn terminal(
    connection: &mut Connection,
    open: Open,
    pty: bool,
    login: &mut Login<'_>,
) -> Result<Outcome, Error> {
    let mut channel = connection.open_terminal(&open).await?;
    let attached = &channel.attached;
    let session = attached.session;
    let terminated = Box::pin(console::termination().map_err(Error::Signals)?);
    let console = Console::setup(pty).map_err(Error::Terminal)?;
    let mut modes = Modes::new();
    if pty && !attached.modes.is_empty() {
        modes.feed(&attached.modes);
        console::write_out(&attached.modes).map_err(Error::Terminal)?;
    }
    let (input, inputs) = mpsc::channel(16);
    let from_stdin = input.clone();
    console::read_input(move |data| {
        let input = data.map_or(Input::Eof, Input::Data);
        from_stdin.blocking_send(input).is_ok()
    });
    let mut state = Terminal {
        session,
        mode: InputMode {
            pty,
            read_only: open.read_only == Some(true),
        },
        input: input.clone(),
        modes,
        offset: attached.offset,
        terminated,
    };
    let mut local = LocalInput {
        inputs,
        escape: Escape::new(),
    };
    let (result, finishing) = loop {
        let attachment = channel.attached.attachment;
        let relayed = state.relay(channel, local, connection).await;
        let reason = match &relayed.result {
            Err(Received::Stream(StreamError::Lost(reason)))
                if pty && !login.reattach.is_zero() && lost_in_transit(reason) =>
            {
                reason.clone()
            }
            _ => {
                break (
                    relayed.result,
                    Some((relayed.sender, relayed.stop, relayed.detached)),
                );
            }
        };
        // The task returns at once: writing to a lost Connection fails.
        let _ = relayed.stop.send(());
        local = relayed.sender.await.expect("input task does not panic");
        match state.reattach(login, &mut local, attachment, reason).await {
            Ok((new, next)) => {
                *connection = new;
                channel = next;
            }
            Err(error) => break (Err(Received::Local(error)), None),
        }
    };
    if pty {
        // Leave the modes the remote programs set; after an early end also their
        // colours, and continue on a new line.
        let mut tail = state.modes.reset();
        if !matches!(result, Ok(Outcome::Exited(_))) {
            tail.extend_from_slice(b"\x1b[0m\r\n");
        }
        let _ = console::write_out(&tail);
    }
    drop(console);
    let mut detached = None;
    if let Some((sender, stop, receiver)) = finishing {
        // The Client's FIN: after the exit status, or a detach when the Client ends
        // early (§14.10); not worth waiting long for. The caller closes the Connection.
        let _ = input.try_send(Input::Finish);
        let _ = timeout(Duration::from_secs(1), sender).await;
        drop(stop);
        detached = Some(receiver);
    }
    match result {
        Ok(outcome) => Ok(outcome),
        // The Server's FIN answers our own detach, or it ended the Attachment.
        Err(Received::Local(Error::TerminalEnded))
            if detached.as_mut().is_some_and(|d| d.try_recv().is_ok()) =>
        {
            Ok(Outcome::Detached(session))
        }
        Err(Received::Local(Error::TerminalEnded)) => Ok(Outcome::DetachedByServer(session)),
        Err(Received::Local(error)) => Err(error),
        Err(Received::Stream(StreamError::Reset(code))) => {
            Err(Error::ChannelReset(code.into_inner()))
        }
        // When the Server shuts down, its Sessions end too (§15.8).
        Err(Received::Stream(StreamError::Lost(reason))) if shutting_down(&reason) => {
            Err(quic::Error::Connection(reason).into())
        }
        Err(Received::Stream(StreamError::Lost(reason))) => Err(Error::SessionContinues {
            error: Box::new(quic::Error::Connection(reason).into()),
            session,
        }),
        Err(Received::Stream(error)) => Err(connection.failed(error).await),
    }
}

/// How long the Client waits for a REQUEST_RESULT; a termination may take the
/// Server's grace period and more.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The escape of the local terminal, as in ssh: after a line end, `~.` detaches and
/// `~~` sends one `~`; `~` before anything else is sent with it. What the terminal
/// emulator sends on its own (mouse, focus, answers to queries) is not typing, and
/// keypad Enter (`ESC O M`, sent in application keypad mode) is a line end.
struct Escape {
    line_start: bool,
    after_tilde: bool,
    /// An escape sequence still coming in.
    sequence: Vec<u8>,
}

/// Longest escape sequence followed; a longer one counts as typing.
const MAX_SEQUENCE: usize = 64;

/// What a complete escape sequence in the input means for the escape.
#[derive(Debug, PartialEq, Eq)]
enum Sequence {
    Pending,
    /// A key: arrows, function keys, Alt with a key.
    Typed,
    /// Keypad Enter.
    LineEnd,
    /// Sent by the terminal emulator itself: mouse, focus, answers to queries.
    Report,
}

fn classify(sequence: &[u8]) -> Sequence {
    use Sequence::*;
    let long = sequence.len() >= MAX_SEQUENCE;
    match sequence {
        [_] | [_, b'[' | b'O' | b']'] => Pending,
        [_, b'O', b'M'] => LineEnd,
        // Alt with a key, or another SS3 key.
        [_, _] | [_, b'O', _] => Typed,
        // OSC answer, ended by BEL or ST.
        [_, b']', rest @ ..] if rest.ends_with(b"\x07") || rest.ends_with(b"\x1b\\") => Report,
        [_, b']', ..] if long => Report,
        [_, b']', ..] => Pending,
        // X10 mouse report: three bytes follow.
        [_, b'[', b'M', rest @ ..] if rest.len() >= 3 => Report,
        [_, b'[', b'M', ..] => Pending,
        [_, b'[', rest @ ..] => match rest.last() {
            Some(&last) if (0x40..=0x7e).contains(&last) => {
                // Private parameters (`<` mouse, `?` and `>` answers) or a focus
                // report (`CSI I`, `CSI O`): never a key.
                let private = matches!(rest.first(), Some(b'<' | b'=' | b'>' | b'?'));
                if private || (rest.len() == 1 && matches!(last, b'I' | b'O')) {
                    Report
                } else {
                    Typed
                }
            }
            _ if long => Typed,
            _ => Pending,
        },
        _ => Typed,
    }
}

impl Escape {
    fn new() -> Self {
        Self {
            line_start: true,
            after_tilde: false,
            sequence: Vec::new(),
        }
    }

    /// The input to send, and whether `~.` was typed (input after it is dropped).
    /// Each read holds whole keys: an ESC alone at the end of one is the Esc key.
    fn filter(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(data.len() + 1);
        for &byte in data {
            if !self.sequence.is_empty() {
                self.sequence.push(byte);
                out.push(byte);
                match classify(&self.sequence) {
                    Sequence::Pending => continue,
                    Sequence::Typed => self.line_start = false,
                    Sequence::LineEnd => self.line_start = true,
                    Sequence::Report => {}
                }
                self.sequence.clear();
                continue;
            }
            if self.after_tilde {
                self.after_tilde = false;
                match byte {
                    b'.' => return (out, true),
                    b'~' => {
                        out.push(b'~');
                        continue;
                    }
                    _ => out.push(b'~'),
                }
            } else if self.line_start && byte == b'~' {
                self.after_tilde = true;
                self.line_start = false;
                continue;
            }
            out.push(byte);
            if byte == 0x1b {
                self.sequence.push(byte);
            } else {
                self.line_start = byte == b'\r' || byte == b'\n';
            }
        }
        if self.sequence == [0x1b] {
            self.sequence.clear();
            self.line_start = false;
        }
        (out, false)
    }
}

/// Local input for the terminal Channel.
enum Input {
    Data(Vec<u8>),
    /// End of standard input.
    Eof,
    /// New size of the local window (with a PTY only).
    Resize(Size),
    /// A signal id for the remote program (§14.9).
    Signal(u64),
    /// The Channel is over: end the Client's direction.
    Finish,
}

/// Ctrl+C presses that end the Client while the remote command runs on.
const INTERRUPTS_TO_QUIT: u32 = 3;

/// Ctrl+C without a PTY (§14.9): each press sends INT to the remote command; the
/// third ends the Client, for a command that ignores INT. Returns then.
async fn interrupts(input: mpsc::Sender<Input>) {
    for _ in 1..INTERRUPTS_TO_QUIT {
        if tokio::signal::ctrl_c().await.is_err() {
            return std::future::pending().await;
        }
        tracing::info!("interrupt sent to the remote command");
        let _ = input.send(Input::Signal(terminal::SIGNAL_INT)).await;
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Sends the size of the local window whenever it changes (§14.8); a burst of
/// changes that arrives together gives one TERMINAL_RESIZE with the latest size.
async fn watch_size(input: mpsc::Sender<Input>, mut last: Size) {
    let Ok(mut changes) = console::SizeChanges::new() else {
        return;
    };
    while changes.next().await {
        if let Some(size) = console::size()
            && size != last
        {
            last = size;
            if input.send(Input::Resize(size)).await.is_err() {
                return;
            }
        }
    }
}

/// Sends local input as TERMINAL_DATA and size changes as TERMINAL_RESIZE; at the
/// end of standard input TERMINAL_EOF without a PTY, nothing with one (Ctrl-D is
/// in-band, §14.7).
/// The shape of input for the log, to diagnose the escape without logging what is
/// typed (passwords): letters, digits and other printable characters become `x`,
/// non-ASCII bytes `?`; `~`, `.`, line ends and control bytes are kept, and so are
/// escape sequences, which are keys and reports, not text (Alt with a key shows it).
fn shape(data: &[u8]) -> String {
    let mut out = String::new();
    // Bytes since an ESC whose sequence has not ended; 0 outside one.
    let mut in_sequence = 0usize;
    for &b in data {
        if b == 0x1b {
            out.push_str("^[");
            in_sequence = 1;
            continue;
        }
        if in_sequence > 0 && (0x20..0x7f).contains(&b) {
            out.push(b as char);
            let introducer = in_sequence == 1 && matches!(b, b'[' | b'O' | b']');
            let ends = !introducer && (0x40..=0x7e).contains(&b);
            in_sequence = if ends || in_sequence > 32 {
                0
            } else {
                in_sequence + 1
            };
            continue;
        }
        in_sequence = 0;
        match b {
            b'~' | b'.' => out.push(b as char),
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            0..0x20 | 0x7f => out.push_str(&format!("^{}", (b ^ 0x40) as char)),
            0x20..0x7f => out.push('x'),
            _ => out.push('?'),
        }
    }
    out
}

/// What the input of a terminal Channel may carry.
#[derive(Clone, Copy)]
struct InputMode {
    pty: bool,
    /// Nothing is sent; only the escape is followed.
    read_only: bool,
}

async fn send_input(
    mut send: quinn::SendStream,
    mut local: LocalInput,
    mode: InputMode,
    limit: u64,
    detach: tokio::sync::oneshot::Sender<()>,
    mut stop: tokio::sync::oneshot::Receiver<()>,
) -> LocalInput {
    let pty = mode.pty;
    loop {
        let input = tokio::select! {
            biased;
            Ok(()) = &mut stop => return local,
            input = local.inputs.recv() => input,
        };
        let Some(input) = input else {
            break;
        };
        let message = match input {
            Input::Data(data) if pty => {
                tracing::trace!(input = %shape(&data), "terminal input");
                let (data, detaching) = local.escape.filter(&data);
                if !data.is_empty() && !mode.read_only {
                    let message = terminal::data(TERMINAL_DATA, &data);
                    if wire::write_message(&mut send, &message, limit)
                        .await
                        .is_err()
                    {
                        return local;
                    }
                }
                if detaching {
                    // FIN: a detach (§14.10).
                    let _ = send.finish();
                    let _ = detach.send(());
                    let _ = send.stopped().await;
                    return local;
                }
                continue;
            }
            Input::Data(_) | Input::Eof | Input::Resize(_) | Input::Signal(_) if mode.read_only => {
                continue;
            }
            Input::Data(data) => terminal::data(TERMINAL_DATA, &data),
            Input::Eof if pty => continue,
            Input::Eof => terminal::eof(),
            Input::Resize(size) => size.resize_message(),
            Input::Signal(id) => terminal::signal(id),
            Input::Finish => break,
        };
        if wire::write_message(&mut send, &message, limit)
            .await
            .is_err()
        {
            return local;
        }
    }
    let _ = send.finish();
    // Closing the Connection drops stream data not yet sent: wait until the Server
    // has the FIN, which confirms the exit status (§15.7).
    let _ = send.stopped().await;
    local
}

/// Why receiving output ended without an exit status.
enum Received {
    Local(Error),
    Stream(StreamError),
}

impl From<StreamError> for Received {
    fn from(error: StreamError) -> Self {
        Self::Stream(error)
    }
}

impl From<Failure> for Received {
    fn from(failure: Failure) -> Self {
        Self::Stream(failure.into())
    }
}

/// Writes remote output until TERMINAL_EXIT (§14.7, §14.10), following the terminal
/// modes in it and counting the output offset (§15.11).
async fn receive_output(
    recv: &mut quinn::RecvStream,
    pty: bool,
    modes: &mut Modes,
    offset: &mut u64,
) -> Result<Exit, Received> {
    let local = |e| Received::Local(Error::Terminal(e));
    loop {
        let Some(message) = wire::read_message(recv, DEFAULT_MESSAGE_LIMIT).await? else {
            return Err(Received::Local(Error::TerminalEnded));
        };
        match message.kind {
            TERMINAL_DATA => {
                let data = terminal::data_of(&message)?;
                if pty {
                    modes.feed(data);
                }
                console::write_out(data).map_err(local)?;
                *offset += data.len() as u64;
            }
            TERMINAL_STDERR if !pty => {
                let data = terminal::data_of(&message)?;
                console::write_err(data).map_err(local)?;
                *offset += data.len() as u64;
            }
            TERMINAL_EXIT => return Ok(Exit::from_message(&message)?),
            kind => {
                return Err(Failure::violation(format!(
                    "message type {kind} on a terminal Channel from the Server"
                ))
                .into());
            }
        }
    }
}

/// The next message from the Server within `deadline`, permitted from the Server in
/// `state` (§8.1); `what` names the expected one.
async fn reply(
    recv: &mut quinn::RecvStream,
    deadline: Duration,
    what: &str,
    state: State,
) -> Result<wire::Message, StreamError> {
    let message = timeout(deadline, wire::read_message(recv, DEFAULT_MESSAGE_LIMIT))
        .await
        .map_err(|_| {
            Failure::new(
                wire::Code::Timeout,
                format!("no {what} within {} s", deadline.as_secs_f32()),
            )
        })??
        .ok_or_else(|| Failure::violation("the Server ended the control stream"))?;
    control::check(message.kind, Sender::Server, state)?;
    Ok(message)
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
                    store.add(address.clone(), key.clone())?;
                    tracing::info!(%address, "Server key verified by fingerprint and stored");
                }
                tracing::debug!(%address, "TLS handshake completed, Server key trusted");
                return Ok(Connection {
                    server_identity: key.clone(),
                    files: None,
                    authenticated: false,
                    endpoint,
                    connection,
                    control: None,
                    peer_limit: DEFAULT_MESSAGE_LIMIT,
                    next_request: 0,
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

    #[tokio::test]
    async fn file_api_requires_authentication_and_selected_capability() {
        for select_files in [true, false] {
            timeout(Duration::from_secs(3), async {
                let key = ServerKey::generate();
                let endpoint = quic::listen("127.0.0.1:0".parse().unwrap(), &key).unwrap();
                let addr = endpoint.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let connection = quic::accept(endpoint.accept().await.unwrap()).await.unwrap();
                    let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                    let hello = wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await.unwrap().unwrap();
                    let offer = ClientHello::from_message(&hello).unwrap();
                    let answer = ServerHello::answer_with_files(&offer, if select_files { 8 } else { 0 }).unwrap();
                    wire::write_message(&mut send, &answer.to_message(), DEFAULT_MESSAGE_LIMIT).await.unwrap();
                    let auth = wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await.unwrap().unwrap();
                    assert_eq!(auth.kind, wire::AUTH_REQUEST);
                    wire::write_message(&mut send, &auth::result_message(true), DEFAULT_MESSAGE_LIMIT).await.unwrap();
                    connection.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(11));
                    if select_files {
                        let (send, mut recv) = connection.accept_bi().await.unwrap();
                        let open = wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await.unwrap().unwrap();
                        assert_eq!(control::channel_kind(&open).unwrap(), crate::files::KIND);
                        crate::files::serve(send, recv, DEFAULT_MESSAGE_LIMIT, &crate::files::Budget::new(1)).await.unwrap();
                    }
                    // Retain the control stream through Connection close.
                    connection.closed().await;
                });
                let path = store_path(&format!("files-{}", addr.port()));
                let mut store = TrustStore::load(path.clone()).unwrap();
                let remote = Remote {
                    destination: format!("alice@{addr}").parse().unwrap(),
                    fingerprint: Some(key.public_key().fingerprint()),
                    identity: None,
                };
                let mut connection = connect(&remote, addr, &mut store, never_asked).await.unwrap();
                assert!(matches!(connection.open_files().await, Err(StreamError::Failure(failure)) if failure.code == Code::ChannelRejected));
                connection.exchange_hello_offer(Duration::from_secs(1), ClientHello::with_files(1)).await.unwrap();
                assert!(matches!(connection.open_files().await, Err(StreamError::Failure(failure)) if failure.code == Code::ChannelRejected));
                assert!(connection.authenticate("alice", &UserKey::generate(), Duration::from_secs(1)).await.unwrap());
                if select_files {
                    let channel = connection.open_files().await.unwrap();
                    assert!(matches!(connection.open_files().await, Err(StreamError::Failure(failure)) if failure.code == Code::LimitExceeded));
                    channel.close().await.unwrap();
                } else {
                    assert!(matches!(connection.open_files().await, Err(StreamError::Failure(failure)) if failure.code == Code::ChannelRejected));
                }
                assert!(connection.connection.close_reason().is_none());
                connection.close().await;
                server.await.unwrap();
                std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
            }).await.unwrap();
        }
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
    fn input_shape_hides_what_is_typed() {
        assert_eq!(shape(b"secret1!\r~."), "xxxxxxxx\\r~.");
        assert_eq!(shape(b"\x1b[Ab\x03\x7f\xd0\x81"), "^[[Ax^C^???");
        assert_eq!(shape(b"\x1b[<35;1;2Mab"), "^[[<35;1;2Mxx");
        assert_eq!(shape(b"\x1bOMa"), "^[OMx");
    }

    #[test]
    fn escape_ignores_reports_and_takes_keypad_enter() {
        let detaches = |reads: &[&[u8]]| {
            let mut escape = Escape::new();
            escape.filter(b"x");
            reads.iter().any(|read| escape.filter(read).1)
        };
        // Mouse motion and focus after Enter do not count as typing.
        assert!(detaches(&[
            b"\r",
            b"\x1b[<35;10;20M",
            b"\x1b[I",
            b"~",
            b"."
        ]));
        assert!(detaches(&[b"\r\x1b[M #!~."]));
        // Answers to queries.
        assert!(detaches(&[
            b"\r",
            b"\x1b[?1;2c",
            b"\x1b]11;rgb:0/0/0\x1b\\",
            b"~."
        ]));
        // Keypad Enter in application keypad mode is a line end.
        assert!(detaches(&[b"\x1bOM", b"~", b"."]));
        // Keys are typing: an arrow, F10, Alt+x, the Esc key alone.
        assert!(!detaches(&[b"\r", b"\x1b[A", b"~."]));
        assert!(!detaches(&[b"\r\x1b[21~", b"~."]));
        assert!(!detaches(&[b"\r\x1bx~."]));
        assert!(!detaches(&[b"\r", b"\x1b", b"~."]));
        // A `~` inside a sequence is not the escape, and all input goes through.
        let mut escape = Escape::new();
        assert_eq!(escape.filter(b"\x1b[21~."), (b"\x1b[21~.".to_vec(), false));
    }

    #[test]
    fn sequences_are_classified() {
        use Sequence::*;
        assert_eq!(classify(b"\x1b"), Pending);
        assert_eq!(classify(b"\x1b[1;5"), Pending);
        assert_eq!(classify(b"\x1b[1;5D"), Typed);
        assert_eq!(classify(b"\x1b[O"), Report);
        assert_eq!(classify(b"\x1b[24;80R"), Typed);
        assert_eq!(classify(b"\x1b]10;x\x07"), Report);
        assert_eq!(classify(&[0x1b, b'[', b'1'].repeat(30)), Typed);
    }

    #[test]
    fn a_message_on_the_last_row_cannot_scroll() {
        let size = |columns, rows| Size {
            columns,
            rows,
            width: 0,
            height: 0,
        };
        assert_eq!(
            on_last_row("lost", size(80, 24)),
            "\x1b7\x1b[24;1H\x1b[0;7mstpt: lost\x1b[0m\x1b[K\x1b8"
        );
        // Cut before the last column.
        assert_eq!(
            on_last_row("lost", size(5, 3)),
            "\x1b7\x1b[3;1H\x1b[0;7mstpt\x1b[0m\x1b[K\x1b8"
        );
        assert!(!on_last_row("lost", size(0, 1)).contains("stpt"));
    }

    #[test]
    fn retry_delays_grow_to_a_limit() {
        let delays: Vec<u64> = (0..8).map(|n| retry_delay(n).as_secs()).collect();
        assert_eq!(delays, [0, 1, 2, 4, 8, 16, 30, 30]);
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY_DELAY);
    }

    #[test]
    fn only_a_loss_in_transit_reattaches() {
        assert!(lost_in_transit(&quinn::ConnectionError::TimedOut));
        assert!(lost_in_transit(&quinn::ConnectionError::Reset));
        assert!(!lost_in_transit(&quinn::ConnectionError::LocallyClosed));
    }

    #[test]
    fn failures_that_no_retry_can_help_end_the_reattach() {
        let code = |c: wire::Code| Error::ChannelRejected(c as u64);
        assert!(worth_retrying(&Error::Transport(quic::Error::Connection(
            quinn::ConnectionError::TimedOut
        ))));
        assert!(worth_retrying(&Error::Protocol(Failure::new(
            wire::Code::Timeout,
            "no SERVER_HELLO"
        ))));
        assert!(worth_retrying(&code(wire::Code::LimitExceeded)));

        assert!(!worth_retrying(&code(wire::Code::SessionNotFound)));
        assert!(!worth_retrying(&Error::Protocol(Failure::violation("x"))));
        let fingerprint = ServerKey::generate().public_key().fingerprint();
        assert!(!worth_retrying(&Error::KeyChanged {
            address: "host".parse().unwrap(),
            stored: fingerprint,
            presented: fingerprint,
        }));
        assert!(!worth_retrying(&Error::AuthRejected {
            account: "alice".into(),
            fingerprint,
            key_line: String::new(),
        }));
    }

    #[test]
    fn escape_detaches_after_a_line_end() {
        let mut escape = Escape::new();
        assert_eq!(escape.filter(b"~."), (vec![], true));
        let mut escape = Escape::new();
        assert_eq!(escape.filter(b"ls ~.\r"), (b"ls ~.\r".to_vec(), false));
        // `~~` sends one `~`; another character after `~` is sent with it.
        assert_eq!(escape.filter(b"~~x\r~y"), (b"~x\r~y".to_vec(), false));
        // The escape may arrive split over reads.
        assert_eq!(escape.filter(b"\n~"), (b"\n".to_vec(), false));
        assert_eq!(escape.filter(b".rest"), (vec![], true));
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
