//! Client role: every subcommand except `server`.

use std::io::{self, IsTerminal, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

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
use crate::logging::{self, Role};
use crate::quic;
use crate::terminal::{self, Attached, Command, Exit, Open, SessionId, Size};
use crate::tls::{Expected, ServerKeyCheck, Verdict};
use crate::trust::{self, TrustStore};
use crate::wire::{
    self, DEFAULT_MESSAGE_LIMIT, Failure, Message, StreamError, TERMINAL_DATA, TERMINAL_EXIT,
    TERMINAL_STDERR,
};

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

    let (remote, action) = match command {
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
            (remote, Action::Terminal(interactive(name), true))
        }
        ClientCommand::Exec {
            remote,
            no_shell,
            command,
        } => (remote, Action::Terminal(exec(command, no_shell), false)),
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
    let mut connection = runtime.block_on(connect(&remote, addr, &mut store, ask_user))?;
    let hello = runtime.block_on(connection.hello(SERVER_HELLO_TIMEOUT))?;
    tracing::info!(
        version = format_args!("{:#x}", hello.version),
        "Connection established"
    );
    let account = &remote.destination.account;
    let accepted = runtime.block_on(connection.authenticate(account, &key, AUTH_RESULT_TIMEOUT))?;
    if !accepted {
        runtime.block_on(connection.close());
        return Err(Error::AuthRejected {
            account: account.clone(),
            fingerprint: key.public_key().fingerprint(),
            key_line: key.public_key().to_base64(),
        });
    }
    tracing::info!(%account, key = %key.public_key().fingerprint(), "Connection authenticated");
    let result = runtime.block_on(perform(&mut connection, action));
    runtime.block_on(connection.close());
    result
}

/// What a Client command does once the Connection is Authenticated.
enum Action {
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

async fn perform(connection: &mut Connection, action: Action) -> Result<ExitCode, Error> {
    match action {
        Action::Terminal(open, pty) => connection.terminal(open, pty).await.map(outcome_code),
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
            connection
                .terminal(open, session.pty)
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
        let (send, recv) = self
            .control
            .insert(self.connection.open_bi().await.map_err(StreamError::Lost)?);
        let _ = send.set_priority(control::CONTROL_PRIORITY);
        let offer = ClientHello::ours();
        wire::write_message(send, &offer.to_message(), DEFAULT_MESSAGE_LIMIT).await?;
        let message = reply(recv, deadline, "SERVER_HELLO", State::Handshaking).await?;
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
        let message = reply(recv, deadline, "AUTH_RESULT", State::Established).await?;
        Ok(auth::result_from_message(&message)?)
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

impl Connection {
    /// Opens a terminal Channel (§14.3) and relays local input and remote output until
    /// the remote program exits or the Attachment ends. With a PTY (`pty`) the local
    /// terminal is in raw mode meanwhile, and `Enter ~ .` detaches.
    async fn terminal(&mut self, open: Open, pty: bool) -> Result<Outcome, Error> {
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

        let terminated = console::termination().map_err(Error::Signals)?;
        let local = Console::setup(pty).map_err(Error::Terminal)?;
        let (input, inputs) = mpsc::channel(16);
        let from_stdin = input.clone();
        console::read_input(move |data| {
            let input = data.map_or(Input::Eof, Input::Data);
            from_stdin.blocking_send(input).is_ok()
        });
        let (detach, mut detached) = tokio::sync::oneshot::channel();
        let sender = tokio::spawn(send_input(send, inputs, pty, self.peer_limit, detach));
        let watcher = match open.size {
            Some(size) if console::size().is_some() => {
                Some(tokio::spawn(watch_size(input.clone(), size)))
            }
            _ => None,
        };
        let interrupted = async {
            if pty {
                // Ctrl+C is input for the remote PTY.
                std::future::pending().await
            } else {
                interrupts(input.clone()).await
            }
        };
        let session = attached.session;
        let result = tokio::select! {
            result = receive_output(&mut recv, pty) => result.map(Outcome::Exited),
            () = interrupted => Err(Received::Local(Error::Interrupted)),
            by = terminated => Err(Received::Local(Error::Terminated(by))),
            Ok(()) = &mut detached => Ok(Outcome::Detached(session)),
        };
        if let Some(watcher) = watcher {
            watcher.abort();
        }
        drop(local);
        // The Client's FIN: after the exit status, or a detach when the Client ends
        // early (§14.10); not worth waiting long for. The caller closes the Connection.
        let _ = input.try_send(Input::Finish);
        let _ = timeout(Duration::from_secs(1), sender).await;
        match result {
            Ok(outcome) => Ok(outcome),
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
            Err(Received::Stream(error)) => Err(self.failed(error).await),
        }
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

/// How long the Client waits for a REQUEST_RESULT; a termination may take the
/// Server's grace period and more.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The escape of the local terminal, as in ssh: after a line end, `~.` detaches and
/// `~~` sends one `~`; `~` before anything else is sent with it.
struct Escape {
    line_start: bool,
    after_tilde: bool,
}

impl Escape {
    fn new() -> Self {
        Self {
            line_start: true,
            after_tilde: false,
        }
    }

    /// The input to send, and whether `~.` was typed (input after it is dropped).
    fn filter(&mut self, data: &[u8]) -> (Vec<u8>, bool) {
        let mut out = Vec::with_capacity(data.len() + 1);
        for &byte in data {
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
            self.line_start = byte == b'\r' || byte == b'\n';
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
async fn send_input(
    mut send: quinn::SendStream,
    mut inputs: mpsc::Receiver<Input>,
    pty: bool,
    limit: u64,
    detach: tokio::sync::oneshot::Sender<()>,
) {
    let mut escape = Escape::new();
    while let Some(input) = inputs.recv().await {
        let message = match input {
            Input::Data(data) if pty => {
                let (data, detaching) = escape.filter(&data);
                if !data.is_empty() {
                    let message = terminal::data(TERMINAL_DATA, &data);
                    if wire::write_message(&mut send, &message, limit)
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
                if detaching {
                    // FIN: a detach (§14.10).
                    let _ = send.finish();
                    let _ = detach.send(());
                    let _ = send.stopped().await;
                    return;
                }
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
            return;
        }
    }
    let _ = send.finish();
    // Closing the Connection drops stream data not yet sent: wait until the Server
    // has the FIN, which confirms the exit status (§15.7).
    let _ = send.stopped().await;
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

/// Writes remote output until TERMINAL_EXIT (§14.7, §14.10).
async fn receive_output(recv: &mut quinn::RecvStream, pty: bool) -> Result<Exit, Received> {
    let local = |e| Received::Local(Error::Terminal(e));
    loop {
        let Some(message) = wire::read_message(recv, DEFAULT_MESSAGE_LIMIT).await? else {
            return Err(Received::Local(Error::TerminalEnded));
        };
        match message.kind {
            TERMINAL_DATA => console::write_out(terminal::data_of(&message)?).map_err(local)?,
            TERMINAL_STDERR if !pty => {
                console::write_err(terminal::data_of(&message)?).map_err(local)?;
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
                    store.add(address.clone(), key)?;
                    tracing::info!(%address, "Server key verified by fingerprint and stored");
                }
                tracing::debug!(%address, "TLS handshake completed, Server key trusted");
                return Ok(Connection {
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
