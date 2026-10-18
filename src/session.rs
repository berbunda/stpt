//! Server side of a terminal Channel (Unix; PROTOCOL.md §14, §15.5).
//!
//! A terminal Channel without a Session ID creates a Session: its program starts as
//! the Account, on a PTY or with pipes, and the Server relays input and output until
//! the program exits; then it sends the exit status and ends its direction of the
//! stream. Session persistence comes with Tier RD: until then a Session lives as long
//! as its Channel, an attach finds no Session, and a detach (Client FIN, reset, lost
//! Connection) ends the Session, as a closed terminal ends it: the PTY is closed, so the
//! processes get SIGHUP; without a PTY the pipes are closed.

use std::future::pending;
use std::time::Duration;

use nix::sys::signal::Signal;
use nix::unistd::Pid;
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::time::{Instant, sleep_until};

use crate::cbor::Value;
use crate::process::{self, Account, Io, Program};
use crate::pty::{Master, Pty};
use crate::terminal::{self, Attached, Command, Exit, Open, SessionId};
use crate::wire::{
    self, Code, DEFAULT_MESSAGE_LIMIT, Failure, Message, StreamError, TERMINAL_DATA, TERMINAL_EOF,
    TERMINAL_RESIZE, TERMINAL_SIGNAL, TERMINAL_STDERR,
};

/// Size of one read of output; one TERMINAL_DATA carries at most this much.
const READ_SIZE: usize = 16 * 1024;

/// Attachment ID of the creating Attachment (§15.9).
const FIRST_ATTACHMENT: u64 = 1;

/// A terminal Channel stream with what the Server knows about its Connection.
pub struct Channel {
    pub send: SendStream,
    pub recv: RecvStream,
    /// Message size limit of the Client.
    pub peer_limit: u64,
    /// The Account of the Connection (§12.4).
    pub account: String,
    /// Remote address, for the log.
    pub remote: std::net::SocketAddr,
}

/// How a terminal Channel ends badly.
#[derive(Debug)]
pub enum Stop {
    /// The Client violated the protocol: the Connection is closed (§0.2).
    Close(Failure),
    /// A local error: only this stream is reset with the code (§14.10).
    Reset(Failure),
    /// The Client reset or stopped the stream, or the Connection is gone.
    Gone,
}

impl From<StreamError> for Stop {
    fn from(error: StreamError) -> Self {
        match error {
            StreamError::Failure(f) if f.code == Code::InternalError => Self::Reset(f),
            StreamError::Failure(f) => Self::Close(f),
            StreamError::Reset(_) | StreamError::Lost(_) => Self::Gone,
        }
    }
}

impl From<Failure> for Stop {
    fn from(failure: Failure) -> Self {
        Self::Close(failure)
    }
}

/// Serves a terminal Channel whose CHANNEL_OPEN was `open`. `Err(failure)`: the
/// Connection is to be closed with it.
pub async fn serve(mut channel: Channel, open: &Message, grace: Duration) -> Result<(), Failure> {
    let open = match Open::from_message(open) {
        Ok(open) => open,
        Err(failure) => {
            reject(&mut channel, failure);
            return Ok(());
        }
    };
    if open.session.is_some() {
        // No Session outlives its Channel yet (Tier RD), so every ID is unknown.
        reject(
            &mut channel,
            Failure::new(Code::SessionNotFound, "attach: no such Session"),
        );
        return Ok(());
    }
    let session = SessionId::generate();
    let (account, started) = match start(&channel.account, &open, session).await {
        Ok(started) => started,
        Err(reason) => {
            reject(&mut channel, Failure::new(Code::ChannelRejected, reason));
            return Ok(());
        }
    };
    tracing::info!(
        remote = %channel.remote,
        account = ?channel.account,
        %session,
        pty = open.size.is_some(),
        "Session created"
    );
    let attached = Attached {
        session,
        attachment: FIRST_ATTACHMENT,
        offset: 0,
    };
    let result = match wire::write_message(
        &mut channel.send,
        &attached.to_message(),
        channel.peer_limit,
    )
    .await
    {
        Ok(()) => relay(&mut channel, &account, started, grace).await,
        Err(error) => Err(error.into()),
    };
    match result {
        Ok(end) => {
            tracing::info!(remote = %channel.remote, %session, %end, "Session ended");
            Ok(())
        }
        Err(Stop::Close(failure)) => Err(failure),
        Err(Stop::Reset(failure)) => {
            tracing::warn!(remote = %channel.remote, %session, reason = %failure, "Channel reset");
            let _ = channel.send.reset(failure.code.varint());
            let _ = channel.recv.stop(failure.code.varint());
            Ok(())
        }
        Err(Stop::Gone) => {
            tracing::info!(remote = %channel.remote, %session, "Channel abandoned, Session ended");
            Ok(())
        }
    }
}

/// Rejects the Channel: RESET_STREAM and STOP_SENDING with the code (§8.3).
fn reject(channel: &mut Channel, failure: Failure) {
    tracing::info!(
        remote = %channel.remote,
        code = failure.code.name(),
        reason = %failure.reason,
        "terminal Channel rejected"
    );
    let _ = channel.send.reset(failure.code.varint());
    let _ = channel.recv.stop(failure.code.varint());
}

/// A started Session program with its input and output.
enum Started {
    Pty { master: Master, child: Child },
    Pipes { child: Child },
}

/// Environment variables taken from the Client (§14.6): the default allowlist.
fn allowed(name: &str) -> bool {
    name == "LANG" || name.starts_with("LC_")
}

/// Starts the program of a new Session as the Account; a failure is the reason to
/// reject it.
async fn start(
    account: &str,
    open: &Open,
    session: SessionId,
) -> Result<(Account, Started), String> {
    let name = account.to_owned();
    let (account, system) = tokio::task::spawn_blocking(move || {
        let system = process::system_environment(&process::SYSTEM_ENVIRONMENT);
        (Account::lookup(&name), system)
    })
    .await
    .map_err(|e| e.to_string())?;
    let account = account
        .map_err(|e| format!("Account lookup: {e}"))?
        .ok_or("the Account no longer exists")?;
    let program = match &open.command {
        None => Program::LoginShell,
        Some(Command::Line(line)) => Program::Shell(line.clone()),
        Some(Command::Argv(argv)) => Program::Argv(argv.clone()),
    };
    // Later variables win: the Client's locale over the system's (as AcceptEnv).
    let mut env = system;
    env.extend(open.env.iter().filter(|(name, _)| allowed(name)).cloned());
    env.push(("STPT_SESSION".to_owned(), session.to_string()));
    let spawn_failed = |e| format!("starting the program: {e}");
    match (open.size, &open.term) {
        (Some(size), Some(term)) => {
            let Pty { master, slave } = Pty::open(size).map_err(|e| format!("PTY: {e}"))?;
            let io = Io::Pty {
                slave,
                term: term.clone(),
            };
            let child = process::spawn(&account, &program, &env, io).map_err(spawn_failed)?;
            Ok((account, Started::Pty { master, child }))
        }
        _ => {
            let child =
                process::spawn(&account, &program, &env, Io::Pipes).map_err(spawn_failed)?;
            Ok((account, Started::Pipes { child }))
        }
    }
}

/// How a Session ended for its Channel.
enum End {
    /// The program exited; its status was sent.
    Exited(Exit),
    /// The Client ended its direction (detach).
    Detached,
}

impl std::fmt::Display for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exited(exit) => write!(f, "exited: {exit:?}"),
            Self::Detached => f.write_str("detached by the Client"),
        }
    }
}

/// Relays input and output until the program exits or the Client detaches.
async fn relay(
    channel: &mut Channel,
    account: &Account,
    started: Started,
    grace: Duration,
) -> Result<End, Stop> {
    let limit = channel.peer_limit;
    let (exit, send, recv) = match started {
        Started::Pty { master, mut child } => {
            let mut source = Output::Pty(&master);
            let input = pty_input(&master, account, &mut channel.recv);
            let output = pump(&mut source, &mut child, &mut channel.send, limit, grace);
            match first(input, output).await? {
                Either::Input => return detached(&mut channel.send),
                Either::Output(exit) => (exit, &mut channel.send, &mut channel.recv),
            }
        }
        Started::Pipes { mut child } => {
            let stdin = child.stdin.take();
            // The program leads its own process group (`process::spawn`).
            let group = child.id().map(|pid| Pid::from_raw(pid as i32));
            let mut source = Output::Pipes {
                stdout: child.stdout.take(),
                stderr: child.stderr.take(),
                buf: vec![0; READ_SIZE],
            };
            let input = pipe_input(stdin, group, account, &mut channel.recv);
            let output = pump(&mut source, &mut child, &mut channel.send, limit, grace);
            match first(input, output).await? {
                Either::Input => return detached(&mut channel.send),
                Either::Output(exit) => (exit, &mut channel.send, &mut channel.recv),
            }
        }
    };
    let _ = send.finish();
    // Messages of the Client that crossed TERMINAL_EXIT are ignored (§14.10).
    while let Ok(Some(_)) = recv.read_chunk(usize::MAX, true).await {}
    Ok(End::Exited(exit))
}

fn detached(send: &mut SendStream) -> Result<End, Stop> {
    let _ = send.finish();
    Ok(End::Detached)
}

enum Either {
    Input,
    Output(Exit),
}

/// Runs input and output until one of them ends: input at the Client's FIN, output
/// after the exit status was sent.
async fn first(
    input: impl Future<Output = Result<(), Stop>>,
    output: impl Future<Output = Result<Exit, Stop>>,
) -> Result<Either, Stop> {
    tokio::select! {
        result = input => result.map(|()| Either::Input),
        result = output => result.map(Either::Output),
    }
}

/// The next input message, checked to belong to a terminal Channel from the Client
/// (§14.7–§14.9); `None` at the Client's FIN.
async fn next_input(recv: &mut RecvStream) -> Result<Option<Message>, Stop> {
    let Some(message) = wire::read_message(recv, DEFAULT_MESSAGE_LIMIT).await? else {
        return Ok(None);
    };
    match message.kind {
        TERMINAL_DATA => {
            terminal::data_of(&message)?;
        }
        TERMINAL_EOF => {}
        TERMINAL_RESIZE => check_resize(&message)?,
        TERMINAL_SIGNAL => {
            signal_of(&message)?;
        }
        kind => {
            return Err(Failure::violation(format!(
                "message type {kind} on a terminal Channel from the Client"
            ))
            .into());
        }
    }
    Ok(Some(message))
}

fn check_resize(message: &Message) -> Result<(), Failure> {
    terminal::Size::from_resize(message).map(|_| ())
}

/// The signal of a TERMINAL_SIGNAL: an id the Client may send, not one marked
/// "report only" (§14.9).
fn signal_of(message: &Message) -> Result<Signal, Failure> {
    let invalid = || Failure::violation("TERMINAL_SIGNAL: invalid signal id");
    match message.field(0) {
        Some(Value::Uint(id @ 1..=terminal::MAX_SENDABLE_SIGNAL)) => terminal::platform_signal(*id)
            .and_then(|number| Signal::try_from(number).ok())
            .ok_or_else(invalid),
        _ => Err(invalid()),
    }
}

/// Sends a signal to a process group of the Session with the permissions of the
/// Account; a target that no longer exists ignores it (§14.9).
async fn deliver(account: &Account, group: Pid, signal: Signal) {
    match process::signal_group(account, group, signal).await {
        Ok(()) => tracing::debug!(?signal, group = group.as_raw(), "signal delivered"),
        Err(e) => {
            tracing::debug!(?signal, group = group.as_raw(), error = %e, "signal not delivered")
        }
    }
}

/// Input of a PTY Session until the Client's FIN.
async fn pty_input(master: &Master, account: &Account, recv: &mut RecvStream) -> Result<(), Stop> {
    while let Some(message) = next_input(recv).await? {
        match message.kind {
            TERMINAL_DATA => {
                let data = terminal::data_of(&message)?;
                if let Err(e) = master.write_all(data).await {
                    tracing::debug!(error = %e, "PTY input dropped");
                }
            }
            TERMINAL_EOF => {
                return Err(Failure::violation("TERMINAL_EOF on a Channel with a PTY").into());
            }
            // §14.8: between the input sent before and after it.
            TERMINAL_RESIZE => {
                if let Err(e) = master.resize(terminal::Size::from_resize(&message)?) {
                    tracing::debug!(error = %e, "PTY resize failed");
                }
            }
            // §14.9: to the foreground process group of the PTY.
            _ => {
                let signal = signal_of(&message)?;
                match master.foreground_group() {
                    Ok(group) => deliver(account, group, signal).await,
                    Err(e) => tracing::debug!(error = %e, "no foreground process group"),
                }
            }
        }
    }
    Ok(())
}

/// Input of a Session without a PTY until the Client's FIN; signals go to the
/// process group `group` of the command.
async fn pipe_input(
    mut stdin: Option<ChildStdin>,
    group: Option<Pid>,
    account: &Account,
    recv: &mut RecvStream,
) -> Result<(), Stop> {
    let mut eof = false;
    while let Some(message) = next_input(recv).await? {
        match message.kind {
            TERMINAL_DATA if eof => {
                return Err(Failure::violation("TERMINAL_DATA after TERMINAL_EOF").into());
            }
            TERMINAL_DATA => {
                let data = terminal::data_of(&message)?;
                // A program that closed its input no longer gets any.
                if let Some(pipe) = &mut stdin
                    && pipe.write_all(data).await.is_err()
                {
                    stdin = None;
                }
            }
            TERMINAL_EOF if eof => {
                return Err(Failure::violation("second TERMINAL_EOF").into());
            }
            TERMINAL_EOF => {
                eof = true;
                stdin = None;
            }
            TERMINAL_RESIZE => {
                return Err(Failure::violation("TERMINAL_RESIZE without a PTY").into());
            }
            // §14.9: also after TERMINAL_EOF.
            _ => {
                let signal = signal_of(&message)?;
                if let Some(group) = group {
                    deliver(account, group, signal).await;
                }
            }
        }
    }
    Ok(())
}

/// Output of the program: the PTY master, or standard output and error.
enum Output<'a> {
    Pty(&'a Master),
    Pipes {
        stdout: Option<ChildStdout>,
        stderr: Option<ChildStderr>,
        buf: Vec<u8>,
    },
}

impl Output<'_> {
    /// The next piece of output as a message; `None` at the end of all output.
    /// Cancel safe: nothing is read unless it is returned.
    async fn next(&mut self, buf: &mut [u8]) -> std::io::Result<Option<Message>> {
        match self {
            Self::Pty(master) => match master.read(buf).await? {
                0 => Ok(None),
                n => Ok(Some(terminal::data(TERMINAL_DATA, &buf[..n]))),
            },
            Self::Pipes {
                stdout,
                stderr,
                buf: err_buf,
            } => loop {
                let (kind, n) = tokio::select! {
                    n = read(stdout, buf), if stdout.is_some() => (TERMINAL_DATA, n?),
                    n = read(stderr, err_buf), if stderr.is_some() => (TERMINAL_STDERR, n?),
                    else => return Ok(None),
                };
                if n == 0 {
                    match kind {
                        TERMINAL_DATA => *stdout = None,
                        _ => *stderr = None,
                    }
                    continue;
                }
                let data = if kind == TERMINAL_DATA {
                    &buf[..n]
                } else {
                    &err_buf[..n]
                };
                return Ok(Some(terminal::data(kind, data)));
            },
        }
    }
}

async fn read(
    pipe: &mut Option<impl tokio::io::AsyncRead + Unpin>,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    match pipe {
        Some(pipe) => pipe.read(buf).await,
        None => pending().await,
    }
}

/// Sends output until its end, or until the grace period after the program exited
/// has passed; then TERMINAL_EXIT (§14.10).
async fn pump(
    output: &mut Output<'_>,
    child: &mut Child,
    send: &mut SendStream,
    limit: u64,
    grace: Duration,
) -> Result<Exit, Stop> {
    let mut buf = vec![0; READ_SIZE];
    let mut status = None;
    let mut deadline = None;
    loop {
        let grace_over = async {
            match deadline {
                Some(deadline) => sleep_until(deadline).await,
                None => pending().await,
            }
        };
        tokio::select! {
            next = output.next(&mut buf) => match next {
                Ok(Some(message)) => wire::write_message(send, &message, limit).await?,
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(error = %e, "reading output");
                    break;
                }
            },
            exited = child.wait(), if status.is_none() => {
                status = Some(exited.map_err(|e| Stop::Reset(waiting_failed(e)))?);
                deadline = Some(Instant::now() + grace);
            }
            () = grace_over => break,
        }
    }
    let status = match status {
        Some(status) => status,
        None => child
            .wait()
            .await
            .map_err(|e| Stop::Reset(waiting_failed(e)))?,
    };
    let exit = Exit::from_status(status);
    wire::write_message(send, &exit.to_message(), limit).await?;
    Ok(exit)
}

fn waiting_failed(error: std::io::Error) -> Failure {
    Failure::new(
        Code::InternalError,
        format!("waiting for the program: {error}"),
    )
}
