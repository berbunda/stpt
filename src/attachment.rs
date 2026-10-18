//! Server side of a terminal Channel (Unix; PROTOCOL.md §14, §15.9): it creates a
//! Session or attaches to one, then relays between the Channel and the Session as
//! one of its Attachments. The Session outlives the Channel: the Client's FIN is a
//! detach (§14.10).

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use nix::sys::signal::Signal;
use quinn::{RecvStream, SendStream};
use tokio::sync::{mpsc, watch};

use crate::authorized::KeyInfo;
use crate::buffer::Replay;
use crate::cbor::Value;
use crate::session::{AttachRequest, AttachmentInfo, Event, Session, Store};
use crate::terminal::{self, Attached, Exit, Open, SessionId};
use crate::wire::{
    self, Code, DEFAULT_MESSAGE_LIMIT, Failure, Message, StreamError, TERMINAL_DATA, TERMINAL_EOF,
    TERMINAL_RESIZE, TERMINAL_SIGNAL,
};

/// A terminal Channel stream with what the Server knows about its Connection.
pub struct Channel {
    pub send: SendStream,
    pub recv: RecvStream,
    /// Message size limit of the Client.
    pub peer_limit: u64,
    /// The Account of the Connection (§12.4) and the key it authenticated with.
    pub account: String,
    pub key: KeyInfo,
    pub connection: quinn::Connection,
    /// Sessions this Connection is attached to: at most one Channel each (§14.3).
    pub attached: Arc<Mutex<HashSet<SessionId>>>,
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
pub async fn serve(
    mut channel: Channel,
    open: &Message,
    store: &Arc<Store>,
) -> Result<(), Failure> {
    let open = match Open::from_message(open) {
        Ok(open) => open,
        Err(failure) => {
            reject(&mut channel, failure);
            return Ok(());
        }
    };
    let (session, attachment) = match attach(&channel, &open, store).await {
        Ok(attached) => attached,
        Err(failure) => {
            reject(&mut channel, failure);
            return Ok(());
        }
    };
    channel.attached.lock().unwrap().insert(session.id);
    let id = attachment.id;
    tracing::info!(
        remote = %channel.connection.remote_address(),
        session = %session.id,
        attachment = id,
        offset = attachment.offset,
        "attached"
    );
    let result = relay(&mut channel, &session, attachment, store).await;
    session.detach(id);
    channel.attached.lock().unwrap().remove(&session.id);
    let remote = channel.connection.remote_address();
    match result {
        Ok(end) => {
            tracing::info!(%remote, session = %session.id, attachment = id, %end, "Attachment ended");
            Ok(())
        }
        Err(Stop::Close(failure)) => Err(failure),
        Err(Stop::Reset(failure)) => {
            tracing::warn!(%remote, session = %session.id, reason = %failure, "Channel reset");
            let _ = channel.send.reset(failure.code.varint());
            let _ = channel.recv.stop(failure.code.varint());
            Ok(())
        }
        Err(Stop::Gone) => {
            tracing::info!(%remote, session = %session.id, attachment = id, "Attachment lost");
            Ok(())
        }
    }
}

/// Creates the Session or finds the one to attach to, and adds this Attachment.
async fn attach(
    channel: &Channel,
    open: &Open,
    store: &Arc<Store>,
) -> Result<(Arc<Session>, crate::session::Attachment), Failure> {
    let info = AttachmentInfo {
        attached: SystemTime::now(),
        key: channel.key.clone(),
        connection: channel.connection.clone(),
    };
    let Some(id) = open.session else {
        let session = store
            .create(&channel.account, channel.key.clone(), open)
            .await?;
        // The creator receives all output from the start.
        let request = AttachRequest {
            replay: Replay::Resume(0),
            read_only: false,
            takeover: false,
            size: None,
            info,
        };
        let attachment = session.attach(request)?;
        return Ok((session, attachment));
    };
    if channel.attached.lock().unwrap().contains(&id) {
        return Err(Failure::new(
            Code::ChannelRejected,
            "this Connection is attached to the Session already",
        ));
    }
    let session = store
        .get(&channel.account, id)
        .ok_or_else(|| Failure::new(Code::SessionNotFound, "attach: no such Session"))?;
    let request = AttachRequest {
        replay: match open.resume {
            Some(offset) => Replay::Resume(offset),
            None => Replay::Fresh(store.policy.fresh_replay),
        },
        read_only: open.read_only.unwrap_or(false),
        takeover: open.takeover.unwrap_or(false),
        size: open.size,
        info,
    };
    let attachment = session.attach(request)?;
    Ok((session, attachment))
}

/// Rejects the Channel: RESET_STREAM and STOP_SENDING with the code (§8.3).
fn reject(channel: &mut Channel, failure: Failure) {
    tracing::info!(
        remote = %channel.connection.remote_address(),
        code = failure.code.name(),
        reason = %failure.reason,
        "terminal Channel rejected"
    );
    let _ = channel.send.reset(failure.code.varint());
    let _ = channel.recv.stop(failure.code.varint());
}

/// How an Attachment ended.
enum End {
    /// The exit status was sent; `confirmed` if the Client's FIN followed (§15.7).
    Exited { exit: Exit, confirmed: bool },
    /// The Client ended its direction.
    Detached,
    /// The Server ended the Attachment with this code (§14.10).
    ByServer(Code),
}

impl std::fmt::Display for End {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exited { exit, confirmed } => {
                let how = if *confirmed {
                    "confirmed"
                } else {
                    "not confirmed"
                };
                write!(f, "exit status sent ({how}): {exit:?}")
            }
            Self::Detached => f.write_str("detached by the Client"),
            Self::ByServer(code) => write!(f, "ended by the Server: {}", code.name()),
        }
    }
}

/// Sends TERMINAL_ATTACHED and the replay, then relays until the program exits,
/// the Client detaches or the Server ends the Attachment.
async fn relay(
    channel: &mut Channel,
    session: &Arc<Session>,
    attachment: crate::session::Attachment,
    store: &Store,
) -> Result<End, Stop> {
    let limit = channel.peer_limit;
    let send = &mut channel.send;
    let attached = Attached {
        session: session.id,
        attachment: attachment.id,
        offset: attachment.offset,
    };
    wire::write_message(send, &attached.to_message(), limit).await?;
    for (kind, data) in &attachment.replay {
        wire::write_message(send, &terminal::data(*kind, data), limit).await?;
    }
    if attachment.redraw {
        let session = session.clone();
        tokio::spawn(async move { session.redraw().await });
    }
    let ended = match attachment.exited {
        Some(exit) => {
            wire::write_message(send, &exit.to_message(), limit).await?;
            Ended::Exit(exit)
        }
        None => {
            let (mut events, mut end) = (attachment.events, attachment.end);
            let read_only = attachment.read_only;
            let input = input(session, attachment.id, read_only, &mut channel.recv);
            let output = output(send, &mut events, &mut end, limit);
            match first(input, output).await? {
                None => {
                    let _ = channel.send.finish();
                    return Ok(End::Detached);
                }
                Some(ended) => ended,
            }
        }
    };
    match ended {
        Ended::Exit(exit) => {
            let _ = channel.send.finish();
            // Messages of the Client that crossed TERMINAL_EXIT are ignored; its FIN
            // confirms the exit status (§14.10, §15.7).
            let confirmed = loop {
                match channel.recv.read_chunk(usize::MAX, true).await {
                    Ok(Some(_)) => continue,
                    Ok(None) => break true,
                    Err(_) => break false,
                }
            };
            if confirmed {
                session.exit_delivered(store);
            }
            Ok(End::Exited { exit, confirmed })
        }
        Ended::ByServer(Code::NoError) => {
            let _ = channel.send.finish();
            Ok(End::ByServer(Code::NoError))
        }
        Ended::ByServer(code) => {
            let _ = channel.send.reset(code.varint());
            let _ = channel.recv.stop(code.varint());
            Ok(End::ByServer(code))
        }
    }
}

/// Runs input and output until one of them ends: `None` at the Client's FIN,
/// `Some` when output ended.
async fn first(
    input: impl Future<Output = Result<(), Stop>>,
    output: impl Future<Output = Result<Ended, Stop>>,
) -> Result<Option<Ended>, Stop> {
    tokio::select! {
        result = input => result.map(|()| None),
        result = output => result.map(Some),
    }
}

enum Ended {
    Exit(Exit),
    ByServer(Code),
}

/// Sends the Session's output and finally its exit status, unless the Server ends
/// the Attachment first.
async fn output(
    send: &mut SendStream,
    events: &mut mpsc::Receiver<Event>,
    end: &mut watch::Receiver<Option<Code>>,
    limit: u64,
) -> Result<Ended, Stop> {
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(Event::Output((kind, data))) => {
                    wire::write_message(send, &terminal::data(kind, &data), limit).await?;
                }
                Some(Event::Exit(exit)) => {
                    wire::write_message(send, &exit.to_message(), limit).await?;
                    return Ok(Ended::Exit(exit));
                }
                // The Session dropped this Attachment; its reason follows on `end`.
                None => {
                    let _ = end.wait_for(Option::is_some).await;
                    return Ok(Ended::ByServer(end.borrow().unwrap_or(Code::NoError)));
                }
            },
            changed = end.changed() => {
                let code = if changed.is_ok() { *end.borrow() } else { None };
                return Ok(Ended::ByServer(code.unwrap_or(Code::NoError)));
            }
        }
    }
}

/// Input of the Client until its FIN (§14.7–§14.9, §15.9).
async fn input(
    session: &Session,
    id: u64,
    read_only: bool,
    recv: &mut RecvStream,
) -> Result<(), Stop> {
    let pty = session.pty();
    let mut eof = false;
    while let Some(message) = wire::read_message(recv, DEFAULT_MESSAGE_LIMIT).await? {
        let violation =
            |reason: &str| -> Result<(), Stop> { Err(Failure::violation(reason).into()) };
        if read_only
            && matches!(
                message.kind,
                TERMINAL_DATA | TERMINAL_EOF | TERMINAL_RESIZE | TERMINAL_SIGNAL
            )
        {
            return violation("input on a read-only Attachment");
        }
        match message.kind {
            TERMINAL_DATA if eof => return violation("TERMINAL_DATA after TERMINAL_EOF"),
            TERMINAL_DATA => session.input(id, terminal::data_of(&message)?).await,
            TERMINAL_EOF if pty => return violation("TERMINAL_EOF on a Channel with a PTY"),
            TERMINAL_EOF if eof => return violation("second TERMINAL_EOF"),
            TERMINAL_EOF => {
                eof = true;
                session.close_input().await;
            }
            TERMINAL_RESIZE if !pty => return violation("TERMINAL_RESIZE without a PTY"),
            // §14.8: between the input sent before and after it.
            TERMINAL_RESIZE => session.resize(id, terminal::Size::from_resize(&message)?),
            // §14.9: also after TERMINAL_EOF.
            TERMINAL_SIGNAL => session.signal(signal_of(&message)?).await,
            kind => {
                return Err(Failure::violation(format!(
                    "message type {kind} on a terminal Channel from the Client"
                ))
                .into());
            }
        }
    }
    Ok(())
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
