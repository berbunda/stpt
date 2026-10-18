//! Sessions of the Server (Unix; PROTOCOL.md §3.2, §15).
//!
//! The store holds every Session of the Server. A Session owns its processes and
//! their output: one task reads the output, numbers it into the output buffer and
//! hands it to the Attachments, with or without any, so the processes never block on
//! a full PTY or pipe (§15.5). Attachments (terminal Channels, `attachment`) come and
//! go; the Session outlives them. Retention Policy and termination requests end
//! Sessions.

use std::collections::BTreeMap;
use std::future::pending;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

use nix::sys::signal::Signal;
use nix::unistd::Pid;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep_until, timeout};

use crate::authorized::KeyInfo;
use crate::buffer::{OutputBuffer, Piece, Replay};
use crate::modes::Modes;
use crate::process::{self, Account, Io, Program};
use crate::pty::{Master, Pty};
use crate::terminal::{Command, Exit, Open, SessionId, Size};
use crate::wire::{Code, Failure, TERMINAL_DATA, TERMINAL_STDERR};

/// Retention Policy and limits (§14.10, §15.6, §15.8, §15.9, §15.11).
#[derive(Debug, Clone, Copy)]
pub struct Policy {
    /// Output still sent after the primary process exited.
    pub exit_grace: Duration,
    /// Time between HUP or TERM and KILL when a Session is terminated.
    pub termination_grace: Duration,
    /// How long an Exited Session waits for its exit status to be delivered.
    pub exited_retention: Duration,
    pub sessions_per_account: usize,
    pub attachments_per_session: usize,
    /// How long output may wait for one Attachment before it is ended.
    pub stall_limit: Duration,
    pub buffer_size: usize,
    /// Most bytes replayed on a fresh attach.
    pub fresh_replay: usize,
}

impl Policy {
    pub const DEFAULT: Self = Self {
        exit_grace: Duration::from_secs(1),
        termination_grace: Duration::from_secs(5),
        exited_retention: Duration::from_secs(24 * 60 * 60),
        sessions_per_account: 64,
        attachments_per_session: 8,
        stall_limit: Duration::from_secs(10),
        buffer_size: 256 * 1024,
        fresh_replay: 16 * 1024,
    };
}

/// Size of one read of output; one TERMINAL_DATA carries at most this much.
const READ_SIZE: usize = 16 * 1024;

/// Longest command shown in the Session list, in bytes (§15.10).
const COMMAND_DISPLAY: usize = 256;

/// Events queued for one Attachment before the output task waits for it.
const EVENT_QUEUE: usize = 8;

/// How often Retention Policy is applied.
const REAPER_TICK: Duration = Duration::from_secs(1);

/// How long the PTY keeps the other size during a redraw, so the programs see it.
const REDRAW_PAUSE: Duration = Duration::from_millis(100);

/// After KILL, how long a termination waits for the processes before it is done
/// anyway: a process in an uninterruptible wait must not delay it (§15.6).
const AFTER_KILL: Duration = Duration::from_secs(1);

/// All Sessions of the Server, ordered by ID (§15.10).
pub struct Store {
    sessions: Mutex<BTreeMap<SessionId, Arc<Session>>>,
    pub policy: Policy,
}

impl Store {
    /// A new store; applies Retention Policy in a task of the current runtime.
    pub fn start(policy: Policy) -> Arc<Self> {
        let store = Arc::new(Self {
            sessions: Mutex::new(BTreeMap::new()),
            policy,
        });
        tokio::spawn(store.clone().reaper());
        store
    }

    /// Creates a Session for `owner` and starts its program (§15.5). A failure
    /// carries the code to reject the Channel with.
    pub async fn create(
        self: &Arc<Self>,
        owner: &str,
        creator: KeyInfo,
        open: &Open,
    ) -> Result<Arc<Session>, Failure> {
        let rejected = |reason: String| Failure::new(Code::ChannelRejected, reason);
        let name = owner.to_owned();
        let (account, system) = tokio::task::spawn_blocking(move || {
            let system = process::system_environment(&process::SYSTEM_ENVIRONMENT);
            (Account::lookup(&name), system)
        })
        .await
        .map_err(|e| rejected(e.to_string()))?;
        let account = account
            .map_err(|e| rejected(format!("Account lookup: {e}")))?
            .ok_or_else(|| rejected("the Account no longer exists".into()))?;

        let id = SessionId::generate();
        let program = match &open.command {
            None => Program::LoginShell,
            Some(Command::Line(line)) => Program::Shell(line.clone()),
            Some(Command::Argv(argv)) => Program::Argv(argv.clone()),
        };
        // Later variables win: the Client's locale over the system's (as AcceptEnv).
        let mut env = system;
        env.extend(open.env.iter().filter(|(name, _)| allowed(name)).cloned());
        env.push(("STPT_SESSION".to_owned(), id.to_string()));

        let mut sessions = self.lock();
        let mine: Vec<&Arc<Session>> = sessions.values().filter(|s| s.owner == owner).collect();
        if mine.len() >= self.policy.sessions_per_account {
            return Err(Failure::new(
                Code::LimitExceeded,
                format!("{} Sessions of the Account", mine.len()),
            ));
        }
        if let Some(name) = &open.name
            && mine.iter().any(|s| s.name.as_ref() == Some(name))
        {
            return Err(Failure::new(
                Code::SessionNameInUse,
                format!("Session name {name:?} in use"),
            ));
        }
        let spawn_failed = |e| rejected(format!("starting the program: {e}"));
        let (io, output, child) = match (open.size, &open.term) {
            (Some(size), Some(term)) => {
                let Pty { master, slave } =
                    Pty::open(size).map_err(|e| rejected(format!("PTY: {e}")))?;
                let slave = Io::Pty {
                    slave,
                    term: term.clone(),
                };
                let child =
                    process::spawn(&account, &program, &env, slave).map_err(spawn_failed)?;
                let master = Arc::new(master);
                (SessionIo::Pty(master.clone()), Output::Pty(master), child)
            }
            _ => {
                let mut child =
                    process::spawn(&account, &program, &env, Io::Pipes).map_err(spawn_failed)?;
                let output = Output::Pipes {
                    stdout: child.stdout.take(),
                    stderr: child.stderr.take(),
                    err_buf: vec![0; READ_SIZE],
                };
                let stdin = tokio::sync::Mutex::new(child.stdin.take());
                (SessionIo::Pipes(stdin), output, child)
            }
        };
        let session = Arc::new(Session {
            id,
            owner: owner.to_owned(),
            name: open.name.clone(),
            created: SystemTime::now(),
            creator,
            command: open.command.as_ref().map(display),
            leader: child.id().map(|pid| Pid::from_raw(pid as i32)),
            account,
            io,
            detach_timeout: open.detach_timeout.map(Duration::from_secs),
            policy: self.policy,
            inner: Mutex::new(Inner {
                state: State::Running,
                buffer: OutputBuffer::new(self.policy.buffer_size),
                slots: Vec::new(),
                next_attachment: 1,
                active: None,
                size: open.size,
                idle_since: Some(Instant::now()),
                exited_at: None,
                modes: Modes::new(),
            }),
            terminated: watch::channel(false).0,
        });
        sessions.insert(id, session.clone());
        drop(sessions);
        tracing::info!(
            account = ?owner,
            session = %id,
            name = ?session.name,
            pty = session.pty(),
            "Session created"
        );
        tokio::spawn(session.clone().run(self.clone(), child, output));
        Ok(session)
    }

    /// The Session `id` if `owner` owns it; a foreign Session is handled exactly as
    /// an unknown one (§15.2).
    pub fn get(&self, owner: &str, id: SessionId) -> Option<Arc<Session>> {
        self.lock().get(&id).filter(|s| s.owner == owner).cloned()
    }

    /// The Sessions of `owner`, ordered by ID.
    pub fn list(&self, owner: &str) -> Vec<Arc<Session>> {
        let sessions = self.lock();
        sessions
            .values()
            .filter(|s| s.owner == owner)
            .cloned()
            .collect()
    }

    fn lock(&self) -> MutexGuard<'_, BTreeMap<SessionId, Arc<Session>>> {
        self.sessions.lock().expect("store lock")
    }

    fn remove(&self, id: SessionId) {
        self.lock().remove(&id);
    }

    /// Applies Retention Policy and detach timeouts (§15.8).
    async fn reaper(self: Arc<Self>) {
        let mut tick = tokio::time::interval(REAPER_TICK);
        loop {
            tick.tick().await;
            let sessions: Vec<Arc<Session>> = self.lock().values().cloned().collect();
            let now = Instant::now();
            for session in sessions {
                let due = {
                    let inner = session.lock();
                    session.deadline(&inner).is_some_and(|d| d <= now)
                };
                if due {
                    tracing::info!(session = %session.id, "Retention Policy ends the Session");
                    let (session, store) = (session.clone(), self.clone());
                    tokio::spawn(async move { session.terminate(&store, false).await });
                }
            }
        }
    }
}

/// Environment variables taken from the Client (§14.6): the default allowlist.
fn allowed(name: &str) -> bool {
    name == "LANG" || name.starts_with("LC_")
}

/// The command for display (§15.10): an argument vector joined with spaces, at most
/// 256 bytes, cut at a character boundary.
fn display(command: &Command) -> String {
    let mut text = match command {
        Command::Line(line) => line.clone(),
        Command::Argv(argv) => argv.join(" "),
    };
    if text.len() > COMMAND_DISPLAY {
        let mut end = COMMAND_DISPLAY;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// Session state (§3.2); Starting is not visible, as a Session enters the store
/// only once its program runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Running,
    Exited(Exit),
    Terminating,
    Terminated,
}

/// What an Attachment receives from its Session.
#[derive(Debug, Clone)]
pub enum Event {
    Output(Piece),
    Exit(Exit),
}

/// Who is attached, for the Session list (§15.10).
#[derive(Debug, Clone)]
pub struct AttachmentInfo {
    pub attached: SystemTime,
    pub key: KeyInfo,
    /// Its Connection, for the current remote address.
    pub connection: quinn::Connection,
}

struct Slot {
    id: u64,
    events: mpsc::Sender<Event>,
    /// Set when the Server ends the Attachment: NO_ERROR for a detach (takeover,
    /// detach request, removal), TIMEOUT for a stall (§14.10).
    end: watch::Sender<Option<Code>>,
    read_only: bool,
    size: Option<Size>,
    info: AttachmentInfo,
}

struct Inner {
    state: State,
    buffer: OutputBuffer,
    slots: Vec<Slot>,
    next_attachment: u64,
    /// The Attachment whose size applies (§15.9).
    active: Option<u64>,
    /// The size of the PTY.
    size: Option<Size>,
    /// Since when the Session has no Attachment.
    idle_since: Option<Instant>,
    exited_at: Option<Instant>,
    /// Terminal modes of the PTY output (§15.11).
    modes: Modes,
}

enum SessionIo {
    Pty(Arc<Master>),
    Pipes(tokio::sync::Mutex<Option<ChildStdin>>),
}

pub struct Session {
    pub id: SessionId,
    pub owner: String,
    pub name: Option<String>,
    pub created: SystemTime,
    pub creator: KeyInfo,
    /// The command for display; `None`: the login shell.
    pub command: Option<String>,
    /// The primary process: leader of the Session's process group and, with a PTY,
    /// of its terminal session.
    leader: Option<Pid>,
    account: Account,
    io: SessionIo,
    detach_timeout: Option<Duration>,
    policy: Policy,
    inner: Mutex<Inner>,
    terminated: watch::Sender<bool>,
}

/// An Attachment just added to a Session: what its Channel sends first, and where
/// it receives the rest.
pub struct Attachment {
    pub id: u64,
    pub read_only: bool,
    /// Output offset of the first replayed byte (§15.11).
    pub offset: u64,
    pub replay: Vec<Piece>,
    /// The exit status, if the Session has exited already.
    pub exited: Option<Exit>,
    pub events: mpsc::Receiver<Event>,
    pub end: watch::Receiver<Option<Code>>,
    /// Whether output was lost for this Client, so the screen is to be redrawn.
    pub redraw: bool,
    /// The sequence that sets the terminal modes as the programs left them (§15.11).
    pub modes: Vec<u8>,
}

/// How an Attachment wants to attach (§14.6, §15.9, §15.11).
pub struct AttachRequest {
    pub replay: Replay,
    pub read_only: bool,
    pub takeover: bool,
    pub size: Option<Size>,
    pub info: AttachmentInfo,
}

/// A snapshot of an Attachment for the Session list.
pub struct AttachmentView {
    pub id: u64,
    pub info: AttachmentInfo,
    pub read_only: bool,
    pub active: bool,
}

impl Session {
    pub fn pty(&self) -> bool {
        matches!(self.io, SessionIo::Pty(_))
    }

    pub fn state(&self) -> State {
        self.lock().state
    }

    pub fn attachments(&self) -> Vec<AttachmentView> {
        let inner = self.lock();
        let views = inner.slots.iter().map(|slot| AttachmentView {
            id: slot.id,
            info: slot.info.clone(),
            read_only: slot.read_only,
            active: inner.active == Some(slot.id),
        });
        views.collect()
    }

    /// When Retention Policy or the detach timeout removes the Session, as Unix
    /// time (§15.10).
    pub fn removal(&self) -> Option<SystemTime> {
        let inner = self.lock();
        let deadline = self.deadline(&inner)?;
        Some(SystemTime::now() + deadline.saturating_duration_since(Instant::now()))
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("session lock")
    }

    /// When the Session is ended for lack of an Attachment, if it is (§15.8).
    fn deadline(&self, inner: &Inner) -> Option<Instant> {
        if !inner.slots.is_empty() {
            return None;
        }
        let detached = inner
            .idle_since
            .zip(self.detach_timeout)
            .map(|(i, t)| i + t);
        match inner.state {
            State::Running => detached,
            State::Exited(_) => {
                let retained = inner.exited_at.map(|e| e + self.policy.exited_retention);
                match (detached, retained) {
                    (Some(a), Some(b)) => Some(a.min(b)),
                    (a, b) => a.or(b),
                }
            }
            State::Terminating | State::Terminated => None,
        }
    }

    /// Adds an Attachment (§15.9): checks state and limits, ends the others for a
    /// takeover, computes the replay (§15.11) and registers the Attachment in one
    /// step, so live output follows the replay without gap or overlap.
    pub fn attach(&self, request: AttachRequest) -> Result<Attachment, Failure> {
        let mut inner = self.lock();
        if !matches!(inner.state, State::Running | State::Exited(_)) {
            return Err(Failure::new(Code::SessionNotFound, "Session is ending"));
        }
        if request.takeover {
            for slot in inner.slots.drain(..) {
                let _ = slot.end.send(Some(Code::NoError));
            }
            inner.active = None;
        }
        if inner.slots.len() >= self.policy.attachments_per_session {
            return Err(Failure::new(
                Code::LimitExceeded,
                format!("{} Attachments", inner.slots.len()),
            ));
        }
        let (offset, replay) = inner.buffer.replay(request.replay).map_err(|_| {
            Failure::new(
                Code::ChannelRejected,
                "resume offset beyond the end of output",
            )
        })?;
        let lost = match request.replay {
            Replay::Fresh(_) => true,
            Replay::Resume(from) => offset > from,
        };
        let id = inner.next_attachment;
        inner.next_attachment += 1;
        let (events_tx, events) = mpsc::channel(EVENT_QUEUE);
        let (end_tx, end) = watch::channel(None);
        inner.slots.push(Slot {
            id,
            events: events_tx,
            end: end_tx,
            read_only: request.read_only,
            size: request.size,
            info: request.info,
        });
        inner.idle_since = None;
        if !request.read_only {
            inner.active = Some(id);
            if let Some(size) = request.size {
                self.apply_size(&mut inner, size);
            }
        }
        let exited = match inner.state {
            State::Exited(exit) => Some(exit),
            _ => None,
        };
        Ok(Attachment {
            id,
            read_only: request.read_only,
            offset,
            replay,
            exited,
            events,
            end,
            redraw: lost && exited.is_none() && self.pty(),
            modes: inner.modes.restore(),
        })
    }

    /// Ends Attachment `id` from the Session's side: its Client detached, its
    /// Connection is gone, or the Server ended it.
    pub fn detach(&self, id: u64) {
        let mut inner = self.lock();
        if let Some(position) = inner.slots.iter().position(|s| s.id == id) {
            inner.slots.remove(position);
        }
        self.after_removal(&mut inner, id);
    }

    /// Ends Attachment `id` as a detach by the Server with `code` (§14.10); false if
    /// there is no such Attachment.
    pub fn end_attachment(&self, id: u64, code: Code) -> bool {
        let mut inner = self.lock();
        let Some(position) = inner.slots.iter().position(|s| s.id == id) else {
            return false;
        };
        let slot = inner.slots.remove(position);
        let _ = slot.end.send(Some(code));
        self.after_removal(&mut inner, id);
        true
    }

    /// Ends every Attachment as a detach by the Server (§15.9).
    pub fn end_all_attachments(&self) {
        let mut inner = self.lock();
        for slot in inner.slots.drain(..) {
            let _ = slot.end.send(Some(Code::NoError));
        }
        inner.active = None;
        if inner.idle_since.is_none() {
            inner.idle_since = Some(Instant::now());
        }
    }

    fn after_removal(&self, inner: &mut Inner, id: u64) {
        if inner.active == Some(id) {
            inner.active = None;
        }
        if inner.slots.is_empty() && inner.idle_since.is_none() {
            inner.idle_since = Some(Instant::now());
        }
    }

    fn apply_size(&self, inner: &mut Inner, size: Size) {
        if let SessionIo::Pty(master) = &self.io
            && inner.size != Some(size)
        {
            if let Err(e) = master.resize(size) {
                tracing::debug!(error = %e, "PTY resize failed");
            }
            inner.size = Some(size);
        }
    }

    /// Makes Attachment `id` the active one: its size applies (§15.9).
    fn activate(&self, inner: &mut Inner, id: u64) {
        if inner.active == Some(id) {
            return;
        }
        inner.active = Some(id);
        if let Some(size) = inner.slots.iter().find(|s| s.id == id).and_then(|s| s.size) {
            self.apply_size(inner, size);
        }
    }

    /// Input from Attachment `id`; it becomes the active one.
    pub async fn input(&self, id: u64, data: &[u8]) {
        self.activate(&mut self.lock(), id);
        match &self.io {
            SessionIo::Pty(master) => {
                if let Err(e) = master.write_all(data).await {
                    tracing::debug!(error = %e, "PTY input dropped");
                }
            }
            SessionIo::Pipes(stdin) => {
                let mut stdin = stdin.lock().await;
                // A program that closed its input no longer gets any.
                if let Some(pipe) = stdin.as_mut()
                    && pipe.write_all(data).await.is_err()
                {
                    *stdin = None;
                }
            }
        }
    }

    /// TERMINAL_EOF from any Attachment ends the input of the command (§15.9).
    pub async fn close_input(&self) {
        if let SessionIo::Pipes(stdin) = &self.io {
            *stdin.lock().await = None;
        }
    }

    /// The new size of Attachment `id`, which becomes the active one (§14.8, §15.9).
    pub fn resize(&self, id: u64, size: Size) {
        let mut inner = self.lock();
        if let Some(slot) = inner.slots.iter_mut().find(|s| s.id == id) {
            slot.size = Some(size);
        }
        inner.active = Some(id);
        self.apply_size(&mut inner, size);
    }

    /// Sends a signal with the permissions of the Account: with a PTY to its
    /// foreground process group, else to the group of the command (§14.9).
    pub async fn signal(&self, signal: Signal) {
        let group = match &self.io {
            SessionIo::Pty(master) => match master.foreground_group() {
                Ok(group) => group,
                Err(e) => {
                    tracing::debug!(error = %e, "no foreground process group");
                    return;
                }
            },
            SessionIo::Pipes(_) => match self.leader {
                Some(leader) => leader,
                None => return,
            },
        };
        self.deliver_signal(group, signal).await;
    }

    async fn deliver_signal(&self, group: Pid, signal: Signal) {
        match process::signal_group(&self.account, group, signal).await {
            Ok(()) => tracing::debug!(?signal, group = group.as_raw(), "signal delivered"),
            Err(e) => {
                tracing::debug!(?signal, group = group.as_raw(), error = %e, "signal not delivered")
            }
        }
    }

    /// Makes full-screen programs redraw the screen for a new Client (§15.11): the
    /// PTY is one row smaller for a moment, as most redraw completely only when the
    /// size really changes; each change sends SIGWINCH to the foreground group.
    pub async fn redraw(&self) {
        let SessionIo::Pty(master) = &self.io else {
            return;
        };
        let Some(size) = self.lock().size else {
            return;
        };
        let rows = if size.rows > 1 {
            size.rows - 1
        } else {
            size.rows + 1
        };
        if let Err(e) = master.resize(Size { rows, ..size }) {
            tracing::debug!(error = %e, "PTY resize failed");
            return;
        }
        tokio::time::sleep(REDRAW_PAUSE).await;
        // Unless an Attachment set another size meanwhile.
        let inner = self.lock();
        if inner.size == Some(size)
            && let Err(e) = master.resize(size)
        {
            tracing::debug!(error = %e, "PTY resize failed");
        }
    }

    /// The Client of an Attachment confirmed the exit status (its FIN after
    /// TERMINAL_EXIT): an Exited Session becomes Terminated (§15.7).
    pub fn exit_delivered(&self, store: &Store) {
        let mut inner = self.lock();
        if let State::Exited(_) = inner.state {
            inner.state = State::Terminated;
            drop(inner);
            self.finish(store, "exit status delivered");
        }
    }

    /// Terminates the Session (§15.6) and returns once it is Terminated: an Exited
    /// one at once; a Running one after its processes ended (HUP to the groups of its
    /// terminal session, or TERM to its process group; KILL after the grace period or
    /// at once with `force`).
    pub async fn terminate(self: &Arc<Self>, store: &Arc<Store>, force: bool) {
        let mut terminated = self.terminated.subscribe();
        let previous = {
            let mut inner = self.lock();
            let previous = inner.state;
            match previous {
                State::Running => inner.state = State::Terminating,
                State::Exited(_) => {
                    inner.state = State::Terminated;
                    for slot in inner.slots.drain(..) {
                        let _ = slot.end.send(Some(Code::NoError));
                    }
                }
                State::Terminating | State::Terminated => {}
            }
            previous
        };
        match previous {
            State::Exited(_) => self.finish(store, "removed"),
            State::Running => {
                // Runs on even if the requester goes away.
                tokio::spawn(self.clone().escalate(store.clone(), force));
            }
            State::Terminating if force => self.signal_all(Signal::SIGKILL).await,
            State::Terminating | State::Terminated => {}
        }
        let _ = terminated.wait_for(|t| *t).await;
    }

    async fn escalate(self: Arc<Self>, store: Arc<Store>, force: bool) {
        let mut terminated = self.terminated.subscribe();
        if !force {
            let first = if self.pty() {
                Signal::SIGHUP
            } else {
                Signal::SIGTERM
            };
            self.signal_all(first).await;
            let grace = self.policy.termination_grace;
            if timeout(grace, terminated.wait_for(|t| *t)).await.is_ok() {
                return;
            }
        }
        self.signal_all(Signal::SIGKILL).await;
        if timeout(AFTER_KILL, terminated.wait_for(|t| *t))
            .await
            .is_err()
        {
            tracing::warn!(session = %self.id, "processes did not end after KILL");
            self.lock().state = State::Terminated;
            self.finish(&store, "terminated, processes left");
        }
    }

    /// Signals every process group of the Session: with a PTY all groups of its
    /// terminal session, else the group of the command.
    async fn signal_all(&self, signal: Signal) {
        let Some(leader) = self.leader else {
            return;
        };
        let groups = if self.pty() {
            tokio::task::spawn_blocking(move || process::groups_in_session(leader))
                .await
                .unwrap_or_default()
        } else {
            vec![leader]
        };
        for group in groups {
            self.deliver_signal(group, signal).await;
        }
    }

    /// The Session is Terminated: it leaves the store, and with its last reference
    /// its PTY is closed (§15.7).
    fn finish(&self, store: &Store, how: &str) {
        store.remove(self.id);
        self.terminated.send_replace(true);
        tracing::info!(session = %self.id, how, "Session ended");
    }

    /// Reads the output until the program has exited, then makes the Session
    /// Exited, or Terminated if it was being terminated.
    async fn run(self: Arc<Self>, store: Arc<Store>, mut child: Child, mut output: Output) {
        let exit = self.pump(&mut output, &mut child).await;
        let (targets, terminated) = {
            let mut inner = self.lock();
            let terminated = match inner.state {
                State::Running => {
                    inner.state = State::Exited(exit);
                    inner.exited_at = Some(Instant::now());
                    false
                }
                State::Terminating => {
                    inner.state = State::Terminated;
                    true
                }
                // Removed already: nobody is told any more.
                State::Exited(_) | State::Terminated => return,
            };
            (targets(&inner), terminated)
        };
        tracing::info!(session = %self.id, ?exit, "program exited");
        self.deliver(targets, Event::Exit(exit)).await;
        if terminated {
            self.finish(&store, "terminated");
        }
    }

    /// Sends output until its end, or until the grace period after the program
    /// exited has passed (§14.10).
    async fn pump(&self, output: &mut Output, child: &mut Child) -> Exit {
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
                    Ok(Some(piece)) => self.publish(piece).await,
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!(error = %e, "reading output");
                        break;
                    }
                },
                exited = child.wait(), if status.is_none() => {
                    status = Some(exited);
                    deadline = Some(Instant::now() + self.policy.exit_grace);
                }
                () = grace_over => break,
            }
        }
        let status = match status {
            Some(status) => status,
            None => child.wait().await,
        };
        match status {
            Ok(status) => Exit::from_status(status),
            Err(e) => {
                tracing::warn!(session = %self.id, error = %e, "waiting for the program");
                Exit::Code(u32::MAX)
            }
        }
    }

    /// Numbers a piece of output into the buffer and hands it to every Attachment.
    async fn publish(&self, piece: Piece) {
        let targets = {
            let mut inner = self.lock();
            if self.pty() {
                let start = inner.buffer.end();
                if let Some(index) = inner.modes.feed(&piece.1) {
                    inner.buffer.screen_starts(start + index as u64);
                }
            }
            inner.buffer.push(piece.0, piece.1.clone());
            targets(&inner)
        };
        self.deliver(targets, Event::Output(piece)).await;
    }

    /// Hands `event` to the Attachments, at the pace of the slowest; one that takes
    /// longer than the stall limit is ended with TIMEOUT (§15.9).
    async fn deliver(&self, targets: Vec<(u64, mpsc::Sender<Event>)>, event: Event) {
        for (id, events) in targets {
            let sent = timeout(self.policy.stall_limit, events.send(event.clone())).await;
            if sent.is_err() && self.end_attachment(id, Code::Timeout) {
                tracing::info!(session = %self.id, attachment = id, "Attachment stalled");
            }
        }
    }
}

fn targets(inner: &Inner) -> Vec<(u64, mpsc::Sender<Event>)> {
    inner
        .slots
        .iter()
        .map(|slot| (slot.id, slot.events.clone()))
        .collect()
}

/// Output of the program: the PTY master, or standard output and error.
enum Output {
    Pty(Arc<Master>),
    Pipes {
        stdout: Option<ChildStdout>,
        stderr: Option<ChildStderr>,
        err_buf: Vec<u8>,
    },
}

impl Output {
    /// The next piece of output; `None` at the end of all output. Cancel safe:
    /// nothing is read unless it is returned.
    async fn next(&mut self, buf: &mut [u8]) -> std::io::Result<Option<Piece>> {
        match self {
            Self::Pty(master) => match master.read(buf).await? {
                0 => Ok(None),
                n => Ok(Some((TERMINAL_DATA, buf[..n].into()))),
            },
            Self::Pipes {
                stdout,
                stderr,
                err_buf,
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
                return Ok(Some((kind, data.into())));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_display_is_cut_at_a_character_boundary() {
        let argv = Command::Argv(vec!["ls".into(), "-l".into()]);
        assert_eq!(display(&argv), "ls -l");
        let long = Command::Line("ж".repeat(200));
        let shown = display(&long);
        assert_eq!(shown.len(), 256);
        assert!(shown.chars().all(|c| c == 'ж'));
        let odd = Command::Line(format!("a{}", "ж".repeat(200)));
        assert_eq!(display(&odd).len(), 255);
    }
}
