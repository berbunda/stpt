//! Connection-local forwarding state and independent, bounded TCP flow tasks.
use super::*;
use crate::wire::{Code, DEFAULT_MESSAGE_LIMIT, StreamError};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore, watch},
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};

#[cfg(test)]
#[path = "review.rs"]
mod review;

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Mode {
    Local,
    Remote,
    Dynamic,
}
impl Mode {
    fn number(self) -> u64 {
        match self {
            Self::Local => 1,
            Self::Remote => 2,
            Self::Dynamic => 3,
        }
    }
}
#[derive(Debug, clap::Args)]
pub struct Options {
    #[arg(long, value_enum)]
    pub mode: Mode,
    /// Numeric TCP listener (port 0 allocates one); IPv6 must be bracketed.
    #[arg(long)]
    pub bind: SocketAddr,
    /// Fixed target for local/remote; omit for dynamic SOCKS5 CONNECT.
    #[arg(long)]
    pub target: Option<Target>,
    /// Explicitly expose the listener beyond loopback.
    #[arg(long)]
    pub allow_non_loopback: bool,
    /// Allowed ingress networks; required for exposed SOCKS.
    #[arg(long)]
    pub ingress: Vec<Net>,
}
impl Options {
    pub fn validate(&self) -> Result<()> {
        if (self.mode.number() != 3) != self.target.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--target is required for local/remote and forbidden for dynamic",
            )
            .into());
        }
        if self.bind.ip() != normal(self.bind.ip())
            || self.bind.ip().is_multicast()
            || self.bind.scope_id() != 0
            || matches!(self.bind.ip(),IpAddr::V6(v) if v.is_unicast_link_local())
        {
            return Err(Status::Unsupported.into());
        }
        if !self.bind.ip().is_loopback()
            && (!self.allow_non_loopback || (self.mode.number() == 3 && self.ingress.is_empty()))
        {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,"non-loopback bind requires --allow-non-loopback; exposed SOCKS also requires --ingress").into());
        }
        if self.mode.number() == 2 && !self.ingress.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "remote ingress is configured in Server policy",
            )
            .into());
        }
        Ok(())
    }
}
pub async fn run(state: Arc<State>, options: Options) -> Result<()> {
    options.validate()?;
    let mode = options.mode.number();
    let mut rule = state
        .open_rule(
            Rule {
                mode,
                target: options.target,
                bind: (mode == 2).then_some(options.bind),
            },
            (mode != 2).then_some(options.bind),
            options.ingress,
        )
        .await?;
    println!("forwarding {:?} on {}", options.mode, rule.actual);
    let result = tokio::select! {r=rule.wait()=>r,r=tokio::signal::ctrl_c()=>r.map_err(Error::Io),_=state.connection.closed()=>Err(Status::Failed.into())};
    rule.close().await;
    result
}

#[derive(Debug)]
pub enum Error {
    Protocol(Failure),
    Stream(StreamError),
    Status(Status),
    Io(std::io::Error),
    Timeout,
}
impl From<Failure> for Error {
    fn from(v: Failure) -> Self {
        Self::Protocol(v)
    }
}
impl From<StreamError> for Error {
    fn from(v: StreamError) -> Self {
        Self::Stream(v)
    }
}
impl From<std::io::Error> for Error {
    fn from(v: std::io::Error) -> Self {
        Self::Io(v)
    }
}
impl From<Status> for Error {
    fn from(v: Status) -> Self {
        Self::Status(v)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            other => write!(f, "{other:?}"),
        }
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy)]
struct Timers {
    open: std::time::Duration,
    progress: std::time::Duration,
}
impl Timers {
    const DEFAULT: Self = Self {
        open: OPEN,
        progress: PROGRESS,
    };
}
struct Reservations {
    _permits: Vec<OwnedSemaphorePermit>,
    _account: Arc<Budget>,
}
pub struct Budget {
    rules: Arc<Semaphore>,
    flows: Arc<Semaphore>,
}
impl Budget {
    fn new(r: usize, f: usize) -> Self {
        Self {
            rules: Arc::new(Semaphore::new(r)),
            flows: Arc::new(Semaphore::new(f)),
        }
    }
}
pub struct Global {
    budget: Budget,
    accounts: Mutex<HashMap<String, Weak<Budget>>>,
}
impl Default for Global {
    fn default() -> Self {
        Self {
            budget: Budget::new(256, 2048),
            accounts: Mutex::new(HashMap::new()),
        }
    }
}
impl Global {
    fn account(&self, n: &str) -> Arc<Budget> {
        let mut a = self.accounts.lock().unwrap();
        a.retain(|_, w| w.strong_count() > 0);
        if let Some(b) = a.get(n).and_then(Weak::upgrade) {
            return b;
        }
        let b = Arc::new(Budget::new(32, 256));
        a.insert(n.into(), Arc::downgrade(&b));
        b
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pending,
    Active,
    Dead,
}
struct Live {
    rule: Rule,
    phase: watch::Sender<Phase>,
    _permits: Reservations,
}
impl native::Authority for Live {
    fn valid(&self) -> bool {
        *self.phase.borrow() != Phase::Dead
    }
}
impl native::Authority for (Reservations, Arc<Live>) {
    fn valid(&self) -> bool {
        self.1.active()
    }
}
impl Live {
    fn active(&self) -> bool {
        *self.phase.borrow() == Phase::Active
    }
}
struct Guard {
    state: Arc<State>,
    id: u64,
    live: Arc<Live>,
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.live.phase.send_replace(Phase::Dead);
        self.state.rules.lock().unwrap().remove(&self.id);
    }
}
pub struct State {
    pub connection: quinn::Connection,
    pub limit: u64,
    selection: Selection,
    account: Option<String>,
    policy: Option<Policy>,
    global: Arc<Global>,
    account_budget: Arc<Budget>,
    budget: Budget,
    rules: Mutex<HashMap<u64, Arc<Live>>>,
    timers: Timers,
}
impl State {
    pub fn new(
        connection: quinn::Connection,
        limit: u64,
        selection: Selection,
        account: Option<String>,
        policy: Option<Policy>,
        global: Arc<Global>,
    ) -> Arc<Self> {
        let account_budget = global.account(account.as_deref().unwrap_or("client"));
        Arc::new(Self {
            connection,
            limit,
            budget: Budget::new(selection.rules, selection.flows),
            selection,
            account,
            policy,
            global,
            account_budget,
            rules: Mutex::new(HashMap::new()),
            timers: Timers::DEFAULT,
        })
    }
    fn reserve(&self, rule: bool) -> Result<Reservations> {
        let permits = [&self.budget, &self.account_budget, &self.global.budget]
            .into_iter()
            .map(|b| {
                if rule {
                    b.rules.clone()
                } else {
                    b.flows.clone()
                }
                .try_acquire_owned()
                .map_err(|_| Error::Status(Status::Limit))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Reservations {
            _permits: permits,
            _account: self.account_budget.clone(),
        })
    }
    fn insert(self: &Arc<Self>, id: u64, rule: Rule, phase: Phase) -> Result<Guard> {
        let permits = self.reserve(true)?;
        let (phase, _) = watch::channel(phase);
        let live = Arc::new(Live {
            rule,
            phase,
            _permits: permits,
        });
        let mut r = self.rules.lock().unwrap();
        if r.contains_key(&id) {
            return Err(bad("duplicate forwarding rule").into());
        }
        r.insert(id, live.clone());
        Ok(Guard {
            state: self.clone(),
            id,
            live,
        })
    }
    fn report(&self, e: &Error) {
        let f = match e {
            Error::Protocol(f) | Error::Stream(StreamError::Failure(f))
                if f.code == Code::ProtocolViolation =>
            {
                Some(f)
            }
            _ => None,
        };
        if let Some(f) = f {
            tracing::debug!(reason=?f.reason,"forwarding violation");
            self.connection.close(Code::ProtocolViolation.varint(), b"");
        }
    }
    fn fail_stream(&self, send: &mut quinn::SendStream, recv: &mut quinn::RecvStream, e: &Error) {
        self.report(e);
        let c = match e {
            Error::Timeout => Code::Timeout,
            Error::Status(Status::Limit) => Code::LimitExceeded,
            Error::Status(Status::Denied) => Code::ChannelRejected,
            _ => Code::InternalError,
        };
        let _ = send.reset(c.varint());
        let _ = recv.stop(c.varint());
    }
    pub async fn dispatch(
        self: Arc<Self>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
        m: Message,
    ) {
        let kind = uint(&m, 0);
        let result = match kind {
            Ok(RULE) if self.account.is_some() => self.server_rule(&mut send, &mut recv, &m).await,
            Ok(RULE) => Err(bad("Server opened a rule").into()),
            Ok(FLOW) => self.receive_flow(&mut send, &mut recv, &m).await,
            _ => Err(bad("invalid forwarding Channel").into()),
        };
        if let Err(e) = result {
            self.fail_stream(&mut send, &mut recv, &e)
        }
    }
    async fn rule_end(
        &self,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
    ) -> Result<()> {
        tokio::select! {
            m=wire::read_message(recv,DEFAULT_MESSAGE_LIMIT)=>match m?{None=>{let _=send.finish();Ok(())},Some(_)=>Err(bad("message after FORWARD_READY").into())},
            _=send.stopped()=>Ok(()),
            _=self.connection.closed()=>Ok(()),
        }
    }
    async fn server_rule(
        self: &Arc<Self>,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        m: &Message,
    ) -> Result<()> {
        let deadline = Instant::now() + self.timers.open;
        let rule = Rule::parse(m)?;
        if !self.selection.modes.contains(&rule.mode) {
            return Err(bad("unselected forwarding mode").into());
        }
        let policy = self.policy.as_ref().ok_or(Status::Denied)?;
        let allowed = match rule.mode {
            1 => policy.local,
            2 => policy.remote,
            3 => policy.dynamic,
            _ => false,
        };
        let setup = async {
            if !allowed {
                return Err(Status::Denied.into());
            }
            if let Some(t) = &rule.target {
                if !t.supported() {
                    return Err(Status::Unsupported.into());
                }
                if !policy.target(t) {
                    return Err(Status::Denied.into());
                }
            }
            let guard = self.insert(u64::from(send.id()), rule.clone(), Phase::Pending)?;
            let listener = if let Some(bind) = rule.bind {
                if normal(bind.ip()) != bind.ip() {
                    return Err(Status::Unsupported.into());
                }
                if !policy.binds.iter().any(|p| p.allows(bind)) {
                    return Err(Status::Denied.into());
                }
                let l =
                    native::bind(self.account.as_deref(), bind, Some(guard.live.clone())).await?;
                let bound = l.local_addr()?;
                if !policy.binds.iter().any(|p| p.allows(bound)) {
                    return Err(Status::Denied.into());
                }
                Some(l)
            } else {
                None
            };
            Ok::<_, Error>((guard, listener))
        };
        let mut input = [0];
        let setup = tokio::select! {biased;
            _=send.stopped()=>return Ok(()),
            m=recv.read(&mut input)=>{match m.map_err(StreamError::from)?{None=>{let _=send.finish();return Ok(())},Some(_)=>return Err(bad("Client sent rule bytes before READY").into())}},
            r=timeout_at(deadline,setup)=>r.map_err(|_|Error::Timeout)?,
        };
        let (guard, listener) = match setup {
            Ok(v) => v,
            Err(Error::Status(s)) => {
                let reply = s.reply(READY, None);
                tokio::select! {biased;
                    _=send.stopped()=>return Ok(()),
                    m=recv.read(&mut input)=>{match m.map_err(StreamError::from)?{None=>{let _=send.finish();return Ok(())},Some(_)=>return Err(bad("Client sent rule bytes before READY").into())}},
                    r=timeout_at(deadline,wire::write_message(send,&reply,self.limit))=>{r.map_err(|_|Error::Timeout)??;}
                }

                send.finish().map_err(|_| Error::Status(Status::Failed))?;
                return timeout(self.timers.open, self.rule_end(send, recv))
                    .await
                    .map_err(|_| Error::Timeout)?;
            }
            Err(e) => return Err(e),
        };
        let bound = listener.as_ref().map(TcpListener::local_addr).transpose()?;
        let reply = Status::Ok.reply(READY, bound);
        tokio::select! {biased;
            _=send.stopped()=>return Ok(()),
            m=recv.read(&mut input)=>{match m.map_err(StreamError::from)?{None=>{let _=send.finish();return Ok(())},Some(_)=>return Err(bad("Client sent rule bytes before READY").into())}},
            r=timeout_at(deadline,wire::write_message(send,&reply,self.limit))=>{r.map_err(|_|Error::Timeout)??;}
        }

        guard.live.phase.send_replace(Phase::Active);
        if let Some(listener) = listener {
            tokio::select! {r=self.rule_end(send,recv)=>r,r=self.listen(listener,guard.id,guard.live.clone(),None,vec![])=>r}
        } else {
            self.rule_end(send, recv).await
        }
    }
    async fn receive_flow(
        self: &Arc<Self>,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        m: &Message,
    ) -> Result<()> {
        let id = uint(m, 1)?;
        if id >= (1 << 62) {
            return Err(bad("invalid rule ID").into());
        }
        let dynamic = m.field(2).map(|v| Target::parse(v, false)).transpose()?;
        let live = self
            .rules
            .lock()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(Status::Denied)?;
        let expected = if self.account.is_some() {
            live.rule.mode != 2
        } else {
            live.rule.mode == 2
        };
        if !expected {
            return Err(Status::Denied.into());
        }
        let target = if live.rule.mode == 3 {
            dynamic.ok_or_else(|| bad("missing dynamic target"))?
        } else {
            if dynamic.is_some() {
                return Err(bad("unexpected flow target").into());
            }
            live.rule.target.clone().ok_or(Status::Denied)?
        };
        let lease: native::Lease = Arc::new((self.reserve(false)?, live.clone()));
        let deadline = Instant::now() + self.timers.open;
        let mut phase = live.phase.subscribe();
        let ready = async {
            loop {
                let p = *phase.borrow_and_update();
                match p {
                    Phase::Active => return Ok(()),
                    Phase::Dead => return Err(Error::Status(Status::Denied)),
                    Phase::Pending => {}
                }
                phase
                    .changed()
                    .await
                    .map_err(|_| Error::Status(Status::Denied))?;
            }
        };
        tokio::select! {biased;
            _=revoked(live.phase.subscribe())=>return Err(Status::Denied.into()),
            _=send.stopped()=>return Err(Status::Failed.into()),
            e=premature(recv)=>return Err(e),
            r=timeout_at(deadline,ready)=>{r.map_err(|_|Error::Timeout)??;}
        }

        let connect = native::connect(
            self.account.as_deref(),
            &target,
            self.policy.as_ref(),
            Some(lease.clone()),
        );
        let connected = tokio::select! {biased;
            _=revoked(live.phase.subscribe())=>return Err(Status::Denied.into()),
            _=send.stopped()=>return Err(Status::Failed.into()),
            e=premature(recv)=>return Err(e),
            r=timeout_at(deadline,connect)=>r.map_err(|_|Error::Timeout)?,
        };
        if !live.active() {
            return Err(Status::Denied.into());
        }
        let (status, socket) = match connected {
            Ok(s) => (Status::Ok, Some(s)),
            Err(s) => (s, None),
        };
        let bound = socket.as_ref().map(TcpStream::local_addr).transpose()?;
        let reply = status.reply(CONNECTED, bound);
        tokio::select! {biased;
            _=revoked(live.phase.subscribe())=>return Err(Status::Denied.into()),
            _=send.stopped()=>return Err(Status::Failed.into()),
            e=premature(recv)=>return Err(e),
            r=timeout_at(deadline,wire::write_message(send,&reply,self.limit))=>{r.map_err(|_|Error::Timeout)??;}
        }
        let Some(socket) = socket else {
            send.finish().map_err(|_| Error::Status(Status::Failed))?;
            return tokio::select! {biased;
                _=revoked(live.phase.subscribe())=>Err(Status::Denied.into()),
                _=send.stopped()=>Err(Status::Failed.into()),
                r=timeout(self.timers.open,next_frame(recv,self.timers.progress))=>match r.map_err(|_|Error::Timeout)??{None=>Ok(()),Some(_)=>Err(bad("DATA after failed CONNECTED").into())}
            };
        };
        self.relay(socket, send, recv, &live).await
    }
    pub async fn open_rule(
        self: &Arc<Self>,
        rule: Rule,
        local_bind: Option<SocketAddr>,
        ingress: Vec<Net>,
    ) -> Result<Running> {
        if !self.selection.modes.contains(&rule.mode) {
            return Err(Status::Unsupported.into());
        }
        let deadline = Instant::now() + self.timers.open;
        let (mut send, mut recv) = timeout_at(deadline, self.connection.open_bi())
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(StreamError::Lost)?;
        // Client target for remote mode is local-only; omit it from rule wire fields.
        let wire_rule = Rule {
            target: if rule.mode == 2 {
                None
            } else {
                rule.target.clone()
            },
            ..rule.clone()
        };
        let guard = match self.insert(u64::from(send.id()), rule.clone(), Phase::Pending) {
            Ok(g) => g,
            Err(e) => {
                self.fail_stream(&mut send, &mut recv, &e);
                return Err(e);
            }
        };
        let setup = async {
            if !self.selection.modes.contains(&rule.mode) {
                return Err(Status::Unsupported.into());
            }
            wire::write_message(&mut send, &wire_rule.message(), self.limit).await?;
            let m = next_frame(&mut recv, self.timers.progress)
                .await?
                .ok_or(Status::Failed)?;
            let (s, bound) = outcome(&m, READY, rule.mode == 2)?;
            if s != Status::Ok {
                return Err(s.into());
            }
            if let Some(request) = rule.bind {
                let a = bound.ok_or_else(|| bad("missing bound socket"))?;
                if normal(a.ip()) != a.ip()
                    || a.ip() != request.ip()
                    || a.port() == 0
                    || (request.port() != 0 && a.port() != request.port())
                {
                    return Err(bad("Server widened remote bind").into());
                }
            }
            let listener = if let Some(a) = local_bind {
                Some(native::bind(None, a, Some(guard.live.clone())).await?)
            } else {
                None
            };
            let actual = match listener.as_ref() {
                Some(l) => l.local_addr()?,
                None => bound.ok_or_else(|| bad("missing remote bind"))?,
            };
            Ok::<_, Error>((listener, actual))
        };
        let setup = match timeout_at(deadline, setup).await {
            Ok(r) => r,
            Err(_) => {
                self.fail_stream(&mut send, &mut recv, &Error::Timeout);
                return Err(Error::Timeout);
            }
        };
        let (listener, actual) = match setup {
            Ok(v) => v,
            Err(e) => {
                if matches!(e, Error::Status(_)) {
                    let _ = send.finish();
                } else {
                    self.fail_stream(&mut send, &mut recv, &e)
                }
                return Err(e);
            }
        };
        guard.live.phase.send_replace(Phase::Active);
        let (cancel, mut cancelled) = watch::channel(false);
        let state = self.clone();
        let task = tokio::spawn(async move {
            let live = guard.live.clone();
            let id = guard.id;
            let run = async {
                if let Some(l) = listener {
                    tokio::select! {r=state.rule_end(&mut send,&mut recv)=>r,r=state.listen(l,id,live,None,ingress)=>r}
                } else {
                    state.rule_end(&mut send, &mut recv).await
                }
            };
            let r = tokio::select! {r=run=>r,_=cancelled.changed()=>Ok(())};
            drop(guard);
            let _ = send.finish();
            let _ = recv.stop(Code::NoError.varint());
            if let Err(ref e) = r {
                state.fail_stream(&mut send, &mut recv, e)
            }
            r
        });
        Ok(Running {
            actual,
            cancel,
            task: Some(task),
        })
    }
    async fn listen(
        self: &Arc<Self>,
        listener: TcpListener,
        id: u64,
        live: Arc<Live>,
        _unused: Option<()>,
        ingress: Vec<Net>,
    ) -> Result<()> {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _=revoked(live.phase.subscribe())=>return Ok(()),
                _=self.connection.closed()=>return Ok(()),
                Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                r=listener.accept()=>{
                    let (socket,source)=r?;
                    if !live.active()||!ingress.is_empty()&&!ingress.iter().any(|n|n.contains(source.ip()))||self.policy.as_ref().is_some_and(|p|!p.ingress(source.ip())){continue}
                    let Ok(permits)=self.reserve(false)else{continue};let state=self.clone();let live=live.clone();
                    tasks.spawn(async move{let _permits=permits;let r=state.outgoing(socket,id,live).await;if let Err(e)=r{state.report(&e)}});
                }
            }
        }
    }
    async fn outgoing(
        self: &Arc<Self>,
        mut socket: TcpStream,
        id: u64,
        live: Arc<Live>,
    ) -> Result<()> {
        let mut phase = live.phase.subscribe();
        let run = async {
            let target = if live.rule.mode == 3 {
                Some(
                    timeout(self.timers.open, socks_request(&mut socket))
                        .await
                        .map_err(|_| Error::Timeout)??,
                )
            } else {
                None
            };
            let mut pair: Option<Streams> = None;
            let setup = async {
                let (send, recv) = self.connection.open_bi().await.map_err(StreamError::Lost)?;
                pair = Some(Streams {
                    send,
                    recv,
                    clean: false,
                });
                let Streams { send, recv, .. } = pair.as_mut().unwrap();
                let mut f = vec![(0, Value::Uint(FLOW)), (1, Value::Uint(id))];
                if let Some(t) = &target {
                    f.push((2, t.value()))
                }
                wire::write_message(send, &Message::new(wire::CHANNEL_OPEN, f), self.limit).await?;
                let m = next_frame(recv, self.timers.progress)
                    .await?
                    .ok_or(Status::Failed)?;
                outcome(&m, CONNECTED, true).map_err(Error::from)
            };
            let result = timeout(self.timers.open, setup)
                .await
                .map_err(|_| Error::Timeout);
            let r = match result {
                Ok(Ok((s, a))) => {
                    if live.rule.mode == 3 {
                        timeout(self.timers.open, socks_reply(&mut socket, s, a))
                            .await
                            .map_err(|_| Error::Timeout)??
                    }
                    if s != Status::Ok {
                        let streams = pair.as_mut().unwrap();
                        let _ = streams.send.finish();
                        match timeout(
                            self.timers.open,
                            wire::read_message(&mut streams.recv, DEFAULT_MESSAGE_LIMIT),
                        )
                        .await
                        .map_err(|_| Error::Timeout)??
                        {
                            None => Ok(()),
                            Some(_) => Err(bad("message after failed CONNECTED").into()),
                        }
                    } else {
                        let Streams { send, recv, .. } = pair.as_mut().unwrap();
                        self.relay(socket, send, recv, &live).await
                    }
                }
                Ok(Err(e)) | Err(e) => {
                    if live.rule.mode == 3 {
                        let _ = timeout(
                            self.timers.open,
                            socks_reply(&mut socket, Status::Failed, None),
                        )
                        .await;
                    }
                    Err(e)
                }
            };
            if let Some(streams) = pair.as_mut() {
                streams.clean = r.is_ok();
                if let Err(ref e) = r {
                    self.fail_stream(&mut streams.send, &mut streams.recv, e)
                }
            }
            r
        };
        tokio::select! {biased;_=phase.changed()=>Err(Status::Denied.into()),_=self.connection.closed()=>Err(Status::Failed.into()),r=run=>r}
    }
    async fn relay(
        &self,
        socket: TcpStream,
        send: &mut quinn::SendStream,
        recv: &mut quinn::RecvStream,
        live: &Arc<Live>,
    ) -> Result<()> {
        let stopped = send.stopped();
        let (mut rd, mut wr) = socket.into_split();
        let upload = async {
            let mut b = [0u8; CHUNK];
            loop {
                let n = rd.read(&mut b).await?;
                if !live.active() {
                    return Err(Status::Denied.into());
                }
                if n == 0 {
                    send.finish().map_err(|_| Error::Status(Status::Failed))?;
                    break;
                }
                progress_write(
                    send,
                    &Message::new(DATA, vec![(0, Value::Bytes(b[..n].to_vec()))]),
                    self.limit,
                    self.timers.progress,
                    live,
                )
                .await?;
            }
            Ok::<_, Error>(())
        };
        let download = async {
            loop {
                let m = next_frame(recv, self.timers.progress).await?;
                if !live.active() {
                    return Err(Status::Denied.into());
                }
                let Some(m) = m else {
                    timeout(self.timers.progress, wr.shutdown())
                        .await
                        .map_err(|_| Error::Timeout)??;
                    break;
                };
                if m.kind != DATA {
                    return Err(bad("unexpected forwarding DATA message").into());
                }
                let Some(Value::Bytes(b)) = m.field(0) else {
                    return Err(bad("invalid forwarding DATA").into());
                };
                if b.is_empty() || b.len() > 61440 {
                    return Err(bad("invalid forwarding DATA size").into());
                }
                let mut b = b.as_slice();
                while !b.is_empty() {
                    if !live.active() {
                        return Err(Status::Denied.into());
                    }
                    let n = timeout(self.timers.progress, wr.write(b))
                        .await
                        .map_err(|_| Error::Timeout)??;
                    if n == 0 {
                        return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
                    }
                    b = &b[n..]
                }
            }
            Ok::<_, Error>(())
        };
        tokio::select! {biased;_=revoked(live.phase.subscribe())=>Err(Status::Denied.into()),_=self.connection.closed()=>Err(Status::Failed.into()),_=async{if !matches!(stopped.await,Ok(None)){return}std::future::pending::<()>().await}=>Err(Status::Failed.into()),r=async{tokio::try_join!(upload,download)?;Ok(())}=>r}
    }
}
pub struct Running {
    pub actual: SocketAddr,
    cancel: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}
impl Running {
    pub async fn wait(&mut self) -> Result<()> {
        let result = self.task.as_mut().unwrap().await;
        self.task = None;
        result.map_err(|_| Error::Status(Status::Failed))?
    }
    pub async fn close(mut self) {
        self.cancel.send_replace(true);
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.send_replace(true);
    }
}
struct Streams {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    clean: bool,
}
impl Drop for Streams {
    fn drop(&mut self) {
        if !self.clean {
            let _ = self.send.reset(Code::InternalError.varint());
            let _ = self.recv.stop(Code::InternalError.varint());
        }
    }
}
// A single-byte read is cancel-safe; a Pending/connecting peer may send no data.
async fn premature(recv: &mut quinn::RecvStream) -> Error {
    let mut b = [0];
    match recv.read(&mut b).await {
        Ok(Some(_)) => bad("flow bytes before CONNECTED").into(),
        Ok(None) => Status::Failed.into(),
        Err(e) => StreamError::from(e).into(),
    }
}
async fn revoked(mut p: watch::Receiver<Phase>) {
    loop {
        if *p.borrow_and_update() == Phase::Dead {
            return;
        }
        if p.changed().await.is_err() {
            return;
        }
    }
}
async fn next_frame(
    recv: &mut quinn::RecvStream,
    progress: std::time::Duration,
) -> Result<Option<Message>> {
    let mut first = [0];
    match recv.read_exact(&mut first).await {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(e) => return Err(StreamError::from(e).into()),
    }
    let size = 1usize << (first[0] >> 6);
    let mut header = [0u8; 8];
    header[0] = first[0];
    read_progress(recv, &mut header[1..size], progress).await?;
    let mut len = u64::from(header[0] & 63);
    for b in &header[1..size] {
        len = (len << 8) | u64::from(*b)
    }
    if len == 0 {
        return Err(bad("empty forwarding frame").into());
    }
    if len > DEFAULT_MESSAGE_LIMIT {
        return Err(Status::Limit.into());
    }
    let mut payload = vec![0; len as usize];
    read_progress(recv, &mut payload, progress).await?;
    Ok(Some(Message::decode(&payload)?))
}
async fn read_progress(
    recv: &mut quinn::RecvStream,
    mut b: &mut [u8],
    progress: std::time::Duration,
) -> Result<()> {
    while !b.is_empty() {
        let n = timeout(progress, recv.read(b))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(StreamError::from)?
            .ok_or(Status::Failed)?;
        b = &mut b[n..]
    }
    Ok(())
}
async fn progress_write(
    send: &mut quinn::SendStream,
    m: &Message,
    limit: u64,
    progress: std::time::Duration,
    live: &Live,
) -> Result<()> {
    let payload = m.encode();
    if payload.len() as u64 > limit {
        return Err(Status::Failed.into());
    }
    let b = wire::frame(&payload);
    let mut b = b.as_slice();
    while !b.is_empty() {
        if !live.active() {
            return Err(Status::Denied.into());
        }
        let n = timeout(progress, send.write(b))
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(StreamError::from)?;
        if n == 0 {
            return Err(Status::Failed.into());
        }
        b = &b[n..]
    }
    Ok(())
}
async fn socks_request(s: &mut TcpStream) -> Result<Target> {
    let mut h = [0; 2];
    s.read_exact(&mut h).await?;
    if h[0] != 5 || h[1] == 0 {
        return Err(Status::Unsupported.into());
    }
    let mut methods = vec![0; h[1] as usize];
    s.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        s.write_all(&[5, 255]).await?;
        return Err(Status::Unsupported.into());
    }
    s.write_all(&[5, 0]).await?;
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    if h[0] != 5 || h[2] != 0 {
        return Err(Status::Unsupported.into());
    }
    if h[1] != 1 {
        s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        return Err(Status::Unsupported.into());
    }
    let host = match h[3] {
        1 => {
            let mut b = [0; 4];
            s.read_exact(&mut b).await?;
            Host::Ip(Ipv4Addr::from(b).into())
        }
        4 => {
            let mut b = [0; 16];
            s.read_exact(&mut b).await?;
            Host::Ip(normal(Ipv6Addr::from(b).into()))
        }
        3 => {
            let n = s.read_u8().await?;
            let mut b = vec![0; n as usize];
            s.read_exact(&mut b).await?;
            let raw = String::from_utf8(b).map_err(|_| Error::Status(Status::Unsupported))?;
            let n = raw.strip_suffix('.').unwrap_or(&raw).to_ascii_lowercase();
            if !name(&n) {
                s.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                return Err(Status::Unsupported.into());
            }
            Host::Name(n)
        }
        _ => {
            s.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
            return Err(Status::Unsupported.into());
        }
    };
    let port = s.read_u16().await?;
    if port == 0 {
        return Err(Status::Unsupported.into());
    }
    Ok(Target { host, port })
}
async fn socks_reply(
    s: &mut TcpStream,
    status: Status,
    a: Option<SocketAddr>,
) -> std::io::Result<()> {
    let rep = match status {
        Status::Ok => 0,
        Status::Denied => 2,
        Status::Network => 3,
        Status::Name | Status::Host => 4,
        Status::Refused => 5,
        Status::Unsupported => 8,
        _ => 1,
    };
    let a = a.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));
    let mut b = vec![5, rep, 0];
    match a.ip() {
        IpAddr::V4(v) => {
            b.push(1);
            b.extend(v.octets())
        }
        IpAddr::V6(v) => {
            b.push(4);
            b.extend(v.octets())
        }
    }
    b.extend(a.port().to_be_bytes());
    s.write_all(&b).await
}

/// The only Server-opened Channels on a forwarding-only Client are remote flows.
pub async fn accept(state: Arc<State>) {
    while let Ok((mut send, mut recv)) = state.connection.accept_bi().await {
        let state = state.clone();
        tokio::spawn(async move {
            let r = timeout(
                state.timers.open,
                wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT),
            )
            .await;
            match r {
                Ok(Ok(Some(m))) if m.kind == wire::CHANNEL_OPEN => {
                    state.dispatch(send, recv, m).await
                }
                Ok(Err(StreamError::Reset(_) | StreamError::Lost(_))) => {}
                Ok(Ok(None)) => {
                    state
                        .connection
                        .close(Code::ProtocolViolation.varint(), b"");
                }
                Err(_) => {
                    let _ = send.reset(Code::Timeout.varint());
                    let _ = recv.stop(Code::Timeout.varint());
                }
                _ => {
                    state
                        .connection
                        .close(Code::ProtocolViolation.varint(), b"");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::tests::Pair;
    fn reverse_rule(target: SocketAddr) -> Rule {
        Rule {
            mode: 2,
            target: Some(Target {
                host: Host::Ip(target.ip()),
                port: target.port(),
            }),
            bind: Some("127.0.0.1:0".parse().unwrap()),
        }
    }
    fn flow(id: u64) -> Message {
        Message::new(
            wire::CHANNEL_OPEN,
            vec![(0, Value::Uint(FLOW)), (1, Value::Uint(id))],
        )
    }
    async fn streams(pair: &Pair, m: Message) -> (quinn::SendStream, quinn::RecvStream) {
        let (mut send, recv) = pair.server.open_bi().await.unwrap();
        wire::write_message(&mut send, &m, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap();
        (send, recv)
    }
    #[tokio::test]
    async fn early_remote_flow_waits_then_revocation_closes_idle_socket() {
        timeout(std::time::Duration::from_secs(4), async {
            let p = Pair::start().await;
            p.client.set_max_concurrent_bi_streams(10u32.into());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let state = State::new(
                p.client.clone(),
                DEFAULT_MESSAGE_LIMIT,
                Selection::offer(),
                None,
                None,
                Default::default(),
            );
            let guard = state
                .insert(
                    44,
                    reverse_rule(listener.local_addr().unwrap()),
                    Phase::Pending,
                )
                .unwrap();
            let task = tokio::spawn(accept(state.clone()));
            let (_s, mut r) = streams(&p, flow(44)).await;
            assert!(
                timeout(std::time::Duration::from_millis(70), listener.accept())
                    .await
                    .is_err()
            );
            guard.live.phase.send_replace(Phase::Active);
            let (mut target, _) = listener.accept().await.unwrap();
            let reply = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(outcome(&reply, CONNECTED, true).unwrap().0, Status::Ok);
            drop(guard);
            let mut b = [0];
            assert_eq!(target.read(&mut b).await.unwrap(), 0);
            assert!(matches!(
                wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT).await,
                Err(StreamError::Reset(_))
            ));
            assert!(p.server.close_reason().is_none());
            task.abort();
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn unknown_and_wrong_direction_rules_have_no_network_side_effect() {
        timeout(std::time::Duration::from_secs(4),async{
            let p=Pair::start().await;p.client.set_max_concurrent_bi_streams(10u32.into());
            let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
            let state=State::new(p.client.clone(),DEFAULT_MESSAGE_LIMIT,Selection::offer(),None,None,Default::default());
            let mut rule=reverse_rule(listener.local_addr().unwrap());rule.mode=1;rule.bind=None;
            let _guard=state.insert(44,rule,Phase::Active).unwrap();let task=tokio::spawn(accept(state));
            for id in [99,44]{let (_s,mut r)=streams(&p,flow(id)).await;assert!(matches!(wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await,Err(StreamError::Reset(c)) if c==Code::ChannelRejected.varint()));}
            assert!(timeout(std::time::Duration::from_millis(50),listener.accept()).await.is_err());assert!(p.server.close_reason().is_none());task.abort();
        }).await.unwrap();
    }
    #[tokio::test]
    async fn hostile_remote_target_and_empty_data_close_connection() {
        for hostile_target in [true, false] {
            timeout(std::time::Duration::from_secs(4), async {
                let p = Pair::start().await;
                p.client.set_max_concurrent_bi_streams(10u32.into());
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let state = State::new(
                    p.client.clone(),
                    DEFAULT_MESSAGE_LIMIT,
                    Selection::offer(),
                    None,
                    None,
                    Default::default(),
                );
                let _guard = state
                    .insert(
                        44,
                        reverse_rule(listener.local_addr().unwrap()),
                        Phase::Active,
                    )
                    .unwrap();
                let task = tokio::spawn(accept(state));
                let mut m = flow(44);
                if hostile_target {
                    m.body
                        .push((Value::Uint(2), socket_value(listener.local_addr().unwrap())))
                }
                let (mut s, mut r) = streams(&p, m).await;
                if !hostile_target {
                    let (_target, _) = listener.accept().await.unwrap();
                    wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                        .await
                        .unwrap()
                        .unwrap();
                    wire::write_message(
                        &mut s,
                        &Message::new(DATA, vec![(0, Value::Bytes(vec![]))]),
                        DEFAULT_MESSAGE_LIMIT,
                    )
                    .await
                    .unwrap();
                }
                let quinn::ConnectionError::ApplicationClosed(close) = p.server.closed().await
                else {
                    panic!("not application close")
                };
                assert_eq!(close.error_code, Code::ProtocolViolation.varint());
                task.abort();
            })
            .await
            .unwrap()
        }
    }
    #[tokio::test]
    async fn truncated_data_frame_aborts_only_flow() {
        timeout(std::time::Duration::from_secs(4), async {
            let p = Pair::start().await;
            p.client.set_max_concurrent_bi_streams(10u32.into());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let state = State::new(
                p.client.clone(),
                DEFAULT_MESSAGE_LIMIT,
                Selection::offer(),
                None,
                None,
                Default::default(),
            );
            let _guard = state
                .insert(
                    44,
                    reverse_rule(listener.local_addr().unwrap()),
                    Phase::Active,
                )
                .unwrap();
            let task = tokio::spawn(accept(state));
            let (mut s, mut r) = streams(&p, flow(44)).await;
            let (_target, _) = listener.accept().await.unwrap();
            wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap();
            s.write_all(&[12, 0x82]).await.unwrap();
            s.finish().unwrap();
            assert!(matches!(
                wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT).await,
                Err(StreamError::Reset(_))
            ));
            assert!(p.server.close_reason().is_none());
            task.abort();
        })
        .await
        .unwrap();
    }
    #[test]
    fn budgets_count_across_connections_and_retained_rules() {
        let b = Budget::new(1, 2);
        let _a = b.rules.clone().try_acquire_owned().unwrap();
        assert!(b.rules.clone().try_acquire_owned().is_err());
        let global = Global::default();
        let a = global.account("a");
        let again = global.account("a");
        let other = global.account("b");
        assert!(Arc::ptr_eq(&a, &again));
        assert!(!Arc::ptr_eq(&a, &other));
    }

    #[tokio::test]
    async fn global_flow_limit_and_stop_sending_release_live_socket() {
        timeout(std::time::Duration::from_secs(4),async{
            let p=Pair::start().await;p.client.set_max_concurrent_bi_streams(10u32.into());
            let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
            let global=Arc::new(Global{budget:Budget::new(4,1),accounts:Default::default()});
            let state=State::new(p.client.clone(),DEFAULT_MESSAGE_LIMIT,Selection::offer(),None,None,global);
            let _guard=state.insert(44,reverse_rule(listener.local_addr().unwrap()),Phase::Active).unwrap();let task=tokio::spawn(accept(state));
            let (_s,mut r)=streams(&p,flow(44)).await;let(mut target,_)=listener.accept().await.unwrap();wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await.unwrap();
            let (_s2,mut r2)=streams(&p,flow(44)).await;assert!(matches!(wire::read_message(&mut r2,DEFAULT_MESSAGE_LIMIT).await,Err(StreamError::Reset(c)) if c==Code::LimitExceeded.varint()));
            r.stop(Code::NoError.varint()).unwrap();let mut b=[0];assert_eq!(target.read(&mut b).await.unwrap(),0);
            // STOP_SENDING alone must abort, even when no TCP bytes are queued.
            assert!(p.server.close_reason().is_none());task.abort();
        }).await.unwrap();
    }

    #[tokio::test]
    async fn fin_before_ready_is_channel_local() {
        timeout(std::time::Duration::from_secs(3), async {
            let p = Pair::start().await;
            let server = p.server.clone();
            let task = tokio::spawn(async move {
                let (mut send, mut recv) = server.accept_bi().await.unwrap();
                wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap();
                send.finish().unwrap();
                assert!(
                    wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
                        .await
                        .unwrap()
                        .is_none()
                );
            });
            let state = State::new(
                p.client.clone(),
                DEFAULT_MESSAGE_LIMIT,
                Selection::offer(),
                None,
                None,
                Default::default(),
            );
            let r = state
                .open_rule(
                    Rule {
                        mode: 1,
                        target: Some("127.0.0.1:9".parse().unwrap()),
                        bind: None,
                    },
                    Some("127.0.0.1:0".parse().unwrap()),
                    vec![],
                )
                .await;
            assert!(matches!(r, Err(Error::Status(Status::Failed))));
            assert!(p.client.close_reason().is_none());
            task.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn migration_preserves_tcp_flow_and_connection_close_ends_it() {
        timeout(std::time::Duration::from_secs(5), async {
            let p = Pair::start().await;
            p.client.set_max_concurrent_bi_streams(10u32.into());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let state = State::new(
                p.client.clone(),
                DEFAULT_MESSAGE_LIMIT,
                Selection::offer(),
                None,
                None,
                Default::default(),
            );
            let _guard = state
                .insert(
                    44,
                    reverse_rule(listener.local_addr().unwrap()),
                    Phase::Active,
                )
                .unwrap();
            let task = tokio::spawn(accept(state));
            let (_s, mut r) = streams(&p, flow(44)).await;
            let (mut target, _) = listener.accept().await.unwrap();
            wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap();
            let before = p.server.remote_address();
            p.rebind_client();
            target.write_all(b"migrated").await.unwrap();
            let data = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(data.field(0), Some(&Value::Bytes(b"migrated".to_vec())));
            assert_ne!(p.server.remote_address(), before);
            p.server.close(Code::NoError.varint(), b"");
            let mut b = [0];
            assert_eq!(target.read(&mut b).await.unwrap(), 0);
            task.abort();
        })
        .await
        .unwrap();
    }
}
