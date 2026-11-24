//! PF003. One authenticated reverse stream per proposal. The owning relay
//! drops in-flight Client work on detach. Stream guards abort on cancellation.
use crate::{
    cbor::Value,
    consent::{self, Pair},
    file_protocol::{self as p, Status},
    permissions::{Action, Permissions, Selection, Ticket},
    session::AttachmentInfo,
    session_local,
    terminal::SessionId,
    wire::{self, Code, Failure, Message, StreamError},
};
use quinn::{Connection, RecvStream, SendStream};
use std::{
    future::Future,
    io::{self, Read, Seek, Write},
    net::Ipv4Addr,
    path::Path,
    process::ExitCode,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, watch},
    time::timeout,
};
const PENDING: u64 = 0x4010;
const APPROVED: u64 = 0x4011;
const START: u64 = 0x4012;
const READY: u64 = 0x4013;
const DATA: u64 = 0x4014;
const END: u64 = 0x4015;
const RESULT: u64 = 0x4016;
const DENIED: u64 = 0x4017;
const OPEN: Duration = Duration::from_secs(10);
const USER: Duration = Duration::from_secs(60);
const PROGRESS: Duration = Duration::from_secs(60);
type R<T> = Result<T, Failure>;
fn invalid() -> Failure {
    Failure::violation("invalid client file access exchange")
}
fn interrupted() -> Failure {
    Failure::new(Code::NoError, "file request interrupted")
}
fn local(e: impl std::fmt::Display) -> Failure {
    Failure::new(Code::InternalError, e.to_string())
}
fn stream(e: StreamError) -> Failure {
    match e {
        StreamError::Failure(f) => f,
        StreamError::Reset(code) => Failure::new(
            Code::from_value(code.into_inner()).unwrap_or(Code::InternalError),
            "file Channel aborted",
        ),
        StreamError::Lost(_) => interrupted(),
    }
}
async fn deadline<T>(d: Duration, f: impl Future<Output = R<T>>) -> R<T> {
    timeout(d, f)
        .await
        .map_err(|_| Failure::new(Code::Timeout, "file request timed out"))?
}
fn number(m: &Message, k: u64) -> R<u64> {
    m.field(k).and_then(Value::as_uint).ok_or_else(invalid)
}
fn bytes(m: &Message, k: u64) -> R<&[u8]> {
    match m.field(k) {
        Some(Value::Bytes(b)) => Ok(b),
        _ => Err(invalid()),
    }
}
fn msg(k: u64) -> Message {
    Message::new(k, vec![])
}
fn nmsg(k: u64, n: u64) -> Message {
    Message::new(k, vec![(0, Value::Uint(n))])
}
#[derive(Clone, Copy)]
struct Timers {
    open: Duration,
    user: Duration,
    progress: Duration,
}
impl Default for Timers {
    fn default() -> Self {
        Self {
            open: OPEN,
            user: USER,
            progress: PROGRESS,
        }
    }
}
struct Channel {
    timers: Timers,
    max_size: u64,
    tx: SendStream,
    rx: RecvStream,
    conn: Connection,
    limit: u64,
    abort: Option<Code>,
}
impl Drop for Channel {
    fn drop(&mut self) {
        if let Some(code) = self.abort {
            let _ = self.tx.reset(code.varint());
            let _ = self.rx.stop(code.varint());
        }
    }
}
impl Channel {
    fn new(conn: &Connection, pair: (SendStream, RecvStream), limit: u64) -> Self {
        Self {
            max_size: p::DEFAULT_MAX_SIZE,
            timers: Timers::default(),
            tx: pair.0,
            rx: pair.1,
            conn: conn.clone(),
            limit,
            abort: Some(Code::NoError),
        }
    }
    async fn send(&mut self, m: Message) -> R<()> {
        deadline(self.timers.progress, async {
            wire::write_message(&mut self.tx, &m, self.limit)
                .await
                .map_err(stream)
        })
        .await
    }
    async fn next(&mut self, d: Duration) -> R<Message> {
        deadline(d, async {
            wire::read_message(&mut self.rx, wire::DEFAULT_MESSAGE_LIMIT)
                .await
                .map_err(stream)?
                .ok_or_else(interrupted)
        })
        .await
    }
    async fn expect(&mut self, k: u64, d: Duration) -> R<Message> {
        let m = self.next(d).await?;
        if m.kind != k {
            return Err(invalid());
        }
        Ok(m)
    }
    fn fin(&mut self) -> R<()> {
        self.tx.finish().map_err(local)
    }
    async fn eof(&mut self) -> R<()> {
        deadline(self.timers.progress, async {
            match wire::read_message(&mut self.rx, wire::DEFAULT_MESSAGE_LIMIT)
                .await
                .map_err(stream)?
            {
                None => Ok(()),
                Some(_) => Err(invalid()),
            }
        })
        .await
    }
    fn outcome<T>(&mut self, r: &R<T>) {
        match r {
            Ok(_) => self.abort = None,
            Err(e) if self.abort.is_none() && e.code != Code::ProtocolViolation => {}
            Err(e) => {
                self.abort = Some(e.code);
                if e.code == Code::ProtocolViolation {
                    self.conn
                        .close(e.code.varint(), b"invalid client file access exchange");
                }
            }
        }
    }
    async fn result(&mut self, status: Status) -> R<()> {
        self.send(nmsg(RESULT, status as u64)).await?;
        self.fin()
    }
    async fn data(&mut self, offset: u64, b: &[u8]) -> R<()> {
        let frame = Message::new(
            DATA,
            vec![(0, Value::Uint(offset)), (1, Value::Bytes(b.into()))],
        );
        before_end(
            &mut self.rx,
            deadline(self.timers.progress, async {
                wire::write_message(&mut self.tx, &frame, self.limit)
                    .await
                    .map_err(stream)
            }),
        )
        .await
    }
    async fn end(&mut self, count: u64, hash: blake3::Hasher) -> R<()> {
        before_end(&mut self.rx, std::future::ready(Ok(()))).await?;
        self.send(Message::new(
            END,
            vec![
                (0, Value::Uint(count)),
                (1, Value::Bytes(hash.finalize().as_bytes().to_vec())),
            ],
        ))
        .await?;
        self.fin()
    }
}
/// Before END no peer bytes are valid. Quinn's one-byte read is cancel-safe.
async fn before_end<T>(rx: &mut RecvStream, work: impl Future<Output = R<T>>) -> R<T> {
    let mut byte = [0];
    tokio::select! { biased;
        input = rx.read(&mut byte) => Err(match input {
            Ok(Some(_)) => invalid(),
            Ok(None) => interrupted(),
            Err(quinn::ReadError::Reset(code)) => stream(StreamError::Reset(code)),
            Err(_) => interrupted(),
        }),
        result = work => result,
    }
}
enum Part<'a> {
    Data(&'a [u8]),
    End(Status),
}
struct Incoming {
    count: u64,
    length: u64,
    hash: blake3::Hasher,
}
impl Incoming {
    fn new(length: u64) -> Self {
        Self {
            count: 0,
            length,
            hash: blake3::Hasher::new(),
        }
    }
    fn accept<'a>(&mut self, m: &'a Message) -> R<Part<'a>> {
        let offset = number(m, 0)?;
        let b = bytes(m, 1)?;
        match m.kind {
            DATA if offset == self.count
                && (1..=p::MAX_CHUNK).contains(&b.len())
                && b.len() as u64 <= self.length - self.count =>
            {
                self.count += b.len() as u64;
                self.hash.update(b);
                Ok(Part::Data(b))
            }
            END if b.len() == 32 => Ok(Part::End(
                if self.count == self.length
                    && self.count == offset
                    && self.hash.finalize().as_bytes() == b
                {
                    Status::Ok
                } else {
                    Status::Integrity
                },
            )),
            _ => Err(invalid()),
        }
    }
}

pub async fn listen(
    conn: &Connection,
    broker: Option<&Pair>,
    mut grants: Permissions,
    session: SessionId,
    attachment: u64,
    limit: u64,
    policy: (u64, Duration),
) {
    let Some(broker) = broker else {
        return std::future::pending().await;
    };
    while let Ok(pair) = conn.accept_bi().await {
        let mut ch = Channel::new(conn, pair, limit);
        ch.max_size = policy.0;
        ch.timers.progress = policy.1;
        let stopped = ch.tx.stopped();
        let r = {
            let work = client(&mut ch, broker, &mut grants, session, attachment);
            tokio::pin!(work);
            let cancel = async {
                if let Ok(None) = stopped.await {
                    std::future::pending::<()>().await // FIN acknowledgement
                }
            };
            tokio::pin!(cancel);
            loop {
                tokio::select! {biased;
                    ()=&mut cancel=>break Err(interrupted()),
                    result=&mut work=>break result,
                    extra=conn.accept_bi()=>match extra{
                        Ok((mut tx,mut rx))=>{let _=tx.reset(Code::LimitExceeded.varint());let _=rx.stop(Code::LimitExceeded.varint());}
                        Err(_)=>break Err(interrupted())
                    }
                }
            }
        };
        grants.clear();
        ch.outcome(&r);
    }
}
#[cfg(target_os = "linux")]
pub(crate) mod mount_client;
#[cfg(target_os = "linux")]
pub mod mount_server;
type Stage = (crate::file_storage::LocalPublication, std::fs::File);
fn selection(path: &Path, action: Action) -> io::Result<(Selection, Option<Stage>)> {
    match action {
        Action::ReadFile => {
            let mut opt = std::fs::File::options();
            opt.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opt.custom_flags(nix::libc::O_NONBLOCK);
            }
            let f = opt.open(path)?;
            Ok((Selection::read(f)?, None))
        }
        Action::CreateFile(n) => {
            let (publication, file, _) = crate::file_storage::LocalPublication::new(path)
                .map_err(|_| io::Error::other("could not prepare private destination"))?;
            let (parent, name) = publication.selected_destination()?;
            Ok((
                Selection::create(parent, name, n)?,
                Some((publication, file)),
            ))
        }
        #[cfg(target_os = "linux")]
        Action::MountReadOnly => Ok((Selection::directory(mount_client::root(path)?)?, None)),
        #[cfg(not(target_os = "linux"))]
        Action::MountReadOnly => Err(io::ErrorKind::Unsupported.into()),
    }
}
async fn choose(
    ui: &mut TcpStream,
    context: String,
    action: Action,
) -> R<Option<(Selection, Option<Stage>)>> {
    consent::put(ui, context.as_bytes()).await.map_err(local)?;
    let path = String::from_utf8(consent::get(ui).await.map_err(local)?).map_err(local)?;
    if !Path::new(&path).is_absolute() {
        return Ok(None);
    }
    let selected = tokio::task::spawn_blocking(move || selection(Path::new(&path), action))
        .await
        .map_err(local)?
        .map_err(local)?;
    ui.write_u8(1).await.map_err(local)?;
    Ok((ui.read_u8().await.map_err(local)? == 1).then_some(selected))
}
async fn client(
    c: &mut Channel,
    broker: &Pair,
    g: &mut Permissions,
    session: SessionId,
    id: u64,
) -> R<()> {
    let opening = tokio::time::Instant::now() + c.timers.open;
    let open = c.expect(wire::CHANNEL_OPEN, c.timers.open).await?;
    let kind = number(&open, 0)?;
    if matches!(kind, 1 | 2) {
        return Err(invalid());
    }
    if kind != 3 {
        return Err(Failure::new(Code::ChannelRejected, "unknown Channel"));
    }
    let target: [u8; 16] = bytes(&open, 1)?.try_into().map_err(|_| invalid())?;
    let attachment = number(&open, 2)?;
    let action = match number(&open, 3)? {
        1 if open.field(4).is_none() => Action::ReadFile,
        2 => {
            let n = number(&open, 4)?;
            if n > p::MAX_SIZE {
                return Err(invalid());
            }
            Action::CreateFile(n)
        }
        3 if broker.mount && cfg!(target_os = "linux") => {
            if open.field(4).is_some() {
                return Err(invalid());
            }
            Action::MountReadOnly
        }
        1 => return Err(invalid()),
        _ => return Err(Failure::new(Code::ChannelRejected, "unsupported action")),
    };
    let reject = || Failure::new(Code::ChannelRejected, "Client file request refused");
    if SessionId(target) != session
        || attachment != id
        || matches!(action,Action::CreateFile(n) if n>c.max_size)
    {
        return Err(reject());
    }
    let t = g.propose(session, id, action, None).ok_or_else(reject)?;
    let result = async {
        let remaining = || opening.saturating_duration_since(tokio::time::Instant::now());
        let mut ui = deadline(remaining(), async {
            broker.connect().await.map_err(|_| reject())
        })
        .await?;
        deadline(remaining(), c.send(msg(PENDING))).await?;
        let operation = match action {
            Action::ReadFile => "send one local file".into(),
            Action::CreateFile(n) => format!("save a new local file ({n} bytes)"),
            Action::MountReadOnly => "mount directory read-only until revoked. Server root can read and retain copies. Other Attachments of this Session can drive processes that read this directory. Press Enter here or stop stpt consent to revoke".into(),
        };
        let context = format!(
            "{operation}. Server {}, Account {:?}, Session {session}, Attachment {id}",
            g.server, g.account
        );
        let consent_timeout = c.timers.user;
        let selected = tokio::select! {
            biased;
            next = c.next(consent_timeout) => return Err(match next {
                Ok(_) => invalid(),
                Err(e) => e,
            }),
            chosen = deadline(consent_timeout, choose(&mut ui, context, action)) => match chosen {
                Err(e) if e.code == Code::Timeout => return Err(e),
                other => other.ok().flatten(),
            },
        };

        let Some((selection, stage)) = selected else {
            c.send(msg(DENIED)).await?;
            c.fin()?;
            return c.eof().await;
        };
        g.approve(&t, selection).ok_or_else(reject)?;
        c.send(msg(APPROVED)).await?;
        #[cfg(target_os="linux")]
        if action==Action::MountReadOnly {
            return tokio::select!{biased;
                _=ui.read_u8()=>Err(interrupted()),
                result=async {
                    c.expect(START,c.timers.open).await?;
                    g.start(&t).ok_or_else(reject)?;
                    let root = g.mount_root(&t).ok_or_else(reject)?;
                    mount_client::serve(c,root).await
                }=>result,
            };
        }
        drop(ui);
        c.expect(START, c.timers.open).await?;
        g.start(&t).ok_or_else(reject)?;
        client_data(c, g, &t, action, stage).await
    }
    .await;
    g.revoke(&t);
    result
}
async fn client_data(
    c: &mut Channel,
    g: &mut Permissions,
    t: &Ticket,
    action: Action,
    stage: Option<Stage>,
) -> R<()> {
    match action {
        Action::ReadFile => {
            let file = g.source(t).ok_or_else(interrupted)?;
            let length = match file.metadata() {
                Ok(m) if m.len() <= c.max_size => m.len(),
                _ => {
                    c.result(Status::Limit).await?;
                    return c.eof().await;
                }
            };
            let mut file = tokio::fs::File::from_std(file.try_clone().map_err(local)?);
            c.send(nmsg(READY, length)).await?;
            let mut hash = blake3::Hasher::new();
            let mut count = 0;
            let mut buf = vec![0; p::CHUNK];
            while count < length {
                let n = buf.len().min((length - count) as usize);
                let n = before_end(
                    &mut c.rx,
                    deadline(c.timers.progress, async {
                        file.read(&mut buf[..n]).await.map_err(local)
                    }),
                )
                .await?;
                if n == 0 {
                    return Err(local("source shortened"));
                }
                g.source(t).ok_or_else(interrupted)?;
                hash.update(&buf[..n]);
                c.data(count, &buf[..n]).await?;
                count += n as u64;
            }
            c.end(count, hash).await?;
            let m = c.expect(RESULT, c.timers.progress).await?;
            number(&m, 0)?;
            c.eof().await
        }
        Action::CreateFile(length) => {
            let (mut dest, file) = stage.ok_or_else(invalid)?;
            let mut file = tokio::fs::File::from_std(file);
            c.send(nmsg(READY, length)).await?;
            let mut incoming = Incoming::new(length);
            let mut status = loop {
                let m = c.next(c.timers.progress).await?;
                match incoming.accept(&m)? {
                    Part::Data(b) => {
                        deadline(c.timers.progress, async {
                            file.write_all(b).await.map_err(local)
                        })
                        .await?
                    }
                    Part::End(status) => break status,
                }
            };
            c.eof().await?;
            if status == Status::Ok {
                let synced = deadline(c.timers.progress, async {
                    file.flush().await.map_err(local)?;
                    file.sync_all().await.map_err(local)
                })
                .await;
                drop(file);
                if let Err(e) = synced {
                    if e.code == Code::Timeout {
                        return Err(e);
                    }
                    status = Status::Io
                } else {
                    g.destination(t).ok_or_else(interrupted)?;
                    if let Err(e) = dest.publish(false) {
                        status = match e {
                            crate::file_worker::Error::Status(s) => s,
                            _ => Status::Io,
                        }
                    }
                }
            }
            c.result(status).await
        }
        _ => Err(invalid()),
    }
}

/// Give the authenticated Session-local caller a short-lived rendezvous. Both
/// sockets must prove the same private ticket. The second monitors caller exit
/// independently of data backpressure.
pub fn dispatch(
    session: SessionId,
    id: u64,
    info: AttachmentInfo,
    mut detached: watch::Receiver<Option<Code>>,
    mut ended: watch::Receiver<bool>,
    action: session_local::Action,
    permit: OwnedSemaphorePermit,
) -> Result<session_local::Reply, String> {
    static GLOBAL_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(64);
    let capacity = GLOBAL_SLOTS
        .try_acquire()
        .map_err(|_| "Server file request limit reached")?;
    let l = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    l.set_nonblocking(true).map_err(|e| e.to_string())?;
    let port = l.local_addr().map_err(|e| e.to_string())?.port();
    let l = TcpListener::from_std(l).map_err(|e| e.to_string())?;
    let pair = Pair::new(port).map_err(|e| e.to_string())?;
    let ticket = pair.clone();
    tokio::spawn(async move {
        let _capacity = capacity;
        let _permit = permit;
        let peers = timeout(OPEN, async {
            let data = ticket.accept(&l).await?;
            let life = ticket.accept(&l).await?;
            Ok::<_, io::Error>((data, life))
        });
        let accepted = tokio::select! {biased;
            _=detached.changed()=>return, _=ended.changed()=>return,
            r=peers=>r,
        };
        let Ok(Ok((mut data, mut life))) = accepted else {
            return;
        };
        drop(l);
        let uncertain = AtomicBool::new(false);
        let slot_state = detached.clone();
        let session_state = ended.clone();
        let live = || {
            if *session_state.borrow()
                || slot_state.borrow().is_some()
                || slot_state.has_changed().is_err()
                || session_state.has_changed().is_err()
            {
                return Err(interrupted());
            }
            match life.try_read(&mut [0]) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
                _ => Err(interrupted()),
            }
        };
        let exchange = async {
            live()?;
            let opening = tokio::time::Instant::now() + OPEN;
            let streams = deadline(OPEN, async {
                info.connection.open_bi().await.map_err(local)
            })
            .await?;
            let mut c = Channel::new(&info.connection, streams, info.peer_limit);
            c.timers.open = opening.saturating_duration_since(tokio::time::Instant::now());
            c.max_size = info.max_size;
            c.timers.progress = info.progress;
            let result = server(&mut c, session, id, action, &mut data, &uncertain, live).await;
            c.outcome(&result);
            result
        };
        let outcome = tokio::select! {biased;
            _=detached.changed()=>Err(interrupted()),_=ended.changed()=>Err(interrupted()),
            _=async { loop {
                if life.readable().await.is_err() || !matches!(life.try_read(&mut [0]),Err(e) if e.kind()==io::ErrorKind::WouldBlock) { break; }
            }}=>Err(interrupted()), result=exchange=>result
        };
        let message = match outcome {
            Ok(()) => "+".into(),
            Err(e) if uncertain.load(Ordering::Relaxed) => format!("unknown create outcome: {e}"),
            Err(e) => e.to_string(),
        };
        let _ = timeout(PROGRESS, consent::put(&mut life, message.as_bytes())).await;
    });
    Ok(session_local::Reply::Transfer(pair))
}

async fn local_put(progress: Duration, s: &mut TcpStream, b: &[u8]) -> R<()> {
    deadline(progress, async { consent::put(s, b).await.map_err(local) }).await
}
async fn local_get(progress: Duration, s: &mut TcpStream) -> R<Vec<u8>> {
    deadline(progress, async { consent::get(s).await.map_err(local) }).await
}
async fn server(
    c: &mut Channel,
    session: SessionId,
    id: u64,
    action: session_local::Action,
    data: &mut TcpStream,
    uncertain: &AtomicBool,
    live: impl Fn() -> R<()>,
) -> R<()> {
    let create = match action {
        session_local::Action::Read { .. } => None,
        session_local::Action::Create { bytes, .. } if bytes <= c.max_size => Some(bytes),
        _ => return Err(local("unsupported request or size limit")),
    };
    let mut fields = vec![
        (0, Value::Uint(3)),
        (1, Value::Bytes(session.0.to_vec())),
        (2, Value::Uint(id)),
        (3, Value::Uint(if create.is_some() { 2 } else { 1 })),
    ];
    if let Some(n) = create {
        fields.push((4, Value::Uint(n)))
    }
    deadline(c.timers.open, async {
        c.send(Message::new(wire::CHANNEL_OPEN, fields)).await?;
        c.expect(PENDING, OPEN).await
    })
    .await?;
    match c.next(c.timers.user).await?.kind {
        DENIED => {
            c.fin()?;
            c.eof().await?;
            c.abort = None;
            return Err(Failure::new(Code::NoError, "Client denied the request"));
        }
        APPROVED => {}
        _ => return Err(invalid()),
    }
    // Let the reactor deliver concurrent caller hangup and detach notifications.
    tokio::task::yield_now().await;
    live()?;
    c.send(msg(START)).await?;
    let ready = c.next(c.timers.progress).await?;
    if ready.kind == RESULT {
        let status = number(&ready, 0)?;
        if status == 0 {
            return Err(invalid());
        }
        c.fin()?;
        c.eof().await?;
        c.abort = None;
        return Err(local(format!("Client refused operation (status {status})")));
    }
    if ready.kind != READY {
        return Err(invalid());
    }
    let length = number(&ready, 0)?;
    if length > p::MAX_SIZE || create.is_some_and(|n| n != length) {
        return Err(invalid());
    }
    if length > c.max_size {
        return Err(Failure::new(
            Code::LimitExceeded,
            "file size limit exceeded",
        ));
    }
    if create.is_some() {
        local_put(c.timers.progress, data, b"W").await?;
        let mut count = 0;
        let mut hash = blake3::Hasher::new();
        while count < length {
            let b = before_end(&mut c.rx, local_get(c.timers.progress, data)).await?;
            if b.is_empty() || b.len() > p::MAX_CHUNK || b.len() as u64 > length - count {
                return Err(local("short or invalid Session input"));
            }
            hash.update(&b);
            c.data(count, &b).await?;
            count += b.len() as u64;
        }
        uncertain.store(true, Ordering::Relaxed);
        c.end(count, hash).await?;
        let result = c.expect(RESULT, c.timers.progress).await?;
        let status = number(&result, 0)?;
        uncertain.store(false, Ordering::Relaxed);
        if let Err(e) = c.eof().await {
            if e.code == Code::ProtocolViolation {
                return Err(e);
            }
            // The full RESULT settled publication even if FIN was lost.
            let _ = c.rx.stop(e.code.varint());
        }
        if status != 0 {
            return Err(local(format!("Client file status {status}")));
        }
    } else {
        local_put(c.timers.progress, data, b"R").await?;
        let mut incoming = Incoming::new(length);
        loop {
            let m = c.next(c.timers.progress).await?;
            match incoming.accept(&m)? {
                Part::Data(b) => local_put(c.timers.progress, data, b).await?,
                Part::End(status) => {
                    c.eof().await?;
                    if status != Status::Ok {
                        c.result(status).await?;
                        c.abort = None;
                        return Err(local("Client file integrity check failed"));
                    }
                    local_put(c.timers.progress, data, &[]).await?; // release verified spool to the local caller
                    let ack = local_get(c.timers.progress, data).await?;
                    if ack != b"ok" {
                        c.result(Status::Io).await?;
                        c.abort = None;
                        return Err(local("Session output failed"));
                    }
                    c.result(Status::Ok).await?;
                    break;
                }
            }
        }
    }
    Ok(())
}

pub fn caller(pair: Pair, action: session_local::Action) -> io::Result<ExitCode> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let (mut data, mut life) = timeout(OPEN, async {
            let d = pair.connect().await?;
            let l = pair.connect().await?;
            Ok::<_, io::Error>((d, l))
        })
        .await??;
        if matches!(action, session_local::Action::Mount { .. }) {
            let result = consent::get(&mut life).await?;
            let text = String::from_utf8(result).map_err(io::Error::other)?;
            if let Some(path) = text.strip_prefix("+/tmp/stpt-mount-")
                && path.len() == 32
                && path.bytes().all(|b| b.is_ascii_hexdigit())
            {
                println!("/tmp/stpt-mount-{path}");
                return Ok(ExitCode::SUCCESS);
            }
            return Err(io::Error::other(text.escape_debug().to_string()));
        }
        let transfer = async {
            let mode = consent::get(&mut data).await?;
            match (mode.as_slice(), action) {
                (b"W", session_local::Action::Create { bytes, .. }) => {
                    // A detached reader thread may be blocked on a terminal. It must
                    // never keep the command alive after the Server cancels the call.
                    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                    std::thread::spawn(move || {
                        let mut input = io::stdin().lock();
                        let mut left = bytes;
                        while left > 0 {
                            let mut b = vec![0; left.min(p::CHUNK as u64) as usize];
                            if input.read_exact(&mut b).is_err() {
                                break;
                            }
                            left -= b.len() as u64;
                            if tx.blocking_send(b).is_err() {
                                break;
                            }
                        }
                    });
                    let mut count = 0;
                    while let Some(b) = rx.recv().await {
                        count += b.len() as u64;
                        consent::put(&mut data, &b).await?
                    }
                    if count != bytes {
                        return Err(io::Error::other(
                            "standard input shorter than declared size",
                        ));
                    }
                }
                (b"R", session_local::Action::Read { .. }) => {
                    // Staging runs as the Session caller, never as the Server Account.
                    let (guard, mut spool, _) = crate::file_storage::LocalPublication::new(
                        &std::env::temp_dir().join("stpt-verified-output"),
                    )
                    .map_err(|_| io::Error::other("cannot stage Session output"))?;
                    loop {
                        let b = consent::get(&mut data).await?;
                        if b.is_empty() {
                            break;
                        }
                        spool.write_all(&b)?
                    }
                    let (tx, rx) = tokio::sync::oneshot::channel();
                    std::thread::spawn(move || {
                        let _guard = guard;
                        let result = (|| {
                            spool.rewind()?;
                            let mut output = io::stdout().lock();
                            io::copy(&mut spool, &mut output)?;
                            output.flush()
                        })();
                        let _ = tx.send(result);
                    });
                    rx.await.map_err(io::Error::other)??;
                    consent::put(&mut data, b"ok").await?;
                }
                _ => return Err(io::Error::other("invalid Session data exchange")),
            }
            Ok::<(), io::Error>(())
        };
        let status = consent::get(&mut life);
        tokio::pin!(status);
        let message = tokio::select! {biased;result=&mut status=>result,result=transfer=>{
            result?;status.await
        }};
        let m = message.map_err(|_| {
            io::Error::other("Session request interrupted; a modifying outcome may be unknown")
        })?;
        if m != b"+" {
            return Err(io::Error::other(
                String::from_utf8_lossy(&m).escape_debug().to_string(),
            ));
        }
        Ok(ExitCode::SUCCESS)
    })
}

#[cfg(test)]
mod tests;
