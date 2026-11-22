//! File Channel lifecycle and bounded relay to an Account-owned filesystem worker.
//! Payload grammar: file_protocol; operations: file_worker; CLI: file_client.

use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, RecvStream, SendStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::cbor::Value;
use crate::hello::Capabilities;
use crate::wire::{self, Code, DEFAULT_MESSAGE_LIMIT, Failure, Message, StreamError};

pub const CAPABILITY: u64 = 1;
pub const KIND: u64 = 2;
pub const DEFAULT_SERVER_CAP: u32 = 8;
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const BULK_PRIORITY: i32 = -1;

pub fn parameters(max_channels: u64) -> Value {
    Value::Map(vec![
        (Value::Uint(0), Value::Uint(1)),
        (Value::Uint(1), Value::Uint(max_channels)),
    ])
}

fn parse(value: &Value) -> Option<u64> {
    let entries = value.as_map()?;
    if !entries.iter().all(|(k, _)| k.is_int()) {
        return None;
    }
    let field = |key| {
        entries
            .iter()
            .find(|(k, _)| *k == Value::Uint(key))
            .map(|(_, v)| v)
    };
    if field(0)?.as_uint()? != 1 {
        return None;
    }
    field(1)?.as_uint().filter(|n| *n > 0)
}

pub fn selected(caps: &Capabilities) -> Option<u64> {
    caps.iter()
        .find(|(id, _)| *id == CAPABILITY)
        .and_then(|(_, v)| parse(v))
}

pub fn select(offered: &Capabilities, cap: u32) -> Capabilities {
    match (selected(offered), cap) {
        (Some(max), 1..) => vec![(CAPABILITY, parameters(max.min(u64::from(cap))))],
        _ => Vec::new(),
    }
}

pub fn check_selection(answer: &Capabilities, offer: &Capabilities) -> Result<(), Failure> {
    if answer.iter().any(|(id, _)| *id == CAPABILITY) {
        match (selected(answer), selected(offer)) {
            (Some(max), Some(offered)) if max <= offered => {}
            _ => return Err(Failure::violation("invalid file capability selection")),
        }
    }
    Ok(())
}

fn abort(send: &mut SendStream, recv: &mut RecvStream, code: Code) {
    let _ = send.reset(code.varint());
    let _ = recv.stop(code.varint());
}

/// One Connection's negotiated file budget. Permits live through both directions.
#[derive(Clone)]
pub struct Budget(Arc<Semaphore>);

impl Budget {
    pub fn new(max: u32) -> Self {
        Self(Arc::new(Semaphore::new(max as usize)))
    }

    fn acquire(&self) -> Result<OwnedSemaphorePermit, Failure> {
        self.0
            .clone()
            .try_acquire_owned()
            .map_err(|_| Failure::new(Code::LimitExceeded, "file Channel limit exceeded"))
    }
}

/// Server side, called only after authentication and capability checks.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "test-only envelope without a filesystem service")
)]
pub async fn serve(
    send: SendStream,
    recv: RecvStream,
    peer_limit: u64,
    budget: &Budget,
) -> Result<(), Failure> {
    serve_inner(
        send,
        recv,
        peer_limit,
        budget,
        #[cfg(unix)]
        None,
    )
    .await
}

#[cfg(unix)]
pub struct Service<'a> {
    pub account: &'a str,
    pub max_size: u64,
    pub timeout: Duration,
    pub workers: Arc<Semaphore>,
    pub resume: Arc<crate::file_resume::Store>,
}

#[cfg(unix)]
pub async fn serve_account(
    send: SendStream,
    recv: RecvStream,
    peer_limit: u64,
    budget: &Budget,
    service: Service<'_>,
) -> Result<(), Failure> {
    serve_inner(send, recv, peer_limit, budget, Some(service)).await
}

async fn serve_inner(
    mut send: SendStream,
    mut recv: RecvStream,
    peer_limit: u64,
    budget: &Budget,
    #[cfg(unix)] service: Option<Service<'_>>,
) -> Result<(), Failure> {
    let _permit = match budget.acquire() {
        Ok(permit) => permit,
        Err(_) => {
            abort(&mut send, &mut recv, Code::LimitExceeded);
            return Ok(());
        }
    };
    let _ = send.set_priority(BULK_PRIORITY);
    let ready = Message::new(wire::FILES_READY, vec![]);
    if let Err(error) = wire::write_message(&mut send, &ready, peer_limit).await {
        return server_error(error, &mut send, &mut recv);
    }
    let next = tokio::select! {
        message = wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT) => message,
        _ = send.stopped() => { abort(&mut send, &mut recv, Code::NoError); return Ok(()); }
    };
    match next {
        Ok(None) => {
            if send.finish().is_ok() {
                // Retain the slot until the peer acknowledges our FIN or resets.
                if timeout(OPEN_TIMEOUT, send.stopped()).await.is_err() {
                    abort(&mut send, &mut recv, Code::Timeout);
                }
            }
            Ok(())
        }
        Ok(Some(message)) if message.kind == wire::FILE_REQUEST => {
            #[cfg(unix)]
            if let Some(service) = service {
                return worker_relay(send, recv, peer_limit, message, service).await;
            }
            // An envelope-only test peer or unsupported platform has no worker.
            abort(&mut send, &mut recv, Code::InternalError);
            Ok(())
        }
        Ok(Some(message)) => Err(Failure::violation(format!(
            "message type {} on idle file Channel",
            message.kind
        ))),
        Err(error) => server_error(error, &mut send, &mut recv),
    }
}

fn server_error(
    error: StreamError,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<(), Failure> {
    match error {
        StreamError::Failure(failure) => Err(failure),
        StreamError::Reset(_) | StreamError::Lost(_) => {
            abort(send, recv, Code::NoError);
            Ok(())
        }
    }
}

/// Client side file Channel, shared by the explicit `fs` commands.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "idle lifecycle API is also used by protocol tests"
    )
)]
pub struct Channel {
    pub(super) connection: Connection,
    pub(super) send: SendStream,
    pub(super) recv: RecvStream,
    _permit: OwnedSemaphorePermit,
    closed: bool,
}

#[cfg(unix)]
async fn worker_relay(
    mut send: SendStream,
    mut recv: RecvStream,
    peer_limit: u64,
    initial: Message,
    service: Service<'_>,
) -> Result<(), Failure> {
    use crate::file_protocol as p;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let request = p::Request::parse(&initial)?;
    let exchange = std::sync::Mutex::new(p::Exchange::new(&request)?);
    let _worker_slot = match service.workers.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            abort(&mut send, &mut recv, Code::LimitExceeded);
            return Ok(());
        }
    };
    let account = service.account.to_owned();
    // Keep admission charged even if an NSS lookup outlives cancellation.
    let lookup = tokio::task::spawn_blocking(move || {
        (crate::process::Account::lookup(&account), _worker_slot)
    });
    let joined = tokio::select! {
        result=timeout(service.timeout,lookup)=>match result {Ok(r)=>r,Err(_)=>{abort(&mut send,&mut recv,Code::Timeout);return Ok(());}},
        _=send.stopped()=>{abort(&mut send,&mut recv,Code::NoError);return Ok(());},
    };
    let (account, _worker_slot) = match joined {
        Ok(result) => result,
        Err(_) => {
            abort(&mut send, &mut recv, Code::InternalError);
            return Ok(());
        }
    };
    let account = match account {
        Ok(Some(a)) => a,
        _ => {
            abort(&mut send, &mut recv, Code::ChannelRejected);
            return Ok(());
        }
    };
    let retained = request.kind == 2
        && request
            .resume
            .as_ref()
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_uint)
            .is_some_and(|n| n <= 1);
    let (lease, parked) = if retained {
        match service.resume.acquire(&account, &request) {
            Ok((l, w)) => (Some(l), w),
            Err(status) => {
                wire::write_message(&mut send, &p::result(request.id, status, None), peer_limit)
                    .await
                    .map_err(|_| Failure::new(Code::InternalError, "resume refusal"))?;
                let _ = send.finish();
                return Ok(());
            }
        }
    } else {
        (None, None)
    };
    let lease = std::sync::Mutex::new(lease);
    let mut worker = if let Some(w) = parked {
        drop(_worker_slot);
        w
    } else {
        let mut child = match account.file_worker(peer_limit, service.max_size) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(?e, "file worker start failed");
                abort(&mut send, &mut recv, Code::ChannelRejected);
                return Ok(());
            }
        };
        crate::file_resume::Worker {
            input: child.stdin.take(),
            output: child.stdout.take(),
            child: Some(child),
            permit: Some(_worker_slot),
        }
    };
    let stdin = worker.input.as_mut().unwrap();
    let stdout = worker.output.as_mut().unwrap();
    let progress = std::sync::Mutex::new((true, tokio::time::Instant::now()));
    let stopped = send.stopped();
    let result = {
        let input = async {
            let first = initial.encode();
            stdin
                .write_all(&(first.len() as u32).to_be_bytes())
                .await
                .map_err(|_| StreamError::Reset(Code::InternalError.varint()))?;
            stdin
                .write_all(&first)
                .await
                .map_err(|_| StreamError::Reset(Code::InternalError.varint()))?;
            loop {
                let Some(mut message) =
                    wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await?
                else {
                    let b = Message::new(2, vec![]).encode();
                    stdin
                        .write_all(&(b.len() as u32).to_be_bytes())
                        .await
                        .map_err(|_| StreamError::Reset(Code::InternalError.varint()))?;
                    stdin
                        .write_all(&b)
                        .await
                        .map_err(|_| StreamError::Reset(Code::InternalError.varint()))?;
                    return Ok::<_, StreamError>(());
                };
                exchange.lock().unwrap().incoming(&message)?;
                if message.kind == p::END {
                    lease.lock().unwrap().take();
                }
                if message.kind == wire::FILE_REQUEST && message.field(7).is_some() {
                    // Retention is admitted on a fresh Channel only.
                    message.body.retain(|(k, _)| *k != Value::Uint(7));
                    message
                        .body
                        .push((Value::Uint(7), Value::Array(vec![Value::Uint(99)])));
                }
                progress.lock().unwrap().0 = true;
                let b = message.encode();
                stdin
                    .write_all(&(b.len() as u32).to_be_bytes())
                    .await
                    .map_err(|_| StreamError::Reset(Code::InternalError.varint()))?;
                stdin
                    .write_all(&b)
                    .await
                    .map_err(|_| StreamError::Reset(Code::InternalError.varint()))?;
                progress.lock().unwrap().1 = tokio::time::Instant::now();
            }
        };
        let output = async {
            loop {
                let mut prefix = [0; 4];
                match stdout.read_exact(&mut prefix).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok::<_, StreamError>(());
                    }
                    Err(_) => return Err(StreamError::Reset(Code::InternalError.varint())),
                }
                let n = u32::from_be_bytes(prefix) as usize;
                if n == 0 || n > 65535 {
                    return Err(StreamError::Reset(Code::InternalError.varint()));
                }
                let mut b = vec![0; n];
                stdout
                    .read_exact(&mut b)
                    .await
                    .map_err(|_| StreamError::Reset(Code::InternalError.varint()))?;
                let m = Message::decode(&b)
                    .map_err(|_| StreamError::Reset(Code::InternalError.varint()))?;
                if m.kind == 0 {
                    let code = m
                        .field(0)
                        .and_then(crate::cbor::Value::as_uint)
                        .and_then(Code::from_value)
                        .unwrap_or(Code::InternalError);
                    return if code == Code::ProtocolViolation {
                        Err(
                            Failure::violation("file worker rejected invalid operation exchange")
                                .into(),
                        )
                    } else {
                        Err(StreamError::Reset(code.varint()))
                    };
                }
                exchange.lock().unwrap().outgoing(&m)?;
                if m.kind == p::RESULT {
                    lease.lock().unwrap().take();
                }
                if m.kind == p::ACCEPTED
                    && let Some(l) = lease.lock().unwrap().as_ref()
                    && let Some(a) = m.field(3).and_then(Value::as_array)
                    && let Value::Bytes(token) = &a[0]
                {
                    l.token(token.clone());
                }
                wire::write_message(&mut send, &m, peer_limit).await?;
                let mut state = progress.lock().unwrap();
                state.1 = tokio::time::Instant::now();
                state.0 = exchange.lock().unwrap().active();
            }
        };
        let deadline = async {
            let mut tick = tokio::time::interval(service.timeout.min(Duration::from_secs(1)));
            loop {
                tick.tick().await;
                let (active, last) = *progress.lock().unwrap();
                if active && last.elapsed() >= service.timeout {
                    return;
                }
            }
        };
        tokio::pin!(input, output, deadline);
        tokio::select! {
            r=&mut input=>match r {Ok(())=>output.await,Err(e)=>Err(e)},
            r=&mut output=>r.and_then(|()|Err(StreamError::Reset(Code::InternalError.varint()))),
            stopped=stopped=>match stopped {
                Ok(Some(code))=>Err(StreamError::Reset(code)),
                Err(error)=>Err(quinn::WriteError::from(error).into()),
                _=>Err(StreamError::Reset(Code::NoError.varint())),
            },
            ()=&mut deadline=>Err(StreamError::Reset(Code::Timeout.varint())),
        }
    };
    let eligible = matches!(&result,Err(StreamError::Reset(c)) if *c==Code::Timeout.varint())
        || matches!(
            &result,
            Err(StreamError::Lost(
                quinn::ConnectionError::TimedOut
                    | quinn::ConnectionError::Reset
                    | quinn::ConnectionError::TransportError(_)
            ))
        );
    if eligible && exchange.lock().unwrap().retaining() {
        if let Some(lease) = lease.into_inner().unwrap() {
            let checkpoint = async {
                let b = Message::new(1, vec![]).encode();
                stdin.write_all(&(b.len() as u32).to_be_bytes()).await?;
                stdin.write_all(&b).await?;
                let mut prefix = [0; 4];
                stdout.read_exact(&mut prefix).await?;
                let n = u32::from_be_bytes(prefix) as usize;
                if n == 0 || n > 65535 {
                    return Err(std::io::Error::other("checkpoint limit"));
                }
                let mut b = vec![0; n];
                stdout.read_exact(&mut b).await?;
                if !Message::decode(&b).is_ok_and(|m| m.kind == 1) {
                    return Err(std::io::Error::other("checkpoint refused"));
                }
                Ok::<_, std::io::Error>(())
            };
            if matches!(
                timeout(Duration::from_secs(2), checkpoint).await,
                Ok(Ok(()))
            ) {
                lease.park(worker);
            }
        }
    } else {
        drop(lease);
        // EOF lets the Account-owned worker remove private staging.
        worker.input.take();
        if result.is_ok()
            && matches!(timeout(Duration::from_secs(2),worker.child.as_mut().unwrap().wait()).await,Ok(Ok(status)) if status.success())
        {
            let _ = send.finish();
            let _ = timeout(OPEN_TIMEOUT, send.stopped()).await;
            return Ok(());
        }
    }
    match result {
        Err(StreamError::Failure(f)) => Err(f),
        Err(StreamError::Reset(code)) => {
            let _ = send.reset(code);
            let _ = recv.stop(code);
            Ok(())
        }
        _ => {
            abort(&mut send, &mut recv, Code::InternalError);
            Ok(())
        }
    }
}

#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "idle lifecycle API is also used by protocol tests"
    )
)]
impl Channel {
    pub(super) fn abort(&mut self, code: Code) {
        abort(&mut self.send, &mut self.recv, code);
        self.closed = true;
    }
    /// Caller holds an authenticated Connection and its selected file budget.
    pub async fn open(
        connection: &Connection,
        peer_limit: u64,
        budget: &Budget,
        deadline: Duration,
    ) -> Result<Self, StreamError> {
        let permit = budget.acquire()?;
        // Waiting for QUIC stream credit is bounded too; no stream exists yet.
        let (send, recv) = timeout(deadline, connection.open_bi())
            .await
            .map_err(|_| Failure::new(Code::Timeout, "waiting for file stream credit"))?
            .map_err(StreamError::Lost)?;
        let mut channel = Self {
            connection: connection.clone(),
            send,
            recv,
            _permit: permit,
            closed: false,
        };
        let _ = channel.send.set_priority(BULK_PRIORITY);
        let result = timeout(deadline, async {
            wire::write_message(
                &mut channel.send,
                &Message::new(wire::CHANNEL_OPEN, vec![(0, Value::Uint(KIND))]),
                peer_limit,
            )
            .await?;
            let ready = wire::read_message(&mut channel.recv, DEFAULT_MESSAGE_LIMIT)
                .await?
                .ok_or_else(|| Failure::violation("file Channel ended before FILES_READY"))?;
            if ready.kind != wire::FILES_READY {
                return Err(Failure::violation("expected FILES_READY").into());
            }
            Ok::<_, StreamError>(())
        })
        .await;
        match result {
            Ok(Ok(())) => Ok(channel),
            Ok(Err(error)) => {
                if let StreamError::Failure(failure) = &error {
                    connection.close(failure.code.varint(), b"");
                }
                Err(error)
            }
            Err(_) => {
                abort(&mut channel.send, &mut channel.recv, Code::Timeout);
                channel.closed = true;
                Err(StreamError::Reset(Code::Timeout.varint()))
            }
        }
    }

    /// Watches an idle Channel for Server FIN and replies with Client FIN.
    /// File-operation code must own the reader instead while an operation runs.
    pub async fn wait_closed(mut self) -> Result<(), StreamError> {
        let message = tokio::select! {
            message = wire::read_message(&mut self.recv, DEFAULT_MESSAGE_LIMIT) => message,
            stopped = self.send.stopped() => {
                return match stopped.map_err(quinn::WriteError::from)? {
                    Some(code) => Err(StreamError::Reset(code)),
                    None => Err(Failure::new(Code::InternalError, "unexpected finished idle file sender").into()),
                };
            }
        };
        let failure = match message {
            Ok(None) => return self.close().await,
            Ok(Some(_)) => Failure::violation("message on idle file Channel"),
            Err(StreamError::Failure(failure)) => failure,
            Err(error) => return Err(error),
        };
        self.connection.close(failure.code.varint(), b"");
        Err(failure.into())
    }

    /// Graceful idle close, waiting for both directions before releasing the slot.
    pub async fn close(mut self) -> Result<(), StreamError> {
        let result = timeout(OPEN_TIMEOUT, async {
            self.send
                .finish()
                .map_err(|e| Failure::new(Code::InternalError, format!("file FIN: {e}")))?;
            if wire::read_message(&mut self.recv, DEFAULT_MESSAGE_LIMIT)
                .await?
                .is_some()
            {
                return Err(Failure::violation("message while closing idle file Channel").into());
            }
            let stopped = self.send.stopped().await.map_err(quinn::WriteError::from)?;
            if let Some(code) = stopped {
                return Err(StreamError::Reset(code));
            }
            Ok::<_, StreamError>(())
        })
        .await;
        match result {
            Ok(Ok(())) => {
                self.closed = true;
                Ok(())
            }
            Ok(Err(error)) => {
                if let StreamError::Failure(failure) = &error {
                    self.connection.close(failure.code.varint(), b"");
                }
                Err(error)
            }
            Err(_) => {
                abort(&mut self.send, &mut self.recv, Code::Timeout);
                self.closed = true;
                Err(StreamError::Reset(Code::Timeout.varint()))
            }
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        if !self.closed {
            abort(&mut self.send, &mut self.recv, Code::NoError);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::hello::{ClientHello, ServerHello};

    #[test]
    fn negotiation_narrows_and_preserves_terminal_only_peers() {
        let offer = ClientHello::with_files(20);
        let answer = ServerHello::answer_with_files(&offer, 8).unwrap();
        assert_eq!(selected(&answer.capabilities), Some(8));
        answer.check(&offer).unwrap();
        let default_offer = ClientHello::with_files(1);
        assert_eq!(
            selected(
                &ServerHello::answer_with_files(&default_offer, 8)
                    .unwrap()
                    .capabilities
            ),
            Some(1)
        );
        assert!(
            ServerHello::answer_with_files(&offer, 0)
                .unwrap()
                .capabilities
                .is_empty()
        );
        assert!(
            ServerHello::answer_with_files(&ClientHello::ours(), 8)
                .unwrap()
                .capabilities
                .is_empty()
        );
        ServerHello::answer(&offer).unwrap().check(&offer).unwrap();
        assert_eq!(
            selected(
                &ClientHello::from_message(&Message::decode(&offer.to_message().encode()).unwrap())
                    .unwrap()
                    .capabilities
            ),
            Some(20)
        );
    }

    #[test]
    fn malformed_offers_are_ignored_and_bad_selections_rejected() {
        let good = ClientHello::with_files(2);
        let invalid = [
            Value::Null,
            Value::Array(vec![]),
            Value::Map(vec![]),
            parameters(0),
            Value::Map(vec![
                (Value::Uint(0), Value::Uint(2)),
                (Value::Uint(1), Value::Uint(1)),
            ]),
            Value::Map(vec![(Value::Uint(0), Value::Uint(1))]),
            Value::Map(vec![
                (Value::Uint(0), Value::Uint(1)),
                (Value::Uint(1), Value::Text("1".into())),
            ]),
            Value::Map(vec![(Value::Text("0".into()), Value::Uint(1))]),
        ];
        for value in invalid {
            let mut offer = good.clone();
            offer.capabilities = vec![(CAPABILITY, value.clone())];
            assert!(
                ServerHello::answer_with_files(&offer, 8)
                    .unwrap()
                    .capabilities
                    .is_empty()
            );
            let mut answer = ServerHello::answer(&good).unwrap();
            answer.capabilities = vec![(CAPABILITY, value)];
            assert_eq!(
                answer.check(&good).unwrap_err().code,
                Code::ProtocolViolation
            );
        }
        let mut excessive = ServerHello::answer(&good).unwrap();
        excessive.capabilities = vec![(CAPABILITY, parameters(3))];
        assert_eq!(
            excessive.check(&good).unwrap_err().code,
            Code::ProtocolViolation
        );
        // Unknown integer fields remain extensible.
        let mut extended = parameters(2);
        if let Value::Map(entries) = &mut extended {
            entries.push((Value::Nint(0), Value::Null));
        }
        assert_eq!(selected(&vec![(CAPABILITY, extended)]), Some(2));
    }

    pub(crate) struct Pair {
        _server: quinn::Endpoint,
        _client: quinn::Endpoint,
        pub(crate) server: Connection,
        pub(crate) client: Connection,
    }

    impl Pair {
        pub(crate) async fn start() -> Self {
            let key = crate::identity::ServerKey::generate();
            let server = crate::quic::listen("127.0.0.1:0".parse().unwrap(), &key).unwrap();
            let addr = server.local_addr().unwrap();
            let client = crate::quic::client(addr).unwrap();
            let check = crate::tls::ServerKeyCheck::new(crate::tls::Expected {
                stored: Some(key.public_key()),
                fingerprint: None,
            });
            let (outbound, inbound) = tokio::join!(
                crate::quic::connect(&client, addr, "localhost", check),
                async { crate::quic::accept(server.accept().await.unwrap()).await }
            );
            let inbound = inbound.unwrap();
            inbound.set_max_concurrent_bi_streams(quinn::VarInt::from_u32(10));
            Self {
                _server: server,
                _client: client,
                server: inbound,
                client: outbound.unwrap(),
            }
        }
    }

    #[tokio::test]
    async fn opening_timeout_resets_only_stream_and_releases_slot() {
        timeout(Duration::from_secs(3), async {
            let pair = Pair::start().await;
            let server = pair.server.clone();
            let task = tokio::spawn(async move {
                let (send, mut recv) = server.accept_bi().await.unwrap();
                assert_eq!(wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await.unwrap().unwrap().kind, wire::CHANNEL_OPEN);
                assert!(matches!(wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await, Err(StreamError::Reset(code)) if code == Code::Timeout.varint()));
                assert_eq!(send.stopped().await.unwrap(), Some(Code::Timeout.varint()));
            });
            let budget = Budget::new(1);
            let error = Channel::open(&pair.client, DEFAULT_MESSAGE_LIMIT, &budget, Duration::from_millis(50)).await;
            assert!(matches!(error, Err(StreamError::Reset(code)) if code == Code::Timeout.varint()));
            assert_eq!(budget.0.available_permits(), 1);
            task.await.unwrap();
            assert!(pair.client.close_reason().is_none());
        }).await.unwrap();
    }

    #[tokio::test]
    async fn invalid_ready_or_fin_before_ready_closes_connection() {
        for bytes in [
            Some(wire::frame(
                &Message::new(wire::TERMINAL_ATTACHED, vec![]).encode(),
            )),
            None,
        ] {
            timeout(Duration::from_secs(3), async {
                let pair = Pair::start().await;
                let server = pair.server.clone();
                let task = tokio::spawn(async move {
                    let (mut send, mut recv) = server.accept_bi().await.unwrap();
                    wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await.unwrap();
                    if let Some(bytes) = bytes { send.write_all(&bytes).await.unwrap(); }
                    else { send.finish().unwrap(); }
                    server.closed().await
                });
                let budget = Budget::new(1);
                assert!(matches!(Channel::open(&pair.client, DEFAULT_MESSAGE_LIMIT, &budget, Duration::from_secs(1)).await,
                    Err(StreamError::Failure(failure)) if failure.code == Code::ProtocolViolation));
                assert_eq!(budget.0.available_permits(), 1);
                assert!(matches!(task.await.unwrap(), quinn::ConnectionError::ApplicationClosed(close) if close.error_code == Code::ProtocolViolation.varint()));
            }).await.unwrap();
        }
    }

    #[tokio::test]
    async fn cancelling_open_resets_both_directions_and_returns_slot() {
        timeout(Duration::from_secs(3), async {
            let pair = Pair::start().await;
            let (opened, opening) = tokio::sync::oneshot::channel();
            let server = pair.server.clone();
            let task = tokio::spawn(async move {
                let (send, mut recv) = server.accept_bi().await.unwrap();
                wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap();
                opened.send(()).unwrap();
                assert!(
                    matches!(wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await,
                    Err(StreamError::Reset(code)) if code == Code::NoError.varint())
                );
                assert_eq!(send.stopped().await.unwrap(), Some(Code::NoError.varint()));
            });
            let budget = Budget::new(1);
            let client_budget = budget.clone();
            let client = pair.client.clone();
            let pending = tokio::spawn(async move {
                Channel::open(
                    &client,
                    DEFAULT_MESSAGE_LIMIT,
                    &client_budget,
                    Duration::from_secs(60),
                )
                .await
            });
            opening.await.unwrap();
            pending.abort();
            assert!(pending.await.is_err());
            task.await.unwrap();
            assert_eq!(budget.0.available_permits(), 1);
            assert!(pair.client.close_reason().is_none());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancellation_and_connection_loss_release_server_slots() {
        timeout(Duration::from_secs(3), async {
            let pair = Pair::start().await;
            let budget = Budget::new(1);
            let client_budget = Budget::new(1);
            let server = pair.server.clone();
            let serving_budget = budget.clone();
            let task = tokio::spawn(async move {
                let (send, mut recv) = server.accept_bi().await.unwrap();
                wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap();
                serve(send, recv, DEFAULT_MESSAGE_LIMIT, &serving_budget)
                    .await
                    .unwrap();
            });
            let mut channel = Channel::open(
                &pair.client,
                DEFAULT_MESSAGE_LIMIT,
                &client_budget,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            // STOP_SENDING alone must wake an idle Server even if Client send remains open.
            channel.recv.stop(Code::NoError.varint()).unwrap();
            task.await.unwrap();
            assert_eq!(budget.0.available_permits(), 1);
            assert!(pair.client.close_reason().is_none());
            drop(channel);

            let server = pair.server.clone();
            let serving_budget = budget.clone();
            let task = tokio::spawn(async move {
                let (send, mut recv) = server.accept_bi().await.unwrap();
                wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap();
                serve(send, recv, DEFAULT_MESSAGE_LIMIT, &serving_budget)
                    .await
                    .unwrap();
            });
            let _channel = Channel::open(
                &pair.client,
                DEFAULT_MESSAGE_LIMIT,
                &client_budget,
                Duration::from_secs(1),
            )
            .await
            .unwrap();
            pair.client.close(Code::NoError.varint(), b"");
            task.await.unwrap();
            assert_eq!(budget.0.available_permits(), 1);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn local_limit_and_server_fin() {
        timeout(Duration::from_secs(3), async {
            let pair = Pair::start().await;
            let budget = Budget::new(1);
            let server = pair.server.clone();
            let task = tokio::spawn(async move {
                let (mut send, mut recv) = server.accept_bi().await.unwrap();
                wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await.unwrap();
                wire::write_message(&mut send, &Message::new(wire::FILES_READY, vec![ (99, Value::Null) ]), DEFAULT_MESSAGE_LIMIT).await.unwrap();
                send.finish().unwrap();
                assert!(wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await.unwrap().is_none());
            });
            let channel = Channel::open(&pair.client, DEFAULT_MESSAGE_LIMIT, &budget, Duration::from_secs(1)).await.unwrap();
            assert!(matches!(Channel::open(&pair.client, DEFAULT_MESSAGE_LIMIT, &budget, Duration::from_secs(1)).await,
                Err(StreamError::Failure(failure)) if failure.code == Code::LimitExceeded));
            channel.wait_closed().await.unwrap();
            task.await.unwrap();
            assert_eq!(budget.0.available_permits(), 1);
            assert!(pair.client.close_reason().is_none());
        }).await.unwrap();
    }
}
