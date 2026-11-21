//! File Channel envelope (PROTOCOL.md §16.2–§16.4, RE001).
//! No filesystem access or file operations are implemented here (RE002–RE004).

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
pub async fn serve(
    mut send: SendStream,
    mut recv: RecvStream,
    peer_limit: u64,
    budget: &Budget,
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
            // RE002's operation dispatcher is not present yet. Refuse local work
            // without inspecting paths, touching files, or claiming a result.
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

/// Client side envelope API, used by RE002's future `fs` command.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "file operation CLI comes with RE002")
)]
pub struct Channel {
    connection: Connection,
    send: SendStream,
    recv: RecvStream,
    _permit: OwnedSemaphorePermit,
    closed: bool,
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "file operation CLI comes with RE002")
)]
impl Channel {
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
mod tests {
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

    struct Pair {
        _server: quinn::Endpoint,
        _client: quinn::Endpoint,
        server: Connection,
        client: Connection,
    }

    impl Pair {
        async fn start() -> Self {
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
