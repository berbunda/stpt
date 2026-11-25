//! PG scenario fault peers and native TCP observations used by the RG review.
use super::*;
use crate::files::tests::Pair;
use std::time::Duration;
const WAIT: Duration = Duration::from_secs(4);
#[tokio::test]
async fn server_opened_rule_is_protocol_violation() {
    timeout(WAIT, async {
        let p = Pair::start().await;
        p.client.set_max_concurrent_bi_streams(4u32.into());
        let state = client(&p);
        let _task = Task(tokio::spawn(accept(state)));
        let (mut s, _r) = p.server.open_bi().await.unwrap();
        wire::write_message(
            &mut s,
            &Rule {
                mode: 3,
                target: None,
                bind: None,
            }
            .message(),
            DEFAULT_MESSAGE_LIMIT,
        )
        .await
        .unwrap();
        let quinn::ConnectionError::ApplicationClosed(c) = p.server.closed().await else {
            panic!("not closed")
        };
        assert_eq!(c.error_code, Code::ProtocolViolation.varint());
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn default_global_limits_reject_257th_rule_and_2049th_flow() {
    let p = Pair::start().await;
    let global = Arc::new(Global::default());
    let mut contexts = Vec::new();
    let mut rules = Vec::new();
    let mut flows = Vec::new();
    for account in 0..8 {
        for _ in 0..4 {
            let s = State::new(
                p.client.clone(),
                DEFAULT_MESSAGE_LIMIT,
                Selection::offer(),
                Some(format!("controlled-{account}")),
                None,
                global.clone(),
            );
            for _ in 0..8 {
                rules.push(s.reserve(true).unwrap());
            }
            for _ in 0..64 {
                flows.push(s.reserve(false).unwrap());
            }
            contexts.push(s);
        }
    }
    let next = State::new(
        p.client.clone(),
        DEFAULT_MESSAGE_LIMIT,
        Selection::offer(),
        Some("controlled-next".into()),
        None,
        global,
    );
    assert!(matches!(
        next.reserve(true),
        Err(Error::Status(Status::Limit))
    ));
    assert!(matches!(
        next.reserve(false),
        Err(Error::Status(Status::Limit))
    ));
    rules.pop();
    flows.pop();
    assert!(next.reserve(true).is_ok());
    assert!(next.reserve(false).is_ok());
}
fn client(pair: &Pair) -> Arc<State> {
    State::new(
        pair.client.clone(),
        DEFAULT_MESSAGE_LIMIT,
        Selection::offer(),
        None,
        None,
        Default::default(),
    )
}
fn remote(target: SocketAddr) -> Rule {
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
async fn open(pair: &Pair, id: u64) -> (quinn::SendStream, quinn::RecvStream) {
    let (mut s, r) = pair.server.open_bi().await.unwrap();
    wire::write_message(&mut s, &flow(id), DEFAULT_MESSAGE_LIMIT)
        .await
        .unwrap();
    (s, r)
}

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Flow {
    pair: Pair,
    state: Arc<State>,
    guard: Option<Guard>,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    target: TcpStream,
    listener: TcpListener,
    _task: Task,
}
impl Flow {
    async fn new() -> Self {
        Self::with_timers(Timers {
            open: Duration::from_millis(500),
            progress: Duration::from_millis(250),
        })
        .await
    }
    async fn with_timers(timers: Timers) -> Self {
        let pair = Pair::start().await;
        pair.client.set_max_concurrent_bi_streams(10u32.into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut state = client(&pair);
        Arc::get_mut(&mut state).unwrap().timers = timers;
        let guard = state
            .insert(44, remote(listener.local_addr().unwrap()), Phase::Active)
            .unwrap();
        let task = Task(tokio::spawn(accept(state.clone())));
        let (send, mut recv) = open(&pair, 44).await;
        let (target, _) = listener.accept().await.unwrap();
        let m = wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome(&m, CONNECTED, true).unwrap().0, Status::Ok);
        Self {
            pair,
            state,
            guard: Some(guard),
            send,
            recv,
            target,
            listener,
            _task: task,
        }
    }
    async fn reset_code(&mut self) -> quinn::VarInt {
        match wire::read_message(&mut self.recv, DEFAULT_MESSAGE_LIMIT).await {
            Err(StreamError::Reset(c)) => c,
            other => panic!("expected reset, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn opening_timeout_is_signalled_as_timeout_not_fin() {
    timeout(OPEN+WAIT,async{
        let p=Pair::start().await;let mut state=client(&p);Arc::get_mut(&mut state).unwrap().timers.open=Duration::from_millis(150);let server=p.server.clone();
        let peer=tokio::spawn(async move{let(_s,mut r)=server.accept_bi().await.unwrap();wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await.unwrap();wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await});
        let result=state.open_rule(Rule{mode:1,target:Some("127.0.0.1:9".parse().unwrap()),bind:None},Some("127.0.0.1:0".parse().unwrap()),vec![]).await;
        assert!(matches!(result,Err(Error::Timeout)));
        assert!(matches!(peer.await.unwrap(),Err(StreamError::Reset(code)) if code==Code::Timeout.varint()));
        assert!(p.client.close_reason().is_none());
    }).await.unwrap();
}

#[tokio::test]
async fn retained_native_lease_keeps_account_budget_identity() {
    let p = Pair::start().await;
    let global = Arc::new(Global::default());
    let state = State::new(
        p.client.clone(),
        DEFAULT_MESSAGE_LIMIT,
        Selection::offer(),
        None,
        None,
        global.clone(),
    );
    let guard = state
        .insert(44, remote("127.0.0.1:9".parse().unwrap()), Phase::Pending)
        .unwrap();
    let lease = guard.live.clone();
    let old = Arc::downgrade(&state.account_budget);
    drop(guard);
    drop(state);
    assert!(
        old.upgrade().is_some(),
        "pending native work must retain the Account budget object"
    );
    assert_eq!(global.account("client").rules.available_permits(), 31);
    drop(lease);
    assert_eq!(global.account("client").rules.available_permits(), 32);
}

#[tokio::test]
async fn cancelled_early_flow_never_connects_after_rule_activation() {
    timeout(Duration::from_secs(8), async {
        for _ in 0..16 {
            let p = Pair::start().await;
            p.client.set_max_concurrent_bi_streams(10u32.into());
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let state = client(&p);
            let guard = state
                .insert(44, remote(listener.local_addr().unwrap()), Phase::Pending)
                .unwrap();
            let task = tokio::spawn(accept(state.clone()));
            let (mut s, _r) = open(&p, 44).await;
            while state.budget.flows.available_permits() == 64 {
                tokio::task::yield_now().await;
            }
            s.reset(Code::NoError.varint()).unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            guard.live.phase.send_replace(Phase::Active);
            assert!(
                timeout(Duration::from_millis(40), listener.accept())
                    .await
                    .is_err(),
                "cancelled flow contacted the Client target"
            );
            task.abort();
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn refused_pending_rule_discards_waiting_flow_without_target_contact() {
    timeout(WAIT,async{
        let p=Pair::start().await;p.client.set_max_concurrent_bi_streams(10u32.into());let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let state=client(&p);
        let guard=state.insert(44,remote(listener.local_addr().unwrap()),Phase::Pending).unwrap();let task=Task(tokio::spawn(accept(state.clone())));let(_s,mut r)=open(&p,44).await;
        while state.budget.flows.available_permits()==64{tokio::task::yield_now().await;}drop(guard);
        assert!(matches!(wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await,Err(StreamError::Reset(c)) if c==Code::ChannelRejected.varint()));
        assert!(timeout(Duration::from_millis(50),listener.accept()).await.is_err());drop(task);
    }).await.unwrap();
}

fn server_state(p: &Pair, policy: Policy) -> Arc<State> {
    let mut s = State::new(
        p.server.clone(),
        DEFAULT_MESSAGE_LIMIT,
        Selection::offer(),
        None,
        Some(policy),
        Default::default(),
    );
    Arc::get_mut(&mut s).unwrap().timers.open = Duration::from_millis(300);
    s
}
async fn rule_exchange(
    p: &Pair,
    state: Arc<State>,
    rule: Rule,
) -> (
    quinn::SendStream,
    quinn::RecvStream,
    tokio::task::JoinHandle<Result<()>>,
) {
    let task = tokio::spawn(async move {
        let (mut s, mut r) = state
            .connection
            .accept_bi()
            .await
            .map_err(StreamError::Lost)?;
        let m = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
            .await?
            .unwrap();
        let result = state.server_rule(&mut s, &mut r, &m).await;
        if let Err(ref e) = result {
            state.fail_stream(&mut s, &mut r, e)
        }
        result
    });
    let (mut s, r) = p.client.open_bi().await.unwrap();
    wire::write_message(&mut s, &rule.message(), DEFAULT_MESSAGE_LIMIT)
        .await
        .unwrap();
    (s, r, task)
}
#[tokio::test]
async fn remote_listener_policy_ephemeral_port_and_collision_are_enforced() {
    timeout(WAIT, async {
        let held = TcpListener::bind("127.0.0.1:0").await.unwrap();
        for (bind, policy, wanted) in [
            (
                "127.0.0.1:0".parse().unwrap(),
                "remote=true\nbinds=[{network='127.0.0.0/8',ports=[0]}]",
                Status::Denied,
            ),
            (
                "0.0.0.0:0".parse().unwrap(),
                "remote=true\nbinds=[{network='127.0.0.0/8'}]",
                Status::Denied,
            ),
            (
                held.local_addr().unwrap(),
                "remote=true\nbinds=[{network='127.0.0.0/8'}]",
                Status::InUse,
            ),
            ("127.0.0.1:0".parse().unwrap(), "", Status::Denied),
        ] {
            let p = Pair::start().await;
            let state = server_state(&p, toml::from_str(policy).unwrap());
            let (mut s, mut r, task) = rule_exchange(
                &p,
                state.clone(),
                Rule {
                    mode: 2,
                    target: None,
                    bind: Some(bind),
                },
            )
            .await;
            let reply = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(outcome(&reply, READY, true).unwrap().0, wanted);
            assert!(
                wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap()
                    .is_none()
            );
            s.finish().unwrap();
            task.await.unwrap().unwrap();
            assert_eq!(state.budget.rules.available_permits(), 8);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stream_credit_starvation_is_bounded_and_rule_cancel_releases_listener() {
    timeout(WAIT, async {
        let p = Pair::start().await; // Client advertises zero server-initiated streams.
        let state = server_state(
            &p,
            toml::from_str("remote=true\nbinds=[{network='127.0.0.0/8'}]").unwrap(),
        );
        let (mut s, mut r, task) = rule_exchange(
            &p,
            state.clone(),
            Rule {
                mode: 2,
                target: None,
                bind: Some("127.0.0.1:0".parse().unwrap()),
            },
        )
        .await;
        let reply = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        let (_, Some(bound)) = outcome(&reply, READY, true).unwrap() else {
            panic!("not accepted")
        };
        let mut socket = TcpStream::connect(bound).await.unwrap();
        while state.budget.flows.available_permits() == 64 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            timeout(Duration::from_secs(1), socket.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(state.budget.flows.available_permits(), 64);
        s.finish().unwrap();
        task.await.unwrap().unwrap();
        // A closed accepted TCP socket may retain the tuple in TIME_WAIT on Linux;
        // a refused new connect tests listener removal without confusing that with a leak.
        assert!(matches!(TcpStream::connect(bound).await,Err(e) if e.kind()==std::io::ErrorKind::ConnectionRefused));
        assert!(state.rules.lock().unwrap().is_empty());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unexpected_rule_message_and_unselected_mode_close_connection() {
    for invalid_mode in [false, true] {
        timeout(WAIT, async {
            let p = Pair::start().await;
            let mut state = server_state(&p, toml::from_str("dynamic=true").unwrap());
            if invalid_mode {
                Arc::get_mut(&mut state).unwrap().selection.modes = vec![1];
            }
            let (mut s, mut r, task) = rule_exchange(
                &p,
                state,
                Rule {
                    mode: 3,
                    target: None,
                    bind: None,
                },
            )
            .await;
            if !invalid_mode {
                wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap();
                wire::write_message(
                    &mut s,
                    &Status::Ok.reply(READY, None),
                    DEFAULT_MESSAGE_LIMIT,
                )
                .await
                .unwrap();
            }
            let quinn::ConnectionError::ApplicationClosed(c) = p.client.closed().await else {
                panic!("not application close")
            };
            assert_eq!(c.error_code, Code::ProtocolViolation.varint());
            assert!(task.await.unwrap().is_err());
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn zero_receive_credit_cancellation_interrupts_success_and_failure_ready() {
    for allowed in [true, false] {
        timeout(WAIT, async {
            let key = crate::identity::ServerKey::generate();
            let endpoint = crate::quic::listen("127.0.0.1:0".parse().unwrap(), &key).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let client_endpoint = crate::quic::client(addr).unwrap();
            let check = crate::tls::ServerKeyCheck::new(crate::tls::Expected {
                stored: Some(key.public_key()),
                fingerprint: None,
            });
            let crypto =
                quinn::crypto::rustls::QuicClientConfig::try_from(crate::tls::client_config(check))
                    .unwrap();
            let mut config = quinn::ClientConfig::new(Arc::new(crypto));
            let mut transport = quinn::TransportConfig::default();
            transport.stream_receive_window(0u32.into());
            config.transport_config(Arc::new(transport));
            let (client, server) = tokio::join!(
                client_endpoint
                    .connect_with(config, addr, "localhost")
                    .unwrap(),
                async { crate::quic::accept(endpoint.accept().await.unwrap()).await }
            );
            let (client, server) = (client.unwrap(), server.unwrap());
            let policy: Policy = toml::from_str(if allowed {
                "remote=true\nbinds=[{network='127.0.0.0/8'}]"
            } else {
                ""
            })
            .unwrap();
            let mut state = State::new(
                server,
                DEFAULT_MESSAGE_LIMIT,
                Selection::offer(),
                None,
                Some(policy),
                Default::default(),
            );
            Arc::get_mut(&mut state).unwrap().timers.open = Duration::from_secs(2);
            let state2 = state.clone();
            let task = tokio::spawn(async move {
                let (mut s, mut r) = state2.connection.accept_bi().await.unwrap();
                let m = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap()
                    .unwrap();
                state2.server_rule(&mut s, &mut r, &m).await
            });
            let (mut s, _r) = client.open_bi().await.unwrap();
            wire::write_message(
                &mut s,
                &Rule {
                    mode: 2,
                    target: None,
                    bind: Some("127.0.0.1:0".parse().unwrap()),
                }
                .message(),
                DEFAULT_MESSAGE_LIMIT,
            )
            .await
            .unwrap();
            tokio::time::sleep(Duration::from_millis(70)).await;
            s.finish().unwrap();
            timeout(Duration::from_millis(300), task)
                .await
                .expect("rule FIN must interrupt a blocked READY")
                .unwrap()
                .unwrap();
            assert!(state.rules.lock().unwrap().is_empty());
            assert_eq!(state.budget.rules.available_permits(), 8);
        })
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn pending_flow_timeout_releases_quota_and_late_activation_cannot_connect() {
    timeout(WAIT,async{
        let p=Pair::start().await;p.client.set_max_concurrent_bi_streams(4u32.into());let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let mut state=client(&p);Arc::get_mut(&mut state).unwrap().timers.open=Duration::from_millis(150);
        let guard=state.insert(44,remote(listener.local_addr().unwrap()),Phase::Pending).unwrap();let _task=Task(tokio::spawn(accept(state.clone())));let(_s,mut r)=open(&p,44).await;
        assert!(matches!(wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await,Err(StreamError::Reset(c)) if c==Code::Timeout.varint()));
        guard.live.phase.send_replace(Phase::Active);assert!(timeout(Duration::from_millis(50),listener.accept()).await.is_err());assert_eq!(state.budget.flows.available_permits(),64);assert!(p.server.close_reason().is_none());
    }).await.unwrap();
}

#[tokio::test]
async fn target_connected_before_lost_success_is_closed_without_retry() {
    timeout(WAIT, async {
        let key = crate::identity::ServerKey::generate();
        let crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(crate::tls::server_config(&key))
                .unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.stream_receive_window(0u32.into());
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let client_endpoint = crate::quic::client(addr).unwrap();
        let check = crate::tls::ServerKeyCheck::new(crate::tls::Expected {
            stored: Some(key.public_key()),
            fingerprint: None,
        });
        let (c, s) = tokio::join!(
            crate::quic::connect(&client_endpoint, addr, "localhost", check),
            async { crate::quic::accept(endpoint.accept().await.unwrap()).await }
        );
        let (c, s) = (c.unwrap(), s.unwrap());
        c.set_max_concurrent_bi_streams(4u32.into());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = State::new(
            c.clone(),
            DEFAULT_MESSAGE_LIMIT,
            Selection::offer(),
            None,
            None,
            Default::default(),
        );
        let _guard = state
            .insert(44, remote(listener.local_addr().unwrap()), Phase::Active)
            .unwrap();
        let _task = Task(tokio::spawn(accept(state.clone())));
        let (mut send, mut recv) = s.open_bi().await.unwrap();
        wire::write_message(&mut send, &flow(44), DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap();
        let (mut target, _) = listener.accept().await.unwrap();
        // Target saw the connect, but CONNECTED cannot fit into the peer's zero receive window.
        send.reset(Code::NoError.varint()).unwrap();
        assert_eq!(
            timeout(Duration::from_millis(400), target.read(&mut [0]))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(matches!(
            wire::read_message(&mut recv, DEFAULT_MESSAGE_LIMIT).await,
            Err(StreamError::Reset(_))
        ));
        assert!(
            timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
        assert!(s.close_reason().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn partial_frame_times_out_but_clean_idle_and_half_closed_flow_do_not() {
    timeout(WAIT, async {
        let mut f = Flow::new().await;
        tokio::time::sleep(Duration::from_millis(600)).await;
        f.target.write_all(b"healthy idle").await.unwrap();
        let m = wire::read_message(&mut f.recv, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(m.field(0), Some(&Value::Bytes(b"healthy idle".to_vec())));
        f.send.finish().unwrap();
        assert_eq!(f.target.read(&mut [0]).await.unwrap(), 0);
        tokio::time::sleep(Duration::from_millis(600)).await;
        f.target.write_all(b"half closed").await.unwrap();
        wire::read_message(&mut f.recv, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        f.target.shutdown().await.unwrap();
        assert!(
            wire::read_message(&mut f.recv, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .is_none()
        );
        let mut f = Flow::new().await;
        f.send.write_all(&[20, 0x82]).await.unwrap();
        assert_eq!(f.reset_code().await, Code::Timeout.varint());
        assert!(f.pair.server.close_reason().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn slow_fragment_progress_restarts_timer_and_max_data_frame_is_accepted() {
    timeout(Duration::from_secs(8), async {
        let mut f = Flow::new().await;
        let bytes =
            wire::frame(&Message::new(DATA, vec![(0, Value::Bytes(vec![37; 16]))]).encode());
        for chunk in bytes.chunks(3) {
            f.send.write_all(chunk).await.unwrap();
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        let mut b = [0; 16];
        f.target.read_exact(&mut b).await.unwrap();
        assert_eq!(b, [37; 16]);
        let data = vec![91; 61440];
        wire::write_message(
            &mut f.send,
            &Message::new(DATA, vec![(0, Value::Bytes(data.clone()))]),
            DEFAULT_MESSAGE_LIMIT,
        )
        .await
        .unwrap();
        let mut b = vec![0; 61440];
        f.target.read_exact(&mut b).await.unwrap();
        assert_eq!(b, data);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stalled_tcp_writer_does_not_block_other_flows_or_revocation() {
    timeout(Duration::from_secs(10), async {
        let mut f = Flow::new().await;
        let socket = socket2::SockRef::from(&f.target);
        socket.set_recv_buffer_size(1024).unwrap();
        let c = f.pair.server.clone();
        let id = 44;
        let writer = tokio::spawn(async move {
            let mut send = f.send;
            let m = Message::new(DATA, vec![(0, Value::Bytes(vec![7; 61440]))]);
            for _ in 0..256 {
                if wire::write_message(&mut send, &m, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        // Keep the first target unread while a second flow makes progress.
        let (_s, mut r) = open(&f.pair, id).await;
        let (mut target, _) = f.listener.accept().await.unwrap();
        wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap();
        target.write_all(b"independent").await.unwrap();
        let m = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(m.field(0), Some(&Value::Bytes(b"independent".to_vec())));
        drop(f.guard.take());
        let mut b = [0];
        assert!(matches!(target.read(&mut b).await, Ok(0) | Err(_)));
        assert!(c.close_reason().is_none());
        writer.abort();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn stalled_tcp_write_times_out_only_its_flow() {
    timeout(Duration::from_secs(8),async{
        let mut f=Flow::new().await;socket2::SockRef::from(&f.target).set_recv_buffer_size(1024).unwrap();
        let writer=tokio::spawn(async move{let mut send=f.send;let m=Message::new(DATA,vec![(0,Value::Bytes(vec![9;61440]))]);for _ in 0..256{if wire::write_message(&mut send,&m,DEFAULT_MESSAGE_LIMIT).await.is_err(){break}}});
        assert!(matches!(wire::read_message(&mut f.recv,DEFAULT_MESSAGE_LIMIT).await,Err(StreamError::Reset(c)) if c==Code::Timeout.varint()));assert!(f.pair.server.close_reason().is_none());
        let(_s,mut r)=open(&f.pair,44).await;let(_target,_)=f.listener.accept().await.unwrap();let m=wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await.unwrap().unwrap();assert_eq!(outcome(&m,CONNECTED,true).unwrap().0,Status::Ok);writer.abort();
    }).await.unwrap();
}

#[tokio::test]
async fn native_tcp_reset_aborts_flow_without_clean_fin() {
    timeout(WAIT, async {
        let mut f = Flow::new().await;
        socket2::SockRef::from(&f.target)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(f.target);
        assert!(matches!(
            wire::read_message(&mut f.recv, DEFAULT_MESSAGE_LIMIT).await,
            Err(StreamError::Reset(_))
        ));
        assert!(f.pair.server.close_reason().is_none());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn another_rule_survives_rule_revocation_and_cross_connection_ids_are_rejected() {
    timeout(WAIT,async{
        let mut f=Flow::new().await;let guard=f.state.insert(48,remote(f.listener.local_addr().unwrap()),Phase::Active).unwrap();
        let(_s,mut r)=open(&f.pair,48).await;let(mut target,_)=f.listener.accept().await.unwrap();wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await.unwrap();
        drop(f.guard.take());target.write_all(b"other rule").await.unwrap();let m=wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await.unwrap().unwrap();assert_eq!(m.field(0),Some(&Value::Bytes(b"other rule".to_vec())));
        let p=Pair::start().await;p.client.set_max_concurrent_bi_streams(2u32.into());let state=client(&p);let task=tokio::spawn(accept(state));let(_s,mut r)=open(&p,48).await;
        assert!(matches!(wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await,Err(StreamError::Reset(c)) if c==Code::ChannelRejected.varint()));task.abort();drop(guard);
    }).await.unwrap();
}

#[tokio::test]
async fn live_rule_and_flow_limits_are_enforced_at_connection_account_and_global_scope() {
    let p = Pair::start().await;
    let global = Arc::new(Global {
        budget: Budget::new(256, 2048),
        accounts: Default::default(),
    });
    let mut states = Vec::new();
    let mut guards = Vec::new();
    for _ in 0..4 {
        let s = State::new(
            p.client.clone(),
            DEFAULT_MESSAGE_LIMIT,
            Selection::offer(),
            None,
            None,
            global.clone(),
        );
        for id in 0..8 {
            guards.push(
                s.insert(id, remote("127.0.0.1:9".parse().unwrap()), Phase::Active)
                    .unwrap(),
            );
        }
        assert!(matches!(
            s.insert(99, remote("127.0.0.1:9".parse().unwrap()), Phase::Active),
            Err(Error::Status(Status::Limit))
        ));
        states.push(s);
    }
    let next = State::new(
        p.client.clone(),
        DEFAULT_MESSAGE_LIMIT,
        Selection::offer(),
        None,
        None,
        global.clone(),
    );
    assert!(matches!(
        next.reserve(true),
        Err(Error::Status(Status::Limit))
    ));
    let flows: Vec<_> = states
        .iter()
        .flat_map(|s| (0..64).map(move |_| s.reserve(false).unwrap()))
        .collect();
    assert!(matches!(
        next.reserve(false),
        Err(Error::Status(Status::Limit))
    ));
    drop(flows);
    drop(guards);
    assert!(next.reserve(true).is_ok());
    assert!(next.reserve(false).is_ok());
    let global = Arc::new(Global {
        budget: Budget::new(2, 1),
        accounts: Default::default(),
    });
    let a = State::new(
        p.client.clone(),
        DEFAULT_MESSAGE_LIMIT,
        Selection::offer(),
        Some("a".into()),
        None,
        global.clone(),
    );
    let b = State::new(
        p.client.clone(),
        DEFAULT_MESSAGE_LIMIT,
        Selection::offer(),
        Some("b".into()),
        None,
        global,
    );
    let held = a.reserve(false).unwrap();
    assert!(matches!(
        b.reserve(false),
        Err(Error::Status(Status::Limit))
    ));
    drop(held);
    assert!(b.reserve(false).is_ok());
}

#[tokio::test]
async fn malformed_data_duplicate_connected_and_oversized_frames_have_correct_scope() {
    for m in [
        Message::new(
            CONNECTED,
            vec![
                (0, Value::Uint(0)),
                (1, socket_value("127.0.0.1:22".parse().unwrap())),
            ],
        ),
        Message::new(DATA, vec![(0, Value::Bytes(vec![0; 61441]))]),
        Message::new(DATA, vec![(0, Value::Uint(2))]),
    ] {
        timeout(WAIT, async {
            let mut f = Flow::new().await;
            wire::write_message(&mut f.send, &m, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap();
            let quinn::ConnectionError::ApplicationClosed(c) = f.pair.server.closed().await else {
                panic!("expected close")
            };
            assert_eq!(c.error_code, Code::ProtocolViolation.varint());
        })
        .await
        .unwrap();
    }
    let mut f = Flow::new().await;
    let bytes = wire::frame(&vec![0; 65536]);
    f.send.write_all(&bytes[..4]).await.unwrap();
    assert_eq!(f.reset_code().await, Code::LimitExceeded.varint());
    assert!(f.pair.server.close_reason().is_none());
}

#[tokio::test]
#[ignore = "61-second default-timer idle scenario; run explicitly during RG review"]
async fn real_default_timer_keeps_healthy_idle_tcp_alive() {
    let mut f = Flow::with_timers(Timers::DEFAULT).await;
    tokio::time::sleep(PROGRESS + Duration::from_secs(1)).await;
    f.target.write_all(b"still live").await.unwrap();
    let m = timeout(WAIT, wire::read_message(&mut f.recv, DEFAULT_MESSAGE_LIMIT))
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(m.field(0), Some(&Value::Bytes(b"still live".to_vec())));
}
