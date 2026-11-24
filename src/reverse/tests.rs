use super::*;
use crate::files::tests::Pair as Quic;
const LIMIT: u64 = wire::DEFAULT_MESSAGE_LIMIT;
const SID: SessionId = SessionId([7; 16]);
const WAIT: Duration = Duration::from_secs(4);

fn frame(kind: u64, n: u64, b: &[u8]) -> Message {
    Message::new(kind, vec![(0, Value::Uint(n)), (1, Value::Bytes(b.into()))])
}
#[test]
fn offsets_length_and_digest_are_checked_before_publication() {
    let mut input = Incoming::new(2);
    for m in [
        frame(DATA, 1, b"a"),
        frame(DATA, 0, b""),
        frame(DATA, 0, b"abc"),
    ] {
        assert!(matches!(input.accept(&m), Err(e) if e.code == Code::ProtocolViolation));
    }
    assert!(matches!(
        input.accept(&frame(DATA, 0, b"ab")),
        Ok(Part::Data(b"ab"))
    ));
    for m in [
        frame(END, 2, &[0; 32]),
        frame(END, 1, blake3::hash(b"ab").as_bytes()),
    ] {
        assert!(matches!(input.accept(&m), Ok(Part::End(Status::Integrity))));
    }
    assert!(matches!(
        Incoming::new(0).accept(&frame(END, 0, blake3::hash(b"").as_bytes())),
        Ok(Part::End(Status::Ok))
    ));
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Stale,
    OtherSession,
    Consent,
    Start,
    MidCreate,
    CancelCreate,
    EarlyStart,
}
#[tokio::test]
async fn client_refuses_stale_target_and_revokes_at_each_deadline() {
    for phase in [
        Phase::Stale,
        Phase::OtherSession,
        Phase::Consent,
        Phase::Start,
        Phase::MidCreate,
        Phase::CancelCreate,
        Phase::EarlyStart,
    ] {
        timeout(WAIT, client_case(phase)).await.unwrap();
    }
}
async fn client_case(phase: Phase) {
    let quic = Quic::start().await;
    quic.client.set_max_concurrent_bi_streams(1u32.into());
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let broker = Pair::new(l.local_addr().unwrap().port()).unwrap();
    let mut g = Permissions::new(
        crate::identity::PublicKey::from_spki(b"test").fingerprint(),
        "user",
        SID,
        1,
    );
    let path = std::env::temp_dir().join(format!("stpt-unpublished-{}", SessionId::generate()));
    let client_task = async {
        let streams = quic.client.accept_bi().await.unwrap();
        let mut c = Channel::new(&quic.client, streams, LIMIT);
        c.timers = Timers {
            open: Duration::from_millis(260),
            user: Duration::from_millis(260),
            progress: Duration::from_millis(260),
        };
        let r = client(&mut c, &broker, &mut g, SID, 1).await;
        assert_eq!(
            r.as_ref().unwrap_err().code,
            match phase {
                Phase::Stale | Phase::OtherSession => Code::ChannelRejected,
                Phase::CancelCreate => Code::NoError,
                Phase::EarlyStart => Code::ProtocolViolation,
                _ => Code::Timeout,
            }
        );
        c.outcome(&r);
    };
    let remote = async {
        let mut c = Channel::new(&quic.server, quic.server.open_bi().await.unwrap(), LIMIT);
        let id = if phase == Phase::Stale { 2 } else { 1 };
        let target = if phase == Phase::OtherSession {
            SessionId([8; 16])
        } else {
            SID
        };
        c.send(Message::new(
            wire::CHANNEL_OPEN,
            vec![
                (0, Value::Uint(3)),
                (1, Value::Bytes(target.0.into())),
                (2, Value::Uint(id)),
                (3, Value::Uint(2)),
                (4, Value::Uint(2)),
            ],
        ))
        .await
        .unwrap();
        if !matches!(phase, Phase::Stale | Phase::OtherSession) {
            c.expect(PENDING, WAIT).await.unwrap();
            if phase == Phase::EarlyStart {
                c.send(msg(START)).await.unwrap();
            }
            if matches!(phase, Phase::Start | Phase::MidCreate | Phase::CancelCreate) {
                c.expect(APPROVED, WAIT).await.unwrap();
                assert!(!path.exists());
                if matches!(phase, Phase::MidCreate | Phase::CancelCreate) {
                    c.send(msg(START)).await.unwrap();
                    c.expect(READY, WAIT).await.unwrap();
                    c.data(0, b"a").await.unwrap();
                    if phase == Phase::CancelCreate {
                        return; // Channel drop resets the incomplete operation.
                    }
                }
            }
        }
        assert!(c.next(WAIT).await.is_err());
    };
    let ui = async {
        if matches!(phase, Phase::Stale | Phase::OtherSession) {
            return;
        }
        let mut s = broker.accept(&l).await.unwrap();
        consent::get(&mut s).await.unwrap();
        if matches!(phase, Phase::Start | Phase::MidCreate | Phase::CancelCreate) {
            consent::put(&mut s, path.to_str().unwrap().as_bytes())
                .await
                .unwrap();
            assert_eq!(s.read_u8().await.unwrap(), 1);
            s.write_u8(1).await.unwrap();
        } else {
            assert!(s.read_u8().await.is_err());
        }
    };
    tokio::join!(client_task, remote, ui);
    assert!(!path.exists());
}

#[derive(Debug, Clone, Copy)]
enum Loss {
    BeforeRendezvous,
    Caller,
    Detach,
    Session,
    FinalResult,
}
#[tokio::test]
async fn caller_and_binding_loss_cancel_before_start_and_lost_result_is_unknown() {
    for loss in [
        Loss::BeforeRendezvous,
        Loss::Caller,
        Loss::Detach,
        Loss::Session,
        Loss::FinalResult,
    ] {
        timeout(WAIT, loss_case(loss)).await.unwrap();
    }
}
async fn loss_case(loss: Loss) {
    let q = Quic::start().await;
    q.client.set_max_concurrent_bi_streams(1u32.into());
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
    let info = AttachmentInfo {
        #[cfg(target_os = "linux")]
        mount: false,
        attached: std::time::SystemTime::now(),
        connection: q.server.clone(),
        key: crate::authorized::KeyInfo {
            key: [0; 32],
            label: None,
        },
        reverse: Some(slots.clone()),
        max_size: 100,
        progress: WAIT,
        peer_limit: LIMIT,
    };
    let (slot, detached) = watch::channel(None);
    let (session, ended) = watch::channel(false);
    let session_local::Reply::Transfer(pair) = dispatch(
        SID,
        1,
        info,
        detached,
        ended,
        session_local::Action::Create {
            bytes: 0,
            attachment: None,
        },
        slots.clone().try_acquire_owned().unwrap(),
    )
    .unwrap() else {
        panic!()
    };
    let mut data = pair.connect().await.unwrap();
    if matches!(loss, Loss::BeforeRendezvous) {
        slot.send(Some(Code::NoError)).unwrap();
        // Detach releases the only slot even if the caller never connects the
        // lifetime socket. No reverse Channel may be proposed.
        let _permit = slots.acquire().await.unwrap();
        assert!(
            timeout(Duration::from_millis(50), q.client.accept_bi())
                .await
                .is_err()
        );
        return;
    }
    let mut life = pair.connect().await.unwrap();
    let mut c = Channel::new(&q.client, q.client.accept_bi().await.unwrap(), LIMIT);
    c.expect(wire::CHANNEL_OPEN, WAIT).await.unwrap();
    c.send(msg(PENDING)).await.unwrap();
    match loss {
        Loss::BeforeRendezvous => unreachable!(),
        Loss::Caller => life.shutdown().await.unwrap(),
        Loss::Detach => slot.send(Some(Code::NoError)).unwrap(),
        Loss::Session => session.send(true).unwrap(),
        Loss::FinalResult => {
            c.send(msg(APPROVED)).await.unwrap();
            c.expect(START, WAIT).await.unwrap();
            c.send(nmsg(READY, 0)).await.unwrap();
            assert_eq!(consent::get(&mut data).await.unwrap(), b"W");
            c.expect(END, WAIT).await.unwrap();
            c.eof().await.unwrap();
        }
    }
    if matches!(loss, Loss::FinalResult) {
        drop(c);
    } else {
        let _ = c.send(msg(APPROVED)).await;
        assert!(
            c.next(WAIT).await.is_err(),
            "late approval admitted: {loss:?}"
        );
    }
    let status = String::from_utf8(consent::get(&mut life).await.unwrap()).unwrap();
    assert_eq!(
        status.contains("unknown create outcome"),
        matches!(loss, Loss::FinalResult),
        "{status}"
    );
    assert_ne!(status, "+");
}
#[tokio::test]
async fn server_deadlines_cover_pending_and_consent_and_reject_duplicate_approval() {
    for phase in [0, 1, 2] {
        timeout(WAIT, async {
            let q = Quic::start().await;
            q.client.set_max_concurrent_bi_streams(1u32.into());
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let (_local, accepted) = tokio::join!(
                TcpStream::connect(listener.local_addr().unwrap()),
                listener.accept()
            );
            let (mut data, _) = accepted.unwrap();
            let serve = async {
                let mut c = Channel::new(&q.server, q.server.open_bi().await.unwrap(), LIMIT);
                c.timers.open = Duration::from_millis(250);
                c.timers.user = Duration::from_millis(250);
                let result = server(
                    &mut c,
                    SID,
                    1,
                    session_local::Action::Read { attachment: None },
                    &mut data,
                    &AtomicBool::new(false),
                    || Ok(()),
                )
                .await;
                let expected = if phase == 2 {
                    Code::ProtocolViolation
                } else {
                    Code::Timeout
                };
                assert_eq!(result.as_ref().unwrap_err().code, expected);
                c.outcome(&result);
            };
            let remote = async {
                let mut c = Channel::new(&q.client, q.client.accept_bi().await.unwrap(), LIMIT);
                c.expect(wire::CHANNEL_OPEN, WAIT).await.unwrap();
                if phase >= 1 {
                    c.send(msg(PENDING)).await.unwrap();
                }
                if phase == 2 {
                    c.send(msg(APPROVED)).await.unwrap();
                    c.expect(START, WAIT).await.unwrap();
                    c.send(msg(APPROVED)).await.unwrap();
                }
                assert!(c.next(WAIT).await.is_err());
            };
            tokio::join!(serve, remote);
            if phase < 2 {
                assert!(q.client.close_reason().is_none());
            }
        })
        .await
        .unwrap();
    }
}
