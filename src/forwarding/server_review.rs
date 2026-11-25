// Included inside server::tests to exercise the real authenticated dispatch.
mod rg_review {
    #[tokio::test]
    async fn rule_quota_is_shared_by_five_authenticated_connections_of_one_account() {
        timeout(Duration::from_secs(10), async {
            let first = peer().await;
            let mut peers = vec![first];
            for _ in 0..4 {
                let next = peers[0].again().await;
                peers.push(next);
            }
            let mut controls = Vec::new();
            for p in &peers {
                controls.push(login(p, true).await);
            }
            let mut rules = Vec::new();
            for p in &peers[..4] {
                for _ in 0..8 {
                    let (mut s, mut r) = p.connection.open_bi().await.unwrap();
                    wire::write_message(
                        &mut s,
                        &f::Rule {
                            mode: 3,
                            target: None,
                            bind: None,
                        }
                        .message(),
                        DEFAULT_MESSAGE_LIMIT,
                    )
                    .await
                    .unwrap();
                    let m = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                        .await
                        .unwrap()
                        .unwrap();
                    assert_eq!(f::outcome(&m, f::READY, false).unwrap().0, f::Status::Ok);
                    rules.push((s, r));
                }
            }
            let (mut s, mut r) = peers[4].connection.open_bi().await.unwrap();
            wire::write_message(
                &mut s,
                &f::Rule {
                    mode: 3,
                    target: None,
                    bind: None,
                }
                .message(),
                DEFAULT_MESSAGE_LIMIT,
            )
            .await
            .unwrap();
            let m = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(f::outcome(&m, f::READY, false).unwrap().0, f::Status::Limit);
            s.finish().unwrap();
            assert!(
                wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap()
                    .is_none()
            );
            let (mut old, mut old_recv) = rules.pop().unwrap();
            old.finish().unwrap();
            assert!(
                wire::read_message(&mut old_recv, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap()
                    .is_none()
            );
            let (mut s, mut r) = peers[4].connection.open_bi().await.unwrap();
            wire::write_message(
                &mut s,
                &f::Rule {
                    mode: 3,
                    target: None,
                    bind: None,
                }
                .message(),
                DEFAULT_MESSAGE_LIMIT,
            )
            .await
            .unwrap();
            let m = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(f::outcome(&m, f::READY, false).unwrap().0, f::Status::Ok);
            rules.push((s, r));
            for (mut s, mut r) in rules {
                s.finish().unwrap();
                assert!(
                    wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                        .await
                        .unwrap()
                        .is_none()
                );
            }
            drop(controls);
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn partial_channel_open_has_absolute_default_deadline_and_control_stays_live() {
        timeout(Duration::from_secs(14),async{
            let p=peer().await;let(mut control,mut reply)=login(&p,true).await;let(mut s,mut r)=p.connection.open_bi().await.unwrap();
            s.write_all(&[0x40,100,0x82]).await.unwrap();
            wire::write_message(&mut control,&crate::listing::list_request(1,None,None),DEFAULT_MESSAGE_LIMIT).await.unwrap();let m=wire::read_message(&mut reply,DEFAULT_MESSAGE_LIMIT).await.unwrap().unwrap();assert_eq!(m.field(1).and_then(Value::as_uint),Some(0));
            let trickle=tokio::spawn(async move{for _ in 0..4{tokio::time::sleep(Duration::from_secs(2)).await;if s.write_all(&[0]).await.is_err(){break}}let _=s.stopped().await;});
            assert!(matches!(wire::read_message(&mut r,DEFAULT_MESSAGE_LIMIT).await,Err(wire::StreamError::Reset(c)) if c==Code::Timeout.varint()));trickle.abort();assert!(p.connection.close_reason().is_none());
        }).await.unwrap();
    }
    use super::*;
    use crate::forwarding as f;
    async fn peer() -> Peer {
        #[cfg(unix)]
        let account = nix::unistd::User::from_uid(nix::unistd::geteuid())
            .unwrap()
            .unwrap()
            .name;
        #[cfg(windows)]
        let account = crate::process::Account::current_name().unwrap();
        let mut forwarding = f::Config::default();
        forwarding.accounts.insert(
            account.clone(),
            f::Policy {
                dynamic: true,
                ..Default::default()
            },
        );
        Peer::serve(Deadlines::DEFAULT, &account, |authorizer| Shared {
            forwarding,
            forward_budget: Default::default(),
            file_workers: Arc::new(tokio::sync::Semaphore::new(32)),
            file_resume: Default::default(),
            max_file_size: crate::file_protocol::DEFAULT_MAX_SIZE,
            file_timeout: Duration::from_secs(60),
            max_file_channels: 0,
            deadlines: Deadlines::DEFAULT,
            authorizer,
            store: Store::start(Policy::DEFAULT),
        })
        .await
    }
    async fn login(p: &Peer, cap: bool) -> (quinn::SendStream, quinn::RecvStream) {
        let (mut s, mut r) = p.connection.open_bi().await.unwrap();
        let mut h = ClientHello::ours();
        if cap {
            h.capabilities.push((4, f::Selection::offer().value()));
        }
        wire::write_message(&mut s, &h.to_message(), DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap();
        wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        s.write_all(&p.request(&p.user, &p.account)).await.unwrap();
        assert!(auth_result(&mut r).await);
        (s, r)
    }
    async fn still_active(p: &Peer, id: u64) {
        let (mut s, mut r) = p.connection.open_bi().await.unwrap();
        let target = "127.0.0.1:9".parse::<f::Target>().unwrap();
        wire::write_message(
            &mut s,
            &Message::new(
                wire::CHANNEL_OPEN,
                vec![
                    (0, Value::Uint(f::FLOW)),
                    (1, Value::Uint(id)),
                    (2, target.value()),
                ],
            ),
            DEFAULT_MESSAGE_LIMIT,
        )
        .await
        .unwrap();
        let m = wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            f::outcome(&m, f::CONNECTED, true).unwrap().0,
            f::Status::Denied
        );
        assert!(
            wire::read_message(&mut r, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .is_none()
        );
        s.finish().unwrap();
    }
    #[tokio::test]
    async fn authenticated_forward_rule_survives_terminal_detach_and_session_termination() {
        timeout(Duration::from_secs(15), async {
            let p = peer().await;
            let (mut control, mut reply) = login(&p, true).await;
            let (mut rule, mut rule_recv) = p.connection.open_bi().await.unwrap();
            let id = u64::from(rule.id());
            wire::write_message(
                &mut rule,
                &f::Rule {
                    mode: 3,
                    target: None,
                    bind: None,
                }
                .message(),
                DEFAULT_MESSAGE_LIMIT,
            )
            .await
            .unwrap();
            let m = wire::read_message(&mut rule_recv, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(f::outcome(&m, f::READY, false).unwrap().0, f::Status::Ok);
            let (mut terminal, mut output) = p.connection.open_bi().await.unwrap();
            let open = crate::terminal::Open {
                command: Some(crate::terminal::Command::Line(
                    if cfg!(windows) {
                        "Start-Sleep -Seconds 30"
                    } else {
                        "sleep 30"
                    }
                    .into(),
                )),
                ..Default::default()
            };
            wire::write_message(&mut terminal, &open.to_message(), DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap();
            let m = wire::read_message(&mut output, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            let attached = crate::terminal::Attached::from_message(&m).unwrap();
            terminal.finish().unwrap();
            while wire::read_message(&mut output, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .is_some()
            {}
            still_active(&p, id).await;
            wire::write_message(
                &mut control,
                &crate::listing::terminate_request(1, attached.session, true),
                DEFAULT_MESSAGE_LIMIT,
            )
            .await
            .unwrap();
            let m = wire::read_message(&mut reply, DEFAULT_MESSAGE_LIMIT)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(m.field(1).and_then(Value::as_uint), Some(0));
            still_active(&p, id).await;
            rule.finish().unwrap();
            assert!(
                wire::read_message(&mut rule_recv, DEFAULT_MESSAGE_LIMIT)
                    .await
                    .unwrap()
                    .is_none()
            );
            p.connection.close(Code::NoError.varint(), b"");
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn forwarding_without_capability_or_before_authentication_is_refused() {
        for authenticated in [true, false] {
            timeout(Duration::from_secs(4), async {
                let p = peer().await;
                let (mut s, _r) = if authenticated {
                    login(&p, false).await
                } else {
                    p.hello().await
                };
                if authenticated {
                    let mut channels = p.connection.open_bi().await.unwrap();
                    wire::write_message(
                        &mut channels.0,
                        &f::Rule {
                            mode: 3,
                            target: None,
                            bind: None,
                        }
                        .message(),
                        DEFAULT_MESSAGE_LIMIT,
                    )
                    .await
                    .unwrap();
                } else {
                    wire::write_message(
                        &mut s,
                        &f::Rule {
                            mode: 3,
                            target: None,
                            bind: None,
                        }
                        .message(),
                        DEFAULT_MESSAGE_LIMIT,
                    )
                    .await
                    .unwrap();
                }
                assert_eq!(p.closed_with().await, Some(Code::ProtocolViolation));
            })
            .await
            .unwrap();
        }
    }
}
