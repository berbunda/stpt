use super::*;
use crate::fuse_mount::Target;
use std::collections::BTreeSet;

pub fn dispatch(
    session: SessionId,
    id: u64,
    info: AttachmentInfo,
    mut detached: watch::Receiver<Option<Code>>,
    mut ended: watch::Receiver<bool>,
    target: Target,
    permit: OwnedSemaphorePermit,
) -> Result<session_local::Reply, String> {
    static MOUNTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
    let capacity = MOUNTS.try_acquire().map_err(|_| "mount limit reached")?;
    let socket =
        std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|e| e.to_string())?;
    socket.set_nonblocking(true).map_err(|e| e.to_string())?;
    let pair = Pair::new(socket.local_addr().map_err(|e| e.to_string())?.port())
        .map_err(|e| e.to_string())?;
    let listener = TcpListener::from_std(socket).map_err(|e| e.to_string())?;
    let ticket = pair.clone();
    tokio::spawn(async move {
        let _slots = (permit, capacity);
        let peers = async {
            let data = ticket.accept(&listener).await?;
            let life = ticket.accept(&listener).await?;
            io::Result::Ok((data, life))
        };
        let accepted = tokio::select! {biased;
            _=detached.changed()=>return, _=ended.changed()=>return,
            r=timeout(OPEN, peers)=>r,
        };
        let Ok(Ok((_data, life))) = accepted else {
            return;
        };
        drop(listener);
        let slot = detached.clone();
        let state = ended.clone();
        let live = || {
            if slot.borrow().is_some()
                || *state.borrow()
                || slot.has_changed().is_err()
                || state.has_changed().is_err()
                || info.connection.close_reason().is_some()
            {
                Err(interrupted())
            } else {
                Ok(())
            }
        };
        let (life_rx, mut life_tx) = life.into_split();
        let caller_live = || match life_rx.try_read(&mut [0]) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(()),
            _ => Err(interrupted()),
        };
        let abandoned = async {
            loop {
                if life_rx.readable().await.is_err() || caller_live().is_err() {
                    break;
                }
            }
        };
        tokio::pin!(abandoned);
        let setup = async {
            live()?;
            caller_live()?;
            let opening = tokio::time::Instant::now() + OPEN;
            let streams = deadline(OPEN, async {
                info.connection.open_bi().await.map_err(local)
            })
            .await?;
            let mut c = Channel::new(&info.connection, streams, info.peer_limit);
            c.timers.progress = info.progress;
            let r = async {
                deadline(
                    opening.saturating_duration_since(tokio::time::Instant::now()),
                    async {
                        c.send(Message::new(
                            wire::CHANNEL_OPEN,
                            vec![
                                (0, Value::Uint(3)),
                                (1, Value::Bytes(session.0.into())),
                                (2, Value::Uint(id)),
                                (3, Value::Uint(3)),
                            ],
                        ))
                        .await?;
                        c.expect(PENDING, OPEN).await
                    },
                )
                .await?;
                match c.next(USER).await?.kind {
                    APPROVED => {}
                    DENIED => {
                        c.fin()?;
                        c.eof().await?;
                        c.abort = None;
                        return Err(local("Client denied the mount"));
                    }
                    _ => return Err(invalid()),
                }
                tokio::task::yield_now().await;
                live()?;
                caller_live()?;
                c.send(msg(START)).await?;
                let ready = c.next(info.progress).await?;
                if ready.kind == RESULT && number(&ready, 0)? != 0 {
                    c.fin()?;
                    c.eof().await?;
                    c.abort = None;
                    return Err(local("Client refused mount setup"));
                }
                if ready.kind != mount_client::MOUNT_READY {
                    return Err(invalid());
                }
                let kind = number(&ready, 0)?;
                if kind > 1 {
                    return Err(invalid());
                }
                live()?;
                let mut worker = target.spawn(kind).map_err(local)?;
                let mut output = worker.child.stdout.take().ok_or_else(interrupted)?;
                before_end(
                    &mut c.rx,
                    deadline(info.progress, async {
                        if output.read_u8().await.map_err(local)? != 1 {
                            return Err(local("FUSE initialization failed"));
                        }
                        Ok(())
                    }),
                )
                .await?;
                worker.arm().map_err(local)?;
                Ok((worker, output, kind))
            }
            .await;
            if r.is_err() {
                c.outcome(&r)
            }
            r.map(|(worker, output, kind)| (c, worker, output, kind))
        };
        let result = tokio::select! {biased;
            _=detached.changed()=>Err(interrupted()),_=ended.changed()=>Err(interrupted()),
            _=&mut abandoned=>Err(interrupted()),r=setup=>r,
        };
        let (mut c, mut worker, output, kind) = match result {
            Ok(v) => v,
            Err(e) => {
                let message = e.to_string();
                let _ = timeout(OPEN, async {
                    life_tx.write_u16(message.len() as u16).await?;
                    life_tx.write_all(message.as_bytes()).await
                })
                .await;
                return;
            }
        };
        let message = format!("+{}", worker.path);
        // Return the pathname before servicing the first filesystem request. A
        // cancelled setup may leave a busy kernel mount, but it never returns data.

        let handoff = async {
            live()?;
            caller_live()?;
            life_tx
                .write_u16(message.len() as u16)
                .await
                .map_err(local)?;
            life_tx.write_all(message.as_bytes()).await.map_err(local)
        };
        let delivered = tokio::select! {biased;
            _=detached.changed()=>Err(interrupted()),_=ended.changed()=>Err(interrupted()),
            _=&mut abandoned=>Err(interrupted()),
            r=before_end(&mut c.rx,deadline(info.progress,handoff))=>r,
        };
        if delivered.is_err() {
            c.outcome(&delivered);
            return;
        }
        drop(life_tx);
        let input = worker
            .child
            .stdin
            .take()
            .expect("FUSE worker has piped stdin");
        let stopped = c.tx.stopped();
        let result = tokio::select! {biased;
            _=detached.changed()=>Err(interrupted()),_=ended.changed()=>Err(interrupted()),
            _=worker.child.wait()=>Err(local("FUSE worker exited")),
            _=stopped=>Err(interrupted()),r=pump(&mut c,input,output,kind,live)=>r,
        };
        c.outcome(&result);
    });
    Ok(session_local::Reply::Transfer(pair))
}
fn validate(call: &Message, reply: &Message, kind: u64) -> R<()> {
    if reply.kind != mount_client::REPLY {
        return Err(invalid());
    }
    let status = number(reply, 0)?;
    let op = number(call, 0)?;
    let key = if status != 0 || op == 5 { 0 } else { op };
    if (1..=4).any(|i| (i == key) != reply.field(i).is_some()) {
        return Err(invalid());
    }
    if status != 0 {
        return Ok(());
    }
    match op {
        1 => {
            p::validate_metadata(reply.field(1).ok_or_else(invalid)?, kind)?;
        }
        2 => {
            let mut names = BTreeSet::new();
            for entry in reply
                .field(2)
                .and_then(Value::as_array)
                .ok_or_else(invalid)?
            {
                let fields = entry
                    .as_array()
                    .filter(|a| a.len() == 2)
                    .ok_or_else(invalid)?;
                if !p::valid_entry_name(&fields[0], kind)
                    || !names.insert(crate::cbor::encode(&fields[0]))
                {
                    return Err(invalid());
                }
                p::validate_metadata(&fields[1], kind)?;
            }
        }
        3 => {
            number(reply, 3)?;
        }
        4 if bytes(reply, 4)?.len() as u64 <= number(call, 4)? => {}
        5 => {}
        _ => return Err(invalid()),
    }
    Ok(())
}
async fn pump(
    c: &mut Channel,
    mut input: tokio::process::ChildStdin,
    mut output: tokio::process::ChildStdout,
    kind: u64,
    live: impl Fn() -> R<()>,
) -> R<()> {
    loop {
        let n =
            before_end(&mut c.rx, async { output.read_u32().await.map_err(local) }).await? as usize;
        if n > wire::DEFAULT_MESSAGE_LIMIT as usize {
            return Err(local("invalid FUSE worker request"));
        }
        let progress = c.timers.progress;
        deadline(progress, async {
            let mut b = vec![0; n];
            output.read_exact(&mut b).await.map_err(local)?;
            let call = Message::decode(&b)?;
            live()?;
            c.send(call.clone()).await?;
            let reply = c.expect(mount_client::REPLY, progress).await?;
            validate(&call, &reply, kind)?;
            let data = reply.encode();
            live()?;
            input.write_u32(data.len() as u32).await.map_err(local)?;
            input.write_all(&data).await.map_err(local)
        })
        .await?;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn detach_wins_when_mount_ready_crosses_setup_cancellation() {
        timeout(Duration::from_secs(4), async {
            use std::{fs::File, sync::Arc};
            let q = crate::files::tests::Pair::start().await;
            q.client.set_max_concurrent_bi_streams(1u32.into());
            let slots = Arc::new(tokio::sync::Semaphore::new(1));
            let info = AttachmentInfo {
                mount: true,
                reverse: Some(slots.clone()),
                max_size: 1,
                progress: OPEN,
                peer_limit: wire::DEFAULT_MESSAGE_LIMIT,
                attached: std::time::SystemTime::now(),
                key: crate::authorized::KeyInfo {
                    key: [0; 32],
                    label: None,
                },
                connection: q.server.clone(),
            };
            let (detach, detached) = watch::channel(None);
            let (_session, ended) = watch::channel(false);
            // No mount syscall can succeed even if a regression reaches setup.
            let target = Target::new(Arc::new(File::open("/dev/null").unwrap()), 1, 0);
            let session_local::Reply::Transfer(pair) = dispatch(
                SessionId([9; 16]),
                1,
                info,
                detached,
                ended,
                target,
                slots.clone().try_acquire_owned().unwrap(),
            )
            .unwrap() else {
                panic!()
            };
            let _data = pair.connect().await.unwrap();
            let mut life = pair.connect().await.unwrap();
            let mut client = Channel::new(
                &q.client,
                q.client.accept_bi().await.unwrap(),
                wire::DEFAULT_MESSAGE_LIMIT,
            );
            client.expect(wire::CHANNEL_OPEN, OPEN).await.unwrap();
            client.send(msg(PENDING)).await.unwrap();
            client.send(msg(APPROVED)).await.unwrap();
            client.expect(START, OPEN).await.unwrap();
            detach.send(Some(Code::NoError)).unwrap();
            let _ = client.send(nmsg(mount_client::MOUNT_READY, 0)).await;
            let result = String::from_utf8(consent::get(&mut life).await.unwrap()).unwrap();
            assert!(result.contains("interrupted"), "{result}");
            assert!(client.next(OPEN).await.is_err());
            slots.acquire().await.unwrap().forget();
        })
        .await
        .unwrap()
    }
    #[test]
    fn replies_match_the_outstanding_call_and_never_return_partial_success() {
        let read = Message::new(
            mount_client::CALL,
            vec![(0, Value::Uint(4)), (4, Value::Uint(1))],
        );
        let reply = |status, bytes: Vec<u8>| {
            Message::new(
                mount_client::REPLY,
                vec![(0, Value::Uint(status)), (4, Value::Bytes(bytes))],
            )
        };
        assert!(validate(&read, &reply(0, vec![1]), 0).is_ok());
        assert!(validate(&read, &reply(0, vec![1, 2]), 0).is_err());
        assert!(validate(&read, &reply(2, vec![]), 0).is_err());
        assert!(validate(&read, &nmsg(mount_client::REPLY, 2), 0).is_ok());
        assert!(validate(&read, &nmsg(mount_client::MOUNT_READY, 0), 0).is_err());
    }
}
