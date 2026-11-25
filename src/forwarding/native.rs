//! Socket creation with the Account's authority; no shell or privileged fallback.
use super::*;
use std::{
    io,
    sync::{Arc, OnceLock},
};
use tokio::net::{TcpListener, TcpStream};
pub trait Authority: Send + Sync {
    fn valid(&self) -> bool;
}
pub type Lease = Arc<dyn Authority>;
fn admitted(lease: &Option<Lease>) -> Result<(), Status> {
    if lease.as_ref().is_some_and(|l| !l.valid()) {
        Err(Status::Denied)
    } else {
        Ok(())
    }
}
fn workers() -> Arc<tokio::sync::Semaphore> {
    static S: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    S.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(64)))
        .clone()
}
fn listen(a: SocketAddr) -> io::Result<std::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(a), Type::STREAM, Some(Protocol::TCP))?;
    if a.is_ipv6() {
        s.set_only_v6(true)?
    }
    s.bind(&a.into())?;
    s.listen(128)?;
    s.set_nonblocking(true)?;
    Ok(s.into())
}
async fn authority(account: Option<&str>) -> Result<(), Status> {
    #[cfg(windows)]
    if let Some(n) = account
        && crate::process::Account::lookup(n)
            .map_err(|e| Status::io(&e))?
            .is_none()
    {
        return Err(Status::Denied);
    }
    let _ = account;
    Ok(())
}
pub async fn bind(
    account: Option<&str>,
    a: SocketAddr,
    lease: Option<Lease>,
) -> Result<TcpListener, Status> {
    admitted(&lease)?;
    authority(account).await?;
    let _lease = lease.clone();
    #[cfg(unix)]
    if let Some(account) = account {
        let (_, fd) = operation(account, "bind", &a.to_string(), lease).await?;
        let fd = fd.ok_or(Status::Failed)?;
        let l = std::net::TcpListener::from(fd);
        l.set_nonblocking(true).map_err(|e| Status::io(&e))?;
        return TcpListener::from_std(l).map_err(|e| Status::io(&e));
    }
    TcpListener::from_std(listen(a).map_err(|e| Status::io(&e))?).map_err(|e| Status::io(&e))
}
async fn addresses(
    account: Option<&str>,
    t: &Target,
    lease: Option<Lease>,
) -> Result<Vec<SocketAddr>, Status> {
    let _ = account;
    if let Some(a) = t.socket() {
        return Ok(vec![a]);
    }
    let Host::Name(n) = &t.host else {
        unreachable!()
    };
    // Absolute DNS query: no resolver search suffixes; Account helper owns blocking NSS.
    let q = format!("{n}.:{}", t.port);
    #[cfg(unix)]
    if let Some(account) = account {
        let (v, fd) = operation(account, "resolve", &q, lease.clone()).await?;
        drop(fd);
        return v
            .as_array()
            .ok_or(Status::Failed)?
            .iter()
            .map(|v| socket_of(v).map_err(|_| Status::Failed))
            .collect();
    }
    use std::net::ToSocketAddrs;
    blocking_lookup(lease, move || {
        q.to_socket_addrs()
            .map(|a| {
                a.take(16)
                    .map(|a| SocketAddr::new(normal(a.ip()), a.port()))
                    .collect()
            })
            .map_err(|_| Status::Name)
    })
    .await
}
async fn blocking_lookup<T: Send + 'static>(
    lease: Option<Lease>,
    operation: impl FnOnce() -> Result<T, Status> + Send + 'static,
) -> Result<T, Status> {
    admitted(&lease)?;
    let permit = workers().try_acquire_owned().map_err(|_| Status::Limit)?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _lease = lease;
        admitted(&_lease)?;
        operation()
    })
    .await
    .map_err(|_| Status::Failed)?
}

pub async fn connect(
    account: Option<&str>,
    t: &Target,
    policy: Option<&Policy>,
    lease: Option<Lease>,
) -> Result<TcpStream, Status> {
    admitted(&lease)?;
    authority(account).await?;
    if !t.supported() {
        return Err(Status::Unsupported);
    }
    if policy.is_some_and(|p| !p.target(t)) {
        return Err(Status::Denied);
    }
    let candidates = addresses(account, t, lease.clone()).await?;
    connect_resolved(account, t, policy, lease, candidates).await
}
// Kept separate so controlled DNS answer sets exercise the actual connector.
async fn connect_resolved(
    account: Option<&str>,
    t: &Target,
    policy: Option<&Policy>,
    lease: Option<Lease>,
    candidates: Vec<SocketAddr>,
) -> Result<TcpStream, Status> {
    let _ = account;
    let _ = account;
    admitted(&lease)?;
    if candidates.is_empty() {
        return Err(Status::Name);
    }
    let mut allowed = false;
    let mut last = Status::Denied;
    for a in candidates.into_iter().take(16) {
        admitted(&lease)?;
        let a = SocketAddr::new(normal(a.ip()), a.port());
        if a.port() != t.port {
            return Err(Status::Failed);
        }
        if !usable(a.ip()) || policy.is_some_and(|p| !p.targets.iter().any(|x| x.allows(a))) {
            continue;
        }
        allowed = true;
        #[cfg(unix)]
        if let Some(account) = account {
            match operation(account, "connect", &a.to_string(), lease.clone()).await {
                Ok((_, Some(fd))) => {
                    let s = std::net::TcpStream::from(fd);
                    s.set_nonblocking(true).map_err(|e| Status::io(&e))?;
                    return TcpStream::from_std(s).map_err(|e| Status::io(&e));
                }
                Ok(_) => last = Status::Failed,
                Err(e) => last = e,
            }
            continue;
        }
        match TcpStream::connect(a).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Status::io(&e),
        }
    }
    Err(if allowed { last } else { Status::Denied })
}

#[cfg(unix)]
struct Child {
    child: Option<tokio::process::Child>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    lease: Option<Lease>,
}
#[cfg(unix)]
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let permit = self.permit.take();
            let lease = self.lease.take();
            let _ = child.start_kill();
            tokio::spawn(async move {
                let _permit = permit;
                let _lease = lease;
                let _ = child.wait().await;
            });
        }
    }
}

#[cfg(unix)]
async fn operation(
    account: &str,
    op: &str,
    value: &str,
    lease: Option<Lease>,
) -> Result<(Value, Option<std::os::fd::OwnedFd>), Status> {
    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    admitted(&lease)?;
    let permit = workers().try_acquire_owned().map_err(|_| Status::Limit)?;
    let name = account.to_owned();
    let pending = lease.clone();
    let (account, permit) = tokio::task::spawn_blocking(move || {
        let _lease = pending;
        admitted(&_lease)?;
        let account = crate::process::Account::lookup(&name)
            .map_err(|e| Status::io(&e))?
            .ok_or(Status::Denied)?;
        Ok::<_, Status>((account, permit))
    })
    .await
    .map_err(|_| Status::Failed)??;
    admitted(&lease)?;
    let (parent, child) = std::os::unix::net::UnixDatagram::pair().map_err(|e| Status::io(&e))?;
    parent.set_nonblocking(true).map_err(|e| Status::io(&e))?;
    let child = account
        .network_worker(op, value, child.into())
        .map_err(|e| Status::io(&e))?;
    let mut child = Child {
        child: Some(child),
        permit: Some(permit),
        lease,
    };
    // SAFETY: parent owns a nonblocking UnixDatagram. Its descriptor is never
    // closed, replaced or exposed to code that could invalidate the registration.
    let parent = unsafe { tokio::io::unix::AsyncFd::register(parent) }
        .map_err(|e| Status::io(&e.into_parts().1))?;
    let (bytes, fd) = loop {
        let mut ready = parent.readable().await.map_err(|e| Status::io(&e))?;
        let result = ready.try_io(|p| {
            let mut b = [0; 4096];
            let mut c = nix::cmsg_space!([i32; 1]);
            let mut io = [std::io::IoSliceMut::new(&mut b)];
            let msg = recvmsg::<()>(
                p.get_ref().as_raw_fd(),
                &mut io,
                Some(&mut c),
                MsgFlags::MSG_CMSG_CLOEXEC,
            )
            .map_err(std::io::Error::from)?;
            let mut fd = None;
            for c in msg.cmsgs().map_err(std::io::Error::from)? {
                if let ControlMessageOwned::ScmRights(fds) = c {
                    for raw in fds {
                        // SAFETY: SCM_RIGHTS installs a fresh descriptor owned by this receiver.
                        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                        if fd.is_none() {
                            fd = Some(owned)
                        }
                    }
                }
            }
            if msg
                .flags
                .intersects(MsgFlags::MSG_TRUNC | MsgFlags::MSG_CTRUNC)
            {
                return Err(io::Error::other("truncated socket reply"));
            }
            let n = msg.bytes;
            Ok((b[..n].to_vec(), fd))
        });
        match result {
            Ok(r) => break r.map_err(|e| Status::io(&e))?,
            Err(_) => continue,
        }
    };
    let status = child
        .child
        .as_mut()
        .unwrap()
        .wait()
        .await
        .map_err(|e| Status::io(&e))?;
    if !status.success() {
        return Err(Status::Failed);
    }
    child.child = None;
    let Value::Array(v) = crate::cbor::decode(&bytes).map_err(|_| Status::Failed)? else {
        return Err(Status::Failed);
    };
    if v.len() != 2 {
        return Err(Status::Failed);
    }
    let status = Status::value(v[0].as_uint().ok_or(Status::Failed)?);
    if status != Status::Ok {
        return Err(status);
    }
    Ok((v[1].clone(), fd))
}

#[cfg(unix)]
pub fn helper() -> std::process::ExitCode {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    use std::{net::ToSocketAddrs, os::fd::AsRawFd};
    let args: Vec<_> = std::env::args().collect();
    let mut socket: Option<socket2::Socket> = None;
    let result = (|| -> Result<Value, Status> {
        if args.len() != 4 {
            return Err(Status::Failed);
        }
        match args[2].as_str() {
            "resolve" => {
                let a: Vec<_> = args[3]
                    .to_socket_addrs()
                    .map_err(|_| Status::Name)?
                    .take(16)
                    .map(socket_value)
                    .collect();
                if a.is_empty() {
                    Err(Status::Name)
                } else {
                    Ok(Value::Array(a))
                }
            }
            "connect" => {
                let a: SocketAddr = args[3].parse().map_err(|_| Status::Failed)?;
                if !usable(a.ip()) {
                    return Err(Status::Unsupported);
                }
                let s =
                    std::net::TcpStream::connect_timeout(&a, OPEN).map_err(|e| Status::io(&e))?;
                let a = s.local_addr().map_err(|e| Status::io(&e))?;
                socket = Some(s.into());
                Ok(socket_value(a))
            }
            "bind" => {
                let a: SocketAddr = args[3].parse().map_err(|_| Status::Failed)?;
                let s = listen(a).map_err(|e| Status::io(&e))?;
                let a = s.local_addr().map_err(|e| Status::io(&e))?;
                socket = Some(s.into());
                Ok(socket_value(a))
            }
            _ => Err(Status::Failed),
        }
    })();
    let (status, value) = match result {
        Ok(v) => (Status::Ok, v),
        Err(s) => (s, Value::Null),
    };
    let b = crate::cbor::encode(&Value::Array(vec![Value::Uint(status as u64), value]));
    let fds: Vec<_> = socket.iter().map(AsRawFd::as_raw_fd).collect();
    let control = if fds.is_empty() {
        vec![]
    } else {
        vec![ControlMessage::ScmRights(&fds)]
    };
    if sendmsg::<()>(
        0,
        &[std::io::IoSlice::new(&b)],
        &control,
        MsgFlags::empty(),
        None,
    )
    .is_ok()
    {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(255)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn listener_cannot_be_rebound_with_reuseaddr() {
        let listener = listen("127.0.0.1:0".parse().unwrap()).unwrap();
        let second = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .unwrap();
        second.set_reuse_address(true).unwrap();
        assert!(
            second.bind(&listener.local_addr().unwrap().into()).is_err(),
            "SO_REUSEADDR stole the forwarding listener address"
        );
    }
    #[test]
    fn ipv6_listener_is_explicitly_v6_only() {
        let listener = listen("[::]:0".parse().unwrap()).unwrap();
        assert!(socket2::SockRef::from(&listener).only_v6().unwrap());
    }
    struct Denied;
    impl Authority for Denied {
        fn valid(&self) -> bool {
            false
        }
    }
    #[tokio::test]
    async fn invalidated_lease_cannot_start_a_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Target {
            host: Host::Ip(listener.local_addr().unwrap().ip()),
            port: listener.local_addr().unwrap().port(),
        };
        assert!(matches!(
            connect(None, &target, None, Some(Arc::new(Denied))).await,
            Err(Status::Denied)
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(40), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn controlled_dns_answers_are_checked_per_candidate_and_per_flow() {
        let allowed = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let forbidden = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = allowed.local_addr().unwrap().port();
        let t = Target {
            host: Host::Name("controlled.example".into()),
            port,
        };
        let policy: Policy = toml::from_str(&format!(
            "targets=[{{network='127.0.0.1/32',ports=[{port}]}}]\nnames=['controlled.example']"
        ))
        .unwrap();
        // Mixed answer set: forbidden loopback address first, then the authorized one.
        let mapped: SocketAddr = format!("[::ffff:127.0.0.1]:{port}").parse().unwrap();
        let socket = connect_resolved(
            None,
            &t,
            Some(&policy),
            None,
            vec![SocketAddr::from(([127, 0, 0, 2], port)), mapped],
        )
        .await
        .unwrap();
        let (_accepted, _) = allowed.accept().await.unwrap();
        drop(socket);
        assert!(matches!(
            connect_resolved(
                None,
                &t,
                Some(&policy),
                None,
                vec![SocketAddr::from(([127, 0, 0, 2], port))]
            )
            .await,
            Err(Status::Denied)
        ));
        assert!(matches!(
            connect_resolved(None, &t, Some(&policy), None, vec![]).await,
            Err(Status::Name)
        ));
        assert!(matches!(
            connect_resolved(
                None,
                &t,
                Some(&policy),
                None,
                vec![forbidden.local_addr().unwrap()]
            )
            .await,
            Err(Status::Failed)
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(40), forbidden.accept())
                .await
                .is_err()
        );
        let badport = Target { port: 1, ..t };
        assert!(
            !policy.target(&badport),
            "reject disallowed port before DNS"
        );
    }

    #[tokio::test]
    async fn cancelled_blocking_lookup_holds_lease_until_native_completion() {
        struct Held(tokio::sync::OwnedSemaphorePermit);
        impl Authority for Held {
            fn valid(&self) -> bool {
                let _ = &self.0;
                true
            }
        }
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let lease = Arc::new(Held(slots.clone().acquire_owned().await.unwrap()));
        let weak = Arc::downgrade(&lease);
        let (started, wait) = tokio::sync::oneshot::channel();
        let (release, gate) = std::sync::mpsc::channel();
        let task = tokio::spawn(blocking_lookup(Some(lease), move || {
            let _ = started.send(());
            gate.recv().unwrap();
            Ok(())
        }));
        wait.await.unwrap();
        task.abort();
        let _ = task.await;
        assert_eq!(slots.available_permits(), 0);
        assert!(weak.upgrade().is_some());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(weak.upgrade().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelled_child_is_killed_reaped_and_keeps_native_slot() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let mut command = tokio::process::Command::new("/bin/sleep");
        command.arg("30").kill_on_drop(true);
        let child = command.spawn().unwrap();
        let pid = child.id().unwrap();
        let guard = Child {
            child: Some(child),
            permit: Some(slots.clone().acquire_owned().await.unwrap()),
            lease: None,
        };
        drop(guard);
        assert_eq!(slots.available_permits(), 0);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while slots.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None),
            Err(nix::errno::Errno::ESRCH)
        );
    }
}
