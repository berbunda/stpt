//! The child inherits one end of an unnamed datagram socketpair. Each caller
//! binds its own abstract reply socket; concurrent calls never share a reader.
use super::*;
use aws_lc_rs::{
    aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey},
    digest::{SHA256, digest},
    rand::{SecureRandom, SystemRandom},
};
use nix::libc;
use std::os::{
    fd::{AsRawFd, FromRawFd},
    linux::net::SocketAddrExt,
    unix::net::{SocketAddr, UnixDatagram},
};
const FD: &str = "STPT_LOCAL_FD";
pub struct Endpoint {
    server: tokio::net::UnixDatagram,
    child: Option<UnixDatagram>,
}
impl Endpoint {
    pub fn new(_: crate::terminal::SessionId, env: &mut Vec<(String, String)>) -> io::Result<Self> {
        let (server, child) = UnixDatagram::pair()?;
        let enabled = 1i32;
        // SAFETY: initialized integer option, valid socket and matching length.
        if unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                (&enabled as *const i32).cast(),
                size_of_val(&enabled) as _,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        server.set_nonblocking(true)?;
        env.push((FD.into(), child.as_raw_fd().to_string()));
        Ok(Self {
            server: tokio::net::UnixDatagram::from_std(server)?,
            child: Some(child),
        })
    }
    pub async fn serve(mut self, session: &Session) -> io::Result<()> {
        self.child.take();
        let mut frame = [0u8; 51];
        loop {
            let (n, peer) = self
                .server
                .async_io(tokio::io::Interest::READABLE, || {
                    receive(self.server.as_raw_fd(), &mut frame)
                })
                .await?;
            if n != 50 {
                continue;
            }
            let nonce = &frame[..32];
            let data = if peer.is_some_and(|cred| session.owns_local_process(cred.pid, cred.uid)) {
                super::reply(session, frame[32..50].try_into().unwrap())
            } else {
                b"\x01caller does not belong to this Session".to_vec()
            };
            let answer = if frame[33] & 0x80 != 0 {
                seal(nonce, data)?
            } else {
                let mut answer = nonce.to_vec();
                answer.extend(data);
                answer
            };
            // This socket has no filesystem path. A dead caller needs no cleanup.
            let socket = UnixDatagram::unbound()?;
            socket.set_nonblocking(true)?;
            let _ = socket.send_to_addr(&answer, &address(nonce)?);
        }
    }
}
/// Receive kernel credentials with this particular request. Discard and close
/// any unsolicited rights, even if the ancillary data was truncated.
fn receive(fd: i32, frame: &mut [u8]) -> io::Result<(usize, Option<libc::ucred>)> {
    let mut control = [0usize; 16];
    let mut iov = libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    // SAFETY: msg points only to the aligned control buffer and the live iovec.
    // The kernel supplies the header lengths after a successful recvmsg.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = size_of_val(&control);
        let n = libc::recvmsg(
            fd,
            &mut msg,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC | libc::MSG_TRUNC,
        );
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut peer = None;
        let mut valid = msg.msg_flags & libc::MSG_CTRUNC == 0;
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            let h = &*header;
            let bytes = h.cmsg_len - libc::CMSG_LEN(0) as usize;
            match (h.cmsg_level, h.cmsg_type) {
                (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) if bytes == size_of::<libc::ucred>() => {
                    peer = Some(
                        libc::CMSG_DATA(header)
                            .cast::<libc::ucred>()
                            .read_unaligned(),
                    );
                }
                (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                    valid = false;
                    for i in 0..bytes / size_of::<i32>() {
                        libc::close(
                            libc::CMSG_DATA(header)
                                .cast::<i32>()
                                .add(i)
                                .read_unaligned(),
                        );
                    }
                }
                _ => valid = false,
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
        Ok((n as usize, peer.filter(|_| valid)))
    }
}
// The reply address is public. A replacement receiver after caller exit
// must never obtain the rendezvous secret. The request key stays on the socketpair.
fn key(secret: &[u8]) -> io::Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, secret)
        .map(LessSafeKey::new)
        .map_err(io::Error::other)
}
fn seal(secret: &[u8], mut data: Vec<u8>) -> io::Result<Vec<u8>> {
    let mut iv = [0; 12];
    SystemRandom::new()
        .fill(&mut iv)
        .map_err(io::Error::other)?;
    key(secret)?
        .seal_in_place_append_tag(Nonce::assume_unique_for_key(iv), Aad::empty(), &mut data)
        .map_err(io::Error::other)?;
    let mut packet = iv.to_vec();
    packet.extend(data);
    Ok(packet)
}
fn open(secret: &[u8], packet: &mut [u8]) -> Option<Vec<u8>> {
    let iv = packet.get(..12)?.try_into().ok()?;
    key(secret)
        .ok()?
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::empty(),
            &mut packet[12..],
        )
        .ok()
        .map(|b| b.to_vec())
}
fn address(nonce: &[u8]) -> io::Result<SocketAddr> {
    let mut name = b"stpt-rf002-".to_vec();
    name.extend(digest(&SHA256, nonce).as_ref());
    SocketAddr::from_abstract_name(name)
}
pub fn call(request: [u8; 18]) -> io::Result<Vec<u8>> {
    let fd = std::env::var(FD)
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|n| *n >= 3)
        .ok_or_else(|| io::Error::other("no inherited STPT Session endpoint"))?;
    // Duplicate through the kernel: untrusted environment integers may be closed.
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    let channel = unsafe { UnixDatagram::from_raw_fd(copy) };
    // Never send to a pathname supplied through the environment.
    if !channel.peer_addr()?.is_unnamed() {
        return Err(io::Error::other("invalid Session endpoint"));
    }
    let mut nonce = [0u8; 32];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| io::Error::other("random source unavailable"))?;
    let receiver = UnixDatagram::bind_addr(&address(&nonce)?)?;
    let mut frame = nonce.to_vec();
    frame.extend(request);
    // MSG_DONTWAIT affects this send only, including when the inherited queue is full.
    let n = unsafe {
        libc::send(
            channel.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    let deadline = std::time::Instant::now() + TIMEOUT;
    let mut buf = vec![0; 32 + MAX_REPLY + 1];
    loop {
        receiver.set_read_timeout(Some(
            deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or(io::ErrorKind::TimedOut)?,
        ))?;
        let n = receiver.recv(&mut buf)?;
        if request[1] & 0x80 != 0 {
            if let Some(data) = open(&nonce, &mut buf[..n]) {
                return Ok(data);
            }
        } else if n > 32 && n <= 32 + MAX_REPLY && buf[..32] == nonce {
            return Ok(buf[32..n].to_vec());
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transfer_reply_is_bound_to_its_calling_process_secret() {
        let key = [19; 32];
        let encoded = seal(&key, b"private transfer ticket".to_vec()).unwrap();
        assert_eq!(
            open(&key, &mut encoded.clone()).unwrap(),
            b"private transfer ticket"
        );
        assert!(open(&[11; 32], &mut encoded.clone()).is_none());
        let mut modified = encoded;
        modified[12] ^= 1;
        assert!(open(&key, &mut modified).is_none());
    }
}
