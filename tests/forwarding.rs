//! Native executable tests: no live credentials or external network targets.
mod common;
use common::*;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Forward {
    child: Child,
    addr: SocketAddr,
}
impl Drop for Forward {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
fn account() -> String {
    if let Ok(account) = std::env::var("STPT_FORWARD_TEST_ACCOUNT") {
        return account;
    }
    #[cfg(unix)]
    {
        String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
            .unwrap()
            .trim()
            .into()
    }
    #[cfg(windows)]
    {
        std::env::var("USERNAME").unwrap()
    }
}
fn start(
    mode: &str,
    target: Option<SocketAddr>,
    policy: &str,
    label: &str,
) -> (RunningServer, Forward) {
    let account = account();
    let conf = server_config(
        &format!("rg-{label}"),
        &format!(
            "[forwarding.accounts.'{account}']\nlocal=true\nremote=true\ndynamic=true\ntargets=[{{network='127.0.0.0/8'}},{{network='::1/128'}}]\nbinds=[{{network='127.0.0.0/8'}}]\n{policy}"
        ),
    );
    let config_path = std::path::Path::new(&conf);
    let keys = config_path
        .parent()
        .unwrap()
        .join("authorized_keys")
        .join(&account);
    std::fs::write(&keys, TEST_USER_KEY_LINE).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let home = dir(&format!("rg-home-{label}"));
    let key = user_key(&home);
    let fingerprint = stdout(&stpt(&["server", "--config", &conf, "--fingerprint"]));
    let server = RunningServer::start(&["--config", &conf, "--listen", "127.0.0.1:0"]);
    let dest = format!("{account}@127.0.0.1:{}", server.port);
    let mut c = Command::new(env!("CARGO_BIN_EXE_stpt"));
    c.args([
        "forward",
        &dest,
        "--mode",
        mode,
        "--bind",
        "127.0.0.1:0",
        "--fingerprint",
        &fingerprint,
        "--identity",
        key.to_str().unwrap(),
    ]);
    if let Some(t) = target {
        c.args(["--target", &t.to_string()]);
    }
    c.env("APPDATA", &home)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x08000000);
    }
    let mut child = c.spawn().unwrap();
    let output = child.stdout.take().unwrap();
    let (ready, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(output).read_line(&mut line).map(|_| line);
        let _ = ready.send(result);
    });
    let line = match result.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(line)) => line,
        other => {
            let _ = child.kill();
            let _ = child.wait();
            panic!("forward startup timed out or failed: {other:?}")
        }
    };
    if line.is_empty() {
        let mut e = String::new();
        child.stderr.take().unwrap().read_to_string(&mut e).unwrap();
        panic!("forward failed: {e}")
    }
    let addr = line.split_whitespace().last().unwrap().parse().unwrap();
    (server, Forward { child, addr })
}
fn responder() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = l.local_addr().unwrap();
    let t = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut input = Vec::new();
        s.read_to_end(&mut input).unwrap();
        assert_eq!(
            input,
            (0..200_000).map(|n| (n % 251) as u8).collect::<Vec<_>>()
        );
        s.write_all(b"response after half-close").unwrap();
    });
    (a, t)
}
fn roundtrip(mut s: TcpStream) {
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(15))).unwrap();
    s.write_all(&(0..200_000).map(|n| (n % 251) as u8).collect::<Vec<_>>())
        .unwrap();
    s.shutdown(std::net::Shutdown::Write).unwrap();
    let mut out = Vec::new();
    s.read_to_end(&mut out).unwrap();
    assert_eq!(out, b"response after half-close");
}
#[test]
fn local_and_remote_binary_data_and_half_close() {
    for mode in ["local", "remote"] {
        let (target, t) = responder();
        let (_server, forward) = start(mode, Some(target), "", mode);
        roundtrip(TcpStream::connect(forward.addr).unwrap());
        t.join().unwrap();
    }
}
#[test]
fn socks_connect_and_unsupported_command() {
    let (target, t) = responder();
    let (_server, forward) = start("dynamic", None, "", "socks");
    let mut s = TcpStream::connect(forward.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut b = [0; 2];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b, [5, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend(target.port().to_be_bytes());
    s.write_all(&req).unwrap();
    let mut b = [0; 10];
    s.read_exact(&mut b).unwrap();
    assert_eq!(&b[..4], &[5, 0, 0, 1]);
    assert_ne!(&b[8..], &[0, 0]);
    roundtrip(s);
    t.join().unwrap();
    let mut s = TcpStream::connect(forward.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    s.read_exact(&mut [0; 2]).unwrap();
    s.write_all(&[5, 3, 0, 1]).unwrap();
    let mut b = [0; 10];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b[1], 7);
}

#[test]
fn socks_server_dns_and_policy_refusal() {
    for deny in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (_server, forward) = start(
            "dynamic",
            None,
            if deny {
                "names=[]"
            } else {
                "names=['localhost']"
            },
            if deny { "dns-deny" } else { "dns-ok" },
        );
        let mut s = TcpStream::connect(forward.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        s.write_all(&[5, 1, 0]).unwrap();
        s.read_exact(&mut [0; 2]).unwrap();
        let mut req = vec![5, 1, 0, 3, 9];
        req.extend(b"localhost");
        req.extend(port.to_be_bytes());
        s.write_all(&req).unwrap();
        let mut reply = [0; 10];
        s.read_exact(&mut reply).unwrap();
        assert_eq!(reply[1], if deny { 2 } else { 0 });
        if deny {
            listener.set_nonblocking(true).unwrap();
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            )
        } else {
            let (mut target, _) = listener.accept().unwrap();
            target.write_all(b"dns target").unwrap();
            let mut b = [0; 10];
            s.read_exact(&mut b).unwrap();
            assert_eq!(&b, b"dns target")
        }
    }
}

#[test]
fn remote_ingress_denial_never_contacts_target() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let (_server, forward) = start(
        "remote",
        Some(listener.local_addr().unwrap()),
        "ingress=['192.0.2.0/24']",
        "ingress",
    );
    let mut s = TcpStream::connect(forward.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut b = [0];
    assert!(matches!(s.read(&mut b), Ok(0) | Err(_)));
    listener.set_nonblocking(true).unwrap();
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn ipv6_target_roundtrip() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let (_server, forward) = start("local", Some(listener.local_addr().unwrap()), "", "ipv6");
    let mut source = TcpStream::connect(forward.addr).unwrap();
    source
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    source.shutdown(std::net::Shutdown::Write).unwrap();
    let (mut target, _) = listener.accept().unwrap();
    target
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut b = Vec::new();
    target.read_to_end(&mut b).unwrap();
    assert!(b.is_empty());
    target.write_all(b"IPv6 target").unwrap();
    target.shutdown(std::net::Shutdown::Write).unwrap();
    source.read_to_end(&mut b).unwrap();
    assert_eq!(b, b"IPv6 target");
}

fn socks_source(address: SocketAddr) -> TcpStream {
    let s = TcpStream::connect(address).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
    s
}
#[test]
fn socks_methods_commands_addresses_and_refusal_statuses() {
    let (_server, forward) = start("dynamic", None, "", "review-socks-errors");
    let mut s = socks_source(forward.addr);
    s.write_all(&[5, 2, 1, 2]).unwrap();
    let mut b = [0; 2];
    s.read_exact(&mut b).unwrap();
    assert_eq!(b, [5, 255]);
    for (request, rep) in [
        (vec![5, 2, 0, 1], 7),
        (vec![5, 3, 0, 1], 7),
        (vec![5, 1, 0, 9], 8),
        (vec![5, 1, 0, 3, 4, b'a', b'.', b'.', b'.', 0, 80], 8),
    ] {
        let mut s = socks_source(forward.addr);
        s.write_all(&[5, 1, 0]).unwrap();
        s.read_exact(&mut [0; 2]).unwrap();
        s.write_all(&request).unwrap();
        let mut reply = [0; 10];
        s.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [5, rep, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
    let reserved = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )
    .unwrap();
    reserved
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    let target = reserved.local_addr().unwrap().as_socket().unwrap();
    let mut s = socks_source(forward.addr);
    s.write_all(&[5, 1, 0]).unwrap();
    s.read_exact(&mut [0; 2]).unwrap();
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
    request.extend(target.port().to_be_bytes());
    s.write_all(&request).unwrap();
    let mut reply = [0; 10];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 5, 0, 1, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn socks_ipv6_pipeline_contains_only_application_bytes() {
    let listener = TcpListener::bind("[::1]:0").unwrap();
    let (_server, forward) = start("dynamic", None, "", "review-pipeline");
    let mut source = socks_source(forward.addr);
    let mut request = vec![5, 1, 0, 5, 1, 0, 4];
    request.extend(std::net::Ipv6Addr::LOCALHOST.octets());
    request.extend(listener.local_addr().unwrap().port().to_be_bytes());
    request.extend(b"early payload");
    source.write_all(&request).unwrap();
    let mut method = [0; 2];
    source.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 0]);
    let mut reply = [0; 22];
    source.read_exact(&mut reply).unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 4]);
    assert_ne!(&reply[20..], &[0, 0]);
    let (mut target, _) = listener.accept().unwrap();
    target
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut bytes = [0; 13];
    target.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"early payload");
    target.write_all(b"response").unwrap();
    let mut reply = [0; 8];
    source.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"response");
}

#[test]
fn forwarding_is_disabled_without_operator_policy() {
    let account = account();
    let conf = server_config("rg-review-disabled", "");
    let keys = std::path::Path::new(&conf)
        .parent()
        .unwrap()
        .join("authorized_keys")
        .join(&account);
    std::fs::write(keys, TEST_USER_KEY_LINE).unwrap();
    let home = dir("rg-review-disabled-home");
    let key = user_key(&home);
    let fingerprint = stdout(&stpt(&["server", "--config", &conf, "--fingerprint"]));
    let server = RunningServer::start(&["--config", &conf, "--listen", "127.0.0.1:0"]);
    let dest = format!("{account}@127.0.0.1:{}", server.port);
    let out = stpt_in(
        &home,
        &[
            "forward",
            &dest,
            "--mode",
            "local",
            "--bind",
            "127.0.0.1:0",
            "--target",
            "127.0.0.1:9",
            "--fingerprint",
            &fingerprint,
            "--identity",
            key.to_str().unwrap(),
        ],
    );
    assert_eq!(out.status.code(), Some(255));
    assert!(stdout(&out).is_empty());
    assert!(stderr(&out).contains("Unsupported"));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root and STPT_FORWARD_TEST_ACCOUNT=nobody"]
fn foreign_account_owns_connect_and_listener_sockets() {
    assert_eq!(
        String::from_utf8(Command::new("id").arg("-u").output().unwrap().stdout)
            .unwrap()
            .trim(),
        "0"
    );
    assert_eq!(account(), "nobody");
    let uid = String::from_utf8(
        Command::new("id")
            .args(["-u", "nobody"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned();
    let owner = |port: u16, state: &str| {
        let text = std::fs::read_to_string("/proc/net/tcp").unwrap();
        let suffix = format!(":{port:04X}");
        text.lines()
            .skip(1)
            .find_map(|l| {
                let f: Vec<_> = l.split_whitespace().collect();
                (f[1].ends_with(&suffix) && f[3] == state).then(|| f[7].to_owned())
            })
            .expect("live TCP socket in procfs")
    };
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    {
        let (_server, forward) = start(
            "local",
            Some(target.local_addr().unwrap()),
            "",
            "foreign-connect",
        );
        let _source = TcpStream::connect(forward.addr).unwrap();
        target.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(12);
        let (_held, peer) = loop {
            match target.accept() {
                Ok(v) => break v,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("Account target was not connected: {e}"),
            }
        };
        assert_eq!(owner(peer.port(), "01"), uid);
    }
    {
        let (_server, forward) = start(
            "remote",
            Some(target.local_addr().unwrap()),
            "",
            "foreign-listen",
        );
        assert_eq!(owner(forward.addr.port(), "0A"), uid);
    }
}
