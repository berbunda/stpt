//! Exercise the normal binary and Session IPC. Only the local user's second
//! terminal is scripted; QUIC, hashing, file publication and authentication are real.
use aws_lc_rs::hmac;
use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};
pub fn scenario(home: &Path, dest: &str, fp: &str) {
    let exe = env!("CARGO_BIN_EXE_stpt");
    let src = home.join("approved-source");
    let out = home.join("approved-destination");
    let contents: Vec<u8> = (0..110_000).map(|v| (v % 253) as u8).collect();
    std::fs::write(&src, &contents).unwrap();
    let pairing = home.join("pairing");
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut ticket = listener.local_addr().unwrap().port().to_be_bytes().to_vec();
    let key = [17; 32];
    ticket.extend(key);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pairing)
            .unwrap()
            .write_all(&ticket)
            .unwrap();
    }
    #[cfg(windows)]
    super::windows_security::create_private(&pairing)
        .unwrap()
        .write_all(&ticket)
        .unwrap();
    let path = out.clone();
    let broker = std::thread::spawn(move || {
        for (index, target) in [Some(src), Some(path.clone()), Some(path), None]
            .into_iter()
            .enumerate()
        {
            let start = std::time::Instant::now();
            let mut s = loop {
                if let Ok((s, _)) = listener.accept() {
                    break s;
                }
                assert!(
                    start.elapsed() < Duration::from_secs(20),
                    "no consent connection"
                );
                std::thread::sleep(Duration::from_millis(10))
            };
            s.set_nonblocking(false).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
            let mut a = [0; 32];
            s.read_exact(&mut a).unwrap();
            let b = [index as u8; 32];
            let proof = |v: u8| {
                let mut c = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA256, &key));
                c.update(&[v]);
                c.update(&a);
                c.update(&b);
                c.sign()
            };
            s.write_all(&b).unwrap();
            s.write_all(proof(1).as_ref()).unwrap();
            let mut tag = [0; 32];
            s.read_exact(&mut tag).unwrap();
            assert_eq!(tag, proof(2).as_ref());
            let mut len = [0; 2];
            s.read_exact(&mut len).unwrap();
            let mut context = vec![0; u16::from_be_bytes(len) as usize];
            s.read_exact(&mut context).unwrap();
            let context = String::from_utf8(context).unwrap();
            assert!(context.contains("Attachment 1"));
            assert!(context.contains("Server SHA256:"));
            let Some(path) = target else {
                s.write_all(&[0, 0]).unwrap();
                continue;
            };
            let name = path.to_str().unwrap().as_bytes();
            s.write_all(&(name.len() as u16).to_be_bytes()).unwrap();
            s.write_all(name).unwrap();
            let mut pinned = [0];
            s.read_exact(&mut pinned).unwrap();
            assert_eq!(pinned, [1]);
            s.write_all(&[1]).unwrap();
        }
    });
    let run = |args: &[&str], input: &[u8]| {
        let mut child = Command::new(exe)
            .env("HOME", home)
            .env("APPDATA", home)
            .env("XDG_CONFIG_HOME", home)
            .env("STPT_CONSENT_FILE", &pairing)
            .args([
                "exec",
                dest,
                "--fingerprint",
                fp,
                "--no-shell",
                exe,
                "session",
            ])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        let bytes = input.to_vec();
        let writer = std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
        let output = child.wait_with_output().unwrap();
        writer.join().unwrap();
        output
    };
    let read = run(&["read"], &[]);
    assert!(read.status.success(), "{}", super::stderr(&read));
    assert_eq!(read.stdout, contents);
    let size = contents.len().to_string();
    let created = run(&["create", &size], &contents);
    assert!(created.status.success(), "{}", super::stderr(&created));
    assert_eq!(std::fs::read(&out).unwrap(), contents);
    let collision = run(&["create", "0"], &[]);
    assert!(!collision.status.success());
    assert_eq!(std::fs::read(&out).unwrap(), contents);
    let denied = run(&["read"], &[]);
    assert!(!denied.status.success());
    assert!(
        super::stderr(&denied).contains("denied"),
        "{}",
        super::stderr(&denied)
    );
    broker.join().unwrap();
}
