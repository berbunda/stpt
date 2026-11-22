//! Real CLI/Server file service and fault injection into the Account worker.
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/cbor.rs"]
mod cbor;
mod common;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/file_protocol.rs"]
mod file_protocol;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/wire.rs"]
mod wire;

#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/auth.rs"]
mod auth;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/identity.rs"]
mod identity;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/quic.rs"]
mod quic;
#[cfg(unix)]
#[allow(dead_code)]
#[path = "../src/tls.rs"]
mod tls;
#[cfg(unix)]
mod hello {
    pub const AUTH_PUBLICKEY_ED25519: u64 = 1;
}

#[cfg(unix)]
mod server {
    use super::{
        cbor::Value,
        common::*,
        file_protocol as p,
        wire::{self, Message},
    };
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    struct Setup {
        server: RunningServer,
        config: String,
        home: PathBuf,
        dest: String,
        fp: String,
        data: PathBuf,
    }
    impl Setup {
        fn new(name: &str, account: Option<&str>, extra: &str) -> Self {
            Self::with_binary(name, account, extra, None)
        }
        fn with_binary(
            name: &str,
            account: Option<&str>,
            extra: &str,
            binary: Option<&Path>,
        ) -> Self {
            let config = server_config(name, extra);
            let fp = stdout(&stpt(&["server", "--fingerprint", "--config", &config]));
            let account = account.map(str::to_owned).unwrap_or_else(|| {
                String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
                    .unwrap()
                    .trim()
                    .to_owned()
            });
            let keys = Path::new(&config)
                .with_file_name("authorized_keys")
                .join(&account);
            std::fs::write(&keys, format!("{TEST_USER_KEY_LINE}\n")).unwrap();
            std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o644)).unwrap();
            let arguments = ["--listen", "127.0.0.1:0", "--config", &config];
            let server = match binary {
                Some(binary) => RunningServer::start_binary(binary, &arguments),
                None => RunningServer::start(&arguments),
            };
            let home = dir(&format!("{name}-home"));
            user_key(&home);
            let data = dir(&format!("{name}-data"));
            Self {
                config,
                dest: format!("{account}@127.0.0.1:{}", server.port),
                server,
                home,
                fp,
                data,
            }
        }
        fn fs(&self, command: &str, args: &[&str]) -> std::process::Output {
            let mut a = vec![
                "fs",
                command,
                self.dest.as_str(),
                "--fingerprint",
                self.fp.as_str(),
            ];
            a.extend_from_slice(args);
            stpt_in(&self.home, &a)
        }
        fn ok(&self, command: &str, args: &[&str]) -> String {
            let out = self.fs(command, args);
            assert!(out.status.success(), "{}", stderr(&out));
            stdout(&out)
        }
    }
    fn text(path: &Path) -> &str {
        path.to_str().unwrap()
    }
    #[test]
    fn cli_roundtrip_and_management() {
        let s = Setup::new("fs-cli", None, "");
        let local = s.data.join("source");
        let remote = s.data.join("remote");
        let copy = s.data.join("copy");
        let bytes: Vec<_> = (0..150000).map(|n| (n % 251) as u8).collect();
        std::fs::write(&local, &bytes).unwrap();
        s.ok("push", &[text(&local), text(&remote)]);
        assert_eq!(std::fs::metadata(&remote).unwrap().mode() & 0o777, 0o600);
        s.ok("pull", &[text(&remote), text(&copy)]);
        assert_eq!(std::fs::read(&copy).unwrap(), bytes);
        assert_eq!(s.ok("stat", &[text(&remote)]), "file\t150000");
        assert!(
            s.ok("list", &[text(&s.data)])
                .contains("file\t150000\tremote")
        );
        assert!(stderr(&s.fs("push", &[text(&local), text(&remote)])).contains("ALREADY_EXISTS"));
        assert!(
            stderr(&s.fs("push", &[text(&local), text(&remote), "--replace"]))
                .contains("UNSUPPORTED")
        );
        assert_eq!(std::fs::read(&remote).unwrap(), bytes);
        assert!(!s.fs("pull", &[text(&remote), text(&copy)]).status.success());
        std::fs::write(&copy, b"old").unwrap();
        s.ok("pull", &[text(&remote), text(&copy), "--replace"]);
        assert_eq!(std::fs::read(&copy).unwrap(), bytes);
        let moved = s.data.join("moved");
        s.ok("rename", &[text(&remote), text(&moved)]);
        assert!(stderr(&s.fs("rename", &[text(&moved), text(&copy)])).contains("ALREADY_EXISTS"));
        s.ok("rename", &[text(&moved), text(&copy), "--replace"]);
        let folder = s.data.join("folder");
        s.ok("mkdir", &[text(&folder)]);
        std::fs::write(folder.join("child"), b"x").unwrap();
        assert!(stderr(&s.fs("remove", &[text(&folder)])).contains("NOT_EMPTY"));
        s.ok("remove", &[text(&folder.join("child"))]);
        s.ok("remove", &[text(&folder)]);
        let link = s.data.join("link");
        std::os::unix::fs::symlink(&copy, &link).unwrap();
        assert_eq!(s.ok("stat", &[text(&link)]), "symlink\t-");
        s.ok("remove", &[text(&link)]);
        assert!(copy.exists());
        let sessions = stpt_in(&s.home, &["sessions", &s.dest, "--fingerprint", &s.fp]);
        assert!(sessions.status.success());
        assert!(!stdout(&sessions).contains("150000"));
        let _ = &s.server;
    }
    #[test]
    fn empty_files_and_explicit_sha256() {
        let s = Setup::new("fs-empty", None, "");
        let local = s.data.join("empty");
        std::fs::write(&local, []).unwrap();
        for hash in ["blake3", "sha256"] {
            let remote = s.data.join(hash);
            let copy = s.data.join(format!("{hash}-copy"));
            s.ok("push", &[text(&local), text(&remote), "--hash", hash]);
            s.ok("pull", &[text(&remote), text(&copy), "--hash", hash]);
            assert_eq!(std::fs::metadata(copy).unwrap().len(), 0);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn worker_uses_running_image_after_server_binary_is_unlinked() {
        let location = dir("fs-server-image");
        let binary = location.join("stpt");
        std::fs::copy(env!("CARGO_BIN_EXE_stpt"), &binary).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = Setup::with_binary("fs-unlinked-image", None, "", Some(&binary));
        std::fs::remove_file(&binary).unwrap();
        let local = s.data.join("source");
        let remote = s.data.join("destination");
        std::fs::write(&local, b"running image").unwrap();
        s.ok("push", &[text(&local), text(&remote)]);
        assert_eq!(std::fs::read(&remote).unwrap(), b"running image");
    }
    #[test]
    fn policy_and_local_source_failures() {
        let s = Setup::new("fs-policy", None, "max_file_size = 2\n");
        let source = s.data.join("source");
        let dest = s.data.join("dest");
        std::fs::write(&source, b"too long").unwrap();
        assert!(stderr(&s.fs("push", &[text(&source), text(&dest)])).contains("LIMIT_EXCEEDED"));
        assert!(!dest.exists());
        let fifo = s.data.join("fifo");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(!s.fs("push", &[text(&fifo), text(&dest)]).status.success());
        assert!(!s.fs("stat", &["relative"]).status.success());
        assert!(!s.fs("stat", &["/tmp/../etc"]).status.success());
    }
    #[test]
    fn account_permissions_are_not_server_permissions() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        let s = Setup::new("fs-account", Some("nobody"), "");
        std::fs::set_permissions(&s.data, std::fs::Permissions::from_mode(0o777)).unwrap();
        let source = s.data.join("source");
        std::fs::write(&source, b"account data").unwrap();
        let dest = s.data.join("dest");
        s.ok("push", &[text(&source), text(&dest)]);
        assert_eq!(
            std::fs::metadata(&dest).unwrap().uid(),
            nix::unistd::User::from_name("nobody")
                .unwrap()
                .unwrap()
                .uid
                .as_raw()
        );
        let secret = s.data.join("secret");
        std::fs::write(&secret, b"private root bytes").unwrap();
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        let local = s.data.join("stolen");
        assert!(stderr(&s.fs("pull", &[text(&secret), text(&local)])).contains("ACCESS_DENIED"));
        assert!(!local.exists());
    }
    fn path(path: &Path) -> Value {
        use std::os::unix::ffi::OsStrExt;
        Value::Array(vec![
            Value::Uint(0),
            Value::Array(
                path.as_os_str()
                    .as_bytes()
                    .split(|b| *b == b'/')
                    .filter(|b| !b.is_empty())
                    .map(|b| Value::Bytes(b.to_vec()))
                    .collect(),
            ),
        ])
    }
    struct Worker {
        child: Child,
        input: Option<std::process::ChildStdin>,
        output: std::process::ChildStdout,
    }
    impl Worker {
        fn new() -> Self {
            let mut child = Command::new(env!("CARGO_BIN_EXE_stpt"))
                .args(["__stpt-file-worker", "65535", "8589934592"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            Self {
                input: child.stdin.take(),
                output: child.stdout.take().unwrap(),
                child,
            }
        }
        fn send(&mut self, m: &Message) {
            p::write_ipc(self.input.as_mut().unwrap(), m).unwrap();
        }
        fn recv(&mut self) -> Message {
            p::read_ipc(&mut self.output).unwrap().unwrap()
        }
        fn upload(&mut self, path: &Path, length: u64) {
            self.send(&Message::new(
                wire::FILE_REQUEST,
                vec![
                    (0, Value::Uint(0)),
                    (1, Value::Uint(2)),
                    (2, self::path(path)),
                    (5, Value::Uint(length)),
                ],
            ));
            assert_eq!(self.recv().kind, p::ACCEPTED);
        }
    }
    impl Drop for Worker {
        fn drop(&mut self) {
            drop(self.input.take());
            let _ = std::io::copy(&mut self.output, &mut std::io::sink());
            let _ = self.child.wait();
        }
    }
    #[test]
    fn worker_integrity_failure_and_interrupt_never_publish() {
        let dir = dir("fs-worker-integrity");
        let target = dir.join("target");
        {
            let mut worker = Worker::new();
            worker.upload(&target, 3);
            worker.send(&p::data(0, 0, b"abc".to_vec()));
            worker.send(&p::end(0, p::Status::Ok, 3, Some([0; 32])));
            assert_eq!(p::status(&worker.recv()).unwrap(), p::Status::Integrity);
        }
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        {
            let mut worker = Worker::new();
            worker.upload(&target, (1u64 << 32) + 1);
            drop(worker.input.take());
            assert_eq!(worker.recv().kind, 0);
        }
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    }
    #[test]
    fn worker_bad_offsets_and_non_utf8_names() {
        use std::os::unix::ffi::OsStringExt;
        let dir = dir("fs-worker-offset");
        let target = dir.join(std::ffi::OsString::from_vec(vec![0xff]));
        {
            let mut worker = Worker::new();
            worker.upload(&target, 3);
            worker.send(&p::data(0, 1, b"abc".to_vec()));
            let fatal = worker.recv();
            assert_eq!(fatal.kind, 0);
            assert_eq!(
                fatal.field(0),
                Some(&Value::Uint(wire::Code::ProtocolViolation as u64))
            );
        }
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        {
            let mut worker = Worker::new();
            worker.upload(&target, 0);
            worker.send(&p::end(
                0,
                p::Status::Ok,
                0,
                Some(p::Hash::new(1).unwrap().finish()),
            ));
            assert_eq!(p::status(&worker.recv()).unwrap(), p::Status::Ok);
        }
        assert!(target.exists());
    }
    #[test]
    fn worker_source_eof_and_reuse_after_refusal() {
        let dir = dir("fs-worker-source");
        let source = dir.join("source");
        std::fs::write(&source, vec![0u8; 1024 * 1024]).unwrap();
        let mut worker = Worker::new();
        worker.send(&Message::new(
            wire::FILE_REQUEST,
            vec![(0, Value::Uint(0)), (1, Value::Uint(1)), (2, path(&source))],
        ));
        assert_eq!(worker.recv().kind, p::ACCEPTED);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&source)
            .unwrap()
            .set_len(0)
            .unwrap();
        let mut count = 0;
        loop {
            let m = worker.recv();
            if m.kind == p::DATA {
                count += match m.field(2).unwrap() {
                    Value::Bytes(b) => b.len() as u64,
                    _ => panic!(),
                };
            } else {
                assert_eq!(m.kind, p::END);
                assert_eq!(p::size(&m, 2).unwrap(), count);
                assert_eq!(p::status(&m).unwrap(), p::Status::Io);
                break;
            }
        }
        worker.send(&p::receipt(0, p::Status::Io));
        assert_eq!(p::status(&worker.recv()).unwrap(), p::Status::Io);
        worker.send(&Message::new(
            wire::FILE_REQUEST,
            vec![(0, Value::Uint(1)), (1, Value::Uint(3)), (2, path(&source))],
        ));
        assert_eq!(p::status(&worker.recv()).unwrap(), p::Status::Ok);
    }
    fn request(
        kind: u64,
        path: &Path,
        resume: Value,
        length: Option<u64>,
        algorithm: u64,
    ) -> Message {
        let mut fields = vec![
            (0, Value::Uint(0)),
            (1, Value::Uint(kind)),
            (2, self::path(path)),
            (6, Value::Uint(algorithm)),
            (7, resume),
        ];
        if let Some(n) = length {
            fields.push((5, Value::Uint(n)));
        }
        Message::new(wire::FILE_REQUEST, fields)
    }
    #[test]
    fn worker_resume_upload_rehashes_prefix_and_handles_offset_at_end() {
        for algorithm in [1, 2] {
            let dir = dir(&format!("resume-upload-{algorithm}"));
            let target = dir.join("target");
            let mut worker = Worker::new();
            let mut q = request(
                2,
                &target,
                Value::Array(vec![Value::Uint(0)]),
                Some(6),
                algorithm,
            );
            worker.send(&q);
            let accepted = worker.recv();
            let a = accepted.field(3).unwrap().as_array().unwrap();
            let token = a[0].clone();
            assert_eq!(a[1], Value::Uint(0));
            worker.send(&p::data(0, 0, b"abc".to_vec()));
            worker.send(&Message::new(1, vec![]));
            assert_eq!(worker.recv().kind, 1);
            assert!(!target.exists());
            q.body.retain(|(k, _)| *k != Value::Uint(7));
            q.body
                .push((Value::Uint(7), Value::Array(vec![Value::Uint(1), token])));
            worker.send(&q);
            let accepted = worker.recv();
            let mut hash = p::Hash::new(algorithm).unwrap();
            hash.update(b"abc");
            let a = accepted.field(3).unwrap().as_array().unwrap();
            assert_eq!(a[1], Value::Uint(3));
            assert_eq!(a[2], Value::Bytes(hash.clone().finish().to_vec()));
            worker.send(&p::data(0, 3, b"def".to_vec()));
            worker.send(&Message::new(1, vec![]));
            assert_eq!(worker.recv().kind, 1);
            worker.send(&q);
            let accepted = worker.recv();
            assert_eq!(
                accepted.field(3).unwrap().as_array().unwrap()[1],
                Value::Uint(6)
            );
            hash.update(b"def");
            worker.send(&p::end(0, p::Status::Ok, 6, Some(hash.finish())));
            assert_eq!(p::status(&worker.recv()).unwrap(), p::Status::Ok);
            assert_eq!(std::fs::read(&target).unwrap(), b"abcdef");
        }
    }
    #[test]
    fn worker_resume_rejects_changed_parent_and_download_prefix() {
        let dir = dir("resume-parent");
        let parent = dir.join("parent");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("target");
        let mut worker = Worker::new();
        let q = request(2, &target, Value::Array(vec![Value::Uint(0)]), Some(3), 1);
        worker.send(&q);
        let token = worker.recv().field(3).unwrap().as_array().unwrap()[0].clone();
        worker.send(&p::data(0, 0, b"abc".to_vec()));
        worker.send(&Message::new(1, vec![]));
        worker.recv();
        std::fs::rename(&parent, dir.join("old-parent")).unwrap();
        std::fs::create_dir(&parent).unwrap();
        worker.send(&request(
            2,
            &target,
            Value::Array(vec![Value::Uint(1), token]),
            Some(3),
            1,
        ));
        assert_eq!(
            p::status(&worker.recv()).unwrap(),
            p::Status::ResumeUnavailable
        );
        assert!(!target.exists());
        drop(worker);
        let source = dir.join("source");
        std::fs::write(&source, b"abcdef").unwrap();
        for algorithm in [1, 2] {
            for (length, offset, good) in [(6, 3, true), (6, 6, true), (7, 3, true), (6, 3, false)]
            {
                let mut worker = Worker::new();
                let mut hash = p::Hash::new(algorithm).unwrap();
                hash.update(if good { &b"abcdef"[..offset] } else { b"bad" });
                worker.send(&request(
                    1,
                    &source,
                    Value::Array(vec![
                        Value::Uint(2),
                        Value::Uint(length),
                        Value::Uint(offset as u64),
                        Value::Bytes(hash.clone().finish().to_vec()),
                    ]),
                    None,
                    algorithm,
                ));
                let first = worker.recv();
                if length != 6 || !good {
                    assert_eq!(p::status(&first).unwrap(), p::Status::ResumeUnavailable);
                    continue;
                }
                assert_eq!(first.kind, p::ACCEPTED);
                assert_eq!(
                    first.field(3),
                    Some(&Value::Array(vec![Value::Uint(offset as u64)]))
                );
                let mut count = offset as u64;
                loop {
                    let m = worker.recv();
                    if m.kind == p::DATA {
                        let bytes = p::bytes(&m, 0, count, 6).unwrap();
                        hash.update(bytes);
                        count += bytes.len() as u64;
                    } else {
                        assert_eq!(
                            p::verify_end(&m, 0, count, 6, hash.finish()).unwrap(),
                            p::Status::Ok
                        );
                        break;
                    }
                }
                worker.send(&p::receipt(0, p::Status::Ok));
                assert_eq!(p::status(&worker.recv()).unwrap(), p::Status::Ok);
            }
        }
    }
    #[test]
    fn cli_resume_opt_in_roundtrip_leaves_no_partial_or_token() {
        let s = Setup::new("fs-cli-resume", None, "");
        let source = s.data.join("source");
        let remote = s.data.join("remote");
        let copy = s.data.join("copy");
        let data = vec![93; 150000];
        std::fs::write(&source, &data).unwrap();
        let push = s.data.join("push-state");
        let pull = s.data.join("pull-state");
        s.ok(
            "push",
            &[text(&source), text(&remote), "--resume-state", text(&push)],
        );
        s.ok(
            "pull",
            &[text(&remote), text(&copy), "--resume-state", text(&pull)],
        );
        assert_eq!(std::fs::read(copy).unwrap(), data);
        for dir in [push, pull] {
            assert!(!dir.join("record").exists());
            assert!(!dir.join("data").exists());
        }
    }
    struct Raw {
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        _control: (quinn::SendStream, quinn::RecvStream),
    }
    impl Raw {
        async fn login(s: &Setup) -> Self {
            let addr = format!("127.0.0.1:{}", s.server.port).parse().unwrap();
            let endpoint = super::quic::client(addr).unwrap();
            let check = super::tls::ServerKeyCheck::new(super::tls::Expected {
                stored: None,
                fingerprint: Some(s.fp.parse().unwrap()),
            });
            let connection = super::quic::connect(&endpoint, addr, "localhost", check)
                .await
                .unwrap();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            let hello = Message::new(
                wire::CLIENT_HELLO,
                vec![
                    (0, Value::Array(vec![Value::Uint(0xff000001)])),
                    (
                        1,
                        Value::Map(vec![(
                            Value::Uint(1),
                            Value::Map(vec![
                                (Value::Uint(0), Value::Uint(1)),
                                (Value::Uint(1), Value::Uint(8)),
                            ]),
                        )]),
                    ),
                ],
            );
            wire::write_message(&mut send, &hello, 65535).await.unwrap();
            assert_eq!(
                wire::read_message(&mut recv, 65535)
                    .await
                    .unwrap()
                    .unwrap()
                    .kind,
                wire::SERVER_HELLO
            );
            let key = super::auth::UserKey::load(&s.home.join("stpt/id_ed25519")).unwrap();
            let account = s.dest.split('@').next().unwrap();
            let q = key.request(&super::auth::exporter(&connection).unwrap(), account);
            wire::write_message(&mut send, &q.to_message(), 65535)
                .await
                .unwrap();
            assert!(
                super::auth::result_from_message(
                    &wire::read_message(&mut recv, 65535).await.unwrap().unwrap()
                )
                .unwrap()
            );
            Self {
                endpoint,
                connection,
                _control: (send, recv),
            }
        }
        async fn open(&self, q: &Message) -> (quinn::SendStream, quinn::RecvStream, Message) {
            let (mut send, mut recv) = self.connection.open_bi().await.unwrap();
            wire::write_message(
                &mut send,
                &Message::new(wire::CHANNEL_OPEN, vec![(0, Value::Uint(2))]),
                65535,
            )
            .await
            .unwrap();
            assert_eq!(
                wire::read_message(&mut recv, 65535)
                    .await
                    .unwrap()
                    .unwrap()
                    .kind,
                wire::FILES_READY
            );
            wire::write_message(&mut send, q, 65535).await.unwrap();
            let first = wire::read_message(&mut recv, 65535).await.unwrap().unwrap();
            (send, recv, first)
        }
        async fn close(self) {
            self.connection.close(wire::Code::NoError.varint(), b"");
            self.endpoint.wait_idle().await;
        }
    }
    #[test]
    fn server_retention_timeout_busy_cancel_and_consumed_token() {
        super::quic::runtime().unwrap().block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(15), async {
                let s = Setup::new("resume-server", None, "file_timeout=2\n");
                let target = s.data.join("target");
                let client = Raw::login(&s).await;
                let fresh = request(2, &target, Value::Array(vec![Value::Uint(0)]), Some(6), 1);
                let (mut send, mut recv, accepted) = client.open(&fresh).await;
                assert_eq!(accepted.kind, p::ACCEPTED);
                let token = accepted.field(3).unwrap().as_array().unwrap()[0].clone();
                let resume = request(
                    2,
                    &target,
                    Value::Array(vec![Value::Uint(1), token]),
                    Some(6),
                    1,
                );
                let (_, _, busy) = client.open(&resume).await;
                assert_eq!(p::status(&busy).unwrap(), p::Status::ResumeBusy);
                wire::write_message(&mut send, &p::data(0, 0, b"abc".to_vec()), 65535)
                    .await
                    .unwrap();
                // Wait for the complete DATA message to reach staging: a QUIC
                // reset may legitimately discard unacknowledged DATA.
                loop {
                    let written = std::fs::read_dir(&s.data)
                        .unwrap()
                        .filter_map(Result::ok)
                        .filter(|e| e.file_name().to_string_lossy().starts_with(".stpt-"))
                        .any(|e| {
                            std::fs::metadata(e.path().join("data")).is_ok_and(|m| m.len() == 3)
                        });
                    if written {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
                // Peer TIMEOUT explicitly qualifies; connection remains usable.
                send.reset(wire::Code::Timeout.varint()).unwrap();
                recv.stop(wire::Code::Timeout.varint()).unwrap();
                let second = Raw::login(&s).await;
                let (mut send, mut recv, accepted) = loop {
                    let attempt = second.open(&resume).await;
                    if attempt.2.kind == p::RESULT
                        && p::status(&attempt.2).unwrap() == p::Status::ResumeBusy
                    {
                        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                        continue;
                    }
                    break attempt;
                };
                assert_eq!(accepted.kind, p::ACCEPTED);
                assert_eq!(
                    accepted.field(3).unwrap().as_array().unwrap()[1],
                    Value::Uint(3)
                );
                assert!(!target.exists());
                wire::write_message(&mut send, &p::data(0, 3, b"def".to_vec()), 65535)
                    .await
                    .unwrap();
                let mut h = p::Hash::new(1).unwrap();
                h.update(b"abcdef");
                wire::write_message(
                    &mut send,
                    &p::end(0, p::Status::Ok, 6, Some(h.finish())),
                    65535,
                )
                .await
                .unwrap();
                assert_eq!(
                    p::status(&wire::read_message(&mut recv, 65535).await.unwrap().unwrap())
                        .unwrap(),
                    p::Status::Ok
                );
                let (_, _, unavailable) = second.open(&resume).await;
                assert_eq!(
                    p::status(&unavailable).unwrap(),
                    p::Status::ResumeUnavailable
                );
                assert_eq!(std::fs::read(&target).unwrap(), b"abcdef");
                send.finish().unwrap();
                let _ = wire::read_message(&mut recv, 65535).await;
                // Explicit cancellation must discard, never retain, another upload.
                let cancel_target = s.data.join("cancelled");
                let q = request(
                    2,
                    &cancel_target,
                    Value::Array(vec![Value::Uint(0)]),
                    Some(6),
                    1,
                );
                let (mut send, mut recv, a) = second.open(&q).await;
                let token = a.field(3).unwrap().as_array().unwrap()[0].clone();
                wire::write_message(&mut send, &p::data(0, 0, b"abc".to_vec()), 65535)
                    .await
                    .unwrap();
                send.reset(wire::Code::NoError.varint()).unwrap();
                recv.stop(wire::Code::NoError.varint()).unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let q = request(
                    2,
                    &cancel_target,
                    Value::Array(vec![Value::Uint(1), token]),
                    Some(6),
                    1,
                );
                let (_, _, a) = second.open(&q).await;
                assert_eq!(p::status(&a).unwrap(), p::Status::ResumeUnavailable);
                assert!(!cancel_target.exists());
                client.close().await;
                second.close().await;
            })
            .await
            .unwrap();
        });
    }
    #[test]
    fn server_deadline_retains_and_restart_discards_unpublished_staging() {
        super::quic::runtime().unwrap().block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(12),async {
                let mut s=Setup::new("resume-restart",None,"file_timeout=1\n");let target=s.data.join("target");let client=Raw::login(&s).await;
                let q=request(2,&target,Value::Array(vec![Value::Uint(0)]),Some(6),1);
                let(mut send,mut recv,a)=client.open(&q).await;let token=a.field(3).unwrap().as_array().unwrap()[0].clone();
                wire::write_message(&mut send,&p::data(0,0,b"abc".to_vec()),65535).await.unwrap();
                assert!(matches!(wire::read_message(&mut recv,65535).await,Err(wire::StreamError::Reset(c)) if c==wire::Code::Timeout.varint()));
                assert!(!target.exists());assert_eq!(std::fs::read_dir(&s.data).unwrap().count(),1);
                client.close().await;
                let replacement=RunningServer::start(&["--listen","127.0.0.1:0","--config",&s.config]);
                let old=std::mem::replace(&mut s.server,replacement);assert_eq!(old.stop(),Some(0));
                s.dest=format!("{}@127.0.0.1:{}",s.dest.split('@').next().unwrap(),s.server.port);
                let client=Raw::login(&s).await;let q=request(2,&target,Value::Array(vec![Value::Uint(1),token]),Some(6),1);
                let(_,_,a)=client.open(&q).await;assert_eq!(p::status(&a).unwrap(),p::Status::ResumeUnavailable);
                assert_eq!(std::fs::read_dir(&s.data).unwrap().count(),0);assert!(!target.exists());client.close().await;
            }).await.unwrap();
        });
    }
    #[test]
    fn root_server_hides_upload_token_from_another_authenticated_account() {
        if !nix::unistd::geteuid().is_root() {
            return;
        }
        super::quic::runtime().unwrap().block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut s = Setup::new("resume-foreign-account", None, "");
                let keys = Path::new(&s.config)
                    .with_file_name("authorized_keys")
                    .join("nobody");
                std::fs::write(&keys, format!("{TEST_USER_KEY_LINE}\n")).unwrap();
                std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o644)).unwrap();
                let owner = Raw::login(&s).await;
                let path = s.data.join("target");
                let q = request(2, &path, Value::Array(vec![Value::Uint(0)]), Some(6), 1);
                let (mut send, mut recv, a) = owner.open(&q).await;
                let token = a.field(3).unwrap().as_array().unwrap()[0].clone();
                let q = request(
                    2,
                    &path,
                    Value::Array(vec![Value::Uint(1), token]),
                    Some(6),
                    1,
                );
                let (_, _, a) = owner.open(&q).await;
                assert_eq!(p::status(&a).unwrap(), p::Status::ResumeBusy);
                s.dest = format!("nobody@127.0.0.1:{}", s.server.port);
                let foreign = Raw::login(&s).await;
                let (_, _, a) = foreign.open(&q).await;
                assert_eq!(p::status(&a).unwrap(), p::Status::ResumeUnavailable);
                assert!(a.field(2).is_none());
                send.reset(wire::Code::NoError.varint()).unwrap();
                recv.stop(wire::Code::NoError.varint()).unwrap();
                owner.close().await;
                foreign.close().await;
            })
            .await
            .unwrap();
        });
    }
}
