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
}
