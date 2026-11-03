//! Terminal Channels between the real Client and Server (PROTOCOL.md §14).

mod common;

#[cfg(unix)]
mod server {
    use std::collections::HashMap;
    use std::io::Write;
    use std::net::{SocketAddr, UdpSocket};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::common::{
        RunningServer, TEST_USER_KEY_LINE, dir, server_config, stderr, stdout, stpt_in, user_key,
    };

    /// The Account the tests run as; the Server, run by the same user, may start its
    /// processes.
    fn account() -> String {
        let out = Command::new("id").arg("-un").output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// A running Server that authorizes the test key for the Account of the test,
    /// and a Client home with that key.
    struct Setup {
        server: RunningServer,
        home: PathBuf,
        dest: String,
        fingerprint: String,
    }

    impl Setup {
        fn new(name: &str) -> Self {
            let config = server_config(name, "");
            let fingerprint = stdout(&stpt_in(
                &dir(&format!("{name}-fp")),
                &["server", "--fingerprint", "--config", &config],
            ));
            let file = Path::new(&config)
                .with_file_name("authorized_keys")
                .join(account());
            std::fs::write(&file, format!("{TEST_USER_KEY_LINE}\n")).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
            let server = RunningServer::start(&["--listen", "127.0.0.1:0", "--config", &config]);
            let home = dir(&format!("{name}-home"));
            user_key(&home);
            Self {
                dest: format!("{}@127.0.0.1:{}", account(), server.port),
                server,
                home,
                fingerprint,
            }
        }

        fn args<'a>(&'a self, command: &'a str, rest: &[&'a str]) -> Vec<&'a str> {
            let mut args = vec![command, &self.dest, "--fingerprint", &self.fingerprint];
            args.extend(rest);
            args
        }

        fn exec(&self, rest: &[&str]) -> Output {
            stpt_in(&self.home, &self.args("exec", rest))
        }

        /// `stpt` with `input` on standard input.
        fn with_input(&self, args: &[&str], input: &[u8]) -> Output {
            let mut child = Command::new(env!("CARGO_BIN_EXE_stpt"))
                .args(args)
                .env("HOME", &self.home)
                .env("XDG_CONFIG_HOME", &self.home)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            child.wait_with_output().unwrap()
        }
    }

    #[test]
    fn exec_runs_a_command() {
        let s = Setup::new("terminal-exec");

        let out = s.exec(&["echo", "hello", "world"]);
        assert_eq!(stdout(&out), "hello world", "{}", stderr(&out));
        assert_eq!(out.status.code(), Some(0));

        let out = s.exec(&["echo out; echo err >&2; exit 3"]);
        assert_eq!(stdout(&out), "out");
        assert_eq!(stderr(&out), "err");
        assert_eq!(out.status.code(), Some(3));

        let out = s.exec(&["--no-shell", "printf", "%s|", "a b", "$HOME"]);
        assert_eq!(stdout(&out), "a b|$HOME|");

        let out = s.with_input(&s.args("exec", &["tr", "a-z", "A-Z"]), b"abc\n");
        assert_eq!(stdout(&out), "ABC");
        assert_eq!(out.status.code(), Some(0));

        let out = s.exec(&["kill -TERM $$"]);
        assert_eq!(
            stderr(&out),
            "stpt: the remote program was killed by signal TERM"
        );
        assert_eq!(out.status.code(), Some(255));
    }

    /// Starts `exec` of `line` with output piped and waits for the line `ready`.
    fn exec_until_ready(
        s: &Setup,
        line: &str,
    ) -> (
        std::process::Child,
        impl Iterator<Item = std::io::Result<String>> + use<>,
    ) {
        use std::io::{BufRead, BufReader};
        let line = format!("{line}; echo ready; while :; do sleep 0.1; done");
        let mut child = Command::new(env!("CARGO_BIN_EXE_stpt"))
            .args(s.args("exec", &[&line]))
            .env("HOME", &s.home)
            .env("XDG_CONFIG_HOME", &s.home)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        assert_eq!(lines.next().unwrap().unwrap(), "ready");
        (child, lines)
    }

    fn interrupt(child: &std::process::Child) {
        let pid = child.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-INT", &pid])
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn hangup_detaches_and_closes_at_once() {
        let s = Setup::new("terminal-hangup");
        let (child, _lines) = exec_until_ready(&s, "true");
        let pid = child.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-HUP", &pid])
                .status()
                .unwrap()
                .success()
        );
        let out = child.wait_with_output().unwrap();
        assert_eq!(stderr(&out), "stpt: terminated by HUP");
        assert_eq!(out.status.code(), Some(255));
        // The Server knows at once, not after the idle timeout of 60 s.
        assert!(s.server.wait_for_log("detached by the Client"));
    }

    #[test]
    fn server_shutdown_closes_connections() {
        let s = Setup::new("terminal-shutdown");
        let (child, _lines) = exec_until_ready(&s, "true");
        assert!(s.server.wait_for_log("Session created"));
        assert_eq!(s.server.stop(), Some(0));
        let out = child.wait_with_output().unwrap();
        assert_eq!(
            stderr(&out),
            "stpt: transport: closed by the peer: SERVER_SHUTDOWN"
        );
        assert_eq!(out.status.code(), Some(255));
    }

    #[test]
    fn ctrl_c_interrupts_the_remote_command() {
        let s = Setup::new("terminal-interrupt");
        let (mut child, lines) = exec_until_ready(&s, "trap 'echo got INT; exit 9' INT");
        interrupt(&child);
        assert_eq!(child.wait().unwrap().code(), Some(9));
        let rest: Vec<String> = lines.map(Result::unwrap).collect();
        assert_eq!(rest, ["got INT"]);

        // A command that ignores INT: the third Ctrl+C ends the Client.
        let (child, _lines) = exec_until_ready(&s, "trap '' INT");
        for _ in 0..3 {
            std::thread::sleep(std::time::Duration::from_millis(300));
            interrupt(&child);
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(stderr(&out), "stpt: interrupted");
        assert_eq!(out.status.code(), Some(255));
    }

    /// Runs `stpt ARGS` in script(1), so it has a terminal, typing `input`.
    fn in_terminal(s: &Setup, args: &[&str], input: &[u8]) -> (String, Option<i32>) {
        let line = format!("{} {}", env!("CARGO_BIN_EXE_stpt"), args.join(" "));
        let mut child = Command::new("script")
            .args(["-qec", &line, "/dev/null"])
            .env("HOME", &s.home)
            .env("XDG_CONFIG_HOME", &s.home)
            .env("TERM", "xterm")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input).unwrap();
        let out = child.wait_with_output().unwrap();
        drop(stdin);
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.code(),
        )
    }

    /// A UDP relay between Clients and a Server, with a switch that cuts the path.
    struct Relay {
        port: u16,
        cut: Arc<AtomicBool>,
    }

    impl Relay {
        fn to(server: u16) -> Self {
            let front = UdpSocket::bind("127.0.0.1:0").unwrap();
            let port = front.local_addr().unwrap().port();
            let cut = Arc::new(AtomicBool::new(false));
            let is_cut = cut.clone();
            std::thread::spawn(move || {
                let mut backs: HashMap<SocketAddr, UdpSocket> = HashMap::new();
                let mut buf = [0; 65536];
                while let Ok((n, client)) = front.recv_from(&mut buf) {
                    if is_cut.load(Ordering::Relaxed) {
                        continue;
                    }
                    let back = backs.entry(client).or_insert_with(|| {
                        let back = UdpSocket::bind("127.0.0.1:0").unwrap();
                        back.connect(("127.0.0.1", server)).unwrap();
                        let (reply, front, is_cut) = (
                            back.try_clone().unwrap(),
                            front.try_clone().unwrap(),
                            is_cut.clone(),
                        );
                        std::thread::spawn(move || {
                            let mut buf = [0; 65536];
                            while let Ok(n) = reply.recv(&mut buf) {
                                if !is_cut.load(Ordering::Relaxed) {
                                    let _ = front.send_to(&buf[..n], client);
                                }
                            }
                        });
                        back
                    });
                    let _ = back.send(&buf[..n]);
                }
            });
            Self { port, cut }
        }

        fn set_cut(&self, cut: bool) {
            self.cut.store(cut, Ordering::Relaxed);
        }
    }

    /// `stpt ARGS` in script(1), with its output collected while it runs.
    struct Interactive {
        child: std::process::Child,
        stdin: std::process::ChildStdin,
        output: Arc<Mutex<String>>,
    }

    impl Interactive {
        fn start(s: &Setup, args: &[&str]) -> Self {
            use std::io::Read;
            let line = format!("{} {}", env!("CARGO_BIN_EXE_stpt"), args.join(" "));
            let mut child = Command::new("script")
                .args(["-qec", &line, "/dev/null"])
                .env("HOME", &s.home)
                .env("XDG_CONFIG_HOME", &s.home)
                .env("TERM", "xterm")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdin = child.stdin.take().unwrap();
            let mut stdout = child.stdout.take().unwrap();
            let output = Arc::new(Mutex::new(String::new()));
            let collected = output.clone();
            std::thread::spawn(move || {
                let mut buf = [0; 4096];
                while let Ok(n) = stdout.read(&mut buf) {
                    if n == 0 {
                        return;
                    }
                    let text = String::from_utf8_lossy(&buf[..n]);
                    collected.lock().unwrap().push_str(&text);
                }
            });
            Self {
                child,
                stdin,
                output,
            }
        }

        fn wait_for(&self, text: &str, seconds: u64) {
            let start = Instant::now();
            while !self.output.lock().unwrap().contains(text) {
                assert!(
                    start.elapsed() < Duration::from_secs(seconds),
                    "no {text:?} in {:?}",
                    self.output.lock().unwrap()
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        fn type_text(&mut self, text: &str) {
            self.stdin.write_all(text.as_bytes()).unwrap();
            self.stdin.flush().unwrap();
        }
    }

    /// Waits for the QUIC idle timeout of 60 s, as a real outage does.
    #[test]
    #[ignore = "takes more than a minute"]
    fn connect_attaches_again_after_a_lost_connection() {
        let s = Setup::new("terminal-reattach");
        let relay = Relay::to(s.server.port);
        let dest = format!("{}@127.0.0.1:{}", account(), relay.port);
        let args = ["connect", &dest, "--fingerprint", &s.fingerprint];
        let mut client = Interactive::start(&s, &args);
        client.type_text("echo one-$((1 + 1))\n");
        client.wait_for("one-2", 10);

        // Output produced during the outage waits in the buffer of the Server.
        client.type_text("(sleep 2; echo two-$((1 + 1))) &\n");
        std::thread::sleep(Duration::from_millis(500));
        relay.set_cut(true);
        client.wait_for("connection lost", 80);
        // Typed during the outage: dropped, not run later.
        client.type_text("echo dropped-$((1 + 1))\n");
        relay.set_cut(false);

        client.wait_for("attached again", 40);
        client.wait_for("two-2", 10);
        let text = client.output.lock().unwrap().clone();
        assert_eq!(text.matches("one-2").count(), 1, "replayed twice: {text}");
        assert!(!text.contains("bytes of output were lost"), "{text}");

        // Only the new Attachment is left: the old one was ended at once.
        let table = stdout(&stpt_in(&s.home, &s.args("sessions", &[])));
        let row = table.lines().nth(1).unwrap();
        let attachments: Vec<&str> = row.split_whitespace().collect();
        assert!(attachments.contains(&"1"), "{table}");

        client.type_text("echo three-$((1 + 2))\n");
        client.wait_for("three-3", 10);
        assert!(!client.output.lock().unwrap().contains("dropped-2"));
        client.type_text("exit 5\n");
        assert_eq!(client.child.wait().unwrap().code(), Some(5));
    }

    /// More output during the outage than the buffer of the Server holds (256 KiB).
    #[test]
    #[ignore = "takes more than a minute"]
    fn reattach_tells_about_lost_output() {
        let s = Setup::new("terminal-reattach-lost");
        let relay = Relay::to(s.server.port);
        let dest = format!("{}@127.0.0.1:{}", account(), relay.port);
        let args = ["connect", &dest, "--fingerprint", &s.fingerprint];
        let mut client = Interactive::start(&s, &args);
        client.type_text(
            "(sleep 2; head -c 400000 /dev/zero | tr '\\0' x; echo; echo end-$((1 + 1))) &\n",
        );
        std::thread::sleep(Duration::from_millis(500));
        relay.set_cut(true);
        client.wait_for("connection lost", 80);
        relay.set_cut(false);
        client.wait_for("bytes of output were lost", 40);
        client.wait_for("end-2", 10);
        client.type_text("exit 6\n");
        assert_eq!(client.child.wait().unwrap().code(), Some(6));
    }

    /// `Enter ~ .` gives up while the Client is trying to reattach.
    #[test]
    #[ignore = "takes more than a minute"]
    fn the_escape_gives_up_reattaching() {
        let s = Setup::new("terminal-reattach-escape");
        let relay = Relay::to(s.server.port);
        let dest = format!("{}@127.0.0.1:{}", account(), relay.port);
        let args = ["connect", &dest, "--fingerprint", &s.fingerprint];
        let mut client = Interactive::start(&s, &args);
        client.type_text("echo ready-$((1 + 1))\n");
        client.wait_for("ready-2", 10);
        relay.set_cut(true);
        client.wait_for("connection lost", 80);
        client.type_text("\r~.");
        client.wait_for("attach again with: stpt connect --attach", 5);
        assert_eq!(client.child.wait().unwrap().code(), Some(255));
    }

    #[test]
    fn client_configuration_sets_the_detach_timeout() {
        let s = Setup::new("terminal-detach-timeout");
        let config = s.home.join("stpt").join("config.toml");

        // It applies to new Sessions only: an attach must not send it (§14.6).
        std::fs::write(&config, "detach_timeout = 3600\n").unwrap();
        let args = s.args("connect", &["--name", "work"]);
        let (text, code) = in_terminal(&s, &args, b"~.");
        assert_eq!(code, Some(0), "{text}");
        let args = s.args("connect", &["--attach", "work"]);
        let (text, code) = in_terminal(&s, &args, b"exit 3\n");
        assert_eq!(code, Some(3), "{text}");

        // 0: the Session ends as soon as it has no Attachment.
        std::fs::write(&config, "detach_timeout = 0\n").unwrap();
        let (child, _lines) = exec_until_ready(&s, "true");
        let pid = child.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-HUP", &pid])
                .status()
                .unwrap()
                .success()
        );
        let _ = child.wait_with_output();
        let start = std::time::Instant::now();
        loop {
            let table = stdout(&stpt_in(&s.home, &s.args("sessions", &[])));
            if table.lines().count() == 1 {
                break;
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(5),
                "Session stays: {table}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[test]
    fn sessions_outlive_the_client() {
        let s = Setup::new("terminal-sessions");

        // Enter ~ . detaches; the Session keeps running.
        let args = s.args("connect", &["--name", "work"]);
        let (text, code) = in_terminal(&s, &args, b"echo $((6 * 7))\n~.");
        assert_eq!(code, Some(0), "{text}");
        assert!(text.contains("stpt: detached; Session "), "{text}");
        let id = text
            .split("Session ")
            .nth(1)
            .and_then(|rest| rest.get(..32))
            .unwrap()
            .to_owned();

        let out = stpt_in(&s.home, &s.args("sessions", &[]));
        let table = stdout(&out);
        assert!(table.contains(&id[..12]), "{table}");
        assert!(table.contains("work"), "{table}");
        assert!(table.contains("running"), "{table}");

        // A read-only Attachment sends nothing of what is typed; `~.` still detaches.
        let args = s.args("connect", &["--attach", "work", "--read-only"]);
        let (text, code) = in_terminal(&s, &args, b"ls\r~.");
        assert_eq!(code, Some(0), "{text}");
        assert!(text.contains("stpt: detached; Session "), "{text}");

        // Attach by name: the earlier output is replayed.
        let args = s.args("connect", &["--attach", "work"]);
        let (text, code) = in_terminal(&s, &args, b"exit 3\n");
        assert!(text.contains("42\r\n"), "{text}");
        assert_eq!(code, Some(3), "{text}");

        // A Session without a PTY whose Client is gone; terminate it by ID prefix.
        let (child, _lines) = exec_until_ready(&s, "true");
        let pid = child.id().to_string();
        assert!(
            Command::new("kill")
                .args(["-HUP", &pid])
                .status()
                .unwrap()
                .success()
        );
        let _ = child.wait_with_output();
        let table = stdout(&stpt_in(&s.home, &s.args("sessions", &[])));
        let line = table.lines().nth(1).unwrap_or_default();
        let prefix = line.split_whitespace().next().unwrap().to_owned();
        let out = stpt_in(&s.home, &s.args("terminate", &[&prefix]));
        assert!(out.status.success(), "{}", stderr(&out));
        let table = stdout(&stpt_in(&s.home, &s.args("sessions", &[])));
        assert_eq!(table.lines().count(), 1, "{table}");
        let out = stpt_in(&s.home, &s.args("terminate", &[&prefix]));
        assert_eq!(stderr(&out), format!("stpt: no Session {prefix}"));
    }

    #[test]
    fn connect_runs_the_login_shell_on_a_pty() {
        let s = Setup::new("terminal-connect");
        // script(1) gives the Client a terminal; the input is typed into it.
        let line = format!(
            "{} {}",
            env!("CARGO_BIN_EXE_stpt"),
            s.args("connect", &[]).join(" ")
        );
        let mut child = Command::new("script")
            .args(["-qec", &line, "/dev/null"])
            .env("HOME", &s.home)
            .env("XDG_CONFIG_HOME", &s.home)
            .env("TERM", "xterm")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input
            .write_all(b"tty; echo $TERM; echo $((6 * 7)); exit 4\n")
            .unwrap();
        let out = child.wait_with_output().unwrap();
        drop(input);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("/dev/pts/"), "{text}");
        assert!(text.contains("xterm\r\n"), "{text}");
        assert!(text.contains("42\r\n"), "{text}");
        assert_eq!(out.status.code(), Some(4), "{text}");
    }
}
