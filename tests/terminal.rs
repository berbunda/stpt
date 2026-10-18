//! Terminal Channels between the real Client and Server (PROTOCOL.md §14).

mod common;

#[cfg(unix)]
mod server {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};

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
        assert!(s.server.wait_for_log("Session ended") || s.server.wait_for_log("abandoned"));
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
