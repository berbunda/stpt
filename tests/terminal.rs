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
            Self::for_user(name, &account())
        }
        fn for_user(name: &str, user: &str) -> Self {
            let config = server_config(name, "");
            let fingerprint = stdout(&stpt_in(
                &dir(&format!("{name}-fp")),
                &["server", "--fingerprint", "--config", &config],
            ));
            let file = Path::new(&config)
                .with_file_name("authorized_keys")
                .join(user);
            std::fs::write(&file, format!("{TEST_USER_KEY_LINE}\n")).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
            let server = RunningServer::start(&["--listen", "127.0.0.1:0", "--config", &config]);
            let home = dir(&format!("{name}-home"));
            user_key(&home);
            Self {
                dest: format!("{user}@127.0.0.1:{}", server.port),
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

    #[cfg(target_os = "linux")]
    #[test]
    fn reverse_file_requests_use_selected_client_and_local_consent() {
        let s = Setup::new("linux-reverse-files");
        super::common::reverse::scenario(&s.home, &s.dest, &s.fingerprint);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn consent_in_a_second_terminal_requires_the_displayed_answer() {
        let s = Setup::new("linux-consent-terminal");
        let exe = env!("CARGO_BIN_EXE_stpt");
        let source = s.home.join("selected.txt");
        std::fs::write(&source, b"local contents").unwrap();
        let mut broker = Interactive::start(&s, &["consent"]);
        broker.wait_for("consent-", 10);
        let pairing = broker
            .output
            .lock()
            .unwrap()
            .lines()
            .find(|line| line.starts_with('/') && line.contains("/consent-"))
            .unwrap()
            .trim()
            .to_owned();
        let run = || {
            Command::new(exe)
                .args(s.args("exec", &["--no-shell", exe, "session", "read"]))
                .env("HOME", &s.home)
                .env("XDG_CONFIG_HOME", &s.home)
                .env("STPT_CONSENT_FILE", &pairing)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        };
        let client = run();
        broker.wait_for("press Enter to refuse", 10);
        broker.type_text(&format!("{}\n", source.display()));
        broker.wait_for("to approve:", 10);
        let challenge = broker
            .output
            .lock()
            .unwrap()
            .rsplit_once("Type ")
            .unwrap()
            .1
            .split(" to approve")
            .next()
            .unwrap()
            .to_owned();
        assert!(challenge.starts_with("yes "));
        broker.type_text(&format!("{challenge}\n"));
        let result = client.wait_with_output().unwrap();
        assert!(result.status.success(), "{}", stderr(&result));
        assert_eq!(result.stdout, b"local contents");

        broker.output.lock().unwrap().clear();
        let denied = run();
        broker.wait_for("press Enter to refuse", 10);
        broker.type_text(&format!("{}\n", source.display()));
        broker.wait_for("to approve:", 10);
        broker.type_text(&format!("{challenge}\n"));
        let result = denied.wait_with_output().unwrap();
        assert!(!result.status.success());
        assert!(stderr(&result).contains("denied"));
        assert!(result.stdout.is_empty());
        broker.type_text("\x03");
        let status = broker.child.wait().unwrap();
        // script(1) can propagate the foreground shell's SIGINT status.
        assert!(status.success() || status.code() == Some(130), "{status}");
        assert!(!Path::new(&pairing).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires /dev/fuse and private mount namespaces"]
    fn fuse_mount_revokes_an_open_descriptor_and_preserves_session_isolation() {
        for end in [
            "account",
            "denied",
            "abandoned",
            "local",
            "detach",
            "takeover",
            "session",
            "connection",
            "helper",
            "server",
        ] {
            if end != "account" || std::env::var_os("STPT_FUSE_TEST_ACCOUNT").is_some() {
                fuse_lifetime(end);
            }
        }
    }

    // The native mount test runs this probe as an ordinary process inside the Session.
    #[cfg(target_os = "linux")]
    #[test]
    fn fuse_mapping_probe() {
        use nix::libc;
        use std::os::fd::AsRawFd;
        let Some(path) = std::env::var_os("STPT_TEST_MAPPED_FILE") else {
            return;
        };
        let f = std::fs::File::open(path).unwrap();
        for mode in [libc::MAP_PRIVATE, libc::MAP_SHARED] {
            // Only a failed map or a failed population is acceptable. No signal handler needed.
            unsafe {
                let addr = libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ,
                    mode,
                    f.as_raw_fd(),
                    0,
                );
                if addr != libc::MAP_FAILED {
                    assert_eq!(
                        libc::madvise(addr, 4096, libc::MADV_POPULATE_READ),
                        -1,
                        "FUSE supplied mapped pages"
                    );
                    assert_eq!(libc::munmap(addr, 4096), 0);
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    fn fuse_lifetime(end: &str) {
        let mut s = if end == "account" {
            Setup::for_user(
                "linux-fuse-account",
                &std::env::var("STPT_FUSE_TEST_ACCOUNT").unwrap(),
            )
        } else {
            Setup::new(&format!("linux-fuse-{end}"))
        };
        let ipc = dir(&format!("linux-fuse-ipc-{end}"));
        if end == "account" {
            nix::unistd::chown(
                &ipc,
                Some(
                    nix::unistd::User::from_name(&std::env::var("STPT_FUSE_TEST_ACCOUNT").unwrap())
                        .unwrap()
                        .unwrap()
                        .uid,
                ),
                None,
            )
            .unwrap();
        }
        let exe = env!("CARGO_BIN_EXE_stpt");
        let source = s.home.join("tree");
        std::fs::create_dir(&source).unwrap();
        std::fs::write(source.join("sample"), b"abcdef").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", source.join("link")).unwrap();
        let mut broker = Interactive::start(&s, &["consent"]);
        broker.wait_for("consent-", 10);
        let pairing = broker
            .output
            .lock()
            .unwrap()
            .lines()
            .find(|line| line.starts_with('/') && line.contains("/consent-"))
            .unwrap()
            .trim()
            .to_owned();
        let marker = ipc.join("mounted");
        let resume = ipc.join("continue");
        let done = ipc.join("verified");
        let line = format!(
            r#"set -e
printf '%s' "$STPT_SESSION" > '{sid_file}'
p=$({exe} session mount)
cat "$p/sample"
STPT_TEST_MAPPED_FILE="$p/sample" '{test_bin}' --exact server::fuse_mapping_probe
ls -a "$p"
if cat "$p/link"; then exit 6; fi
if touch "$p/new"; then exit 7; fi
exec 3<"$p/sample"
dd bs=1 count=1 <&3 2>/dev/null
cd "$p"
printf '%s %s %s' "$$" "$STPT_SESSION" "$p" > '{}'
while ! test -e '{}'; do
  if test -e '{route}' && ! test -e '{routed}'; then
    if {exe} session read 2>'{error}'; then exit 10; fi
    grep -q 'several live Attachments' '{error}'
    if {exe} session read --attachment 2 2>'{error}'; then exit 11; fi
    grep -q 'Attachment 2: client file access was not negotiated' '{error}'
    if {exe} session read --attachment 1 2>'{error}'; then exit 12; fi
    grep -q 'Channel limit exceeded' '{error}'
    touch '{routed}'
  fi
  if test -e '{pending}' && ! test -e '{failed}'; then
    if dd bs=1 count=1 <&3 2>/dev/null; then exit 13; fi
    touch '{failed}'
  fi
  if test -e '{check}' && ! test -e '{checked}'; then cat sample >/dev/null && touch '{checked}'; fi
  sleep .05
done
if dd bs=1 count=1 <&3 2>/dev/null; then exit 8; fi
if cat sample; then exit 9; fi
touch '{}'
"#,
            marker.display(),
            resume.display(),
            done.display(),
            sid_file = ipc.join("session-id").display(),
            test_bin = std::env::current_exe().unwrap().display(),
            route = ipc.join("route").display(),
            routed = ipc.join("routed").display(),
            error = ipc.join("route-error").display(),
            pending = ipc.join("pending").display(),
            failed = ipc.join("read-failed").display(),
            check = ipc.join("check").display(),
            checked = ipc.join("checked").display()
        );
        let mut child = Command::new(exe)
            .args(s.args("exec", &["--no-shell", "/bin/sh", "-c", &line]))
            .env("HOME", &s.home)
            .env("XDG_CONFIG_HOME", &s.home)
            .env("STPT_CONSENT_FILE", pairing)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let start = Instant::now();
        while !broker
            .output
            .lock()
            .unwrap()
            .contains("press Enter to refuse")
        {
            if child.try_wait().unwrap().is_some() {
                let output = child.wait_with_output().unwrap();
                panic!(
                    "request stopped before consent ({end}): {} / {}",
                    stdout(&output),
                    stderr(&output)
                )
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "mount prompt timed out ({end})"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            broker
                .output
                .lock()
                .unwrap()
                .contains("Server root can read and retain copies")
        );
        if end == "denied" || end == "abandoned" {
            if end == "denied" {
                broker.type_text("\n");
            } else {
                let id = std::fs::read_to_string(ipc.join("session-id")).unwrap();
                let out = stpt_in(&s.home, &s.args("detach", &[&id, "--id", "1"]));
                assert!(out.status.success(), "{}", stderr(&out));
            }
            broker.wait_for("Request closed.", 8);
            let r = child.wait_with_output().unwrap();
            if end == "denied" {
                assert!(!r.status.success());
                assert!(stderr(&r).contains("denied"));
            }
            assert!(!marker.exists());
            broker.type_text("\x03");
            broker.child.wait().unwrap();
            return;
        }
        broker.type_text(&format!("{}\n", source.display()));
        broker.wait_for("to approve:", 10);
        let answer = broker
            .output
            .lock()
            .unwrap()
            .rsplit_once("Type ")
            .unwrap()
            .1
            .split(" to approve")
            .next()
            .unwrap()
            .to_owned();
        broker.type_text(&format!("{answer}\n"));
        let start = Instant::now();
        while !marker.exists() {
            if child.try_wait().unwrap().is_some() {
                let r = child.wait_with_output().unwrap();
                panic!("mount setup failed: {} / {}", stdout(&r), stderr(&r))
            }
            assert!(
                start.elapsed() < Duration::from_secs(8),
                "mount setup timed out"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
        let location = std::fs::read_to_string(&marker).unwrap();
        let mut parts = location.split_whitespace();
        let pid = parts.next().unwrap();
        let sid = parts.next().unwrap();
        let path = parts.next().unwrap();
        assert!(std::fs::read(Path::new(path).join("sample")).is_err());
        let foreign = format!("/proc/{pid}/root{path}/sample");
        assert!(std::fs::read(foreign).is_err());
        if end == "local" {
            let args = s.args("connect", &["--attach", sid, "--read-only"]);
            let mut other = Interactive::start(&s, &args);
            other.wait_for("abcdef", 8);
            std::fs::write(ipc.join("route"), b"").unwrap();
            let start = Instant::now();
            while !ipc.join("routed").exists() {
                assert!(
                    start.elapsed() < Duration::from_secs(8),
                    "routing while mounted: {:?}",
                    std::fs::read_to_string(ipc.join("route-error"))
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            let detached = stpt_in(&s.home, &s.args("detach", &[sid, "--id", "2"]));
            assert!(detached.status.success(), "{}", stderr(&detached));
            other.child.wait().unwrap();
            std::fs::write(ipc.join("check"), b"").unwrap();
            let start = Instant::now();
            while !ipc.join("checked").exists() {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "unrelated detach revoked mount"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        let mut takeover = None;
        match end {
            "takeover" => {
                let args = s.args("connect", &["--attach", sid, "--takeover", "--read-only"]);
                let other = Interactive::start(&s, &args);
                other.wait_for("abcdef", 8);
                takeover = Some(other);
            }
            "detach" => {
                let out = stpt_in(&s.home, &s.args("detach", &[sid, "--id", "1"]));
                assert!(out.status.success(), "{}", stderr(&out));
            }
            "session" => {
                let out = stpt_in(&s.home, &s.args("terminate", &[sid, "--force"]));
                assert!(out.status.success(), "{}", stderr(&out));
            }
            "connection" => child.kill().unwrap(),
            "server" => s.server.kill_test_server(),
            "helper" => {
                // Hold the Client's already-open file read in flight. Wait for the
                // CALL to reach its worker pipe without consuming it.
                use std::os::fd::AsRawFd;
                let client_pid = child.id();
                let tree = std::fs::read_dir("/proc")
                    .unwrap()
                    .flatten()
                    .find(|entry| {
                        std::fs::read(entry.path().join("cmdline")).is_ok_and(|cmd| {
                            cmd.split(|b| *b == 0).nth(1) == Some(b"__stpt-mount-tree")
                        }) && std::fs::read_to_string(entry.path().join("status")).is_ok_and(|s| {
                            s.lines().any(|line| {
                                line.strip_prefix("PPid:")
                                    .is_some_and(|id| id.trim().parse() == Ok(client_pid))
                            })
                        })
                    })
                    .unwrap();
                let tree_pid =
                    nix::unistd::Pid::from_raw(tree.file_name().to_str().unwrap().parse().unwrap());
                nix::sys::signal::kill(tree_pid, nix::sys::signal::Signal::SIGSTOP).unwrap();
                let pipe = std::fs::File::open(tree.path().join("fd/0")).unwrap();
                std::fs::write(ipc.join("pending"), b"").unwrap();
                let start = Instant::now();
                loop {
                    let mut waiting: i32 = 0;
                    assert_eq!(
                        unsafe {
                            nix::libc::ioctl(pipe.as_raw_fd(), nix::libc::FIONREAD, &mut waiting)
                        },
                        0
                    );
                    if waiting > 0 {
                        break;
                    }
                    assert!(
                        start.elapsed() < Duration::from_secs(5),
                        "read did not reach the Client worker"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                let helper = std::fs::read_dir("/proc")
                    .unwrap()
                    .flatten()
                    .find_map(|entry| {
                        let id = entry.file_name().to_str()?.parse::<i32>().ok()?;
                        let cmd = std::fs::read(entry.path().join("cmdline")).ok()?;
                        let mut args = cmd.split(|b| *b == 0);
                        args.next();
                        (args.next() == Some(b"__stpt-fuse")
                            && args.next() == Some(path.as_bytes()))
                        .then_some(id)
                    })
                    .unwrap();
                nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(helper),
                    nix::sys::signal::Signal::SIGKILL,
                )
                .unwrap();
            }
            _ => broker.type_text("\n"),
        }
        broker.wait_for("Request closed.", if end == "server" { 85 } else { 10 });
        let mounts = format!("/proc/{pid}/mountinfo");
        let start = Instant::now();
        while std::fs::read_to_string(&mounts)
            .unwrap_or_default()
            .contains(path)
            || Path::new(path).exists()
        {
            assert!(
                start.elapsed() < Duration::from_secs(if end == "connection" { 85 } else { 8 }),
                "busy mount still attached ({end})"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        std::fs::write(resume, b"").unwrap();
        if end == "server" && child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
        }
        let result = child.wait_with_output().unwrap();
        if matches!(end, "local" | "helper" | "account") {
            assert!(result.status.success(), "{}", stderr(&result));
            assert!(stdout(&result).contains("abcdef"));
            assert!(stdout(&result).contains("sample"));
        }
        if end != "session" {
            let start = Instant::now();
            while !done.exists() {
                assert!(
                    start.elapsed() < Duration::from_secs(8),
                    "old descriptor returned data ({end})"
                );
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        assert!(!source.join("new").exists());
        if let Some(mut other) = takeover {
            assert!(other.child.wait().unwrap().success());
        }
        broker.type_text("\x03");
        broker.child.wait().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_local_requires_the_inherited_endpoint() {
        let s = Setup::new("terminal-rf002");
        let exe = env!("CARGO_BIN_EXE_stpt");
        let out = s.exec(&["--no-shell", exe, "session", "attachments"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "1");
        let out = s.exec(&[
            "--no-shell",
            exe,
            "session",
            "create",
            "123",
            "--attachment",
            "1",
        ]);
        assert!(!out.status.success());
        assert!(
            stderr(&out).contains("Attachment 1: client file access was not negotiated"),
            "{}",
            stderr(&out)
        );
        let out = s.exec(&[
            "--no-shell",
            "/usr/bin/env",
            "-u",
            "STPT_LOCAL_FD",
            exe,
            "session",
            "attachments",
        ]);
        assert!(!out.status.success());
        assert!(stderr(&out).contains("no inherited STPT Session endpoint"));
        let out = s.exec(&[
            "--no-shell",
            "setsid",
            "--wait",
            exe,
            "session",
            "attachments",
        ]);
        assert!(!out.status.success());
        assert!(
            stderr(&out).contains("caller does not belong to this Session"),
            "{}",
            stderr(&out)
        );
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
            // script(1) with a pipe as output gives its terminal no size.
            let line = format!(
                "stty rows 24 cols 80; {} {}",
                env!("CARGO_BIN_EXE_stpt"),
                args.join(" ")
            );
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

    /// A full-screen program: the messages do not scroll its screen, and it is made to
    /// repaint after the resume, which the Server does not do without lost output.
    #[test]
    #[ignore = "takes more than a minute"]
    fn reattach_leaves_a_full_screen_program_intact() {
        let s = Setup::new("terminal-reattach-screen");
        let relay = Relay::to(s.server.port);
        let dest = format!("{}@127.0.0.1:{}", account(), relay.port);
        let args = ["connect", &dest, "--fingerprint", &s.fingerprint];
        let mut client = Interactive::start(&s, &args);
        client.type_text(
            "sh -c 'printf \"\\033[?1049h\"; trap \"echo winch-$((1 + 1))\" WINCH; \
             echo ready-$((1 + 1)); while :; do sleep 0.2; done'\n",
        );
        client.wait_for("ready-2", 10);
        relay.set_cut(true);
        client.wait_for("connection lost", 80);
        relay.set_cut(false);
        client.wait_for("attached again", 40);
        client.wait_for("winch-2", 10);
        let text = client.output.lock().unwrap().clone();
        assert!(text.contains("\x1b7\x1b[24;1H"), "{text:?}");
        assert!(!text.contains("\r\nstpt: "), "scrolls: {text:?}");
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
