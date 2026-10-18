#![allow(dead_code, reason = "every test crate uses a part of the helpers")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Runs `stpt` with a new empty user directory, so the user's own Client
/// configuration and trust store are never read.
pub fn stpt(args: &[&str]) -> Output {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let n = CALLS.fetch_add(1, Ordering::Relaxed);
    stpt_in(&dir(&format!("home-{}-{n}", std::process::id())), args)
}

/// Runs `stpt` with `home` as the user directory: the Client configuration and
/// trust store are in `home/stpt` on every platform.
pub fn stpt_in(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stpt"))
        .args(args)
        .env("APPDATA", home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .output()
        .expect("run stpt")
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).trim_end().to_owned()
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).trim_end().to_owned()
}

/// Ed25519 user key for tests only, written by `openssl genpkey -algorithm ed25519`.
pub const TEST_USER_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
    MC4CAQAwBQYDK2VwBCIEIPSgAC0ev0Odcs+ZVkJmGoVuFuG4QdHWbwBYaB3GW1Qp\n\
    -----END PRIVATE KEY-----\n";

/// Its authorized keys line: second line of `openssl pkey -pubout`.
pub const TEST_USER_KEY_LINE: &str = "MCowBQYDK2VwAyEAk9YxouLpNL+A/ZjwtDwMeKhGGVbPOnq2vhNQXSwd7Q4=";

/// Writes the test user key as the default user key of `home`, owner only.
pub fn user_key(home: &Path) -> PathBuf {
    let path = home.join("stpt").join("id_ed25519");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, TEST_USER_KEY).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// Directory for files of one test, created empty.
pub fn dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes a configuration file and returns its path as text.
pub fn config_file(name: &str, text: &str) -> String {
    let path = dir(name).join("config.toml");
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_owned()
}

/// Writes a Server configuration whose key file and authorized keys directory
/// (`authorized_keys`, empty) are in the test directory.
pub fn server_config(name: &str, text: &str) -> String {
    let dir = dir(name);
    let key = dir.join("server_key");
    let keys = dir.join("authorized_keys");
    std::fs::create_dir_all(&keys).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = dir.join("server.toml");
    let text = format!(
        "identity_key = {:?}\nauthorized_keys = {:?}\n{text}",
        key.to_str().unwrap(),
        keys.to_str().unwrap()
    );
    std::fs::write(&path, text).unwrap();
    path.to_str().unwrap().to_owned()
}

/// Runs `stpt server` until it logs `listening`, then kills it; returns the log lines
/// up to that one. If the Server exits before, all its lines.
#[cfg(unix)]
pub fn server_until_listening(args: &[&str]) -> Vec<String> {
    use std::io::{BufRead, BufReader};
    use std::process::Stdio;

    let mut server = Command::new(env!("CARGO_BIN_EXE_stpt"))
        .arg("server")
        .args(args)
        .stderr(Stdio::piped())
        .spawn()
        .expect("run stpt");
    let mut lines = Vec::new();
    for line in BufReader::new(server.stderr.take().unwrap()).lines() {
        let line = line.unwrap();
        let done = line.contains("listening");
        lines.push(line);
        if done {
            break;
        }
    }
    let _ = server.kill();
    server.wait().unwrap();
    lines
}

/// `stpt server` running until dropped.
#[cfg(unix)]
pub struct RunningServer {
    child: std::process::Child,
    pub port: u16,
    /// Log lines after `listening`, collected while it runs.
    log: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
}

#[cfg(unix)]
impl RunningServer {
    /// Starts `stpt server` with `args` and waits until it listens.
    pub fn start(args: &[&str]) -> Self {
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;

        let mut child = Command::new(env!("CARGO_BIN_EXE_stpt"))
            .arg("server")
            .args(args)
            .stderr(Stdio::piped())
            .spawn()
            .expect("run stpt");
        let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
        let mut log = Vec::new();
        let port = loop {
            let Some(line) = lines.next() else {
                let _ = child.kill();
                panic!("Server exited before listening: {log:?}");
            };
            let line = line.unwrap();
            if line.contains("listening") {
                break line.rsplit(':').next().unwrap().parse().unwrap();
            }
            log.push(line);
        };
        // Keep reading, so the Server never blocks on a full pipe.
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let collected = log.clone();
        std::thread::spawn(move || {
            for line in lines.map_while(Result::ok) {
                collected.lock().unwrap().push(line);
            }
        });
        Self { child, port, log }
    }

    /// Waits up to 5 s for a log line containing `text`.
    pub fn wait_for_log(&self, text: &str) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(5) {
            if self.log.lock().unwrap().iter().any(|l| l.contains(text)) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        false
    }

    /// Stops the Server with TERM, as systemd does; returns its exit code.
    pub fn stop(mut self) -> Option<i32> {
        let pid = self.child.id().to_string();
        let sent = Command::new("kill").args(["-TERM", &pid]).status().unwrap();
        assert!(sent.success());
        let start = std::time::Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code();
            }
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "Server still runs"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

/// Stops the Server with TERM, so its Sessions end with it; KILL would leave their
/// processes running.
#[cfg(unix)]
impl Drop for RunningServer {
    fn drop(&mut self) {
        // Stopped already (`stop`): its process ID may belong to another process now.
        if let Ok(Some(_)) = self.child.try_wait() {
            return;
        }
        let pid = self.child.id().to_string();
        let _ = Command::new("kill").args(["-TERM", &pid]).status();
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(10) {
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
