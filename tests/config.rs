//! Configuration files given with `--config`.

mod common;

use common::{config_file, dir, stderr, stpt};

#[test]
fn missing_explicit_file() {
    let path = dir("config-missing").join("none.toml");
    let path = path.to_str().unwrap();
    let out = stpt(&["--config", path, "connect", "alice@host"]);
    assert_eq!(out.status.code(), Some(255));
    assert!(
        stderr(&out).starts_with(&format!("stpt: config: {path}: ")),
        "{}",
        stderr(&out)
    );
}

#[test]
fn unknown_client_key() {
    let path = config_file("config-unknown", "detach_timeout = 60\n");
    let out = stpt(&["connect", "alice@host", "--config", &path]);
    assert_eq!(out.status.code(), Some(255));
    let err = stderr(&out);
    assert!(err.starts_with(&format!("stpt: config: {path}: ")), "{err}");
    assert!(err.contains("detach_timeout"), "{err}");
}

#[test]
fn empty_client_file() {
    let path = config_file("config-empty", "# no settings\n");
    let out = stpt(&["--config", &path, "trust", "list"]);
    assert!(out.status.success());
    assert_eq!(stderr(&out), "");
}

#[cfg(unix)]
#[test]
fn invalid_server_listen() {
    let path = config_file("config-listen", "listen = \"host\"\n");
    let out = stpt(&["server", "--config", &path]);
    assert_eq!(out.status.code(), Some(255));
    assert!(stderr(&out).contains("listen"), "{}", stderr(&out));
}
