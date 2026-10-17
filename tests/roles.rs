//! One binary provides both roles; the subcommand selects the role.

mod common;

use common::{stderr, stpt};

#[cfg(unix)]
#[test]
fn server_role() {
    let config = common::server_config("roles-server", "");
    let lines = common::server_until_listening(&["--listen", "127.0.0.1:0", "--config", &config]);
    let last = lines.last().expect("Server logs");
    assert!(last.contains("listening listen=127.0.0.1:"), "{lines:?}");
}

#[cfg(windows)]
#[test]
fn server_role() {
    let config = common::config_file("roles-server", "");
    let out = stpt(&["server", "--listen", "127.0.0.1:0", "--config", &config]);
    assert_eq!(out.status.code(), Some(255));
    assert_eq!(
        stderr(&out),
        "stpt: server: Server mode is not available on this platform"
    );
}

#[test]
fn client_role() {
    let out = stpt(&["trust", "list"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn usage_error() {
    let out = stpt(&["connect", "host"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn version() {
    let out = stpt(&["--version"]);
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim_end(),
        concat!("stpt ", env!("CARGO_PKG_VERSION"))
    );
}
