//! One binary provides both roles; the subcommand selects the role.

use std::process::{Command, Output};

fn stpt(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stpt"))
        .args(args)
        .output()
        .expect("run stpt")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn server_role() {
    let out = stpt(&["server", "--listen", "127.0.0.1:0"]);
    assert_eq!(out.status.code(), Some(255));
    let expected = if cfg!(unix) {
        "stpt: server: not implemented yet"
    } else {
        "stpt: server: Server mode is not available on this platform"
    };
    assert_eq!(stderr(&out).trim_end(), expected);
}

#[test]
fn client_role() {
    let out = stpt(&["connect", "alice@host"]);
    assert_eq!(out.status.code(), Some(255));
    assert_eq!(
        stderr(&out).trim_end(),
        "stpt: connect: not implemented yet"
    );
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
