//! Log level options and log output on standard error.

mod common;

use common::{config_file, stderr, stpt};

#[test]
fn client_debug_shows_configuration_source() {
    let out = stpt(&["-vv", "connect", "alice@host"]);
    let err = stderr(&out);
    assert!(
        err.contains("DEBUG no configuration file, built-in defaults"),
        "{err}"
    );
    assert!(err.ends_with("stpt: connect: not implemented yet"), "{err}");
}

#[test]
fn client_default_level_hides_debug() {
    let path = config_file("logging-default", "");
    let out = stpt(&["connect", "alice@host", "--config", &path]);
    assert_eq!(stderr(&out), "stpt: connect: not implemented yet");
}

#[test]
fn quiet_and_verbose_conflict() {
    let out = stpt(&["-q", "connect", "alice@host", "-v"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("--quiet cannot be used with --verbose"));
}

#[cfg(unix)]
#[test]
fn server_log_level_from_configuration() {
    let path = config_file("logging-server", "log_level = \"debug\"\n");
    let out = stpt(&["server", "--config", &path, "--listen", "127.0.0.1:2222"]);
    let err = stderr(&out);
    assert!(err.contains("configuration file read"), "{err}");
    assert!(err.contains("listen=127.0.0.1:2222"), "{err}");

    let out = stpt(&["server", "--config", &path, "-q"]);
    assert_eq!(stderr(&out), "stpt: server: not implemented yet");
}
