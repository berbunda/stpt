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
    let path = config_file(
        "logging-server",
        "log_level = \"debug\"
",
    );
    let lines = common::server_until_listening(&["--config", &path, "--listen", "127.0.0.1:0"]);
    let log = lines.join(
        "
",
    );
    assert!(
        log.contains("DEBUG stpt::config: configuration file read"),
        "{log}"
    );
    assert!(
        log.contains("WARN stpt::server: temporary Server key"),
        "{log}"
    );
    assert!(
        log.contains("INFO stpt::server: listening listen=127.0.0.1:"),
        "{log}"
    );
}

#[cfg(unix)]
#[test]
fn server_quiet_shows_only_the_error() {
    // 192.0.2.1 (TEST-NET-1) is not a local address, so binding fails.
    let out = stpt(&["server", "-q", "--listen", "192.0.2.1:1"]);
    assert_eq!(out.status.code(), Some(255));
    let err = stderr(&out);
    assert!(err.starts_with("stpt: transport: 192.0.2.1:1: "), "{err}");
    assert_eq!(err.lines().count(), 1, "{err}");
}
