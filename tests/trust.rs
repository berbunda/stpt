//! Server Identity and trust store (PROTOCOL.md §9): Server key, first contact,
//! out-of-band fingerprint, changed key, `stpt trust`.

mod common;

use common::{dir, stderr, stdout, stpt_in};

#[test]
fn trust_list_and_remove() {
    let home = dir("trust-list");
    std::fs::create_dir_all(home.join("stpt")).unwrap();
    std::fs::write(
        home.join("stpt").join("known_servers"),
        "# test\nhost.example:843 AAAA\n[::1]:900 AAAAAAAA\n",
    )
    .unwrap();

    let out = stpt_in(&home, &["trust", "list"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let list = stdout(&out);
    let lines: Vec<_> = list.lines().collect();
    assert_eq!(lines.len(), 2, "{list}");
    assert!(lines[0].starts_with("host.example:843 SHA256:"), "{list}");
    assert!(lines[1].starts_with("[::1]:900 SHA256:"), "{list}");

    let out = stpt_in(&home, &["trust", "remove", "HOST.example"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = stpt_in(&home, &["trust", "list"]);
    assert_eq!(stdout(&out), lines[1]);

    let out = stpt_in(&home, &["trust", "remove", "host.example"]);
    assert_eq!(out.status.code(), Some(255));
    assert_eq!(
        stderr(&out),
        "stpt: trust store: no entry for host.example:843"
    );
}

#[test]
fn damaged_trust_store_is_an_error() {
    let home = dir("trust-damaged");
    std::fs::create_dir_all(home.join("stpt")).unwrap();
    let path = home.join("stpt").join("known_servers");
    std::fs::write(&path, "host.example:843\n").unwrap();
    let out = stpt_in(&home, &["trust", "list"]);
    assert_eq!(out.status.code(), Some(255));
    assert_eq!(
        stderr(&out),
        format!(
            "stpt: trust store: {}:1: expected HOST:PORT KEY",
            path.display()
        )
    );
}

#[cfg(unix)]
mod server {
    use super::*;
    use common::{RunningServer, server_config};

    /// `stpt server --fingerprint`: creates the key at the first call.
    fn fingerprint(config: &str) -> (String, String) {
        let out = stpt_in(
            &dir("trust-fp-home"),
            &["server", "--fingerprint", "--config", config],
        );
        assert!(out.status.success(), "{}", stderr(&out));
        (stdout(&out), stderr(&out))
    }

    #[test]
    fn server_key_is_created_once_and_private() {
        use std::os::unix::fs::PermissionsExt;

        let config = server_config("trust-key", "");
        let (fp, log) = fingerprint(&config);
        assert!(fp.starts_with("SHA256:") && fp.len() == 50, "{fp}");
        assert!(log.contains("Server key created"), "{log}");
        let (again, log) = fingerprint(&config);
        assert_eq!(again, fp);
        assert!(!log.contains("created"), "{log}");

        let key = std::path::Path::new(&config).with_file_name("server_key");
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o640)).unwrap();
        let out = stpt_in(
            &dir("trust-fp-home"),
            &["server", "--fingerprint", "--config", &config],
        );
        assert_eq!(out.status.code(), Some(255));
        assert!(
            stderr(&out).contains("permissions 640 are too open"),
            "{}",
            stderr(&out)
        );
    }

    #[test]
    fn first_contact_fingerprint_and_changed_key() {
        let config = server_config("trust-flow", "");
        let (fp, _) = fingerprint(&config);
        let server = RunningServer::start(&["--listen", "127.0.0.1:0", "--config", &config]);
        let port = server.port;
        let address = format!("127.0.0.1:{port}");
        let dest = format!("alice@{address}");
        let home = dir("trust-flow-home");

        // First contact without a terminal and without --fingerprint: refused.
        let out = stpt_in(&home, &["connect", &dest]);
        assert_eq!(out.status.code(), Some(255));
        let err = stderr(&out);
        assert!(
            err.starts_with(&format!(
                "stpt: the key of the Server {address} is not known\n  fingerprint: {fp}\n"
            )),
            "{err}"
        );
        assert_eq!(stdout(&stpt_in(&home, &["trust", "list"])), "");

        // A wrong fingerprint: refused, nothing stored.
        let wrong = "SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU";
        let out = stpt_in(&home, &["connect", &dest, "--fingerprint", wrong]);
        assert_eq!(out.status.code(), Some(255));
        let err = stderr(&out);
        assert!(err.contains("does not match --fingerprint"), "{err}");
        assert!(err.contains(&format!("presented: {fp}")), "{err}");
        assert_eq!(stdout(&stpt_in(&home, &["trust", "list"])), "");

        // The right fingerprint: the Connection is established and the key stored.
        let out = stpt_in(&home, &["connect", &dest, "--fingerprint", &fp]);
        assert_eq!(stderr(&out), "stpt: connect: not implemented yet");
        assert_eq!(
            stdout(&stpt_in(&home, &["trust", "list"])),
            format!("{address} {fp}")
        );

        // Known key: no fingerprint needed.
        let out = stpt_in(&home, &["sessions", &dest]);
        assert_eq!(stderr(&out), "stpt: sessions: not implemented yet");

        // Same address, new Server key: refused, both fingerprints shown.
        drop(server);
        let config = server_config("trust-flow-new", "");
        let (new_fp, _) = fingerprint(&config);
        let _server = RunningServer::start(&["--listen", &address, "--config", &config]);
        let out = stpt_in(&home, &["connect", &dest, "--fingerprint", &new_fp]);
        assert_eq!(out.status.code(), Some(255));
        let err = stderr(&out);
        assert!(
            err.starts_with(&format!(
                "stpt: the key of the Server {address} has changed"
            )),
            "{err}"
        );
        assert!(err.contains(&format!("stored:    {fp}\n")), "{err}");
        assert!(err.contains(&format!("presented: {new_fp}\n")), "{err}");
        assert!(
            err.ends_with(&format!("stpt trust remove {address}")),
            "{err}"
        );

        // Replacing the key is a separate explicit action.
        let out = stpt_in(&home, &["trust", "remove", &address]);
        assert!(out.status.success(), "{}", stderr(&out));
        let out = stpt_in(&home, &["connect", &dest, "--fingerprint", &new_fp]);
        assert_eq!(stderr(&out), "stpt: connect: not implemented yet");
        assert_eq!(
            stdout(&stpt_in(&home, &["trust", "list"])),
            format!("{address} {new_fp}")
        );
    }
}
