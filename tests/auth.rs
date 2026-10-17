//! User authentication between the real Client and Server (PROTOCOL.md §12).

mod common;

#[cfg(unix)]
mod server {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use super::common::{
        RunningServer, TEST_USER_KEY_LINE, dir, server_config, stderr, stdout, stpt_in, user_key,
    };

    /// The Account the tests run as: it exists on this system.
    fn account() -> String {
        let out = std::process::Command::new("id")
            .arg("-un")
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn user_key_authorization() {
        let config = server_config("auth-flow", "");
        let out = stpt_in(
            &dir("auth-fp"),
            &["server", "--fingerprint", "--config", &config],
        );
        let fingerprint = stdout(&out);
        let server = RunningServer::start(&["--listen", "127.0.0.1:0", "--config", &config]);
        let account = account();
        let dest = format!("{account}@127.0.0.1:{}", server.port);
        let home = dir("auth-home");
        let connect = || stpt_in(&home, &["connect", &dest, "--fingerprint", &fingerprint]);

        // No user key: the Client says how to create one, before it connects.
        let err = stderr(&connect());
        assert!(err.starts_with("stpt: no user key at "), "{err}");
        assert!(err.contains("openssl genpkey -algorithm ed25519"), "{err}");

        // A key the Server does not know: refused, with the line to add.
        let key = user_key(&home);
        let err = stderr(&connect());
        assert!(
            err.starts_with("stpt: the Server did not accept the key SHA256:"),
            "{err}"
        );
        assert!(
            err.contains(&format!("for the Account {account}\n")),
            "{err}"
        );
        assert!(err.ends_with(TEST_USER_KEY_LINE), "{err}");

        // The administrator authorizes the key: the Connection is Authenticated.
        let keys = Path::new(&config).with_file_name("authorized_keys");
        let file = keys.join(&account);
        std::fs::write(&file, format!("{TEST_USER_KEY_LINE} test key\n")).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(stderr(&connect()), "stpt: connect: not implemented yet");

        // A file others may change is ignored.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(stderr(&connect()).starts_with("stpt: the Server did not accept the key"));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Another Account with the same key: refused like an unknown key.
        let other = format!("no-such-account-stpt@127.0.0.1:{}", server.port);
        let out = stpt_in(&home, &["sessions", &other, "--fingerprint", &fingerprint]);
        assert!(stderr(&out).starts_with("stpt: the Server did not accept the key"));

        // A user key readable by others is refused before connecting.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = stderr(&connect());
        assert!(err.contains("permissions 644 are too open"), "{err}");

        // --identity selects another key file.
        let moved = home.join("other_key");
        std::fs::rename(&key, &moved).unwrap();
        std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o600)).unwrap();
        let out = stpt_in(
            &home,
            &[
                "connect",
                &dest,
                "--fingerprint",
                &fingerprint,
                "-i",
                moved.to_str().unwrap(),
            ],
        );
        assert_eq!(stderr(&out), "stpt: connect: not implemented yet");
    }
}
