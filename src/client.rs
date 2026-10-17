//! Client role: every subcommand except `server`.

use std::io::{self, IsTerminal, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::process::ExitCode;

use crate::cli::{ClientCommand, Common, Remote, TrustAction};
use crate::config::{self, ClientConfig};
use crate::destination::Address;
use crate::error::Error;
use crate::identity::Fingerprint;
use crate::logging::{self, Role};
use crate::quic;
use crate::tls::{Expected, ServerKeyCheck, Verdict};
use crate::trust::{self, TrustStore};

pub fn run(command: ClientCommand, common: &Common) -> Result<ExitCode, Error> {
    let (_config, path) =
        config::load::<ClientConfig>(common.config.as_deref(), config::client_path())?;
    logging::init(
        Role::Client,
        logging::level(Role::Client, common.verbose, common.quiet, None),
    );
    config::log_source(path.as_deref());

    let (name, remote) = match command {
        ClientCommand::Trust { action } => return trust_command(action),
        ClientCommand::Connect { remote, .. } => ("connect", remote),
        ClientCommand::Exec { remote, .. } => ("exec", remote),
        ClientCommand::Sessions { remote } => ("sessions", remote),
        ClientCommand::Detach { remote, .. } => ("detach", remote),
        ClientCommand::Terminate { remote, .. } => ("terminate", remote),
    };
    let mut store = trust_store()?;
    let runtime = quic::runtime()?;
    let _guard = runtime.enter();
    let addr = resolve(&remote.destination.address)?;
    let connection = runtime.block_on(connect(&remote, addr, &mut store, ask_user))?;
    // Until HELLO (RB004) there is nothing to do on the Connection.
    runtime.block_on(connection.close());
    Err(Error::NotImplemented(name))
}

fn trust_store() -> Result<TrustStore, Error> {
    let dir = config::client_dir().ok_or(Error::NoTrustStore)?;
    Ok(TrustStore::load(dir.join(trust::FILE_NAME))?)
}

fn trust_command(action: TrustAction) -> Result<ExitCode, Error> {
    let mut store = trust_store()?;
    match action {
        TrustAction::List => {
            for (address, key) in store.entries() {
                println!("{address} {}", key.fingerprint());
            }
        }
        TrustAction::Remove { address } => {
            if !store.remove(&address)? {
                return Err(Error::NoTrustEntry(address));
            }
            tracing::info!(path = %store.path().display(), %address, "entry removed");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// First address of the host; addresses of a DNS name are tried in later versions.
fn resolve(address: &Address) -> Result<SocketAddr, Error> {
    (address.host.as_str(), address.port)
        .to_socket_addrs()
        .and_then(|mut addrs| {
            addrs
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address"))
        })
        .map_err(|source| Error::Resolve {
            address: address.clone(),
            source,
        })
}

/// Established Connection with a trusted Server key.
pub struct Connection {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

impl Connection {
    /// Closes the Connection regularly and waits until the peer is told.
    async fn close(self) {
        self.connection.close(quic::NO_ERROR, b"");
        self.endpoint.wait_idle().await;
    }
}

/// Connects to the Server at `addr` and verifies its key against the trust store
/// and `--fingerprint` (§9.3). At first contact without a fingerprint the handshake
/// is aborted, `confirm` asks the user, and after a confirmation the Client connects
/// again expecting the confirmed key; so no deadline of the Server runs while the
/// user decides. A key confirmed or verified by fingerprint is added to the store.
async fn connect(
    remote: &Remote,
    addr: SocketAddr,
    store: &mut TrustStore,
    confirm: impl Fn(&Address, &Fingerprint) -> Result<bool, Error>,
) -> Result<Connection, Error> {
    let address = &remote.destination.address;
    let endpoint = quic::client(addr)?;
    loop {
        let check = ServerKeyCheck::new(Expected {
            stored: store.get(address).cloned(),
            fingerprint: remote.fingerprint,
        });
        let result = quic::connect(&endpoint, addr, &address.host, check.clone()).await;
        let outcome = check.outcome();
        let error = match result {
            Ok(connection) => {
                let (key, _) = outcome.expect("a Connection is established with a trusted key");
                if store.get(address).is_none() {
                    store.add(address.clone(), key)?;
                    tracing::info!(%address, "Server key verified by fingerprint and stored");
                }
                tracing::info!(%address, "Connection established");
                return Ok(Connection {
                    endpoint,
                    connection,
                });
            }
            Err(error) => error,
        };
        let address = address.clone();
        match outcome {
            Some((key, Verdict::Unknown)) => {
                if !confirm(&address, &key.fingerprint())? {
                    return Err(Error::KeyNotTrusted(address));
                }
                store.add(address, key)?;
            }
            Some((key, Verdict::Changed { stored })) => {
                return Err(Error::KeyChanged {
                    address,
                    stored: stored.fingerprint(),
                    presented: key.fingerprint(),
                });
            }
            Some((key, Verdict::Mismatch { expected })) => {
                return Err(Error::FingerprintMismatch {
                    address,
                    expected,
                    presented: key.fingerprint(),
                });
            }
            Some((_, Verdict::Trusted)) | None => return Err(error.into()),
        }
    }
}

/// Shows the fingerprint of an unknown Server key and asks the user to trust it;
/// only `yes` confirms. Without a terminal there is nobody to ask (§9.3).
fn ask_user(address: &Address, fingerprint: &Fingerprint) -> Result<bool, Error> {
    if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
        return Err(Error::KeyNotKnown {
            address: address.clone(),
            presented: *fingerprint,
        });
    }
    let mut stderr = io::stderr().lock();
    write!(
        stderr,
        "The key of the Server {address} is not known.\n  \
         fingerprint: {fingerprint}\n\
         Compare it in full with the output of `stpt server --fingerprint` on the Server.\n\
         Trust this key? Type yes to confirm: "
    )
    .and_then(|()| stderr.flush())
    .map_err(Error::Terminal)?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(Error::Terminal)?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::destination::Destination;
    use crate::identity::{PublicKey, ServerKey};
    use std::cell::Cell;
    use std::path::{Path, PathBuf};

    struct Server {
        endpoint: quinn::Endpoint,
        key: PublicKey,
    }

    impl Server {
        fn start(key: &ServerKey) -> Self {
            let endpoint = quic::listen("127.0.0.1:0".parse().unwrap(), key).unwrap();
            let accepting = endpoint.clone();
            tokio::spawn(async move {
                while let Some(incoming) = accepting.accept().await {
                    tokio::spawn(async move {
                        if let Ok(c) = quic::accept(incoming).await {
                            c.closed().await;
                        }
                    });
                }
            });
            Self {
                endpoint,
                key: key.public_key(),
            }
        }

        fn addr(&self) -> SocketAddr {
            self.endpoint.local_addr().unwrap()
        }

        fn remote(&self, fingerprint: Option<Fingerprint>) -> Remote {
            Remote {
                destination: format!("alice@127.0.0.1:{}", self.addr().port())
                    .parse::<Destination>()
                    .unwrap(),
                fingerprint,
            }
        }
    }

    fn store_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("stpt-client-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(trust::FILE_NAME)
    }

    fn answer(yes: bool) -> impl Fn(&Address, &Fingerprint) -> Result<bool, Error> {
        move |_, _| Ok(yes)
    }

    fn never_asked(_: &Address, _: &Fingerprint) -> Result<bool, Error> {
        panic!("the user must not be asked")
    }

    async fn run(
        server: &Server,
        fingerprint: Option<Fingerprint>,
        path: &Path,
        confirm: impl Fn(&Address, &Fingerprint) -> Result<bool, Error>,
    ) -> Result<(), Error> {
        let mut store = TrustStore::load(path.to_owned()).unwrap();
        let remote = server.remote(fingerprint);
        let connection = connect(&remote, server.addr(), &mut store, confirm).await?;
        connection.close().await;
        Ok(())
    }

    fn stored(path: &Path, server: &Server) -> Option<PublicKey> {
        let store = TrustStore::load(path.to_owned()).unwrap();
        let address = server.remote(None).destination.address;
        store.get(&address).cloned()
    }

    #[tokio::test]
    async fn first_contact_confirmed_then_known() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("confirmed");
        let asked = Cell::new(0);
        let confirm = |_: &Address, fp: &Fingerprint| {
            assert_eq!(*fp, server.key.fingerprint());
            asked.set(asked.get() + 1);
            Ok(true)
        };
        run(&server, None, &path, confirm).await.unwrap();
        assert_eq!(asked.get(), 1);
        assert_eq!(stored(&path, &server), Some(server.key.clone()));
        run(&server, None, &path, never_asked).await.unwrap();
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn first_contact_declined() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("declined");
        let err = run(&server, None, &path, answer(false)).await.unwrap_err();
        assert!(matches!(err, Error::KeyNotTrusted(_)), "{err}");
        assert_eq!(stored(&path, &server), None);
    }

    #[tokio::test]
    async fn fingerprint_verifies_and_stores() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("fingerprint");
        let fp = Some(server.key.fingerprint());
        run(&server, fp, &path, never_asked).await.unwrap();
        assert_eq!(stored(&path, &server), Some(server.key.clone()));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn wrong_fingerprint_is_refused() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("mismatch");
        let other = ServerKey::generate().public_key().fingerprint();
        let err = run(&server, Some(other), &path, never_asked)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::FingerprintMismatch { expected, .. } if expected == other),
            "{err}"
        );
        assert_eq!(stored(&path, &server), None);
    }

    #[tokio::test]
    async fn changed_key_is_refused_and_kept() {
        let server = Server::start(&ServerKey::generate());
        let path = store_path("changed");
        let old = ServerKey::generate().public_key();
        let mut store = TrustStore::load(path.to_owned()).unwrap();
        store
            .add(server.remote(None).destination.address, old.clone())
            .unwrap();
        let err = run(&server, None, &path, never_asked).await.unwrap_err();
        let Error::KeyChanged {
            stored: s,
            presented,
            ..
        } = err
        else {
            panic!("{err}")
        };
        assert_eq!(s, old.fingerprint());
        assert_eq!(presented, server.key.fingerprint());
        assert_eq!(stored(&path, &server), Some(old));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
