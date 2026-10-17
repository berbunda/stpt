//! TLS 1.3 profile of a Connection (PROTOCOL.md §6.2–§6.5, §9.1).
//!
//! The Server authenticates with an Ed25519 Raw Public Key (RFC 7250); there are no
//! X.509 certificates, no client certificates, no 0-RTT and no session resumption.

use std::sync::{Arc, Mutex};

use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs as provider};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::{
    AlwaysResolvesServerRawPublicKeys, ClientHello, NoServerSessionStorage, ResolvesServerCert,
};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, NamedGroup, ServerConfig, SignatureScheme};

use crate::identity::{Fingerprint, PublicKey, ServerKey};

/// ALPN token (§6.3).
pub const ALPN: &[u8] = b"stpt";

/// Cipher suites and key exchange groups of §6.2, in order of preference.
pub(crate) fn crypto_provider() -> Arc<CryptoProvider> {
    use provider::{cipher_suite, kx_group};
    Arc::new(CryptoProvider {
        cipher_suites: vec![
            cipher_suite::TLS13_AES_128_GCM_SHA256,
            cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            cipher_suite::TLS13_AES_256_GCM_SHA384,
        ],
        kx_groups: vec![kx_group::X25519MLKEM768, kx_group::X25519],
        ..provider::default_provider()
    })
}

/// TLS configuration of the Server.
pub fn server_config(key: &ServerKey) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("provider supports TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ServerIdentity(
            AlwaysResolvesServerRawPublicKeys::new(key.certified()),
        )));
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config
}

/// Presents the Server key, but only to a Client whose key exchange preference
/// lets the Server select X25519MLKEM768 whenever the Client supports it (§6.2).
/// rustls selects the first supported group in the Client's order and has no option
/// to override it, so the handshake is aborted instead.
#[derive(Debug)]
struct ServerIdentity(AlwaysResolvesServerRawPublicKeys);

impl ResolvesServerCert for ServerIdentity {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if !hybrid_selected(client_hello.named_groups().unwrap_or_default()) {
            tracing::debug!("TLS: Client supports X25519MLKEM768 but prefers X25519");
            return None;
        }
        self.0.resolve(client_hello)
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

/// Whether choosing the first group of the Client that the Server supports yields
/// X25519MLKEM768 if the Client offers it.
fn hybrid_selected(client_groups: &[NamedGroup]) -> bool {
    let position = |group| client_groups.iter().position(|g| *g == group);
    match (
        position(NamedGroup::X25519MLKEM768),
        position(NamedGroup::X25519),
    ) {
        (Some(hybrid), Some(classic)) => hybrid < classic,
        _ => true,
    }
}

/// TLS configuration of the Client; `check` decides whether the Server key is trusted.
pub fn client_config(check: Arc<ServerKeyCheck>) -> ClientConfig {
    client_config_with(crypto_provider(), check)
}

fn client_config_with(provider: Arc<CryptoProvider>, check: Arc<ServerKeyCheck>) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(check)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config
}

/// What the Client knows of the Server key before the handshake (§9.3).
#[derive(Debug, Clone, Default)]
pub struct Expected {
    /// Key of the trust store entry for the Server address.
    pub stored: Option<PublicKey>,
    /// Fingerprint supplied out of band.
    pub fingerprint: Option<Fingerprint>,
}

/// Decision on the key the Server presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Equal to the stored key and to the given fingerprint, whichever are known.
    Trusted,
    /// No stored key and no fingerprint: first contact, the user decides.
    Unknown,
    /// Differs from the stored key.
    Changed { stored: PublicKey },
    /// Does not match the given fingerprint.
    Mismatch { expected: Fingerprint },
}

/// Verifies the Server key (§9.1, §9.3): only Raw Public Keys, signature scheme
/// Ed25519. The handshake goes on only if the key is trusted; otherwise it is aborted
/// and [`ServerKeyCheck::outcome`] tells why, so the Client can report it.
#[derive(Debug)]
pub struct ServerKeyCheck {
    expected: Expected,
    outcome: Mutex<Option<(PublicKey, Verdict)>>,
}

impl ServerKeyCheck {
    pub fn new(expected: Expected) -> Arc<Self> {
        Arc::new(Self {
            expected,
            outcome: Mutex::new(None),
        })
    }

    /// The presented key and the verdict on it; `None` before the Server presented one.
    pub fn outcome(&self) -> Option<(PublicKey, Verdict)> {
        self.outcome.lock().expect("not poisoned").clone()
    }

    fn verdict(&self, presented: &PublicKey) -> Verdict {
        if let Some(stored) = &self.expected.stored
            && stored != presented
        {
            return Verdict::Changed {
                stored: stored.clone(),
            };
        }
        if let Some(expected) = self.expected.fingerprint
            && expected != presented.fingerprint()
        {
            return Verdict::Mismatch { expected };
        }
        if self.expected.stored.is_none() && self.expected.fingerprint.is_none() {
            return Verdict::Unknown;
        }
        Verdict::Trusted
    }
}

impl ServerCertVerifier for ServerKeyCheck {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let rejected = || {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
        };
        if !intermediates.is_empty() {
            return rejected();
        }
        let presented = PublicKey::from_spki(end_entity.as_ref());
        let verdict = self.verdict(&presented);
        let trusted = verdict == Verdict::Trusted;
        *self.outcome.lock().expect("not poisoned") = Some((presented, verdict));
        if trusted {
            Ok(ServerCertVerified::assertion())
        } else {
            rejected()
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(rustls::Error::PeerMisbehaved(
                rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        rustls::crypto::verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &crypto_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, ServerConnection};

    fn trusting(key: PublicKey) -> Arc<ServerKeyCheck> {
        ServerKeyCheck::new(Expected {
            stored: Some(key),
            fingerprint: None,
        })
    }

    /// Handshake with a Client expecting `expected`; returns the outcome of its check.
    fn check(expected: Expected, key: &ServerKey) -> (bool, Option<(PublicKey, Verdict)>) {
        let check = ServerKeyCheck::new(expected);
        let ok = handshake(client_config(check.clone()), server_config(key)).is_ok();
        (ok, check.outcome())
    }

    #[test]
    fn verdicts() {
        let key = ServerKey::generate();
        let presented = key.public_key();
        let other = ServerKey::generate().public_key();
        let verdict = |stored: Option<&PublicKey>, fingerprint: Option<Fingerprint>| {
            let expected = Expected {
                stored: stored.cloned(),
                fingerprint,
            };
            let (ok, outcome) = check(expected, &key);
            let (seen, verdict) = outcome.unwrap();
            assert_eq!(seen, presented);
            assert_eq!(ok, verdict == Verdict::Trusted);
            verdict
        };
        let fp = Some(presented.fingerprint());
        let other_fp = Some(other.fingerprint());

        assert_eq!(verdict(None, None), Verdict::Unknown);
        assert_eq!(verdict(Some(&presented), None), Verdict::Trusted);
        assert_eq!(verdict(None, fp), Verdict::Trusted);
        assert_eq!(verdict(Some(&presented), fp), Verdict::Trusted);
        assert_eq!(
            verdict(Some(&other), None),
            Verdict::Changed {
                stored: other.clone()
            }
        );
        assert_eq!(
            verdict(None, other_fp),
            Verdict::Mismatch {
                expected: other.fingerprint()
            }
        );
        // A changed key is reported as such even with a matching fingerprint.
        assert!(matches!(verdict(Some(&other), fp), Verdict::Changed { .. }));
        assert!(matches!(
            verdict(Some(&presented), other_fp),
            Verdict::Mismatch { .. }
        ));
    }

    /// Runs a TLS handshake in memory (TLS over TCP framing, same configuration).
    fn handshake(
        client: ClientConfig,
        server: ServerConfig,
    ) -> Result<(ClientConnection, ServerConnection), rustls::Error> {
        let name = ServerName::try_from("server.example").unwrap();
        let mut c = ClientConnection::new(Arc::new(client), name)?;
        let mut s = ServerConnection::new(Arc::new(server))?;
        while c.is_handshaking() || s.is_handshaking() {
            let mut buf = Vec::new();
            c.write_tls(&mut buf).unwrap();
            s.read_tls(&mut buf.as_slice()).unwrap();
            s.process_new_packets()?;
            let mut buf = Vec::new();
            s.write_tls(&mut buf).unwrap();
            if buf.is_empty() && !c.wants_write() {
                break;
            }
            c.read_tls(&mut buf.as_slice()).unwrap();
            c.process_new_packets()?;
        }
        Ok((c, s))
    }

    #[test]
    fn profile() {
        let key = ServerKey::generate();
        let (c, s) = handshake(
            client_config(trusting(key.public_key())),
            server_config(&key),
        )
        .unwrap();
        assert_eq!(c.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
        assert_eq!(c.alpn_protocol(), Some(ALPN));
        assert_eq!(s.alpn_protocol(), Some(ALPN));
        let group = c.negotiated_key_exchange_group().unwrap().name();
        assert_eq!(group, NamedGroup::X25519MLKEM768);
        assert_eq!(
            c.negotiated_cipher_suite().unwrap().suite(),
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
        );
    }

    #[test]
    fn hybrid_preference() {
        use NamedGroup::*;
        assert!(hybrid_selected(&[X25519MLKEM768, X25519]));
        assert!(hybrid_selected(&[secp256r1, X25519MLKEM768, X25519]));
        assert!(hybrid_selected(&[X25519]));
        assert!(hybrid_selected(&[X25519MLKEM768]));
        assert!(!hybrid_selected(&[X25519, X25519MLKEM768]));
    }

    #[test]
    fn client_preferring_x25519_over_hybrid_is_rejected() {
        let key = ServerKey::generate();
        let mut groups = crypto_provider().kx_groups.clone();
        groups.reverse();
        let provider = CryptoProvider {
            kx_groups: groups,
            ..(*crypto_provider()).clone()
        };
        let client = client_config_with(Arc::new(provider), trusting(key.public_key()));
        assert!(handshake(client, server_config(&key)).is_err());
    }

    #[test]
    fn client_without_hybrid_gets_x25519() {
        let key = ServerKey::generate();
        let provider = CryptoProvider {
            kx_groups: vec![provider::kx_group::X25519],
            ..(*crypto_provider()).clone()
        };
        let client = client_config_with(Arc::new(provider), trusting(key.public_key()));
        let (c, _) = handshake(client, server_config(&key)).unwrap();
        let group = c.negotiated_key_exchange_group().unwrap().name();
        assert_eq!(group, NamedGroup::X25519);
    }

    #[test]
    fn other_key_is_rejected() {
        let key = ServerKey::generate();
        let other = ServerKey::generate();
        assert_ne!(key.public_key(), other.public_key());
        let err = handshake(
            client_config(trusting(other.public_key())),
            server_config(&key),
        )
        .unwrap_err();
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "{err:?}"
        );
    }

    #[test]
    fn other_alpn_is_rejected() {
        let key = ServerKey::generate();
        let mut client = client_config(trusting(key.public_key()));
        client.alpn_protocols = vec![b"h3".to_vec()];
        let err = handshake(client, server_config(&key)).unwrap_err();
        assert_eq!(err, rustls::Error::NoApplicationProtocol);
    }

    #[test]
    fn x509_client_cannot_connect() {
        let key = ServerKey::generate();
        let client = ClientConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        assert!(handshake(client, server_config(&key)).is_err());
    }
}
