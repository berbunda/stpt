//! TLS 1.3 profile of a Connection (PROTOCOL.md §6.2–§6.5, §9.1).
//!
//! The Server authenticates with an Ed25519 Raw Public Key (RFC 7250); there are no
//! X.509 certificates, no client certificates, no 0-RTT and no session resumption.

use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, aws_lc_rs as provider};
use rustls::pki_types::{
    CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::{
    AlwaysResolvesServerRawPublicKeys, ClientHello, NoServerSessionStorage, ResolvesServerCert,
};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, DigitallySignedStruct, NamedGroup, ServerConfig, SignatureScheme};

/// ALPN token (§6.3).
pub const ALPN: &[u8] = b"stpt";

/// Cipher suites and key exchange groups of §6.2, in order of preference.
fn crypto_provider() -> Arc<CryptoProvider> {
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

/// Public key of a Server Identity: DER-encoded SubjectPublicKeyInfo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(Vec<u8>);

/// Key pair of a Server Identity (§9.1). Persistent storage comes with RB003.
pub struct ServerKey {
    certified: Arc<CertifiedKey>,
}

impl ServerKey {
    /// Generates a new Ed25519 key pair.
    pub fn generate() -> Self {
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("Ed25519 key generation");
        let signing = crypto_provider()
            .key_provider
            .load_private_key(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()).into())
            .expect("generated Ed25519 key is valid");
        let spki = signing.public_key().expect("Ed25519 key has a public key");
        let certified = CertifiedKey::new(vec![CertificateDer::from(spki.to_vec())], signing);
        Self {
            certified: Arc::new(certified),
        }
    }

    #[cfg_attr(not(test), expect(dead_code, reason = "Client connects from RB003 on"))]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.certified.end_entity_cert().expect("one key").to_vec())
    }
}

/// TLS configuration of the Server.
pub fn server_config(key: &ServerKey) -> ServerConfig {
    let mut config = ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("provider supports TLS 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(ServerIdentity(
            AlwaysResolvesServerRawPublicKeys::new(key.certified.clone()),
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

/// TLS configuration of the Client; the Server must present `expected`.
pub fn client_config(expected: PublicKey) -> ClientConfig {
    client_config_with(crypto_provider(), expected)
}

fn client_config_with(provider: Arc<CryptoProvider>, expected: PublicKey) -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ExpectedKey(expected)))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config
}

/// Accepts only the Raw Public Key it was given (§9.1); the trust store is RB003.
#[derive(Debug)]
struct ExpectedKey(PublicKey);

impl ServerCertVerifier for ExpectedKey {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if intermediates.is_empty() && end_entity.as_ref() == self.0.0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ))
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
        let (c, s) = handshake(client_config(key.public_key()), server_config(&key)).unwrap();
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
        let client = client_config_with(Arc::new(provider), key.public_key());
        assert!(handshake(client, server_config(&key)).is_err());
    }

    #[test]
    fn client_without_hybrid_gets_x25519() {
        let key = ServerKey::generate();
        let provider = CryptoProvider {
            kx_groups: vec![provider::kx_group::X25519],
            ..(*crypto_provider()).clone()
        };
        let client = client_config_with(Arc::new(provider), key.public_key());
        let (c, _) = handshake(client, server_config(&key)).unwrap();
        let group = c.negotiated_key_exchange_group().unwrap().name();
        assert_eq!(group, NamedGroup::X25519);
    }

    #[test]
    fn other_key_is_rejected() {
        let key = ServerKey::generate();
        let other = ServerKey::generate();
        assert_ne!(key.public_key(), other.public_key());
        let err = handshake(client_config(other.public_key()), server_config(&key)).unwrap_err();
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "{err:?}"
        );
    }

    #[test]
    fn other_alpn_is_rejected() {
        let key = ServerKey::generate();
        let mut client = client_config(key.public_key());
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
