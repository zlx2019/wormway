//! TLS of Wormway: the certificates of the listeners, and the rustls settings that present them.
//!
//! [`Certificates`] loads the certificates of every configuration as an engine of the runtime,
//! and builds the rustls [`ServerConfig`] of each TLS listener. A handshake gets, among the
//! certificates of its listener, the one whose names cover the host name the client sends
//! (SNI). Replaced certificate files take effect for new handshakes when the configuration is
//! applied again, without touching the listeners or their connections. Certificates that the
//! configuration gets through ACME are installed as they are issued, and the [`Challenges`]
//! hold the answers to the HTTP-01 challenges meanwhile.
//!
//! Signatures and key exchange use aws-lc-rs, with post-quantum key exchange first, whatever
//! the process-wide default of rustls is.

mod challenge;
mod engine;
mod load;
mod publish;
mod resolve;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, UNIX_EPOCH};

use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::server::ServerSessionMemoryCache;
use wormway_core::config::{Issue, Name};
use wormway_runtime::{CertificateReport, Services, TlsReport};
use x509_parser::extensions::ParsedExtension;

pub use crate::challenge::Challenges;
use crate::engine::Loader;
pub use crate::load::{CertificateInfo, ClientCertificate};
use crate::load::{Loaded, parse_issued};
use crate::publish::Published;
use crate::resolve::ListenerResolver;

/// TLS 1.2 sessions that each listener keeps for resumption by session ID.
const SESSION_CACHE_SIZE: usize = 4096;

/// The certificates of the listeners. Clones share them.
#[derive(Clone)]
pub struct Certificates {
    /// Directory that relative certificate paths are resolved against.
    base: PathBuf,
    /// The certificates in effect and the index of every TLS listener, with what they are
    /// built from.
    published: Arc<Published>,
    /// The answers to the HTTP-01 challenges in progress.
    challenges: Challenges,
}

impl Certificates {
    /// Creates the certificates of a configuration file in directory `base`: relative
    /// certificate paths are resolved against it.
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            published: Arc::default(),
            challenges: Challenges::default(),
        }
    }

    /// Registers the engine that loads the certificates of every configuration with
    /// `services`, and the report of the certificates in effect.
    pub fn register(&self, services: &mut Services) {
        services.add_engine(Loader::new(self.base.clone(), self.published.clone()));
        services.set_tls_report(self.clone());
    }

    /// Builds the rustls settings of TLS listener `listener`, which offers the application
    /// protocols `alpn`, such as `h2` and `http/1.1`, in order of preference. Every handshake
    /// takes its certificate from the ones in effect when it starts.
    pub fn server_config(
        &self,
        listener: &Name,
        alpn: &[&[u8]],
    ) -> Result<Arc<ServerConfig>, rustls::Error> {
        let resolver = ListenerResolver::new(listener.clone(), self.published.clone());
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
        // Resumption: stateless tickets for TLS 1.3 and 1.2, and a cache for TLS 1.2 session
        // IDs. Both belong to this listener and start over when it is rebuilt.
        config.session_storage = ServerSessionMemoryCache::new(SESSION_CACHE_SIZE);
        config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new()?;
        Ok(Arc::new(config))
    }

    /// Reads the certificate authorities in the PEM file at `path`, relative to the directory of
    /// the configuration file. The problem comes with path `at`. It reads the file, so call it
    /// on the blocking pool.
    pub fn read_authorities(
        &self,
        path: &Path,
        at: &str,
    ) -> Result<Vec<CertificateDer<'static>>, Issue> {
        load::load_authorities(&self.base.join(path)).map_err(|problem| Issue::new(at, problem))
    }

    /// Reads the client certificate in the PEM files at `cert` and `key`, relative to the
    /// directory of the configuration file, and checks that the key belongs to it. Problems
    /// come with paths under `at`, such as `<at>.cert`. It reads files, so call it on the
    /// blocking pool.
    pub fn read_client_certificate(
        &self,
        cert: &Path,
        key: &Path,
        at: &str,
    ) -> Result<ClientCertificate, Issue> {
        load::load_client_certificate(&provider(), &self.base.join(cert), &self.base.join(key), at)
    }

    /// Returns the details of the certificates in effect, by name.
    pub fn details(&self) -> BTreeMap<Name, CertificateInfo> {
        self.published
            .snapshot
            .load()
            .certificates
            .iter()
            .map(|(name, loaded)| (name.clone(), loaded.info.clone()))
            .collect()
    }

    /// Reads a certificate chain and its private key from PEM text, as ACME issues them, and
    /// checks that the key belongs to the leaf certificate. It parses the key, which takes some
    /// CPU time.
    pub fn read_issued(&self, chain: &str, key: &str) -> Result<IssuedCertificate, String> {
        parse_issued(&provider(), chain, key).map(|loaded| IssuedCertificate(Arc::new(loaded)))
    }

    /// Presents `certificate` as certificate `name` from the next handshake on, while the
    /// configuration gets `name` through ACME, in place of the one presented before.
    pub fn install(&self, name: &Name, certificate: &IssuedCertificate) {
        self.published.set_issued(name, Some(certificate.0.clone()));
    }

    /// Stops presenting the certificate issued for `name`.
    pub fn uninstall(&self, name: &Name) {
        self.published.set_issued(name, None);
    }

    /// Returns the certificate installed for `name`, if any.
    pub fn issued(&self, name: &Name) -> Option<IssuedCertificate> {
        self.published.issued(name).map(IssuedCertificate)
    }

    /// Returns the answers to the HTTP-01 challenges, which the HTTP listeners serve.
    pub fn challenges(&self) -> &Challenges {
        &self.challenges
    }
}

/// A certificate that ACME issued, read and checked, ready to be installed. Clones share it.
#[derive(Clone, Debug)]
pub struct IssuedCertificate(Arc<Loaded>);

impl IssuedCertificate {
    /// Returns the details of the leaf certificate.
    pub fn info(&self) -> &CertificateInfo {
        &self.0.info
    }

    /// Returns what identifies the certificate to ACME renewal information (RFC 9773): the key
    /// identifier of its authority and its serial number, as they are encoded in it; `None`
    /// without an authority key identifier.
    pub fn renewal_id(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let leaf = self.0.leaf()?;
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf).ok()?;
        let authority =
            parsed
                .iter_extensions()
                .find_map(|extension| match extension.parsed_extension() {
                    ParsedExtension::AuthorityKeyIdentifier(authority) => {
                        authority.key_identifier.as_ref().map(|id| id.0.to_vec())
                    }
                    _ => None,
                })?;
        Some((authority, parsed.tbs_certificate.raw_serial().to_vec()))
    }
}

impl TlsReport for Certificates {
    /// Returns the certificates in effect, in name order. Validity before 1970 counts as 1970.
    fn certificates(&self) -> Vec<CertificateReport> {
        self.details()
            .into_iter()
            .map(|(name, info)| CertificateReport {
                name,
                not_after: UNIX_EPOCH
                    + Duration::from_secs(u64::try_from(info.not_after).unwrap_or(0)),
            })
            .collect()
    }
}

/// Returns the crypto provider of Wormway's TLS: aws-lc-rs, with post-quantum key exchange
/// first. The other TLS clients of Wormway use it too, whatever the process-wide default of
/// rustls is.
pub fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: LazyLock<Arc<CryptoProvider>> =
        LazyLock::new(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    PROVIDER.clone()
}

#[cfg(test)]
mod tests {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, SerialNumber,
    };

    use super::*;

    /// A certificate signed by an authority tells the key identifier of the authority and its
    /// serial number; a self-signed one has no authority key identifier.
    #[test]
    fn tells_the_renewal_id() {
        let certificates = Certificates::new(".");
        let mut authority = CertificateParams::new(Vec::<String>::new()).unwrap();
        authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = CertifiedIssuer::self_signed(authority, KeyPair::generate().unwrap()).unwrap();
        let mut params = CertificateParams::new(vec!["site.test".to_owned()]).unwrap();
        params.serial_number = Some(SerialNumber::from(vec![1, 2, 3]));
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().unwrap();
        let leaf = params.signed_by(&key, &issuer).unwrap();
        let signed = certificates
            .read_issued(&leaf.pem(), &key.serialize_pem())
            .unwrap();
        let (authority_id, serial) = signed.renewal_id().unwrap();
        assert!(!authority_id.is_empty());
        assert_eq!(serial, [1, 2, 3]);

        let own = KeyPair::generate().unwrap();
        let self_signed = CertificateParams::new(vec!["site.test".to_owned()])
            .unwrap()
            .self_signed(&own)
            .unwrap();
        let unsigned = certificates
            .read_issued(&self_signed.pem(), &own.serialize_pem())
            .unwrap();
        assert_eq!(unsigned.renewal_id(), None);
        let mismatch = certificates.read_issued(&leaf.pem(), &own.serialize_pem());
        assert!(mismatch.is_err());
    }
}
