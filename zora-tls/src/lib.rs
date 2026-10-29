//! TLS of zora: the certificates of the listeners, and the rustls settings that present them.
//!
//! [`Certificates`] loads the certificates of every configuration as an engine of the runtime,
//! and builds the rustls [`ServerConfig`] of each TLS listener. A handshake gets, among the
//! certificates of its listener, the one whose names cover the host name the client sends
//! (SNI). Replaced certificate files take effect for new handshakes when the configuration is
//! applied again, without touching the listeners or their connections.
//!
//! Signatures and key exchange use aws-lc-rs, with post-quantum key exchange first, whatever
//! the process-wide default of rustls is.

mod engine;
mod load;
mod resolve;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::server::ServerSessionMemoryCache;
use zora_core::config::{Issue, Name};
use zora_runtime::Services;

use crate::engine::Loader;
pub use crate::load::{CertificateInfo, ClientCertificate};
use crate::resolve::{ListenerResolver, TlsSnapshot};

/// TLS 1.2 sessions that each listener keeps for resumption by session ID.
const SESSION_CACHE_SIZE: usize = 4096;

/// The certificates of the listeners. Clones share them.
#[derive(Clone)]
pub struct Certificates {
    /// Directory that relative certificate paths are resolved against.
    base: PathBuf,
    /// The certificates in effect and the index of every TLS listener.
    snapshot: Arc<ArcSwap<TlsSnapshot>>,
}

impl Certificates {
    /// Creates the certificates of a configuration file in directory `base`: relative
    /// certificate paths are resolved against it.
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: base.into(),
            snapshot: Arc::default(),
        }
    }

    /// Registers the engine that loads the certificates of every configuration with
    /// `services`.
    pub fn register(&self, services: &mut Services) {
        services.add_engine(Loader::new(self.base.clone(), self.snapshot.clone()));
    }

    /// Builds the rustls settings of TLS listener `listener`, which offers the application
    /// protocols `alpn`, such as `h2` and `http/1.1`, in order of preference. Every handshake
    /// takes its certificate from the ones in effect when it starts.
    pub fn server_config(
        &self,
        listener: &Name,
        alpn: &[&[u8]],
    ) -> Result<Arc<ServerConfig>, rustls::Error> {
        let resolver = ListenerResolver::new(listener.clone(), self.snapshot.clone());
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
        self.snapshot
            .load()
            .certificates
            .iter()
            .map(|(name, loaded)| (name.clone(), loaded.info.clone()))
            .collect()
    }
}

/// The crypto provider of zora's TLS: aws-lc-rs, with post-quantum key exchange first.
fn provider() -> Arc<CryptoProvider> {
    static PROVIDER: LazyLock<Arc<CryptoProvider>> =
        LazyLock::new(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    PROVIDER.clone()
}
