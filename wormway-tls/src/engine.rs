//! The engine of the certificates: loads those read from files for every configuration, and
//! publishes them when the change commits, together with those that ACME issued.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::crypto::CryptoProvider;
use tracing::{info, warn};
use wormway_core::config::{Certificate, Config, Issue, Name};
use wormway_runtime::{BoxFuture, Engine, Staged};
use x509_parser::time::ASN1Time;

use crate::load::{Loaded, load};
use crate::provider;
use crate::publish::{ConfigCertificates, Published};
use crate::resolve::TlsSnapshot;

/// Loads the certificates of every configuration that come from files, and notes the ones that
/// ACME issues. The files are read every time, so that replaced files take effect on the next
/// change or reload.
pub(crate) struct Loader {
    /// Directory that relative certificate paths are resolved against.
    base: PathBuf,
    /// Where the certificates in effect are published.
    published: Arc<Published>,
}

impl Loader {
    /// Creates the engine that publishes to `published`.
    pub(crate) fn new(base: PathBuf, published: Arc<Published>) -> Self {
        Self { base, published }
    }
}

impl Engine for Loader {
    /// Loads the certificates of `config` that come from files, and takes its TLS listeners.
    fn prepare<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<Box<dyn Staged>, Vec<Issue>>> {
        Box::pin(async move {
            let base = self.base.clone();
            let settings = config.certificates.clone();
            // Reading files and parsing keys block, so they run on the blocking pool.
            let files =
                tokio::task::spawn_blocking(move || load_all(&provider(), &base, &settings))
                    .await
                    .map_err(|error| {
                        vec![Issue::new(
                            "certificates",
                            format!("loading stopped: {error}"),
                        )]
                    })??;
            let acme = config
                .certificates
                .iter()
                .filter(|(_, certificate)| certificate.acme.is_some())
                .map(|(name, _)| name.clone())
                .collect();
            let next = ConfigCertificates {
                files,
                acme,
                listeners: ConfigCertificates::tls_listeners(&config.listeners),
            };
            let staged: Box<dyn Staged> = Box::new(Publish {
                target: self.published.clone(),
                next: Arc::new(next),
            });
            Ok(staged)
        })
    }
}

/// Loads every certificate of `settings` that comes from files; the problems of all of them
/// come back together.
fn load_all(
    provider: &CryptoProvider,
    base: &Path,
    settings: &BTreeMap<Name, Certificate>,
) -> Result<BTreeMap<Name, Arc<Loaded>>, Vec<Issue>> {
    let mut loaded = BTreeMap::new();
    let mut issues = Vec::new();
    for (name, certificate) in settings {
        // Validation made sure that the others get their certificates through ACME.
        let (Some(cert), Some(key)) = (&certificate.cert, &certificate.key) else {
            continue;
        };
        match load(provider, base, name, cert, key) {
            Ok(certificate) => {
                loaded.insert(name.clone(), Arc::new(certificate));
            }
            Err(issue) => issues.push(issue),
        }
    }
    if issues.is_empty() {
        Ok(loaded)
    } else {
        Err(issues)
    }
}

/// Certificates loaded for a change, waiting to be published.
struct Publish {
    /// Where to publish them.
    target: Arc<Published>,
    /// The certificates and the TLS listeners of the change.
    next: Arc<ConfigCertificates>,
}

impl Staged for Publish {
    /// Publishes the certificates for new handshakes and logs the ones that changed.
    fn commit(self: Box<Self>) {
        let previous = self.target.set_config(self.next);
        log_changes(&previous, &self.target.snapshot.load());
    }
}

/// Logs the certificates that are new or changed, with a warning for the expired ones and for
/// the ones that cover no host name.
fn log_changes(previous: &TlsSnapshot, next: &TlsSnapshot) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        });
    for (name, loaded) in &next.certificates {
        let unchanged = previous
            .certificates
            .get(name)
            .is_some_and(|old| old.leaf() == loaded.leaf());
        if unchanged {
            continue;
        }
        let details = &loaded.info;
        let expires = ASN1Time::from_timestamp(details.not_after)
            .map_or_else(|_| details.not_after.to_string(), |time| time.to_string());
        if details.not_after <= now {
            warn!(certificate = %name, names = ?details.names, %expires, "certificate loaded, but it has expired");
        } else if details.names.is_empty() {
            warn!(certificate = %name, %expires, "certificate loaded, but it covers no host name, so only clients without a known name get it");
        } else {
            info!(certificate = %name, names = ?details.names, %expires, "certificate loaded");
        }
    }
}
