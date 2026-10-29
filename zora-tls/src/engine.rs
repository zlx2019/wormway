//! The engine of the certificates: loads them for every configuration and publishes them when
//! the change commits.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use rustls::crypto::CryptoProvider;
use tracing::{info, warn};
use x509_parser::time::ASN1Time;
use zora_core::config::{Certificate, Config, Issue, Name};
use zora_runtime::{BoxFuture, Engine, Staged};

use crate::load::{Loaded, load};
use crate::provider;
use crate::resolve::TlsSnapshot;

/// Loads the certificates of every configuration and indexes them for its TLS listeners. The
/// files are read every time, so that replaced files take effect on the next change or reload.
pub(crate) struct Loader {
    /// Directory that relative certificate paths are resolved against.
    base: PathBuf,
    /// Where the certificates in effect are published.
    snapshot: Arc<ArcSwap<TlsSnapshot>>,
}

impl Loader {
    /// Creates the engine that publishes to `snapshot`.
    pub(crate) fn new(base: PathBuf, snapshot: Arc<ArcSwap<TlsSnapshot>>) -> Self {
        Self { base, snapshot }
    }
}

impl Engine for Loader {
    /// Loads every certificate of `config` and indexes them for its TLS listeners.
    fn prepare<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<Box<dyn Staged>, Vec<Issue>>> {
        Box::pin(async move {
            let base = self.base.clone();
            let settings = config.certificates.clone();
            // Reading files and parsing keys block, so they run on the blocking pool.
            let loaded =
                tokio::task::spawn_blocking(move || load_all(&provider(), &base, &settings))
                    .await
                    .map_err(|error| {
                        vec![Issue::new(
                            "certificates",
                            format!("loading stopped: {error}"),
                        )]
                    })??;
            let staged: Box<dyn Staged> = Box::new(Publish {
                target: self.snapshot.clone(),
                next: Arc::new(TlsSnapshot::new(loaded, &config.listeners)),
            });
            Ok(staged)
        })
    }
}

/// Loads every certificate of `settings`; the problems of all of them come back together.
fn load_all(
    provider: &CryptoProvider,
    base: &Path,
    settings: &BTreeMap<Name, Certificate>,
) -> Result<BTreeMap<Name, Arc<Loaded>>, Vec<Issue>> {
    let mut loaded = BTreeMap::new();
    let mut issues = Vec::new();
    for (name, certificate) in settings {
        match load(provider, base, name, certificate) {
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
    target: Arc<ArcSwap<TlsSnapshot>>,
    /// The certificates and the listener indexes.
    next: Arc<TlsSnapshot>,
}

impl Staged for Publish {
    /// Publishes the certificates for new handshakes and logs the ones that changed.
    fn commit(self: Box<Self>) {
        let previous = self.target.swap(self.next.clone());
        log_changes(&previous, &self.next);
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
