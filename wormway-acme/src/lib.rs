//! ACME for Wormway: gets the certificates that the configuration asks for through ACME, from
//! Let's Encrypt or another certificate authority, and renews them before they expire.
//!
//! [`Acme::register`] adds an engine to the runtime: for every configuration, it learns the
//! certificates to get through ACME, reads the tokens of their DNS providers, and installs the
//! certificates issued before as the change commits. [`Acme::run`] orders the missing
//! certificates and renews the others, one at a time, on the runtime of the control plane. The
//! HTTP listeners answer HTTP-01 challenges from the [`Challenges`](wormway_tls::Challenges) of
//! the certificates; DNS-01 challenges go through the DNS provider of the certificate. Accounts
//! and issued certificates live in a [`Storage`].

mod cloudflare;
mod engine;
mod https;
mod issue;
mod manager;
mod schedule;
mod secret;

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::watch;
use wormway_core::config::{AcmeSettings, Name};
use wormway_runtime::{BoxError, BoxFuture, Services};
use wormway_tls::{Certificates, IssuedCertificate};

use crate::engine::{AcmeEngine, Desired};

/// Certificates ordered through ACME, by result.
const RENEWALS_TOTAL: &str = "wormway_acme_renewals_total";

/// Where ACME keeps its accounts and the certificates it issued, such as the database of the
/// control plane.
pub trait Storage: Send + Sync + 'static {
    /// Returns the credentials of the account at ACME directory `directory`, if saved.
    fn account<'a>(&'a self, directory: &'a str)
    -> BoxFuture<'a, Result<Option<String>, BoxError>>;

    /// Saves the credentials of the account at ACME directory `directory`.
    fn save_account<'a>(
        &'a self,
        directory: &'a str,
        credentials: &'a str,
    ) -> BoxFuture<'a, Result<(), BoxError>>;

    /// Returns the certificate issued for certificate `name`, if saved.
    fn certificate<'a>(
        &'a self,
        name: &'a Name,
    ) -> BoxFuture<'a, Result<Option<StoredCertificate>, BoxError>>;

    /// Saves `certificate` as the one issued for certificate `name`, in place of any before.
    fn save_certificate<'a>(
        &'a self,
        name: &'a Name,
        certificate: &'a StoredCertificate,
    ) -> BoxFuture<'a, Result<(), BoxError>>;

    /// Removes the certificate issued for certificate `name`, if there is one.
    fn remove_certificate<'a>(&'a self, name: &'a Name) -> BoxFuture<'a, Result<(), BoxError>>;
}

/// A certificate issued through ACME, as kept: what it was ordered for, and its chain and key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCertificate {
    /// The ACME directory that issued it.
    pub directory: String,
    /// The host names it was ordered for, sorted.
    pub domains: Vec<String>,
    /// The certificate chain, leaf first, as PEM.
    pub chain: String,
    /// The private key, as PEM.
    pub key: String,
}

/// Gets and renews the certificates that the configuration asks for through ACME.
pub struct Acme {
    /// What the engine and the manager share.
    shared: Arc<Shared>,
    /// The certificates of the configuration in effect, as the engine hands them over.
    desired: watch::Receiver<Arc<Desired>>,
}

impl Acme {
    /// Creates ACME as `settings` say, installing the certificates in `certificates` and
    /// keeping them in `storage`. Relative paths are resolved against `base`, the directory of
    /// the configuration file.
    pub fn new(
        settings: &AcmeSettings,
        certificates: Certificates,
        storage: impl Storage,
        base: impl Into<PathBuf>,
    ) -> Self {
        let base = base.into();
        metrics::describe_counter!(
            RENEWALS_TOTAL,
            "Certificates ordered through ACME, first ones and renewals, by result (ok or error)."
        );
        let (desired, receiver) = watch::channel(Arc::default());
        let shared = Shared {
            directory: settings.directory_url().to_owned(),
            contact: settings
                .email
                .as_ref()
                .map(|email| format!("mailto:{email}")),
            ca: settings.ca.as_ref().map(|ca| base.join(ca)),
            certificates,
            storage: Box::new(storage),
            base,
            desired,
        };
        Self {
            shared: Arc::new(shared),
            desired: receiver,
        }
    }

    /// Registers the engine that learns the ACME certificates of every configuration with
    /// `services`.
    pub fn register(&self, services: &mut Services) {
        services.add_engine(AcmeEngine::new(self.shared.clone()));
    }

    /// Orders the missing certificates and renews the others before they expire, one at a time,
    /// for as long as the runtime runs.
    pub async fn run(self) {
        manager::run(self.shared, self.desired).await;
    }
}

/// Returns `error` with the errors that caused it, as `outer: inner: innermost`, leaving out a
/// cause whose text the error shows already.
pub(crate) fn reason(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        let more = next.to_string();
        if !text.contains(&more) {
            text.push_str(": ");
            text.push_str(&more);
        }
        cause = next.source();
    }
    text
}

/// What the engine and the manager share.
pub(crate) struct Shared {
    /// URL of the ACME directory.
    directory: String,
    /// Contact of the account, as a `mailto:` URL.
    contact: Option<String>,
    /// PEM file with the authorities that the HTTPS certificate of the directory is checked
    /// against; those of the system without one.
    ca: Option<PathBuf>,
    /// Where certificates are installed and HTTP-01 challenges answered.
    certificates: Certificates,
    /// Where accounts and certificates are kept.
    storage: Box<dyn Storage>,
    /// Directory of the configuration file, for secrets in files.
    base: PathBuf,
    /// Hands the certificates of the configuration in effect to the manager.
    desired: watch::Sender<Arc<Desired>>,
}

impl Shared {
    /// Returns the certificate issued before for certificate `name` by the directory in effect
    /// for exactly `domains`, read and checked, if there is one.
    async fn stored(&self, name: &Name, domains: &[String]) -> Option<IssuedCertificate> {
        let stored = match self.storage.certificate(name).await {
            Ok(stored) => stored?,
            Err(error) => {
                tracing::warn!(certificate = %name, "cannot read the stored certificate: {}", reason(&*error));
                return None;
            }
        };
        if stored.directory != self.directory || stored.domains != domains {
            return None;
        }
        match self.certificates.read_issued(&stored.chain, &stored.key) {
            Ok(issued) => Some(issued),
            Err(error) => {
                tracing::warn!(certificate = %name, "the stored certificate is unusable: {error}");
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::*;

    /// An error with a message and maybe a cause.
    #[derive(Debug)]
    struct Failure(&'static str, Option<Box<Failure>>);

    impl fmt::Display for Failure {
        /// Writes the message.
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Failure {
        /// Returns the cause.
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|cause| cause as _)
        }
    }

    /// Causes follow the error, unless the error tells them already.
    #[test]
    fn tells_the_causes() {
        let refused = Failure("connection refused", None);
        let connect = Failure("tcp connect error", Some(Box::new(refused)));
        let client = Failure("client error (Connect)", Some(Box::new(connect)));
        assert_eq!(
            reason(&client),
            "client error (Connect): tcp connect error: connection refused"
        );
        let telling = Failure(
            "cannot connect: connection refused",
            Some(Box::new(Failure("connection refused", None))),
        );
        assert_eq!(reason(&telling), "cannot connect: connection refused");
    }
}
