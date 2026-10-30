//! The storage of ACME: its accounts and certificates live in the database of the control plane.

use wormway_acme::{Storage, StoredCertificate};
use wormway_control::{AcmeCertificateRecord, Store};
use wormway_core::config::Name;
use wormway_runtime::{BoxError, BoxFuture};

/// Keeps the accounts and certificates of ACME in the database.
pub struct AcmeStore(pub Store);

impl Storage for AcmeStore {
    /// Reads the credentials of the account at `directory`.
    fn account<'a>(
        &'a self,
        directory: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, BoxError>> {
        Box::pin(async move { Ok(self.0.acme_account(directory).await?) })
    }

    /// Writes the credentials of the account at `directory`.
    fn save_account<'a>(
        &'a self,
        directory: &'a str,
        credentials: &'a str,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move { Ok(self.0.save_acme_account(directory, credentials).await?) })
    }

    /// Reads the certificate of `name`.
    fn certificate<'a>(
        &'a self,
        name: &'a Name,
    ) -> BoxFuture<'a, Result<Option<StoredCertificate>, BoxError>> {
        Box::pin(async move {
            let record = self.0.acme_certificate(name.as_str()).await?;
            Ok(record.map(|record| StoredCertificate {
                directory: record.directory,
                domains: record.domains,
                chain: record.chain,
                key: record.key,
            }))
        })
    }

    /// Writes the certificate of `name`.
    fn save_certificate<'a>(
        &'a self,
        name: &'a Name,
        certificate: &'a StoredCertificate,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            let record = AcmeCertificateRecord {
                directory: certificate.directory.clone(),
                domains: certificate.domains.clone(),
                chain: certificate.chain.clone(),
                key: certificate.key.clone(),
            };
            Ok(self.0.save_acme_certificate(name.as_str(), &record).await?)
        })
    }

    /// Deletes the certificate of `name`.
    fn remove_certificate<'a>(&'a self, name: &'a Name) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move { Ok(self.0.remove_acme_certificate(name.as_str()).await?) })
    }
}
