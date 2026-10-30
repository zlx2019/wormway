//! Helpers shared by the integration tests: storage in memory.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use wormway_acme::{Storage, StoredCertificate};
use wormway_core::config::Name;
use wormway_runtime::{BoxError, BoxFuture};

/// Storage in memory, shared by its clones, that remembers what was removed.
#[derive(Clone, Default)]
pub struct Memory {
    /// Credentials of the accounts, by directory.
    pub accounts: Arc<Mutex<BTreeMap<String, String>>>,
    /// Certificates by name.
    pub certificates: Arc<Mutex<BTreeMap<Name, StoredCertificate>>>,
    /// Names of the certificates removed.
    pub removed: Arc<Mutex<Vec<Name>>>,
}

impl Storage for Memory {
    /// Returns the credentials of the account at `directory`.
    fn account<'a>(
        &'a self,
        directory: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>, BoxError>> {
        Box::pin(async move { Ok(self.accounts.lock().expect("lock").get(directory).cloned()) })
    }

    /// Keeps the credentials of the account at `directory`.
    fn save_account<'a>(
        &'a self,
        directory: &'a str,
        credentials: &'a str,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            let mut accounts = self.accounts.lock().expect("lock");
            accounts.insert(directory.to_owned(), credentials.to_owned());
            Ok(())
        })
    }

    /// Returns the certificate of `name`.
    fn certificate<'a>(
        &'a self,
        name: &'a Name,
    ) -> BoxFuture<'a, Result<Option<StoredCertificate>, BoxError>> {
        Box::pin(async move { Ok(self.certificates.lock().expect("lock").get(name).cloned()) })
    }

    /// Keeps the certificate of `name`.
    fn save_certificate<'a>(
        &'a self,
        name: &'a Name,
        certificate: &'a StoredCertificate,
    ) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            let mut certificates = self.certificates.lock().expect("lock");
            certificates.insert(name.clone(), certificate.clone());
            Ok(())
        })
    }

    /// Drops the certificate of `name` and notes it.
    fn remove_certificate<'a>(&'a self, name: &'a Name) -> BoxFuture<'a, Result<(), BoxError>> {
        Box::pin(async move {
            self.certificates.lock().expect("lock").remove(name);
            self.removed.lock().expect("lock").push(name.clone());
            Ok(())
        })
    }
}
