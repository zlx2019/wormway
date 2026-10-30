//! Answers to the HTTP-01 challenges of ACME: the gateway serves them at
//! `/.well-known/acme-challenge/<token>` while a certificate is being issued.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

/// The answers to the HTTP-01 challenges in progress: the key authorization of each token.
/// Clones share them.
#[derive(Clone, Debug, Default)]
pub struct Challenges(Arc<Mutex<HashMap<String, String>>>);

impl Challenges {
    /// Starts answering `token` with `key_authorization`.
    pub fn insert(&self, token: &str, key_authorization: &str) {
        self.lock()
            .insert(token.to_owned(), key_authorization.to_owned());
    }

    /// Stops answering `token`.
    pub fn remove(&self, token: &str) {
        self.lock().remove(token);
    }

    /// Returns the answer to `token`, if a challenge for it is in progress.
    pub fn answer(&self, token: &str) -> Option<String> {
        self.lock().get(token).cloned()
    }

    /// Locks the answers; a holder that panicked left them whole, so the lock is taken anyway.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
