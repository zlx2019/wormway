//! What ACME tells the runtime: how the manager is doing with each certificate. Renewals asked
//! for come in the other way, and go on to the manager.

use std::sync::Arc;

use wormway_core::config::Name;
use wormway_runtime::{AcmeCertificateReport, AcmeReport};

use crate::{Shared, lock};

/// Reports the certificates of the manager, and passes renewals on to it.
pub(crate) struct Report {
    /// What the engine and the manager share.
    shared: Arc<Shared>,
}

impl Report {
    /// Creates the report of the manager that `shared` belongs to.
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }
}

impl AcmeReport for Report {
    /// Returns what the manager last told, in name order.
    fn certificates(&self) -> Vec<AcmeCertificateReport> {
        lock(&self.shared.report).clone()
    }

    /// Asks the manager to order `name` again, unless an order of it is in progress already.
    fn renew(&self, name: &Name) -> bool {
        let shared = &self.shared;
        if !shared.desired.borrow().orders.contains_key(name) {
            return false;
        }
        let ordering = lock(&shared.report)
            .iter()
            .any(|certificate| certificate.name == *name && certificate.ordering);
        if !ordering {
            lock(&shared.renewals).insert(name.clone());
            shared.wake.notify_one();
        }
        true
    }
}
