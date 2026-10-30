//! The control plane of Wormway: the SQLite database with the versions of the dynamic settings,
//! and the Admin API with token authentication and Prometheus metrics. The `ui` feature adds
//! the dashboard.

mod api;
mod prometheus;
mod store;
mod token;
#[cfg(feature = "ui")]
mod ui;

pub use api::{Admin, serve};
pub use prometheus::{Metrics, MetricsError};
pub use store::{AcmeCertificateRecord, ChangeSource, SavedVersion, Store, StoreError};
pub use token::{AdminToken, TokenError};
