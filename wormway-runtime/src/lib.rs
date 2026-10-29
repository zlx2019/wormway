//! The Wormway runtime: owns the listeners, hands each accepted connection to the service of its
//! protocol, switches to new configurations without dropping connections, and drains them on
//! shutdown.
//!
//! Protocols plug in through [`ServiceFactory`], and state shared by their services, such as a
//! routing table, through [`Engine`]; [`Server`] runs the listeners of a configuration and
//! applies new ones.

mod engine;
mod host;
mod server;
mod service;
mod snapshot;
mod socket;
mod telemetry;

pub use engine::{Engine, Staged};
pub use server::{ApplyError, Prepared, Server};
pub use service::{BoxError, BoxFuture, Connection, Service, ServiceFactory, Services, Shutdown};
pub use snapshot::Snapshot;
