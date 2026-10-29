//! How protocols plug in: a factory builds one service per listener, and the service serves the
//! connections that listener accepts. Engines build the state that the services share.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::watch;
use zora_core::config::{Listener, Name, Protocol};

use crate::engine::Engine;

/// A boxed future, as returned by [`Service`] and [`Engine`] methods.
pub type BoxFuture<'a, T = ()> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Error type of [`ServiceFactory::create`].
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Turns `true` when the service starts draining: finish the work in progress, then close the
/// connection. It is the same type as Pingora's `ShutdownWatch`.
pub type Shutdown = watch::Receiver<bool>;

/// An accepted connection.
#[derive(Debug)]
pub struct Connection {
    /// The TCP stream.
    pub stream: TcpStream,
    /// Address of the client.
    pub peer: SocketAddr,
}

/// Serves the connections of one listener.
///
/// Every listener has its own service. When the settings of a listener change, new connections
/// go to a new service, and the old one keeps its connections until they end or the shutdown
/// timeout closes them.
pub trait Service: Send + Sync + 'static {
    /// Serves one connection until it ends.
    fn serve(self: Arc<Self>, conn: Connection, shutdown: Shutdown) -> BoxFuture<'static>;

    /// Called once when the service starts draining, after `shutdown` turned `true`. Close idle
    /// connections here, such as HTTP keep-alive connections waiting for their next request.
    fn drain(&self) -> BoxFuture<'_> {
        Box::pin(async {})
    }
}

/// Builds the services of one protocol.
pub trait ServiceFactory: Send + Sync + 'static {
    /// Builds the service of listener `name`.
    fn create(&self, name: &Name, listener: &Listener) -> Result<Arc<dyn Service>, BoxError>;
}

/// Service factories by protocol, and the engines that build their shared state. A listener
/// whose protocol has no factory is rejected.
#[derive(Default)]
pub struct Services {
    /// The factory of each available protocol.
    factories: HashMap<Protocol, Arc<dyn ServiceFactory>>,
    /// Engines in the order they were added, which is the order they prepare and commit in.
    engines: Vec<Arc<dyn Engine>>,
}

impl Services {
    /// Creates an empty set, which rejects every listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers the factory of `protocol`, replacing any previous one.
    pub fn register(&mut self, protocol: Protocol, factory: impl ServiceFactory) {
        self.factories.insert(protocol, Arc::new(factory));
    }

    /// Adds an engine. Engines prepare and commit in the order they were added.
    pub fn add_engine(&mut self, engine: impl Engine) {
        self.engines.push(Arc::new(engine));
    }

    /// Returns the factory of `protocol`.
    pub(crate) fn get(&self, protocol: Protocol) -> Option<&Arc<dyn ServiceFactory>> {
        self.factories.get(&protocol)
    }

    /// Returns the engines in the order they were added.
    pub(crate) fn engines(&self) -> &[Arc<dyn Engine>] {
        &self.engines
    }
}
