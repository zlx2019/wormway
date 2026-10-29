//! Helpers shared by the integration tests: upstreams, configurations and servers.

use std::net::SocketAddr;
use std::path::Path;

use axum::extract::Request;
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use zora_core::config::Config;
use zora_gateway::Gateway;
use zora_runtime::{Server, Services};
use zora_tls::Certificates;

/// Starts an upstream that answers `<name> <host> <path>` to every request.
pub async fn upstream(name: &'static str) -> SocketAddr {
    serve(
        axum::Router::new().fallback(move |request: Request| async move {
            let host = request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-");
            format!("{name} {host} {}", request.uri().path())
        }),
    )
    .await
}

/// Serves `app` on a free loopback port and returns the address.
pub async fn serve(app: axum::Router) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    addr
}

/// Parses a configuration, adding `version = 1` in front.
pub fn parse(text: &str) -> Config {
    Config::from_toml(&format!("version = 1\n{text}")).expect("valid configuration")
}

/// Starts a server with the certificates and the gateway on the test runtime. Relative
/// certificate paths are resolved against `certificates_dir`.
pub async fn start(text: &str, certificates_dir: &Path) -> Server {
    let mut services = Services::new();
    let certificates = Certificates::new(certificates_dir);
    certificates.register(&mut services);
    Gateway::new(2, certificates).register(&mut services);
    match Server::start(Handle::current(), services, parse(text)).await {
        Ok(server) => server,
        Err(error) => panic!("cannot start: {error:?}"),
    }
}

/// The first bound address of `listener`.
pub async fn addr(server: &Server, listener: &str) -> SocketAddr {
    server.listeners().await[listener][0]
}
