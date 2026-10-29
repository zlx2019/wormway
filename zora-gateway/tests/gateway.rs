//! Integration tests of the gateway: a runtime server with the gateway in front of axum
//! upstreams, driven by reqwest and by a raw HTTP/1.1 client that shows the connection handling.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::Request;
use axum::routing::get;
use reqwest::StatusCode;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Handle;
use zora_core::config::Config;
use zora_gateway::Gateway;
use zora_runtime::{Server, Services};

/// A listener on any free loopback port.
const WEB: &str = "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";

/// Starts an upstream that answers `<name> <host> <path>` to every request, and `<name>` to
/// `/slow` after 300 ms.
async fn upstream(name: &'static str) -> SocketAddr {
    let app = axum::Router::new()
        .route(
            "/slow",
            get(move || async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                name
            }),
        )
        .fallback(move |request: Request| async move {
            let host = request
                .headers()
                .get("host")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-");
            format!("{name} {host} {}", request.uri().path())
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    tokio::spawn(async move { axum::serve(listener, app).await.expect("serve") });
    addr
}

/// A loopback address where nothing listens.
fn dead_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("local address")
}

/// Parses a configuration, adding `version = 1` in front.
fn parse(text: &str) -> Config {
    Config::from_toml(&format!("version = 1\n{text}")).expect("valid configuration")
}

/// A listener named `web` with the given keep-alive timeout, and one route to `addr`.
fn proxy_to(addr: SocketAddr, keepalive: &str) -> String {
    format!(
        "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\nhttp = {{ keepalive_timeout = \"{keepalive}\" }}\n[routes.all]\nupstream = \"app\"\n[upstreams.app]\ntargets = [\"{addr}\"]\n"
    )
}

/// Starts a server with the gateway on the test runtime.
async fn start(text: &str) -> Server {
    let mut services = Services::new();
    Gateway::new(2).register(&mut services);
    match Server::start(Handle::current(), services, parse(text)).await {
        Ok(server) => server,
        Err(error) => panic!("cannot start: {error:?}"),
    }
}

/// The first bound address of `listener`.
async fn addr(server: &Server, listener: &str) -> SocketAddr {
    server.listeners().await[listener][0]
}

/// Sends `GET path` with a `Host` header to `addr`, ignoring the proxy settings of the
/// environment, and returns the status and the body.
async fn get_with_host(addr: SocketAddr, host: &str, path: &str) -> (StatusCode, String) {
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("client");
    let response = client
        .get(format!("http://{addr}{path}"))
        .header("host", host)
        .send()
        .await
        .expect("send");
    let status = response.status();
    (status, response.text().await.expect("body"))
}

/// One HTTP/1.1 connection, written and read by hand to see how the server handles it.
struct Raw {
    /// The connection.
    stream: BufReader<TcpStream>,
}

/// A response read from a raw connection.
struct RawResponse {
    /// Status code.
    status: u16,
    /// Headers with lowercase names.
    headers: HashMap<String, String>,
    /// Body, read by its `Content-Length`.
    body: String,
}

impl RawResponse {
    /// Returns the value of header `name`.
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

impl Raw {
    /// Connects to `addr`.
    async fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("connect");
        Self {
            stream: BufReader::new(stream),
        }
    }

    /// Sends `GET path` and reads the response.
    async fn get(&mut self, path: &str) -> RawResponse {
        self.send(path).await;
        self.response().await
    }

    /// Sends `GET path` with host `test`.
    async fn send(&mut self, path: &str) {
        let request = format!("GET {path} HTTP/1.1\r\nHost: test\r\n\r\n");
        self.stream
            .get_mut()
            .write_all(request.as_bytes())
            .await
            .expect("write");
    }

    /// Reads one response.
    async fn response(&mut self) -> RawResponse {
        let mut line = String::new();
        self.stream.read_line(&mut line).await.expect("status line");
        let status = line
            .split(' ')
            .nth(1)
            .and_then(|code| code.parse().ok())
            .unwrap_or_else(|| panic!("bad status line {line:?}"));
        let mut headers = HashMap::new();
        loop {
            line.clear();
            self.stream.read_line(&mut line).await.expect("header");
            let Some((name, value)) = line.trim_end().split_once(':') else {
                break;
            };
            headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        let length: usize = headers
            .get("content-length")
            .and_then(|length| length.parse().ok())
            .expect("content-length");
        let mut body = vec![0; length];
        self.stream.read_exact(&mut body).await.expect("body");
        RawResponse {
            status,
            headers,
            body: String::from_utf8(body).expect("UTF-8 body"),
        }
    }

    /// Whether the server closes the connection within `limit`.
    async fn closed_within(&mut self, limit: Duration) -> bool {
        let mut byte = [0; 1];
        matches!(
            tokio::time::timeout(limit, self.stream.read(&mut byte)).await,
            Ok(Ok(0))
        )
    }
}

/// Exact hosts beat wildcards, a longer path beats a shorter one, the `Host` header reaches the
/// upstream unchanged, and requests without a route get 404.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn routes_by_host_and_path() {
    let a = upstream("a").await;
    let b = upstream("b").await;
    let server = start(&format!(
        r#"{WEB}
        [routes.api]
        match = {{ hosts = ["api.example.com"], paths = ["/v1/"] }}
        upstream = "a"
        [routes.site]
        match = {{ hosts = ["*.example.com"] }}
        upstream = "b"
        [upstreams.a]
        targets = ["{a}"]
        [upstreams.b]
        targets = ["{b}"]
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let ok = |body: &str| (StatusCode::OK, body.to_owned());
    assert_eq!(
        get_with_host(web, "api.example.com", "/v1/users").await,
        ok("a api.example.com /v1/users")
    );
    assert_eq!(
        get_with_host(web, "API.Example.com:8080", "/v1/").await,
        ok("a API.Example.com:8080 /v1/")
    );
    assert_eq!(
        get_with_host(web, "api.example.com", "/v2/").await,
        ok("b api.example.com /v2/")
    );
    assert_eq!(
        get_with_host(web, "www.example.com", "/v1/users").await,
        ok("b www.example.com /v1/users")
    );
    let (status, _) = get_with_host(web, "example.org", "/").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Requests go to the targets in turn, in proportion to their weights.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balances_by_weight() {
    let a = upstream("a").await;
    let b = upstream("b").await;
    let server = start(&format!(
        "{WEB}[routes.all]\nupstream = \"app\"\n[upstreams.app]\ntargets = [\"{a}\", {{ address = \"{b}\", weight = 2 }}]\n"
    ))
    .await;
    let web = addr(&server, "web").await;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for _ in 0..30 {
        let (_, body) = get_with_host(web, "test", "/").await;
        let target = body.split(' ').next().unwrap_or_default().to_owned();
        *counts.entry(target).or_default() += 1;
    }
    assert_eq!(counts, HashMap::from([("a".into(), 10), ("b".into(), 20)]));
}

/// A target that refuses connections gives 502.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_bad_gateway_when_the_target_is_down() {
    let server = start(&proxy_to(dead_addr(), "75s")).await;
    let (status, _) = get_with_host(addr(&server, "web").await, "test", "/").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
}

/// A new configuration applies to the next request of an open connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applies_new_routes_to_open_connections() {
    let a = upstream("a").await;
    let b = upstream("b").await;
    let server = start(&proxy_to(a, "75s")).await;
    let mut raw = Raw::connect(addr(&server, "web").await).await;
    assert_eq!(raw.get("/").await.body, "a test /");

    server
        .apply(parse(&proxy_to(b, "75s")))
        .await
        .expect("apply");
    let response = raw.get("/").await;
    assert_eq!(response.body, "b test /");
    assert_eq!(response.header("connection"), Some("keep-alive"));
}

/// Kept-alive connections close after the keep-alive timeout of their listener, and the default
/// timeout keeps them open longer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closes_idle_connections_after_the_keepalive_timeout() {
    let a = upstream("a").await;
    let server = start(&format!(
        "{}[listeners.default]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n",
        proxy_to(a, "1s")
    ))
    .await;
    let mut short = Raw::connect(addr(&server, "web").await).await;
    let mut default = Raw::connect(addr(&server, "default").await).await;
    assert_eq!(
        short.get("/").await.header("connection"),
        Some("keep-alive")
    );
    assert_eq!(default.get("/").await.status, 200);

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(short.closed_within(Duration::from_secs(1)).await);
    assert_eq!(default.get("/").await.status, 200);
}

/// A keep-alive timeout of zero closes every connection after its response.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_keepalive_closes_after_each_response() {
    let server = start(&proxy_to(upstream("a").await, "0s")).await;
    let mut raw = Raw::connect(addr(&server, "web").await).await;
    let response = raw.get("/").await;
    assert_eq!(response.status, 200);
    assert_eq!(response.header("connection"), Some("close"));
    assert!(raw.closed_within(Duration::from_secs(1)).await);
}

/// A request in flight when its listener starts draining completes, and its response asks the
/// client to close the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn asks_clients_to_close_while_draining() {
    let a = upstream("a").await;
    let server = start(&proxy_to(a, "75s")).await;
    let mut raw = Raw::connect(addr(&server, "web").await).await;
    raw.send("/slow").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // New HTTP settings give the listener a new service, and the old one drains.
    server
        .apply(parse(&proxy_to(a, "30s")))
        .await
        .expect("apply");
    let response = raw.response().await;
    assert_eq!(response.status, 200);
    assert_eq!(response.body, "a");
    assert_eq!(response.header("connection"), Some("close"));
    assert!(raw.closed_within(Duration::from_secs(1)).await);
}

/// Removing a listener closes its idle kept-alive connections at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closes_idle_connections_of_removed_listeners() {
    let a = upstream("a").await;
    let server = start(&proxy_to(a, "75s")).await;
    let mut raw = Raw::connect(addr(&server, "web").await).await;
    assert_eq!(raw.get("/").await.status, 200);

    server.apply(parse("")).await.expect("apply");
    assert!(raw.closed_within(Duration::from_secs(1)).await);
}
