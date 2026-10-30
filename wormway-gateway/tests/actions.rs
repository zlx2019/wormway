//! Integration tests of what routes do besides forwarding: redirects, fixed responses, path
//! rewrites, header changes, the headers that tell upstreams about clients, and compression;
//! and of the answers to the HTTP-01 challenges of ACME, which come before every route.

mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use axum::extract::Request;
use axum::http::StatusCode;
use axum::routing::get;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use wormway_runtime::Server;
use wormway_tls::Certificates;

use crate::common::{addr, serve, upstream};

/// How long any exchange of a test may take, so that a test that hangs fails instead.
const LIMIT: Duration = Duration::from_secs(10);

/// A listener on any free loopback port, which also accepts HTTP/2 without TLS.
const WEB: &str =
    "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\nhttp = { h2c = true }\n";

/// Starts a server with the gateway on the test runtime, without certificates.
async fn start(text: &str) -> Server {
    common::start(&format!("{WEB}{text}"), Path::new(".")).await
}

/// A client that ignores the proxy settings of the environment, does not follow redirects, does
/// not ask for compression, and gives up on a request after [`LIMIT`].
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(LIMIT)
        .build()
        .expect("client")
}

/// Starts an upstream that answers with the request line, then the request headers, one per
/// line and sorted.
async fn echo_upstream() -> SocketAddr {
    serve(axum::Router::new().fallback(|request: Request| async move {
        let mut lines: Vec<String> = request
            .headers()
            .iter()
            .map(|(name, value)| format!("{name}: {}", value.to_str().unwrap_or("?")))
            .collect();
        lines.sort();
        format!(
            "{} {}\n{}",
            request.method(),
            request.uri(),
            lines.join("\n")
        )
    }))
    .await
}

/// Text that compresses well.
fn text() -> String {
    "Wormway compresses text. ".repeat(100)
}

/// Starts an upstream with the same text as a page, as a stream of server-sent events and as
/// partial content.
async fn content_upstream() -> SocketAddr {
    let page = || async {
        let headers = [
            ("content-type", "text/plain"),
            ("server-timing", "app;dur=1"),
            ("x-upstream", "app"),
        ];
        (headers, text())
    };
    let events = || async { ([("content-type", "text/event-stream")], text()) };
    let partial = || async {
        let headers = [
            ("content-type", "text/plain"),
            ("content-range", "bytes 0-2199/5000"),
        ];
        (StatusCode::PARTIAL_CONTENT, headers, text())
    };
    let app = axum::Router::new()
        .route("/text", get(page))
        .route("/events", get(events))
        .route("/partial", get(partial));
    serve(app).await
}

/// Sends `request`, an HTTP/1.0 request that ends with an empty line, on a new connection and
/// returns the status code of the response, read until the server closes the connection.
async fn raw_status(addr: SocketAddr, request: &str) -> u16 {
    let exchange = async {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(request.as_bytes()).await.expect("write");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("read");
        response
    };
    let response = tokio::time::timeout(LIMIT, exchange)
        .await
        .expect("the server closes the connection after the response");
    let response = String::from_utf8_lossy(&response);
    response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("bad response {response:?}"))
}

/// Redirects fill in the host name and the request target, with the status and the response
/// headers of the route; without a host name to fill in, the answer is 400.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redirects_with_placeholders() {
    let server = start(
        r#"
        [routes.https]
        redirect = { to = "https://{host}{uri}", status = 301 }
        response_headers = { set = { "Cache-Control" = "no-store" } }
        [routes.moved]
        match = { paths = ["/old"] }
        redirect = { to = "/new" }
        "#,
    )
    .await;
    let web = addr(&server, "web").await;
    let response = client()
        .get(format!("http://{web}/a%20b/c?x=1&y=2"))
        .header("host", "example.com:8080")
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
    let headers = response.headers();
    assert_eq!(headers["location"], "https://example.com/a%20b/c?x=1&y=2");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["content-length"], "0");

    let response = client()
        .get(format!("http://{web}/old"))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()["location"], "/new");

    // At least 24 bytes: from those, a listener with h2c tells HTTP/2 from HTTP/1.1.
    let without_host = "GET /a/longer/path HTTP/1.0\r\n\r\n";
    assert_eq!(raw_status(web, without_host).await, 400);
}

/// Fixed responses carry their status and body, as plain text unless the route sets another
/// type; HEAD gets the length without the body, and 204 gets neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_with_fixed_responses() {
    let server = start(
        r#"
        [routes.down]
        match = { paths = ["/down"] }
        respond = { status = 503, body = "down for maintenance" }
        [routes.json]
        match = { paths = ["/json"] }
        respond = { status = 200, body = '{"ok":true}' }
        response_headers = { set = { "Content-Type" = "application/json" } }
        [routes.empty]
        match = { paths = ["/empty"] }
        respond = { status = 204 }
        "#,
    )
    .await;
    let web = addr(&server, "web").await;
    let url = |path: &str| format!("http://{web}{path}");

    let response = client().get(url("/down")).send().await.expect("send");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; charset=utf-8"
    );
    assert_eq!(response.headers()["content-length"], "20");
    assert_eq!(response.text().await.expect("body"), "down for maintenance");

    let response = client().head(url("/down")).send().await.expect("send");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.headers()["content-length"], "20");
    assert_eq!(response.text().await.expect("body"), "");

    let response = client().get(url("/json")).send().await.expect("send");
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.text().await.expect("body"), r#"{"ok":true}"#);

    let response = client().get(url("/empty")).send().await.expect("send");
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().get("content-length").is_none());
    assert_eq!(response.text().await.expect("body"), "");
}

/// Rewrites change the normalized path and encode it again, and keep the query; other routes
/// forward the path as sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rewrites_paths_for_the_upstream() {
    let echo = echo_upstream().await;
    let plain = upstream("plain").await;
    let server = start(&format!(
        r#"
        [routes.api]
        match = {{ paths = ["/v1/"] }}
        upstream = "echo"
        rewrite = {{ strip_prefix = "/v1", add_prefix = "/api" }}
        [routes.plain]
        upstream = "plain"
        [upstreams.echo]
        targets = ["{echo}"]
        [upstreams.plain]
        targets = ["{plain}"]
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let request_line = async |path: &str| {
        let body = client()
            .get(format!("http://{web}{path}"))
            .send()
            .await
            .expect("send")
            .text()
            .await
            .expect("body");
        body.lines().next().unwrap_or_default().to_owned()
    };
    assert_eq!(
        request_line("/v1/users?x=1&y=%20").await,
        "GET /api/users?x=1&y=%20"
    );
    assert_eq!(
        request_line("/v1/a%20b/c%3Fd").await,
        "GET /api/a%20b/c%3Fd"
    );
    assert_eq!(request_line("/v2//x").await, format!("plain {web} /v2//x"));
}

/// The forwarding headers replace those of the client, every request gets its own ID, and the
/// request header rules of the route come after them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tells_upstreams_about_the_client() {
    let echo = echo_upstream().await;
    let server = start(&format!(
        r#"
        [routes.all]
        upstream = "echo"
        request_headers = {{ remove = ["X-Debug", "X-Real-IP"], set = {{ "X-Env" = "prod" }}, add = {{ "X-Tag" = "wormway" }} }}
        [upstreams.echo]
        targets = ["{echo}"]
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let headers_seen = async || {
        let body = client()
            .get(format!("http://{web}/p"))
            .header("host", "example.com:8080")
            .header("x-forwarded-for", "6.6.6.6")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "evil.example")
            .header("x-request-id", "chosen")
            .header("x-debug", "1")
            .header("x-env", "dev")
            .header("x-tag", "client")
            .send()
            .await
            .expect("send")
            .text()
            .await
            .expect("body");
        body.lines().skip(1).map(str::to_owned).collect::<Vec<_>>()
    };
    let first = headers_seen().await;
    let value = |name: &str| -> Vec<&str> {
        first
            .iter()
            .filter_map(|line| line.strip_prefix(&format!("{name}: ")))
            .collect()
    };
    assert_eq!(value("x-forwarded-for"), ["127.0.0.1"]);
    assert_eq!(value("x-forwarded-proto"), ["http"]);
    assert_eq!(value("x-forwarded-host"), ["example.com:8080"]);
    assert!(value("x-real-ip").is_empty());
    assert!(value("x-debug").is_empty());
    assert_eq!(value("x-env"), ["prod"]);
    assert_eq!(value("x-tag"), ["client", "wormway"]);
    let id = value("x-request-id");
    assert_eq!(id.len(), 1);
    assert_eq!(id[0].len(), 32);
    assert!(id[0].bytes().all(|b| b.is_ascii_hexdigit()), "{id:?}");

    let second = headers_seen().await;
    let second_id = second
        .iter()
        .find(|line| line.starts_with("x-request-id: "))
        .expect("an ID");
    assert_ne!(*second_id, format!("x-request-id: {}", id[0]));
}

/// Response header rules apply to the responses of the upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changes_response_headers() {
    let app = content_upstream().await;
    let server = start(&format!(
        r#"
        [routes.all]
        upstream = "app"
        response_headers = {{ remove = ["Server-Timing"], set = {{ "X-Upstream" = "wormway" }}, add = {{ "X-Extra" = "1" }} }}
        [upstreams.app]
        targets = ["{app}"]
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let response = client()
        .get(format!("http://{web}/text"))
        .send()
        .await
        .expect("send");
    let headers = response.headers();
    assert!(headers.get("server-timing").is_none());
    assert_eq!(headers["x-upstream"], "wormway");
    assert_eq!(headers["x-extra"], "1");
    assert_eq!(response.text().await.expect("body"), text());
}

/// Sends `GET path` to `host` over HTTP/2 without TLS, with `accept-encoding`, and returns the
/// status, the content encoding and the body.
async fn get_h2c(
    addr: SocketAddr,
    host: &str,
    path: &str,
    accept_encoding: &str,
) -> (u16, Option<String>, Vec<u8>) {
    let exchange = exchange_h2c(addr, host, path, accept_encoding);
    tokio::time::timeout(LIMIT, exchange)
        .await
        .expect("the HTTP/2 response ends in time")
}

/// The exchange of [`get_h2c`], without a time limit.
async fn exchange_h2c(
    addr: SocketAddr,
    host: &str,
    path: &str,
    accept_encoding: &str,
) -> (u16, Option<String>, Vec<u8>) {
    let stream = TcpStream::connect(addr).await.expect("connect");
    let (client, connection) = h2::client::handshake(stream).await.expect("handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::get(format!("http://{host}{path}"))
        .header("accept-encoding", accept_encoding)
        .body(())
        .expect("request");
    let mut client = client.ready().await.expect("ready");
    let (response, _) = client.send_request(request, true).expect("send");
    let (head, mut body) = response.await.expect("response").into_parts();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("body");
        let _ = body.flow_control().release_capacity(chunk.len());
        bytes.extend_from_slice(&chunk);
    }
    let encoding = head
        .headers
        .get("content-encoding")
        .map(|value| value.to_str().expect("text").to_owned());
    (head.status.as_u16(), encoding, bytes)
}

/// Routes with compression compress text with the encoding the client accepts, over HTTP/1.1
/// and HTTP/2, but not streams of events, partial content, or routes without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compresses_text_responses() {
    let app = content_upstream().await;
    let server = start(&format!(
        r#"
        [routes.compressed]
        match = {{ hosts = ["compressed"] }}
        upstream = "app"
        compress = true
        [routes.plain]
        upstream = "app"
        [upstreams.app]
        targets = ["{app}"]
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let get = async |host: &str, path: &str, accept_encoding: Option<&str>| {
        let mut request = client()
            .get(format!("http://{web}{path}"))
            .header("host", host);
        if let Some(accept) = accept_encoding {
            request = request.header("accept-encoding", accept);
        }
        let response = request.send().await.expect("send");
        let status = response.status().as_u16();
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .map(|value| value.to_str().expect("text").to_owned())
        };
        let (encoding, vary) = (header("content-encoding"), header("vary"));
        let body = response.bytes().await.expect("body").to_vec();
        (status, encoding, vary, body)
    };
    let text = text().into_bytes();

    let (status, encoding, vary, body) = get("compressed", "/text", Some("gzip")).await;
    assert_eq!((status, encoding.as_deref()), (200, Some("gzip")));
    assert!(
        vary.is_some_and(|vary| vary.eq_ignore_ascii_case("accept-encoding")),
        "Vary names Accept-Encoding"
    );
    assert!(body.starts_with(&[0x1f, 0x8b]), "not gzip");
    assert!(body.len() < text.len() / 4, "{} bytes", body.len());

    let (_, encoding, _, _) = get("compressed", "/text", Some("br, gzip")).await;
    assert_eq!(encoding.as_deref(), Some("br"));
    let (_, encoding, _, body) = get("compressed", "/text", Some("zstd")).await;
    assert_eq!(encoding.as_deref(), Some("zstd"));
    assert!(body.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]), "not zstd");

    for (host, path, accept) in [
        ("compressed", "/text", None),
        ("compressed", "/events", Some("gzip")),
        ("plain", "/text", Some("gzip")),
    ] {
        let (_, encoding, _, body) = get(host, path, accept).await;
        assert_eq!(encoding, None, "{host}{path}");
        assert_eq!(body, text, "{host}{path}");
    }
    let (status, encoding, _, _) = get("compressed", "/partial", Some("gzip")).await;
    assert_eq!((status, encoding), (206, None));

    let (status, encoding, body) = get_h2c(web, "compressed", "/text", "gzip").await;
    assert_eq!((status, encoding.as_deref()), (200, Some("gzip")));
    assert!(body.starts_with(&[0x1f, 0x8b]), "not gzip");
}

/// The answer to an HTTP-01 challenge in progress comes before every route, for any host, even
/// one that redirects to HTTPS; other tokens, other methods and challenges no longer in
/// progress go to the routes as usual.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_acme_challenges() {
    let blue = upstream("blue").await;
    let certificates = Certificates::new(".");
    let text = format!(
        r#"{WEB}
        [routes.all]
        upstream = "app"
        [routes.to-https]
        match = {{ hosts = ["secure.test"] }}
        redirect = {{ to = "https://{{host}}{{uri}}", status = 301 }}
        [upstreams.app]
        targets = ["{blue}"]
        "#
    );
    let server = common::start_with(&text, certificates.clone(), None).await;
    let web = addr(&server, "web").await;
    certificates
        .challenges()
        .insert("token-1", "token-1.thumbprint");
    let challenge = format!("http://{web}/.well-known/acme-challenge/token-1");

    let response = client()
        .get(&challenge)
        .header("Host", "secure.test")
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/plain");
    assert_eq!(response.text().await.expect("body"), "token-1.thumbprint");

    let other = format!("http://{web}/.well-known/acme-challenge/token-2");
    let routed = client().get(&other).header("Host", "a.test").send().await;
    assert_eq!(
        routed.expect("send").text().await.expect("body"),
        "blue a.test /.well-known/acme-challenge/token-2"
    );
    let posted = client()
        .post(&challenge)
        .header("Host", "a.test")
        .send()
        .await;
    assert_eq!(
        posted.expect("send").text().await.expect("body"),
        "blue a.test /.well-known/acme-challenge/token-1"
    );
    certificates.challenges().remove("token-1");
    let ended = client()
        .get(&challenge)
        .header("Host", "secure.test")
        .send()
        .await;
    assert_eq!(ended.expect("send").status(), StatusCode::MOVED_PERMANENTLY);
}
