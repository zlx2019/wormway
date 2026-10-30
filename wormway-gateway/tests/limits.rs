//! Integration tests of the limits of routes: the rate of requests by key, the requests in
//! progress, and the size of request bodies.

#[allow(
    dead_code,
    reason = "these tests start their servers with an access log"
)]
mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Semaphore, mpsc};
use wormway_core::config::{AccessLogFormat, AccessLogSettings};
use wormway_core::time::LogTime;
use wormway_gateway::AccessLog;
use wormway_runtime::Server;

use crate::common::{addr, serve, start_logged, upstream};

/// How long any exchange of a test may take, so that a test that hangs fails instead.
const LIMIT: Duration = Duration::from_secs(10);

/// Starts a server with the gateway on the test runtime and a listener on any free loopback
/// port, writing JSON lines to the access log at `log` if set.
async fn start(text: &str, log: Option<&Path>) -> Server {
    let config =
        format!("[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n{text}");
    let access_log = log.map(|path| {
        let settings = AccessLogSettings {
            format: AccessLogFormat::Json,
            path: Some(path.to_owned()),
        };
        AccessLog::open(&settings, LogTime::default(), Path::new(".")).expect("access log")
    });
    start_logged(&config, Path::new("."), access_log).await
}

/// A client that ignores the proxy settings of the environment and gives up after [`LIMIT`].
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(LIMIT)
        .build()
        .expect("client")
}

/// Sends `GET path` to `web`, with header `X-Tenant` if set, and returns the status and the
/// `Retry-After` and `Access-Control-Allow-Origin` headers.
async fn get(web: SocketAddr, path: &str, tenant: Option<&str>) -> (u16, String, String) {
    let mut request = client().get(format!("http://{web}{path}"));
    if let Some(tenant) = tenant {
        request = request.header("X-Tenant", tenant);
    }
    let response = request.send().await.expect("send");
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-")
            .to_owned()
    };
    let (retry_after, origin) = (header("retry-after"), header("access-control-allow-origin"));
    (response.status().as_u16(), retry_after, origin)
}

/// Each client gets `requests` at once, then 429 with the seconds to wait and the headers of
/// the route; a header key counts each value apart, and requests without the header by client.
/// The access log tells why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limits_the_rate_of_requests() {
    let dir = tempfile::tempdir().expect("directory");
    let log = dir.path().join("access.log");
    let app = upstream("app").await;
    let server = start(
        &format!(
            r#"
            [routes.api]
            match = {{ paths = ["/api"] }}
            upstream = "app"
            rate_limit = {{ requests = 2, per = "1m" }}
            response_headers = {{ set = {{ "Access-Control-Allow-Origin" = "*" }} }}
            [routes.tenant]
            match = {{ paths = ["/tenant"] }}
            upstream = "app"
            rate_limit = {{ requests = 1, per = "1m", key = {{ header = "X-Tenant" }} }}
            [upstreams.app]
            targets = ["{app}"]
            "#
        ),
        Some(&log),
    )
    .await;
    let web = addr(&server, "web").await;

    assert_eq!(get(web, "/api", None).await.0, 200);
    assert_eq!(get(web, "/api", None).await.0, 200);
    // Two requests per minute: the next one comes back in half a minute.
    let limited = (429, "30".to_owned(), "*".to_owned());
    assert_eq!(get(web, "/api", None).await, limited);

    assert_eq!(get(web, "/tenant", Some("a")).await.0, 200);
    assert_eq!(get(web, "/tenant", Some("a")).await.0, 429);
    assert_eq!(get(web, "/tenant", Some("b")).await.0, 200);
    assert_eq!(get(web, "/tenant", None).await.0, 200);
    assert_eq!(get(web, "/tenant", None).await.0, 429);

    let lines = logged(&log, 8).await;
    let turned_away: Vec<&str> = lines
        .lines()
        .filter(|line| line.contains("\"status\":429"))
        .collect();
    assert_eq!(turned_away.len(), 3, "{lines}");
    for line in turned_away {
        assert!(line.contains("\"error\":\"rate limit reached\""), "{line}");
    }
}

/// Waits up to [`LIMIT`] for `count` lines in the access log at `path`, and returns them.
async fn logged(path: &Path, count: usize) -> String {
    let deadline = tokio::time::Instant::now() + LIMIT;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.lines().count() >= count {
            return text;
        }
        assert!(tokio::time::Instant::now() < deadline, "{text}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Starts an upstream whose requests report on `arrived` and then wait for a permit of the
/// returned semaphore.
async fn held_upstream(arrived: mpsc::UnboundedSender<()>) -> (SocketAddr, Arc<Semaphore>) {
    let gate = Arc::new(Semaphore::new(0));
    let permits = gate.clone();
    let app = axum::Router::new().fallback(move || {
        let (arrived, permits) = (arrived.clone(), permits.clone());
        async move {
            let _ = arrived.send(());
            let _permit = permits.acquire().await.expect("permit");
            "done"
        }
    });
    (serve(app).await, gate)
}

/// Beyond the requests in progress that the route allows, requests get 503 right away; once
/// one ends, the next goes through.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limits_requests_in_progress() {
    let (arrived, mut arrivals) = mpsc::unbounded_channel();
    let (app, gate) = held_upstream(arrived).await;
    let server = start(
        &format!(
            "[routes.app]\nupstream = \"app\"\nconcurrency_limit = 1\n[upstreams.app]\ntargets = [\"{app}\"]\n"
        ),
        None,
    )
    .await;
    let web = addr(&server, "web").await;

    let first = tokio::spawn(get(web, "/first", None));
    tokio::time::timeout(LIMIT, arrivals.recv())
        .await
        .expect("the first request reaches the upstream");
    assert_eq!(get(web, "/second", None).await.0, 503);

    gate.add_permits(1);
    assert_eq!(first.await.expect("first request").0, 200);
    // The first request leaves the count when it is logged, just after its response.
    gate.add_permits(10);
    let deadline = tokio::time::Instant::now() + LIMIT;
    loop {
        let status = get(web, "/third", None).await.0;
        if status == 200 {
            break;
        }
        assert_eq!(status, 503);
        assert!(tokio::time::Instant::now() < deadline, "still 503");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Starts an upstream that answers with the length of the request body.
async fn length_upstream() -> SocketAddr {
    serve(
        axum::Router::new()
            .fallback(|body: axum::body::Bytes| async move { body.len().to_string() }),
    )
    .await
}

/// Sends `request` over a new connection to `web` and returns everything that comes back
/// until the connection closes.
async fn exchange(web: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(web).await.expect("connect");
    stream.write_all(request.as_bytes()).await.expect("write");
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, stream.read_to_end(&mut answer))
        .await
        .expect("the connection closes")
        .expect("read");
    String::from_utf8_lossy(&answer).into_owned()
}

/// Bodies up to the limit go through; a longer announced length gets 413 before the body is
/// read, and the connection closes rather than reading it; a streamed body gets 413 once it
/// grows past the limit. The access log tells why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn limits_the_size_of_request_bodies() {
    let dir = tempfile::tempdir().expect("directory");
    let log = dir.path().join("access.log");
    let app = length_upstream().await;
    let server = start(
        &format!(
            "[routes.app]\nupstream = \"app\"\nmax_body_size = \"10B\"\n[upstreams.app]\ntargets = [\"{app}\"]\n"
        ),
        Some(&log),
    )
    .await;
    let web = addr(&server, "web").await;
    let post = |body: &'static str| client().post(format!("http://{web}/")).body(body).send();

    let fits = post("0123456789").await.expect("send");
    assert_eq!(fits.status().as_u16(), 200);
    assert_eq!(fits.text().await.expect("body"), "10");
    assert_eq!(
        post("0123456789A").await.expect("send").status().as_u16(),
        413
    );

    // The body never comes: the answer must not wait for it.
    let announced = exchange(
        web,
        "POST / HTTP/1.1\r\nHost: app\r\nContent-Length: 1000000\r\n\r\n",
    )
    .await;
    assert!(announced.starts_with("HTTP/1.1 413 "), "{announced}");

    let streamed = exchange(
        web,
        "POST / HTTP/1.1\r\nHost: app\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
         8\r\n01234567\r\n8\r\n01234567\r\n0\r\n\r\n",
    )
    .await;
    assert!(streamed.starts_with("HTTP/1.1 413 "), "{streamed}");

    let lines = logged(&log, 4).await;
    let turned_away: Vec<&str> = lines
        .lines()
        .filter(|line| line.contains("\"status\":413"))
        .collect();
    assert_eq!(turned_away.len(), 3, "{lines}");
    for line in turned_away {
        let reason = "\"error\":\"request body larger than max_body_size\"";
        assert!(line.contains(reason), "{line}");
    }
}
