//! Integration tests of health checks: active checks over HTTP and TCP, probes of new targets
//! before they get requests, health kept across changes, and passive checks.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;
use wormway_runtime::Server;

use crate::common::{addr, parse, serve, upstream};

/// How long any exchange of a test may take, so that a test that hangs fails instead.
const LIMIT: Duration = Duration::from_secs(10);

/// A listener on any free loopback port.
const WEB: &str = "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";

/// Starts a server with the gateway on the test runtime, without certificates.
async fn start(text: &str) -> Server {
    common::start(&format!("{WEB}{text}"), Path::new(".")).await
}

/// Applies `text` with the listener of [`start`].
async fn apply(server: &Server, text: &str) {
    if let Err(error) = server.apply(parse(&format!("{WEB}{text}"))).await {
        panic!("cannot apply: {error:?}");
    }
}

/// An upstream that answers its name, and on `/healthz` the status it is told to.
struct Checked {
    /// Its address.
    addr: SocketAddr,
    /// Status of `/healthz`.
    status: Arc<AtomicU16>,
    /// Requests for `/healthz`.
    probes: Arc<AtomicUsize>,
    /// Other requests.
    requests: Arc<AtomicUsize>,
    /// `Host` and `User-Agent` of the last request for `/healthz`.
    probed_with: Arc<Mutex<String>>,
}

impl Checked {
    /// Starts the upstream `name`, whose `/healthz` answers `status`.
    async fn start(name: &'static str, status: u16) -> Self {
        let status = Arc::new(AtomicU16::new(status));
        let (probes, requests) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let probed_with = Arc::new(Mutex::new(String::new()));
        let health = {
            let (status, probes, probed_with) =
                (status.clone(), probes.clone(), probed_with.clone());
            move |headers: HeaderMap| async move {
                probes.fetch_add(1, Ordering::SeqCst);
                let header = |name: &str| {
                    headers
                        .get(name)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("-")
                        .to_owned()
                };
                *probed_with.lock().expect("lock") =
                    format!("{} {}", header("host"), header("user-agent"));
                StatusCode::from_u16(status.load(Ordering::SeqCst)).expect("status")
            }
        };
        let answer = {
            let requests = requests.clone();
            move || async move {
                requests.fetch_add(1, Ordering::SeqCst);
                name
            }
        };
        let app = axum::Router::new()
            .route("/healthz", axum::routing::get(health))
            .fallback(answer);
        Self {
            addr: serve(app).await,
            status,
            probes,
            requests,
            probed_with,
        }
    }

    /// Makes `/healthz` answer `status` from now on.
    fn answer(&self, status: u16) {
        self.status.store(status, Ordering::SeqCst);
    }

    /// Returns the number of requests for `/healthz`.
    fn probes(&self) -> usize {
        self.probes.load(Ordering::SeqCst)
    }

    /// Returns the number of other requests.
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

/// A client that ignores the proxy settings of the environment and gives up on a request after
/// [`LIMIT`].
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(LIMIT)
        .build()
        .expect("client")
}

/// Sends `GET path` to `web` and returns the status and the body.
async fn get(web: SocketAddr, path: &str) -> (u16, String) {
    let response = client()
        .get(format!("http://{web}{path}"))
        .send()
        .await
        .expect("send");
    let status = response.status().as_u16();
    (status, response.text().await.expect("body"))
}

/// Counts the upstreams that answered `count` requests for `path`, all of which must succeed.
async fn tally(web: SocketAddr, path: &str, count: usize) -> BTreeMap<String, usize> {
    let mut tally = BTreeMap::new();
    for _ in 0..count {
        let (status, body) = get(web, path).await;
        assert_eq!(status, 200, "{body}");
        let name = body.split(' ').next().unwrap_or_default();
        *tally.entry(name.to_owned()).or_default() += 1;
    }
    tally
}

/// Tallies 6 requests for `path` until `done` holds for the tally, which it returns; fails
/// after [`LIMIT`].
async fn settle(
    web: SocketAddr,
    path: &str,
    done: impl Fn(&BTreeMap<String, usize>) -> bool,
) -> BTreeMap<String, usize> {
    let deadline = Instant::now() + LIMIT;
    loop {
        let tally = tally(web, path, 6).await;
        if done(&tally) {
            return tally;
        }
        assert!(Instant::now() < deadline, "never settled: {tally:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// An address where nothing listens: connecting to it is refused.
async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    listener.local_addr().expect("local address")
}

/// Starts an upstream that reads each request and closes the connection without answering.
/// Returns the address and the number of requests read.
async fn failing_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counted = counted.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte).await {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                counted.fetch_add(1, Ordering::SeqCst);
            });
        }
    });
    (addr, requests)
}

/// Starts an upstream that answers each request with a status line, headers and part of the
/// body it announces, then closes the connection. Returns the address and the number of
/// requests read.
async fn truncating_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let counted = counted.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte).await {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                counted.fetch_add(1, Ordering::SeqCst);
                let response = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
                let _ = stream.write_all(response).await;
            });
        }
    });
    (addr, requests)
}

/// Sends `GET path` to `web` and reads the response, whatever happens.
async fn fetch(web: SocketAddr, path: &str) {
    if let Ok(response) = client().get(format!("http://{web}{path}")).send().await {
        let _ = response.bytes().await;
    }
}

/// A target whose probes fail gets no requests until its probes pass again; probes name the
/// target in `Host` and say what they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn takes_unhealthy_targets_out_and_back() {
    let (blue, green) = (
        Checked::start("blue", 200).await,
        Checked::start("green", 200).await,
    );
    let server = start(&format!(
        r#"
        [routes.app]
        upstream = "app"
        [upstreams.app]
        targets = ["{}", "{}"]
        health_check = {{ kind = "http", path = "/healthz", interval = "100ms", healthy = 1, unhealthy = 1 }}
        "#,
        blue.addr, green.addr
    ))
    .await;
    let web = addr(&server, "web").await;
    assert_eq!(tally(web, "/", 6).await.len(), 2);
    let expected = format!("{} wormway-health-check", green.addr);
    assert_eq!(*green.probed_with.lock().expect("lock"), expected);

    green.answer(503);
    settle(web, "/", |tally| tally.get("blue") == Some(&6)).await;
    green.answer(200);
    settle(web, "/", |tally| tally.contains_key("green")).await;
}

/// Targets are probed once before they get requests, at start and when a change adds them, so
/// that a failing one never gets any.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn probes_new_targets_before_they_get_requests() {
    let (blue, green) = (
        Checked::start("blue", 200).await,
        Checked::start("green", 503).await,
    );
    let settings = |targets: &[SocketAddr]| {
        let targets: Vec<String> = targets
            .iter()
            .map(|target| format!("\"{target}\""))
            .collect();
        format!(
            r#"
            [routes.app]
            upstream = "app"
            [upstreams.app]
            targets = [{}]
            retries = 0
            health_check = {{ kind = "http", path = "/healthz", interval = "1h" }}
            "#,
            targets.join(", ")
        )
    };
    let server = start(&settings(&[blue.addr, green.addr])).await;
    let web = addr(&server, "web").await;
    assert_eq!(tally(web, "/", 10).await["blue"], 10);
    assert_eq!((green.probes(), green.requests()), (1, 0));

    let red = Checked::start("red", 503).await;
    apply(&server, &settings(&[blue.addr, green.addr, red.addr])).await;
    assert_eq!(tally(web, "/", 10).await["blue"], 10);
    assert_eq!((red.probes(), red.requests()), (1, 0));
    assert_eq!(green.probes(), 1);
}

/// Changing the targets keeps the health of those that stay, whatever their weight; changing
/// the health checks starts over with a probe of every target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_health_until_the_checks_change() {
    let (blue, green) = (
        Checked::start("blue", 200).await,
        Checked::start("green", 503).await,
    );
    let red = Checked::start("red", 200).await;
    let settings = |targets: &str, healthy: u32| {
        format!(
            r#"
            [routes.app]
            upstream = "app"
            [upstreams.app]
            targets = [{targets}]
            health_check = {{ kind = "http", path = "/healthz", interval = "1h", healthy = {healthy} }}
            "#
        )
    };
    let server = start(&settings(
        &format!("\"{}\", \"{}\"", blue.addr, green.addr),
        3,
    ))
    .await;
    let web = addr(&server, "web").await;
    assert_eq!(tally(web, "/", 4).await["blue"], 4);
    green.answer(200);

    let three = format!(
        "\"{}\", {{ address = \"{}\", weight = 2 }}, \"{}\"",
        blue.addr, green.addr, red.addr
    );
    apply(&server, &settings(&three, 3)).await;
    let tally_after = tally(web, "/", 8).await;
    assert!(!tally_after.contains_key("green"), "{tally_after:?}");
    assert_eq!((green.probes(), red.probes()), (1, 1));

    apply(&server, &settings(&three, 2)).await;
    assert_eq!(green.probes(), 2);
    assert!(tally(web, "/", 8).await.contains_key("green"));
}

/// TCP checks keep requests away from a target that refuses connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn checks_tcp_connections() {
    let (blue, closed) = (upstream("blue").await, closed_port().await);
    let server = start(&format!(
        r#"
        [routes.app]
        upstream = "app"
        [upstreams.app]
        targets = ["{blue}", "{closed}"]
        retries = 0
        health_check = {{ kind = "tcp", interval = "1h" }}
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    assert_eq!(tally(web, "/", 10).await["blue"], 10);
}

/// Requests that fail `max_fails` times take a target out for `fail_timeout`, after which it
/// gets requests again; an upstream whose targets are all out keeps sending to them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn takes_failing_targets_out_for_a_while() {
    let blue = upstream("blue").await;
    let (failing, failures) = failing_upstream().await;
    let server = start(&format!(
        r#"
        [routes.pair]
        match = {{ paths = ["/pair"] }}
        upstream = "pair"
        [routes.alone]
        match = {{ paths = ["/alone"] }}
        upstream = "alone"
        [upstreams.pair]
        targets = ["{blue}", "{failing}"]
        retries = 0
        passive = {{ max_fails = 2, fail_timeout = "1s" }}
        [upstreams.alone]
        targets = ["{failing}"]
        passive = {{ max_fails = 1, fail_timeout = "1h" }}
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let mut statuses = BTreeMap::new();
    for _ in 0..10 {
        *statuses.entry(get(web, "/pair").await.0).or_insert(0) += 1;
    }
    assert_eq!(statuses, BTreeMap::from([(200, 8), (502, 2)]));
    assert_eq!(failures.load(Ordering::SeqCst), 2);

    tokio::time::sleep(Duration::from_millis(1100)).await;
    for _ in 0..4 {
        if failures.load(Ordering::SeqCst) > 2 {
            break;
        }
        get(web, "/pair").await;
    }
    assert_eq!(failures.load(Ordering::SeqCst), 3);

    for _ in 0..2 {
        assert_eq!(get(web, "/alone").await.0, 502);
    }
    assert_eq!(failures.load(Ordering::SeqCst), 5);
}

/// Failures after the response header do not count for the passive checks: the target
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ignores_failures_after_the_response_header() {
    let blue = upstream("blue").await;
    let (truncating, requests) = truncating_upstream().await;
    let server = start(&format!(
        r#"
        [routes.app]
        upstream = "app"
        [upstreams.app]
        targets = ["{blue}", "{truncating}"]
        retries = 0
        passive = {{ max_fails = 1, fail_timeout = "1h" }}
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    for _ in 0..6 {
        fetch(web, "/").await;
    }
    assert_eq!(requests.load(Ordering::SeqCst), 3);
}
