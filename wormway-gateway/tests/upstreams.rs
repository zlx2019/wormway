//! Integration tests of upstreams: the ways of balancing, host names, retries, time limits and
//! the HTTP version of responses.

mod common;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::http::StatusCode;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use wormway_runtime::Server;

use crate::common::{addr, serve, upstream};

/// How long any exchange of a test may take, so that a test that hangs fails instead.
const LIMIT: Duration = Duration::from_secs(10);

/// A listener on any free loopback port.
const WEB: &str = "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";

/// Starts a server with the gateway on the test runtime, without certificates.
async fn start(text: &str) -> Server {
    common::start(&format!("{WEB}{text}"), Path::new(".")).await
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

/// Sends `GET path` to `web` with `headers` and returns the status and the body.
async fn get_with(web: SocketAddr, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    let mut request = client().get(format!("http://{web}{path}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.expect("send");
    let status = response.status().as_u16();
    (status, response.text().await.expect("body"))
}

/// Sends `GET path` to `web` and returns the status and the body.
async fn get(web: SocketAddr, path: &str) -> (u16, String) {
    get_with(web, path, &[]).await
}

/// The name of the upstream that answered, the first word of the body of [`upstream`].
fn answered_by(body: &str) -> &str {
    body.split(' ').next().unwrap_or_default()
}

/// Counts the upstreams that answered `count` requests for `path`.
async fn tally(web: SocketAddr, path: &str, count: usize) -> BTreeMap<String, usize> {
    let mut tally = BTreeMap::new();
    for _ in 0..count {
        let (status, body) = get(web, path).await;
        assert_eq!(status, 200, "{body}");
        *tally.entry(answered_by(&body).to_owned()).or_default() += 1;
    }
    tally
}

/// An address where nothing listens: connecting to it is refused.
async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    listener.local_addr().expect("local address")
}

/// What an upstream written by hand does with a request.
#[derive(Clone, Copy)]
enum Reply {
    /// Sends the response and waits for the next request on the connection.
    Keep(&'static str),
    /// Sends the response and closes the connection.
    Close(&'static str),
    /// Closes the connection without a response.
    Drop,
}

/// Starts an upstream that reads each request on a connection and replies with `reply`, given
/// the number of the request on its connection, from 0. Returns the address and the number of
/// requests read.
async fn raw_upstream(
    reply: impl Fn(usize) -> Reply + Clone + Send + Sync + 'static,
) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let (reply, counted) = (reply.clone(), counted.clone());
            tokio::spawn(async move {
                let mut stream = stream;
                let mut index = 0;
                while read_request(&mut stream).await {
                    counted.fetch_add(1, Ordering::SeqCst);
                    let (response, keep) = match reply(index) {
                        Reply::Keep(response) => (response, true),
                        Reply::Close(response) => (response, false),
                        Reply::Drop => return,
                    };
                    if stream.write_all(response.as_bytes()).await.is_err() || !keep {
                        return;
                    }
                    index += 1;
                }
            });
        }
    });
    (addr, requests)
}

/// Reads a request without a body up to its empty line; `false` when the connection ends first.
async fn read_request(stream: &mut TcpStream) -> bool {
    let mut request = Vec::new();
    let mut byte = [0; 1];
    while !request.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte).await {
            Ok(1) => request.push(byte[0]),
            _ => return false,
        }
    }
    true
}

/// Round robin follows the weights, and random reaches every target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn balances_by_weight() {
    let (blue, green) = (upstream("blue").await, upstream("green").await);
    let server = start(&format!(
        r#"
        [routes.turns]
        match = {{ paths = ["/turns"] }}
        upstream = "turns"
        [routes.chance]
        match = {{ paths = ["/chance"] }}
        upstream = "chance"
        [upstreams.turns]
        targets = ["{blue}", {{ address = "{green}", weight = 3 }}]
        [upstreams.chance]
        targets = ["{blue}", "{green}"]
        balance = "random"
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let turns = tally(web, "/turns", 8).await;
    assert_eq!(turns["blue"], 2, "{turns:?}");
    assert_eq!(turns["green"], 6, "{turns:?}");
    let chance = tally(web, "/chance", 40).await;
    assert_eq!(chance.len(), 2, "{chance:?}");
}

/// Starts an upstream named `name` whose `/hold` answers once `gate` opens, after telling
/// `arrived`; other paths answer at once.
async fn holding_upstream(
    name: &'static str,
    gate: watch::Receiver<bool>,
    arrived: mpsc::UnboundedSender<&'static str>,
) -> SocketAddr {
    let hold = move || {
        let (mut gate, arrived) = (gate.clone(), arrived.clone());
        async move {
            let _ = arrived.send(name);
            let _ = gate.wait_for(|open| *open).await;
            name
        }
    };
    let app = axum::Router::new()
        .route("/hold", axum::routing::get(hold))
        .fallback(move || async move { name });
    serve(app).await
}

/// least_conn sends new requests away from a target that is busy with one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn avoids_busy_targets() {
    let (open, gate) = watch::channel(false);
    let (arrived, mut arrivals) = mpsc::unbounded_channel();
    let blue = holding_upstream("blue", gate.clone(), arrived.clone()).await;
    let green = holding_upstream("green", gate, arrived).await;
    let server = start(&format!(
        r#"
        [routes.app]
        upstream = "app"
        [upstreams.app]
        targets = ["{blue}", "{green}"]
        balance = "least_conn"
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let held = tokio::spawn(get(web, "/hold"));
    let busy = tokio::time::timeout(LIMIT, arrivals.recv())
        .await
        .expect("the held request arrives")
        .expect("arrival");
    for _ in 0..4 {
        let (status, body) = get(web, "/").await;
        assert_eq!(status, 200);
        assert_ne!(body, busy, "a request went to the busy target");
    }
    open.send(true).expect("open the gate");
    let (status, body) = tokio::time::timeout(LIMIT, held)
        .await
        .expect("the held request ends")
        .expect("held request");
    assert_eq!((status, body.as_str()), (200, busy));
}

/// Consistent hashing sends a key to the same target every time; requests without the key
/// go by the client address, which is the same for all of them here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hashes_requests_to_targets() {
    let (blue, green) = (upstream("blue").await, upstream("green").await);
    let server = start(&format!(
        r#"
        [routes.header]
        match = {{ paths = ["/header"] }}
        upstream = "header"
        [routes.cookie]
        match = {{ paths = ["/cookie"] }}
        upstream = "cookie"
        [upstreams.header]
        targets = ["{blue}", "{green}"]
        balance = "consistent_hash"
        hash_key = {{ header = "X-User" }}
        [upstreams.cookie]
        targets = ["{blue}", "{green}"]
        balance = "consistent_hash"
        hash_key = {{ cookie = "sid" }}
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let mut seen = BTreeMap::new();
    for user in 0..20 {
        let user = format!("user-{user}");
        let headers = [("x-user", user.as_str())];
        let (_, first) = get_with(web, "/header", &headers).await;
        for _ in 0..2 {
            let (status, again) = get_with(web, "/header", &headers).await;
            assert_eq!(status, 200);
            assert_eq!(answered_by(&again), answered_by(&first), "{user}");
        }
        let cookie = format!("theme=dark; sid={user}");
        let (_, by_cookie) = get_with(web, "/cookie", &[("cookie", &cookie)]).await;
        let (_, again) = get_with(web, "/cookie", &[("cookie", &cookie)]).await;
        assert_eq!(answered_by(&again), answered_by(&by_cookie), "{user}");
        *seen.entry(answered_by(&first).to_owned()).or_insert(0) += 1;
    }
    assert_eq!(seen.len(), 2, "keys spread over both targets: {seen:?}");
    let anonymous = tally(web, "/header", 6).await;
    assert_eq!(anonymous.len(), 1, "{anonymous:?}");
}

/// A target that refuses connections makes the request try another one, unless the upstream
/// allows no retries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_other_targets_when_connecting_fails() {
    let (dead, live) = (closed_port().await, upstream("live").await);
    let server = start(&format!(
        r#"
        [routes.spare]
        match = {{ paths = ["/spare"] }}
        upstream = "spare"
        [routes.once]
        match = {{ paths = ["/once"] }}
        upstream = "once"
        [upstreams.spare]
        targets = ["{dead}", "{live}"]
        [upstreams.once]
        targets = ["{dead}", "{live}"]
        retries = 0
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let spare = tally(web, "/spare", 4).await;
    assert_eq!(spare["live"], 4, "{spare:?}");
    let mut statuses = Vec::new();
    for _ in 0..4 {
        statuses.push(get(web, "/once").await.0);
    }
    statuses.sort();
    assert_eq!(statuses, [200, 200, 502, 502]);
}

/// A request that reached a target is not sent to another one when the target fails, even for
/// GET; and a reused connection that fails in the middle of a response is not retried either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn does_not_retry_requests_that_reached_a_target() {
    let (closing, read) = raw_upstream(|_| Reply::Drop).await;
    let live = upstream("live").await;
    let (cutting, served) = raw_upstream(|index| match index {
        0 => Reply::Keep("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        _ => Reply::Close("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial"),
    })
    .await;
    let server = start(&format!(
        r#"
        [routes.closing]
        match = {{ paths = ["/closing"] }}
        upstream = "closing"
        [routes.cutting]
        match = {{ paths = ["/cutting"] }}
        upstream = "cutting"
        [upstreams.closing]
        targets = ["{closing}", "{live}"]
        [upstreams.cutting]
        targets = ["{cutting}"]
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    let mut statuses = Vec::new();
    for _ in 0..2 {
        statuses.push(get(web, "/closing").await.0);
    }
    statuses.sort();
    assert_eq!(statuses, [200, 502]);
    assert_eq!(read.load(Ordering::SeqCst), 1);

    assert_eq!(get(web, "/cutting").await, (200, "ok".to_owned()));
    let response = client()
        .get(format!("http://{web}/cutting"))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.text().await.is_err(), "the body is cut short");
    assert_eq!(served.load(Ordering::SeqCst), 2, "no third request");
}

/// An idle connection that the upstream closed is retried over a new one for GET, but not for
/// POST, which the upstream may have acted on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_closed_idle_connections() {
    let (stale, read) = raw_upstream(|index| match index {
        0 => Reply::Keep("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
        _ => Reply::Drop,
    })
    .await;
    let server = start(&format!(
        r#"
        [routes.app]
        upstream = "stale"
        [upstreams.stale]
        targets = ["{stale}"]
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    assert_eq!(get(web, "/").await, (200, "ok".to_owned()));
    assert_eq!(get(web, "/").await, (200, "ok".to_owned()));
    assert_eq!(
        read.load(Ordering::SeqCst),
        3,
        "the second GET was sent twice"
    );
    let response = client()
        .post(format!("http://{web}/"))
        .send()
        .await
        .expect("send");
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(read.load(Ordering::SeqCst), 4, "the POST was sent once");
}

/// An upstream that takes too long gets 504, unless the route allows it more time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_504_when_upstreams_take_too_long() {
    let slow = serve(axum::Router::new().fallback(|| async {
        tokio::time::sleep(Duration::from_millis(1500)).await;
        "late"
    }))
    .await;
    let server = start(&format!(
        r#"
        [routes.strict]
        match = {{ paths = ["/strict"] }}
        upstream = "slow"
        [routes.patient]
        match = {{ paths = ["/patient"] }}
        upstream = "slow"
        timeouts = {{ read = "5s" }}
        [upstreams.slow]
        targets = ["{slow}"]
        timeouts = {{ read = "300ms" }}
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    assert_eq!(get(web, "/strict").await.0, 504);
    assert_eq!(get(web, "/patient").await, (200, "late".to_owned()));
}

/// Responses of HTTP/1.0 upstreams reach HTTP/1.1 clients as HTTP/1.1, with or without a
/// length.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_http_1_1_for_http_1_0_upstreams() {
    let (sized, _) =
        raw_upstream(|_| Reply::Close("HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nsized")).await;
    let (bare, _) = raw_upstream(|_| Reply::Close("HTTP/1.0 200 OK\r\n\r\nunsized")).await;
    let server = start(&format!(
        r#"
        [routes.sized]
        match = {{ paths = ["/sized"] }}
        upstream = "sized"
        [routes.unsized]
        match = {{ paths = ["/unsized"] }}
        upstream = "unsized"
        [upstreams.sized]
        targets = ["{sized}"]
        [upstreams.unsized]
        targets = ["{bare}"]
        "#
    ))
    .await;
    let web = addr(&server, "web").await;
    for path in ["/sized", "/unsized"] {
        let response = client()
            .get(format!("http://{web}{path}"))
            .send()
            .await
            .expect("send");
        assert_eq!(response.version(), reqwest::Version::HTTP_11, "{path}");
        assert_eq!(response.text().await.expect("body"), &path[1..]);
    }
}

/// Targets can be host names; each of their addresses is a target, and the ones where nothing
/// listens are retried elsewhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resolves_host_names() {
    let blue = upstream("blue").await;
    let server = start(&format!(
        r#"
        [routes.app]
        upstream = "app"
        [upstreams.app]
        targets = ["localhost:{}"]
        "#,
        blue.port()
    ))
    .await;
    let web = addr(&server, "web").await;
    let answers = tally(web, "/", 4).await;
    assert_eq!(answers["blue"], 4, "{answers:?}");
}
