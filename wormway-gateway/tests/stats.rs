//! Integration tests of the traffic of the last minute, as the gateway reports it to the Admin
//! API: by route, by upstream and all together.

#[allow(
    dead_code,
    reason = "these tests need an upstream that sends its body late, not the shared ones"
)]
mod common;

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;
use wormway_runtime::{Server, TrafficReport};

use crate::common::{addr, parse};

/// How long any exchange of a test may take, so that a test that hangs fails instead.
const LIMIT: Duration = Duration::from_secs(10);

/// How long the upstream of these tests waits between the response header and the body.
const BODY_DELAY: Duration = Duration::from_millis(300);

/// Routes to the upstream at `target`, a fixed response of 503, and `extra`.
fn config(target: SocketAddr, extra: &str) -> String {
    format!(
        r#"
        [listeners.web]
        listen = ["127.0.0.1:0"]
        protocol = "http"
        [routes.app]
        match = {{ paths = ["/app"] }}
        upstream = "app"
        [routes.down]
        match = {{ paths = ["/down"] }}
        respond = {{ status = 503 }}
        [upstreams.app]
        targets = ["{target}"]
        {extra}
        "#
    )
}

/// Starts an upstream that sends the response header at once and the body [`BODY_DELAY`]
/// later, then closes the connection, and returns its address.
async fn late_body_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buffer[..read]),
                    }
                }
                let header = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n";
                if stream.write_all(header).await.is_err() || stream.flush().await.is_err() {
                    return;
                }
                tokio::time::sleep(BODY_DELAY).await;
                let _ = stream.write_all(b"hello").await;
            });
        }
    });
    addr
}

/// Sends `GET path` to `web` and returns the status, once the whole body arrived.
async fn get(web: SocketAddr, path: &str) -> u16 {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(LIMIT)
        .build()
        .expect("client");
    let response = client
        .get(format!("http://{web}{path}"))
        .send()
        .await
        .expect("send");
    let status = response.status().as_u16();
    response.bytes().await.expect("body");
    status
}

/// Waits up to [`LIMIT`] for a report with `requests` requests in all, which comes once the
/// second of the last one is over.
async fn traffic(server: &Server, requests: u64) -> TrafficReport {
    let deadline = Instant::now() + LIMIT;
    loop {
        let report = server.traffic().expect("a traffic report");
        if report.all.total.requests >= requests {
            return report;
        }
        assert!(Instant::now() < deadline, "{report:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Requests count by route, by upstream and all together, with errors for statuses of 500 and
/// above; upstreams count the time until the response header, routes until the end of the
/// body. A change keeps the counts of the routes and upstreams that keep their names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_the_traffic_of_the_last_minute() {
    let target = late_body_upstream().await;
    let server = common::start(&config(target, ""), Path::new(".")).await;
    let web = addr(&server, "web").await;
    for _ in 0..3 {
        assert_eq!(get(web, "/app").await, 200);
    }
    assert_eq!(get(web, "/down").await, 503);
    assert_eq!(get(web, "/none").await, 404);

    let report = traffic(&server, 5).await;
    assert_eq!(report.routes["app"].seconds.len(), 60);
    let app = report.routes["app"].total;
    assert_eq!((app.requests, app.errors), (3, 0), "{app:?}");
    assert!(
        app.p50.is_some_and(|p50| p50 >= BODY_DELAY * 3 / 4),
        "{app:?}"
    );
    let upstream = report.upstreams["app"].total;
    assert_eq!(upstream.requests, 3, "{upstream:?}");
    assert!(
        upstream.p99.is_some_and(|p99| p99 < BODY_DELAY / 2),
        "{upstream:?}"
    );
    let down = report.routes["down"].total;
    assert_eq!((down.requests, down.errors), (1, 1), "{down:?}");
    let all = report.all.total;
    assert_eq!((all.requests, all.errors), (5, 1), "{all:?}");

    let extra = r#"
        [routes.extra]
        match = { paths = ["/extra"] }
        upstream = "app"
    "#;
    if let Err(error) = server.apply(parse(&config(target, extra))).await {
        panic!("cannot apply: {error:?}");
    }
    let report = server.traffic().expect("a traffic report");
    assert_eq!(report.routes["app"].total.requests, 3);
    assert_eq!(report.routes["extra"].total.requests, 0);
    assert_eq!(report.upstreams["app"].total.requests, 3);
    assert_eq!(report.all.total.requests, 5);
}
