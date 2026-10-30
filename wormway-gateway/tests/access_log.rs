//! Integration tests of the access log: a line for every request, with what happened to it.

#[allow(
    dead_code,
    reason = "these tests start their servers with an access log"
)]
mod common;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::net::TcpListener;
use wormway_core::config::{AccessLogFormat, AccessLogSettings};
use wormway_gateway::AccessLog;
use wormway_runtime::Server;

use crate::common::{addr, start_logged, upstream};

/// How long any exchange of a test may take, so that a test that hangs fails instead.
const LIMIT: Duration = Duration::from_secs(10);

/// Starts a server with the gateway on the test runtime, writing JSON lines to `log`.
async fn start(text: &str, log: &Path) -> Server {
    let config =
        format!("[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n{text}");
    start_logged(&config, Path::new("."), Some(json_log(log))).await
}

/// An access log that writes JSON lines to the file at `path`.
fn json_log(path: &Path) -> AccessLog {
    let settings = AccessLogSettings {
        format: AccessLogFormat::Json,
        path: Some(path.to_owned()),
    };
    AccessLog::open(&settings, Path::new(".")).expect("open the access log")
}

/// Sends `GET path` to `web` with a `User-Agent` and returns the status.
async fn get(web: SocketAddr, path: &str) -> u16 {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(LIMIT)
        .build()
        .expect("client");
    let response = client
        .get(format!("http://{web}{path}"))
        .header("User-Agent", "tester \"one\"")
        .send()
        .await
        .expect("send");
    response.status().as_u16()
}

/// An address where nothing listens: connecting to it is refused.
async fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    listener.local_addr().expect("local address")
}

/// Waits up to [`LIMIT`] for `count` lines in the file at `path`, and returns them.
async fn lines(path: &PathBuf, count: usize) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + LIMIT;
    loop {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let lines: Vec<String> = text.lines().map(str::to_owned).collect();
        if lines.len() >= count {
            return lines;
        }
        assert!(tokio::time::Instant::now() < deadline, "{lines:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Every request gets a line with its route, upstream, target, status and error, except those
/// of routes that leave the access log out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn writes_a_line_per_request() {
    let dir = tempfile::tempdir().expect("directory");
    let log = dir.path().join("access.log");
    let (blue, closed) = (upstream("blue").await, closed_port().await);
    let server = start(
        &format!(
            r#"
            [routes.app]
            match = {{ paths = ["/app"] }}
            upstream = "app"
            [routes.broken]
            match = {{ paths = ["/broken"] }}
            upstream = "broken"
            [routes.quiet]
            match = {{ paths = ["/quiet"] }}
            respond = {{ status = 204 }}
            access_log = false
            [upstreams.app]
            targets = ["{blue}"]
            [upstreams.broken]
            targets = ["{closed}"]
            retries = 0
            "#
        ),
        &log,
    )
    .await;
    let web = addr(&server, "web").await;
    assert_eq!(get(web, "/app/x?q=1").await, 200);
    assert_eq!(get(web, "/quiet").await, 204);
    assert_eq!(get(web, "/none").await, 404);
    assert_eq!(get(web, "/broken").await, 502);

    // Lines come in the order of the requests, so the one of /quiet would be second.
    let lines = lines(&log, 3).await;
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(
        lines.iter().all(|line| !line.contains("/quiet")),
        "{lines:?}"
    );
    let expected = [
        vec![
            r#""method":"GET""#.to_owned(),
            r#""uri":"/app/x?q=1""#.to_owned(),
            r#""protocol":"HTTP/1.1""#.to_owned(),
            r#""status":200"#.to_owned(),
            r#""listener":"web","route":"app","upstream":"app""#.to_owned(),
            format!(r#""target":"{blue}""#),
            r#""user_agent":"tester \"one\"""#.to_owned(),
            r#""tls":null,"error":null"#.to_owned(),
            r#""client_ip":"127.0.0.1""#.to_owned(),
        ],
        vec![
            r#""uri":"/none""#.to_owned(),
            r#""status":404"#.to_owned(),
            r#""route":null,"upstream":null,"target":null"#.to_owned(),
        ],
        vec![
            r#""status":502"#.to_owned(),
            r#""route":"broken","upstream":"broken""#.to_owned(),
            format!(r#""target":"{closed}""#),
            r#""error":"connection refused""#.to_owned(),
        ],
    ];
    for (line, parts) in lines.iter().zip(expected) {
        for part in parts {
            assert!(line.contains(&part), "{part} not in {line}");
        }
    }
    let upstream_time = lines[0]
        .split(r#""upstream_duration":"#)
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .and_then(|seconds| seconds.parse::<f64>().ok());
    assert!(
        upstream_time.is_some_and(|seconds| seconds > 0.0),
        "{}",
        lines[0]
    );
}
