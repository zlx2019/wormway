//! Integration tests of the Admin API with a real server and database.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tower::ServiceExt;
use wormway_control::{Admin, AdminToken, Metrics, Store};
use wormway_core::config::{Config, HealthCheckKind, Listener, Name, Protocol};
use wormway_runtime::{
    BoxError, BoxFuture, CertificateReport, Connection, HealthReport, Server, Service,
    ServiceFactory, Services, Shutdown, TargetReport, TargetState, TlsReport, UpstreamReport,
};

/// Token of the Admin API in these tests.
const TOKEN: &str = "test-token";

/// Greets every connection with `hello` and closes it.
struct Hello;

impl Service for Hello {
    /// Writes the greeting.
    fn serve(self: Arc<Self>, conn: Connection, _: Shutdown) -> BoxFuture<'static> {
        Box::pin(async move {
            let mut stream = conn.stream;
            let _ = stream.write_all(b"hello\n").await;
        })
    }
}

impl ServiceFactory for Hello {
    /// Every listener gets the same kind of service.
    fn create(&self, _: &Name, _: &Listener) -> Result<Arc<dyn Service>, BoxError> {
        Ok(Arc::new(Hello))
    }
}

/// Reports an upstream with a target in each state and one without checks, at fixed times.
struct Report;

impl HealthReport for Report {
    /// Returns the same upstreams every time.
    fn upstreams(&self) -> Vec<UpstreamReport> {
        let at = |secs| Some(UNIX_EPOCH + Duration::from_secs(secs));
        let target = |address: &str, state, since, reason: Option<&str>| TargetReport {
            address: address.parse().expect("address"),
            host: None,
            weight: 1,
            state,
            since,
            reason: reason.map(str::to_owned),
        };
        let mut named = target("10.0.0.1:80", TargetState::Healthy, at(1_761_696_000), None);
        named.host = Some("api.internal".to_owned());
        named.weight = 2;
        let ejected = TargetState::Ejected {
            until: UNIX_EPOCH + Duration::from_secs(1_761_696_070),
        };
        vec![
            UpstreamReport {
                name: "app".parse().expect("name"),
                health_check: Some(HealthCheckKind::Http),
                passive: true,
                targets: vec![
                    named,
                    target(
                        "10.0.0.2:80",
                        TargetState::Unhealthy,
                        at(1_761_696_030),
                        Some("status 503"),
                    ),
                    target(
                        "[::1]:80",
                        ejected,
                        at(1_761_696_060),
                        Some("connection refused"),
                    ),
                ],
            },
            UpstreamReport {
                name: "plain".parse().expect("name"),
                health_check: None,
                passive: false,
                targets: vec![target("10.0.0.3:80", TargetState::Healthy, None, None)],
            },
        ]
    }
}

/// Reports two certificates that expire at fixed times.
struct Tls;

impl TlsReport for Tls {
    /// Returns the same certificates every time.
    fn certificates(&self) -> Vec<CertificateReport> {
        let certificate = |name: &str, expiry| CertificateReport {
            name: name.parse().expect("name"),
            not_after: UNIX_EPOCH + Duration::from_secs(expiry),
        };
        vec![
            certificate("example", 1_793_000_000),
            certificate("wildcard", 1_800_000_000),
        ]
    }
}

/// A server and its Admin API on a fresh database.
struct Harness {
    /// Routes of the Admin API.
    router: Router,
    /// The server the API controls.
    server: Arc<Server>,
    /// The database.
    store: Store,
    /// Directory of the database, removed when the test ends.
    dir: TempDir,
}

impl Harness {
    /// Starts without dynamic settings; `source` is `db` or `file`.
    async fn start(source: &str) -> Self {
        let dir = tempfile::tempdir().expect("temporary directory");
        let store = Store::open(&dir.path().join("wormway.db"))
            .await
            .expect("open the database");
        Self::with_store(source, store, dir).await
    }

    /// Starts on an existing database, with the newest saved version in database mode.
    async fn with_store(source: &str, store: Store, dir: TempDir) -> Self {
        let mut services = Services::new();
        services.register(Protocol::Http, Hello);
        services.set_health_report(Report);
        services.set_tls_report(Tls);
        let text = format!("version = 1\n[config]\nsource = \"{source}\"\n");
        let mut config = Config::from_toml(&text).expect("configuration");
        if let Some((_, dynamic)) = store.latest_version().await.expect("latest version") {
            config.set_dynamic(dynamic);
        }
        let server = Server::start(Handle::current(), services, config)
            .await
            .map(Arc::new)
            .unwrap_or_else(|error| panic!("cannot start: {error}"));
        let token = AdminToken::new(TOKEN).expect("token");
        let admin = Admin::new(server.clone(), store.clone(), token, Metrics::detached())
            .await
            .expect("Admin API");
        Self {
            router: admin.router(),
            server,
            store,
            dir,
        }
    }

    /// Sends `request` and returns the status, the headers and the body.
    async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.expect("body");
        let text = String::from_utf8(bytes.to_vec()).expect("UTF-8 body");
        (parts.status, parts.headers, text)
    }

    /// Sends an authenticated request with an optional JSON body and extra headers, and
    /// returns the status, the headers and the JSON answer.
    async fn call(
        &self,
        method: &str,
        uri: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, HeaderMap, Value) {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let request = match body {
            Some(json) => builder
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json.to_string())),
            None => builder.body(Body::empty()),
        }
        .expect("request");
        let (status, headers, text) = self.send(request).await;
        (
            status,
            headers,
            serde_json::from_str(&text).unwrap_or(Value::Null),
        )
    }

    /// `GET` with the token.
    async fn get(&self, uri: &str) -> (StatusCode, Value) {
        let (status, _, body) = self.call("GET", uri, None, &[]).await;
        (status, body)
    }

    /// `PUT /api/v1/config` with the token.
    async fn put_config(&self, config: Value, headers: &[(&str, &str)]) -> (StatusCode, Value) {
        let body = json!({ "config": config, "comment": "test" });
        let (status, _, body) = self
            .call("PUT", "/api/v1/config", Some(body), headers)
            .await;
        (status, body)
    }
}

/// Dynamic settings with listener `name` on `addr`.
fn listener(name: &str, addr: &str) -> Value {
    json!({ "listeners": { name: { "listen": [addr], "protocol": "http" } } })
}

/// Reads the greeting of the listener at `addr`.
async fn greeting(addr: &str) -> String {
    let addr: SocketAddr = addr.parse().expect("address");
    let mut stream = TcpStream::connect(addr).await.expect("connect");
    let mut text = String::new();
    stream.read_to_string(&mut text).await.expect("read");
    text
}

/// `/healthz` answers without a token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_needs_no_token() {
    let harness = Harness::start("db").await;
    let request = Request::get("/healthz").body(Body::empty()).unwrap();
    let (status, _, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, r#"{"status":"ok"}"#);
}

/// Everything else needs the right token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requires_the_token() {
    let harness = Harness::start("db").await;
    for (uri, credential) in [
        ("/api/v1/status", None),
        ("/api/v1/status", Some("Bearer wrong")),
        ("/api/v1/status", Some("Basic dGVzdA==")),
        ("/metrics", None),
    ] {
        let mut builder = Request::get(uri);
        if let Some(credential) = credential {
            builder = builder.header(header::AUTHORIZATION, credential);
        }
        let (status, headers, body) = harness.send(builder.body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri} {credential:?}");
        assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
        assert!(body.contains(r#""code":"unauthorized""#), "{body}");
    }

    let (status, headers, _) = harness.call("GET", "/metrics", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        headers[header::CONTENT_TYPE]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
}

/// The metrics end with the state in effect, as the reports tell it at the scrape: whether each
/// target gets requests, and when each certificate expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exports_the_state_as_metrics() {
    let harness = Harness::start("db").await;
    let request = Request::get("/metrics").header(header::AUTHORIZATION, format!("Bearer {TOKEN}"));
    let (status, _, body) = harness.send(request.body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    let lines: Vec<&str> = body
        .lines()
        .filter(|line| !line.starts_with("# HELP "))
        .collect();
    let expected = [
        "# TYPE wormway_upstream_target_healthy gauge",
        r#"wormway_upstream_target_healthy{upstream="app",target="10.0.0.1:80"} 1"#,
        r#"wormway_upstream_target_healthy{upstream="app",target="10.0.0.2:80"} 0"#,
        r#"wormway_upstream_target_healthy{upstream="app",target="[::1]:80"} 0"#,
        r#"wormway_upstream_target_healthy{upstream="plain",target="10.0.0.3:80"} 1"#,
        "",
        "# TYPE wormway_certificate_expiry_timestamp_seconds gauge",
        r#"wormway_certificate_expiry_timestamp_seconds{certificate="example"} 1793000000"#,
        r#"wormway_certificate_expiry_timestamp_seconds{certificate="wildcard"} 1800000000"#,
        "",
    ];
    assert_eq!(lines, expected, "{body}");
    assert_eq!(body.matches("# HELP ").count(), 2, "{body}");
}

/// The status reports the version, the configuration and the listeners.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_status() {
    let harness = Harness::start("db").await;
    let (status, body) = harness.get("/api/v1/status").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["instance"].as_str().map(str::len), Some(32));
    assert_eq!(body["config"], json!({ "source": "db", "version": null }));
    assert_eq!(body["snapshot"], 1);
    assert_eq!(body["listeners"], json!([]));
}

/// The health of the upstreams comes from the report of the gateway, with RFC 3339 times, and
/// needs the token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_the_health_of_upstreams() {
    let harness = Harness::start("db").await;
    let request = Request::get("/api/v1/status/upstreams").body(Body::empty());
    let (status, _, _) = harness.send(request.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = harness.get("/api/v1/status/upstreams").await;
    assert_eq!(status, StatusCode::OK);
    let target = |address: &str,
                  host: Value,
                  weight,
                  state: &str,
                  since: Value,
                  until: Value,
                  reason: Value| {
        json!({
            "address": address, "host": host, "weight": weight, "state": state,
            "since": since, "until": until, "reason": reason,
        })
    };
    let expected = json!({ "upstreams": [
        {
            "name": "app",
            "health_check": "http",
            "passive": true,
            "targets": [
                target("10.0.0.1:80", json!("api.internal"), 2, "healthy", json!("2025-10-29T00:00:00.000Z"), Value::Null, Value::Null),
                target("10.0.0.2:80", Value::Null, 1, "unhealthy", json!("2025-10-29T00:00:30.000Z"), Value::Null, json!("status 503")),
                target("[::1]:80", Value::Null, 1, "ejected", json!("2025-10-29T00:01:00.000Z"), json!("2025-10-29T00:01:10.000Z"), json!("connection refused")),
            ],
        },
        {
            "name": "plain",
            "health_check": null,
            "passive": false,
            "targets": [target("10.0.0.3:80", Value::Null, 1, "healthy", Value::Null, Value::Null, Value::Null)],
        },
    ]});
    assert_eq!(body, expected);
}

/// A change is saved as a version, applied, and visible in the configuration and the status.
/// Sending the settings in effect again changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applies_and_saves_changes() {
    let harness = Harness::start("db").await;
    let web = listener("web", "127.0.0.1:0");
    let (status, body) = harness.put_config(web.clone(), &[]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "version": 1, "changed": true }));

    let (status, headers, body) = harness.call("GET", "/api/v1/config", None, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers[header::ETAG], "\"1\"");
    assert_eq!(body["version"], 1);
    assert_eq!(
        body["config"]["listeners"]["web"]["listen"],
        json!(["127.0.0.1:0"])
    );

    let (_, status_body) = harness.get("/api/v1/status").await;
    let addr = status_body["listeners"][0]["addresses"][0]
        .as_str()
        .expect("bound address");
    assert_eq!(greeting(addr).await, "hello\n");

    let (status, body) = harness.put_config(web, &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "version": 1, "changed": false }));
    let (_, body) = harness.get("/api/v1/config/versions").await;
    assert_eq!(body["versions"].as_array().map(Vec::len), Some(1));
    assert_eq!(body["versions"][0]["source"], "api");
    assert_eq!(body["versions"][0]["comment"], "test");
}

/// Invalid settings are refused with the path of each problem, and nothing is saved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_invalid_changes() {
    let harness = Harness::start("db").await;
    let invalid = json!({ "listeners": { "web": { "listen": [], "protocol": "http" } } });
    let (status, body) = harness.put_config(invalid, &[]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "invalid_config");
    assert_eq!(
        body["error"]["details"],
        json!([{ "path": "listeners.web.listen", "message": "must list at least one address" }])
    );
    let (_, body) = harness.get("/api/v1/config/versions").await;
    assert_eq!(body["versions"], json!([]));
}

/// Bodies that are not JSON, or JSON of another shape, are bad requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_malformed_bodies() {
    let harness = Harness::start("db").await;
    let request = Request::put("/api/v1/config")
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let (status, _, body) = harness.send(request).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains(r#""code":"invalid_request""#), "{body}");

    let (status, body) = harness.put_config(json!({ "route": {} }), &[]).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}

/// When an address cannot be bound, the version is not saved.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn saves_nothing_when_applying_fails() {
    let harness = Harness::start("db").await;
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let taken = blocker.local_addr().expect("address").to_string();
    let (status, body) = harness.put_config(listener("web", &taken), &[]).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["code"], "apply_failed");
    assert!(
        body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("cannot listen on")),
        "{body}"
    );
    let (_, body) = harness.get("/api/v1/config/versions").await;
    assert_eq!(body["versions"], json!([]));
}

/// When the version cannot be saved, the change is not applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn applies_nothing_when_saving_fails() {
    let harness = Harness::start("db").await;
    harness.store.close().await;
    let (status, body) = harness
        .put_config(listener("web", "127.0.0.1:0"), &[])
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"]["code"], "internal");
    assert!(harness.server.listeners().await.is_empty());
    assert_eq!(harness.server.snapshot().version, 1);
}

/// `If-Match` with another version than the one in effect refuses the change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guards_against_concurrent_changes() {
    let harness = Harness::start("db").await;
    harness
        .put_config(listener("web", "127.0.0.1:0"), &[])
        .await;

    let api = listener("api", "127.0.0.1:0");
    let (status, body) = harness
        .put_config(api.clone(), &[("if-match", "\"7\"")])
        .await;
    assert_eq!(status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(body["error"]["code"], "version_mismatch");

    let (status, body) = harness.put_config(api, &[("if-match", "\"1\"")]).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["version"], 2);
}

/// A rollback saves the settings of an older version as a new version and applies them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rolls_back_to_older_versions() {
    let harness = Harness::start("db").await;
    let web = listener("web", "127.0.0.1:0");
    harness.put_config(web.clone(), &[]).await;
    harness
        .put_config(listener("api", "127.0.0.1:0"), &[])
        .await;

    let (status, _, body) = harness
        .call("POST", "/api/v1/config/versions/1/rollback", None, &[])
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({ "version": 3, "changed": true }));
    let (_, body) = harness.get("/api/v1/config").await;
    assert_eq!(body["config"]["listeners"], web["listeners"]);

    let (_, body) = harness.get("/api/v1/config/versions?limit=2").await;
    let ids: Vec<_> = body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["id"].clone())
        .collect();
    assert_eq!(ids, [json!(3), json!(2)]);
    assert_eq!(body["versions"][0]["comment"], "rollback to version 1");
    let (_, body) = harness.get("/api/v1/config/versions?before=2").await;
    assert_eq!(body["versions"][0]["id"], 1);

    let (status, body) = harness.get("/api/v1/config/versions/1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["config"]["listeners"], web["listeners"]);
    let (status, _) = harness.get("/api/v1/config/versions/99").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = harness
        .call("POST", "/api/v1/config/versions/99/rollback", None, &[])
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The `Wormway-Client` header is saved as the source of a change; unknown clients are refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn records_the_client_of_a_change() {
    let harness = Harness::start("db").await;
    let ui = [("wormway-client", "ui")];
    harness
        .put_config(listener("web", "127.0.0.1:0"), &ui)
        .await;
    harness
        .put_config(listener("api", "127.0.0.1:0"), &[])
        .await;
    let (status, _, body) = harness
        .call(
            "POST",
            "/api/v1/config/versions/1/rollback",
            None,
            &[("wormway-client", "cli")],
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, body) = harness.get("/api/v1/config/versions").await;
    let sources: Vec<_> = body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["source"].clone())
        .collect();
    assert_eq!(sources, [json!("cli"), json!("api"), json!("ui")]);

    let (status, body) = harness
        .put_config(
            listener("other", "127.0.0.1:0"),
            &[("wormway-client", "browser")],
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_request");
}

/// Validation checks settings without saving or applying them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validates_without_applying() {
    let harness = Harness::start("db").await;
    let valid = json!({ "config": listener("web", "127.0.0.1:0") });
    let (status, _, body) = harness
        .call("POST", "/api/v1/config/validate", Some(valid), &[])
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "valid": true }));

    let invalid =
        json!({ "config": { "listeners": { "web": { "listen": [], "protocol": "http" } } } });
    let (status, _, body) = harness
        .call("POST", "/api/v1/config/validate", Some(invalid), &[])
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"]["details"][0]["path"], "listeners.web.listen");

    assert!(harness.server.listeners().await.is_empty());
    let (_, body) = harness.get("/api/v1/config/versions").await;
    assert_eq!(body["versions"], json!([]));
}

/// In file mode the dynamic settings come from the file, so the API cannot change them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn is_read_only_in_file_mode() {
    let harness = Harness::start("file").await;
    let (status, body) = harness
        .put_config(listener("web", "127.0.0.1:0"), &[])
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"]["code"], "read_only");
    let (status, _, _) = harness
        .call("POST", "/api/v1/config/versions/1/rollback", None, &[])
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (_, body) = harness.get("/api/v1/config").await;
    assert_eq!(body["source"], "file");
    assert_eq!(body["version"], Value::Null);
}

/// Unknown paths and methods get JSON errors too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_unknown_paths_and_methods() {
    let harness = Harness::start("db").await;
    let (status, body) = harness.get("/api/v1/nothing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "not_found");
    let (status, _, body) = harness.call("DELETE", "/api/v1/config", None, &[]).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"]["code"], "method_not_allowed");
}

/// Saved versions survive a restart, and the newest one is applied again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_versions_across_restarts() {
    let harness = Harness::start("db").await;
    harness
        .put_config(listener("web", "127.0.0.1:0"), &[])
        .await;
    let Harness {
        server, store, dir, ..
    } = harness;
    server.shutdown().await;
    store.close().await;

    let store = Store::open(&dir.path().join("wormway.db"))
        .await
        .expect("reopen the database");
    let restarted = Harness::with_store("db", store, dir).await;
    let (_, body) = restarted.get("/api/v1/status").await;
    assert_eq!(body["config"]["version"], 1);
    assert_eq!(body["listeners"][0]["name"], "web");
}
