//! Integration tests of upstreams with TLS and HTTP/2: certificate checks, names, client
//! certificates, connections kept apart by trust, and HTTP/2 with and without TLS.

#[allow(
    dead_code,
    reason = "the upstreams of the shared helpers are not used: these tests need TLS and HTTP/2"
)]
mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::body::Bytes;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tempfile::TempDir;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use zora_runtime::Server;

use crate::common::addr;

/// How long any exchange of a test may take, so that a test that hangs fails instead.
const LIMIT: Duration = Duration::from_secs(10);

/// A listener on any free loopback port.
const WEB: &str = "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";

/// A test certificate authority and the directory of the files the gateway reads.
struct Pki {
    /// Directory of the certificate and key files.
    dir: TempDir,
    /// The authority that signs the certificates.
    ca: CertifiedIssuer<'static, KeyPair>,
}

impl Pki {
    /// Creates the authority and writes its certificate as `ca.crt`.
    fn new() -> Self {
        let pki = Self {
            dir: TempDir::new().expect("directory"),
            ca: authority(),
        };
        pki.write("ca.crt", &pki.ca.pem());
        pki
    }

    /// Writes `text` to `file` in the directory.
    fn write(&self, file: &str, text: &str) {
        std::fs::write(self.dir.path().join(file), text).expect("write");
    }

    /// Issues a certificate for `names`, writes it and its key as `<file>.crt` and
    /// `<file>.key`, and returns both.
    fn issue(
        &self,
        file: &str,
        names: &[&str],
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().expect("key");
        let names: Vec<String> = names.iter().map(|name| (*name).to_owned()).collect();
        let cert = CertificateParams::new(names)
            .expect("parameters")
            .signed_by(&key, &*self.ca)
            .expect("certificate");
        self.write(&format!("{file}.crt"), &cert.pem());
        self.write(&format!("{file}.key"), &key.serialize_pem());
        let key = PrivatePkcs8KeyDer::from(key.serialize_der()).into();
        (cert.der().clone(), key)
    }

    /// Starts a server with the gateway, which reads its TLS files from the directory.
    async fn start(&self, text: &str) -> Server {
        common::start(&format!("{WEB}{text}"), self.dir.path()).await
    }
}

/// A new certificate authority.
fn authority() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let key = KeyPair::generate().expect("CA key");
    CertifiedIssuer::self_signed(params, key).expect("CA certificate")
}

/// The crypto provider of the test upstreams.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// What a test upstream with TLS presents and asks for.
struct TlsUpstream<'a> {
    /// Names of its certificate, issued by the authority of the PKI.
    names: &'a [&'a str],
    /// Application protocols it agrees to, in order of preference.
    alpn: &'a [&'a [u8]],
    /// Whether it requires a client certificate issued by the authority of the PKI.
    client_auth: bool,
}

/// Starts an upstream with TLS. Each response tells the name the client sent, whether it
/// presented a certificate, the protocol agreed on and the path. Returns the address and the
/// number of connections accepted.
async fn tls_upstream(pki: &Pki, upstream: TlsUpstream<'_>) -> (SocketAddr, Arc<AtomicUsize>) {
    let (cert, key) = pki.issue("upstream", upstream.names);
    let builder = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("protocol versions");
    let builder = if upstream.client_auth {
        let mut roots = RootCertStore::empty();
        roots.add(pki.ca.der().clone()).expect("root certificate");
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .expect("client verifier");
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder
        .with_single_cert(vec![cert], key)
        .expect("server certificate");
    config.alpn_protocols = upstream.alpn.iter().map(|alpn| alpn.to_vec()).collect();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(stream).await else {
                    return;
                };
                let (_, connection) = stream.get_ref();
                let alpn = connection.alpn_protocol().unwrap_or(b"-").to_vec();
                let info = format!(
                    "sni={} client={} alpn={}",
                    connection.server_name().unwrap_or("-"),
                    connection.peer_certificates().is_some(),
                    String::from_utf8_lossy(&alpn),
                );
                if alpn == b"h2" {
                    serve_h2(stream, info).await;
                } else {
                    serve_h1(stream, info).await;
                }
            });
        }
    });
    (addr, connections)
}

/// Starts an upstream that speaks HTTP/2 without TLS. Returns the address and the number of
/// connections accepted.
async fn h2c_upstream() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local address");
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = connections.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_h2(stream, "h2c".to_owned()));
        }
    });
    (addr, connections)
}

/// Answers each HTTP/1.1 request without a body on `stream` with `<info> <path>`.
async fn serve_h1(mut stream: impl AsyncRead + AsyncWrite + Unpin, info: String) {
    loop {
        let mut head = Vec::new();
        let mut byte = [0; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte).await {
                Ok(1) => head.push(byte[0]),
                _ => return,
            }
        }
        let head = String::from_utf8_lossy(&head);
        let path = head.split(' ').nth(1).unwrap_or("-");
        let body = format!("{info} {path}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if stream.write_all(response.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// Answers each HTTP/2 request on `stream` with `<info> <path>`, after 300 ms for `/slow`, and
/// for `/grpc` with the trailers of a successful gRPC call.
async fn serve_h2(stream: impl AsyncRead + AsyncWrite + Unpin, info: String) {
    let Ok(mut connection) = h2::server::handshake(stream).await else {
        return;
    };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        let path = request.uri().path().to_owned();
        let body = format!("{info} {path}");
        tokio::spawn(async move {
            if path == "/slow" {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            let response = axum::http::Response::new(());
            let Ok(mut send) = respond.send_response(response, false) else {
                return;
            };
            if path == "/grpc" {
                let _ = send.send_data(Bytes::from(body), false);
                let mut trailers = axum::http::HeaderMap::new();
                trailers.insert("grpc-status", axum::http::HeaderValue::from_static("0"));
                let _ = send.send_trailers(trailers);
            } else {
                let _ = send.send_data(Bytes::from(body), true);
            }
        });
    }
}

/// Sends `GET path` to `web` and returns the status and the body.
async fn get(web: SocketAddr, path: &str) -> (u16, String) {
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
    (status, response.text().await.expect("body"))
}

/// A route for `path` to upstream `name` with `settings`.
fn route(name: &str, path: &str, settings: &str) -> String {
    format!(
        "[routes.{name}]\nmatch = {{ paths = [\"{path}\"] }}\nupstream = \"{name}\"\n\
         [upstreams.{name}]\n{settings}\n"
    )
}

/// Certificates are checked against the authorities of `ca`, for the host name of the target,
/// its IP address or the configured name; unknown authorities and other names fail, unless
/// checks are off.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn checks_upstream_certificates() {
    let pki = Pki::new();
    let names = ["upstream.test", "localhost", "127.0.0.1"];
    let (upstream, _) = tls_upstream(
        &pki,
        TlsUpstream {
            names: &names,
            alpn: &[b"http/1.1"],
            client_auth: false,
        },
    )
    .await;
    let port = upstream.port();
    let server = pki
        .start(&[
            route("ip", "/ip", &format!("targets = [\"{upstream}\"]\ntls = {{ ca = \"ca.crt\" }}")),
            route("name", "/name", &format!("targets = [\"localhost:{port}\"]\ntls = {{ ca = \"ca.crt\" }}")),
            route("sni", "/sni", &format!("targets = [\"{upstream}\"]\ntls = {{ ca = \"ca.crt\", sni = \"upstream.test\" }}")),
            route("wrong", "/wrong", &format!("targets = [\"{upstream}\"]\ntls = {{ ca = \"ca.crt\", sni = \"wrong.test\" }}")),
            route("system", "/system", &format!("targets = [\"{upstream}\"]\ntls = {{}}")),
            route("unchecked", "/unchecked", &format!("targets = [\"{upstream}\"]\ntls = {{ verify = false, sni = \"wrong.test\" }}")),
        ]
        .concat())
        .await;
    let web = addr(&server, "web").await;
    let ok = |body: &str| (200, body.to_owned());
    assert_eq!(
        get(web, "/ip").await,
        ok("sni=- client=false alpn=http/1.1 /ip")
    );
    assert_eq!(
        get(web, "/name").await,
        ok("sni=localhost client=false alpn=http/1.1 /name")
    );
    assert_eq!(
        get(web, "/sni").await,
        ok("sni=upstream.test client=false alpn=http/1.1 /sni")
    );
    assert_eq!(get(web, "/wrong").await.0, 502);
    assert_eq!(get(web, "/system").await.0, 502);
    assert_eq!(
        get(web, "/unchecked").await,
        ok("sni=wrong.test client=false alpn=http/1.1 /unchecked")
    );
}

/// Upstreams that require a client certificate get the configured one, and refuse requests
/// without it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn presents_client_certificates() {
    let pki = Pki::new();
    pki.issue("zora", &["zora.test"]);
    let (upstream, _) = tls_upstream(
        &pki,
        TlsUpstream {
            names: &["127.0.0.1"],
            alpn: &[b"http/1.1"],
            client_auth: true,
        },
    )
    .await;
    let server = pki
        .start(&[
            route("with", "/with", &format!("targets = [\"{upstream}\"]\ntls = {{ ca = \"ca.crt\", cert = \"zora.crt\", key = \"zora.key\" }}")),
            route("without", "/without", &format!("targets = [\"{upstream}\"]\ntls = {{ ca = \"ca.crt\" }}")),
        ]
        .concat())
        .await;
    let web = addr(&server, "web").await;
    assert_eq!(
        get(web, "/with").await,
        (200, "sni=- client=true alpn=http/1.1 /with".to_owned())
    );
    assert_eq!(get(web, "/without").await.0, 502);
}

/// A connection checked against one authority is reused by its upstream, but not by another
/// upstream of the same target that trusts another authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_connections_of_different_trust_apart() {
    let pki = Pki::new();
    pki.write("other-ca.crt", &authority().pem());
    let (upstream, connections) = tls_upstream(
        &pki,
        TlsUpstream {
            names: &["127.0.0.1"],
            alpn: &[b"http/1.1"],
            client_auth: false,
        },
    )
    .await;
    let server = pki
        .start(
            &[
                route(
                    "trusting",
                    "/trusting",
                    &format!("targets = [\"{upstream}\"]\ntls = {{ ca = \"ca.crt\" }}"),
                ),
                route(
                    "doubting",
                    "/doubting",
                    &format!("targets = [\"{upstream}\"]\ntls = {{ ca = \"other-ca.crt\" }}"),
                ),
            ]
            .concat(),
        )
        .await;
    let web = addr(&server, "web").await;
    for _ in 0..2 {
        assert_eq!(get(web, "/trusting").await.0, 200);
    }
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "the connection is reused"
    );
    assert_eq!(get(web, "/doubting").await.0, 502);
}

/// HTTP/2 reaches upstreams over TLS when agreed on and without TLS from the first byte, and
/// requests at the same time share one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn speaks_http2_to_upstreams() {
    let pki = Pki::new();
    let (secure, _) = tls_upstream(
        &pki,
        TlsUpstream {
            names: &["127.0.0.1"],
            alpn: &[b"h2", b"http/1.1"],
            client_auth: false,
        },
    )
    .await;
    let (plain, connections) = h2c_upstream().await;
    let server = pki
        .start(
            &[
                route(
                    "h2",
                    "/h2",
                    &format!(
                        "targets = [\"{secure}\"]\nprotocol = \"h2\"\ntls = {{ ca = \"ca.crt\" }}"
                    ),
                ),
                route(
                    "h1",
                    "/h1",
                    &format!("targets = [\"{secure}\"]\ntls = {{ ca = \"ca.crt\" }}"),
                ),
                route(
                    "h2c",
                    "/h2c",
                    &format!("targets = [\"{plain}\"]\nprotocol = \"h2c\""),
                ),
                route(
                    "slow",
                    "/slow",
                    &format!("targets = [\"{plain}\"]\nprotocol = \"h2c\""),
                ),
            ]
            .concat(),
        )
        .await;
    let web = addr(&server, "web").await;
    assert_eq!(
        get(web, "/h2").await,
        (200, "sni=- client=false alpn=h2 /h2".to_owned())
    );
    assert_eq!(
        get(web, "/h1").await,
        (200, "sni=- client=false alpn=http/1.1 /h1".to_owned())
    );
    assert_eq!(get(web, "/h2c").await, (200, "h2c /h2c".to_owned()));
    let requests: Vec<_> = (0..4).map(|_| tokio::spawn(get(web, "/slow"))).collect();
    for request in requests {
        let response = request.await.expect("request");
        assert_eq!(response, (200, "h2c /slow".to_owned()));
    }
    // The connection of the first request, and at most one more opened at the same time.
    let opened = connections.load(Ordering::SeqCst);
    assert!(opened <= 2, "{opened} connections for 5 requests");
}

/// Sends `POST path` over HTTP/2 without TLS to `web` and returns the body and the value of
/// trailer `grpc-status`.
async fn post_http2(web: SocketAddr, path: &str) -> (String, Option<String>) {
    let exchange = async {
        let stream = TcpStream::connect(web).await.expect("connect");
        let (client, connection) = h2::client::handshake(stream).await.expect("handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = axum::http::Request::post(format!("http://{web}{path}"))
            .header("content-type", "application/grpc")
            .body(())
            .expect("request");
        let mut client = client.ready().await.expect("ready");
        let (response, _) = client.send_request(request, true).expect("send");
        let mut body = response.await.expect("response").into_body();
        let mut bytes = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.expect("data");
            let _ = body.flow_control().release_capacity(chunk.len());
            bytes.extend_from_slice(&chunk);
        }
        let trailers = body.trailers().await.expect("trailers");
        let status = trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-status"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        (String::from_utf8(bytes).expect("UTF-8 body"), status)
    };
    tokio::time::timeout(LIMIT, exchange)
        .await
        .expect("the exchange ends in time")
}

/// The trailers of an HTTP/2 upstream, which gRPC needs for the status of a call, reach HTTP/2
/// clients.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn passes_trailers_for_grpc() {
    let (plain, _) = h2c_upstream().await;
    let listener = "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n\
                    http = { h2c = true }\n";
    let routes = route(
        "grpc",
        "/grpc",
        &format!("targets = [\"{plain}\"]\nprotocol = \"h2c\""),
    );
    let server = common::start(&format!("{listener}{routes}"), std::path::Path::new(".")).await;
    let web = addr(&server, "web").await;
    assert_eq!(
        post_http2(web, "/grpc").await,
        ("h2c /grpc".to_owned(), Some("0".to_owned()))
    );
}
