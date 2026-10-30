//! End-to-end test of ACME against Pebble, the test certificate authority of Let's Encrypt,
//! which CI runs with pebble-challtestsrv answering its DNS queries with 127.0.0.1: the gateway
//! answers the HTTP-01 challenges, and the certificate is installed and stored. Without Pebble,
//! as on most machines, the test passes without doing anything, unless
//! `WORMWAY_REQUIRE_PEBBLE` is set.

mod common;

use std::path::PathBuf;
use std::time::Duration;

use tokio::runtime::Handle;
use tokio::time::Instant;
use wormway_acme::Acme;
use wormway_core::config::{Config, Name};
use wormway_gateway::Gateway;
use wormway_runtime::{Server, Services};
use wormway_tls::Certificates;

use crate::common::Memory;

/// URL of the directory of Pebble.
const DIRECTORY_ENV: &str = "WORMWAY_PEBBLE_DIRECTORY";
/// PEM file with the authority of the HTTPS certificate of Pebble.
const CA_ENV: &str = "WORMWAY_PEBBLE_CA";
/// Set where Pebble must run, so that the test cannot pass without it.
const REQUIRE_ENV: &str = "WORMWAY_REQUIRE_PEBBLE";
/// The port that Pebble sends HTTP-01 challenges to, as its test configuration says.
const HTTP_PORT: u16 = 5002;
/// How long Pebble may take to issue a certificate.
const LIMIT: Duration = Duration::from_secs(60);

/// Returns the directory of Pebble and its authority, or `None` when Pebble is not running.
fn pebble() -> Option<(String, PathBuf)> {
    match (std::env::var(DIRECTORY_ENV), std::env::var(CA_ENV)) {
        (Ok(directory), Ok(ca)) => Some((directory, ca.into())),
        _ => {
            let required = std::env::var_os(REQUIRE_ENV).is_some();
            assert!(!required, "{DIRECTORY_ENV} and {CA_ENV} must name Pebble");
            eprintln!("skipped: {DIRECTORY_ENV} and {CA_ENV} do not name Pebble");
            None
        }
    }
}

/// Pebble checks the HTTP-01 challenges of two host names through the gateway, then issues a
/// certificate for both, which is presented and stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issues_certificates_through_pebble() {
    let Some((directory, ca)) = pebble() else {
        return;
    };
    let text = format!(
        r#"
        version = 1
        [config]
        source = "file"
        [acme]
        directory = "{directory}"
        ca = "{}"
        email = "ops@wormway.test"
        [listeners.web]
        listen = ["127.0.0.1:{HTTP_PORT}"]
        protocol = "http"
        [certificates.site]
        acme = {{ domains = ["site.wormway.test", "www.wormway.test"] }}
        "#,
        ca.display()
    );
    let config = Config::from_toml(&text).expect("configuration");
    let storage = Memory::default();
    let mut services = Services::new();
    let certificates = Certificates::new(".");
    certificates.register(&mut services);
    let acme = Acme::new(&config.acme, certificates.clone(), storage.clone(), ".");
    acme.register(&mut services);
    Gateway::new(2, certificates.clone()).register(&mut services);
    let _server = Server::start(Handle::current(), services, config)
        .await
        .expect("server");
    tokio::spawn(acme.run());

    let site: Name = "site".parse().expect("name");
    let deadline = Instant::now() + LIMIT;
    let issued = loop {
        if let Some(issued) = certificates.issued(&site) {
            break issued;
        }
        assert!(Instant::now() < deadline, "no certificate from Pebble");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let mut names = issued.info().names.clone();
    names.sort();
    assert_eq!(names, ["site.wormway.test", "www.wormway.test"]);
    assert!(
        issued.info().issuer.contains("Pebble"),
        "{}",
        issued.info().issuer
    );
    let stored = storage
        .certificates
        .lock()
        .expect("lock")
        .get(&site)
        .cloned();
    let stored = stored.expect("stored certificate");
    assert_eq!(stored.directory, directory);
    assert_eq!(stored.domains, ["site.wormway.test", "www.wormway.test"]);
    assert_eq!(storage.accounts.lock().expect("lock").len(), 1);
}
