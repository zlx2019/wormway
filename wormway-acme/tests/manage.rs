//! Integration tests of ACME that need no certificate authority: certificates issued before
//! come back from storage, the tokens of DNS providers must be readable, certificates that the
//! configuration drops are removed, and the report tells how orders go.

mod common;

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rcgen::{CertificateParams, KeyPair};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::sync::Notify;
use tokio::time::Instant;
use wormway_acme::{Acme, StoredCertificate};
use wormway_core::config::{Config, ConfigError, Name};
use wormway_runtime::{AcmeCertificateReport, ApplyError, Server, Services};
use wormway_tls::Certificates;

use crate::common::Memory;

/// A directory that nothing answers at; these tests never reach it.
const DIRECTORY: &str = "https://127.0.0.1:9/directory";

/// How long a test may wait for the manager.
const LIMIT: Duration = Duration::from_secs(10);

/// A certificate for `domains` from [`DIRECTORY`], as ACME would have issued it.
fn issued(domains: &[&str]) -> StoredCertificate {
    issued_until(domains, 2030)
}

/// A certificate for `domains` from [`DIRECTORY`] that is valid until the start of `year`.
fn issued_until(domains: &[&str], year: i32) -> StoredCertificate {
    issued_within(domains, 1975, year)
}

/// A certificate for `domains` from [`DIRECTORY`] that is valid from the start of year `from`
/// until the start of year `until`.
fn issued_within(domains: &[&str], from: i32, until: i32) -> StoredCertificate {
    let key = KeyPair::generate().expect("key");
    let names: Vec<String> = domains.iter().map(|domain| (*domain).to_owned()).collect();
    let mut params = CertificateParams::new(names.clone()).expect("certificate parameters");
    params.not_before = rcgen::date_time_ymd(from, 1, 1);
    params.not_after = rcgen::date_time_ymd(until, 1, 1);
    let cert = params.self_signed(&key).expect("certificate");
    StoredCertificate {
        directory: DIRECTORY.to_owned(),
        domains: names,
        chain: cert.pem(),
        key: key.serialize_pem(),
    }
}

/// The configuration of [`DIRECTORY`] with the certificates of `text`.
fn config(text: &str) -> Config {
    config_at(DIRECTORY, text)
}

/// The configuration of ACME directory `directory` with the certificates of `text`.
fn config_at(directory: &str, text: &str) -> Config {
    let text = format!(
        "version = 1\n[config]\nsource = \"file\"\n[acme]\ndirectory = \"{directory}\"\n{text}"
    );
    Config::from_toml(&text).expect("configuration")
}

/// Starts a server with the certificates and ACME on `storage`, and returns it with them.
async fn start(text: &str, storage: Memory) -> (Server, Certificates, Acme) {
    start_at(config(text), storage).await
}

/// Starts a server like [`start`], with `config`.
async fn start_at(config: Config, storage: Memory) -> (Server, Certificates, Acme) {
    let mut services = Services::new();
    let certificates = Certificates::new(".");
    certificates.register(&mut services);
    let acme = Acme::new(&config.acme, certificates.clone(), storage, ".");
    acme.register(&mut services);
    let server = Server::start(Handle::current(), services, config)
        .await
        .expect("server");
    (server, certificates, acme)
}

/// A certificate issued before for the same host names by the same directory is presented
/// from the start; one for other names, or from another directory, is not. A DNS provider whose
/// token is missing turns the change down.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn installs_stored_certificates() {
    let storage = Memory::default();
    let name = |name: &str| -> Name { name.parse().unwrap() };
    {
        let mut certificates = storage.certificates.lock().unwrap();
        certificates.insert(name("site"), issued(&["site.test", "www.site.test"]));
        certificates.insert(name("other"), issued(&["old.test"]));
        let mut staging = issued(&["staging.test"]);
        staging.directory = "https://127.0.0.1:9/staging".to_owned();
        certificates.insert(name("staging"), staging);
    }
    let text = r#"
        [certificates.site]
        acme = { domains = ["www.site.test", "site.test"] }
        [certificates.other]
        acme = { domains = ["other.test"] }
        [certificates.staging]
        acme = { domains = ["staging.test"] }
    "#;
    let (server, certificates, _acme) = start(text, storage).await;
    let details = certificates.details();
    assert_eq!(
        details.keys().map(Name::as_str).collect::<Vec<_>>(),
        ["site"]
    );
    assert_eq!(details["site"].names, ["site.test", "www.site.test"]);

    let wild = r#"
        [certificates.wild]
        acme = { domains = ["*.site.test"], challenge = "dns-01", dns = { provider = "cloudflare", api_token = { env = "WORMWAY_TEST_SURELY_UNSET" } } }
    "#;
    match server.apply(config(wild)).await {
        Err(ApplyError::Config(ConfigError::Invalid(issues))) => {
            let issues: Vec<String> = issues.iter().map(ToString::to_string).collect();
            assert_eq!(
                issues,
                [
                    "certificates.wild.acme.dns.api_token: environment variable WORMWAY_TEST_SURELY_UNSET is not set"
                ]
            );
        }
        other => panic!("expected the change to be turned down, got {other:?}"),
    }
}

/// The token of a DNS provider may come from a file, relative to the configuration file.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_tokens_from_files() {
    let dir = tempfile::tempdir().expect("directory");
    std::fs::write(dir.path().join("token"), "a-token\n").expect("write the token");
    let config = config(
        r#"
        [certificates.wild]
        acme = { domains = ["*.site.test"], challenge = "dns-01", dns = { provider = "cloudflare", api_token = { file = "token" } } }
    "#,
    );
    let mut services = Services::new();
    let certificates = Certificates::new(dir.path());
    certificates.register(&mut services);
    let acme = Acme::new(&config.acme, certificates, Memory::default(), dir.path());
    acme.register(&mut services);
    if let Err(error) = Server::start(Handle::current(), services, config).await {
        panic!("the token should be read: {error:?}");
    }
}

/// When the configuration drops a certificate, the manager stops presenting it and removes it
/// from storage.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removes_dropped_certificates() {
    let storage = Memory::default();
    let site: Name = "site".parse().unwrap();
    storage
        .certificates
        .lock()
        .unwrap()
        .insert(site.clone(), issued(&["site.test"]));
    let text = "[certificates.site]\nacme = { domains = [\"site.test\"] }\n";
    let (server, certificates, acme) = start(text, storage.clone()).await;
    assert!(certificates.issued(&site).is_some());
    tokio::spawn(acme.run());

    server.apply(config("")).await.unwrap();
    let deadline = Instant::now() + LIMIT;
    while storage.removed.lock().unwrap().is_empty() {
        assert!(Instant::now() < deadline, "the certificate was not removed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        storage.removed.lock().unwrap().as_slice(),
        std::slice::from_ref(&site)
    );
    assert!(storage.certificates.lock().unwrap().is_empty());
    assert!(certificates.issued(&site).is_none());
}

/// Certificates stored for names that the configuration does not have, such as ones dropped
/// while Wormway was stopped, are removed when the manager starts; the others stay.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removes_certificates_dropped_before_the_start() {
    let storage = Memory::default();
    let site: Name = "site".parse().expect("name");
    let old: Name = "old".parse().expect("name");
    {
        let mut certificates = storage.certificates.lock().expect("lock");
        certificates.insert(site.clone(), issued(&["site.test"]));
        certificates.insert(old.clone(), issued(&["old.test"]));
    }
    let text = "[certificates.site]\nacme = { domains = [\"site.test\"] }\n";
    let (_server, certificates, acme) = start(text, storage.clone()).await;
    tokio::spawn(acme.run());

    let deadline = Instant::now() + LIMIT;
    while storage.removed.lock().expect("lock").is_empty() {
        assert!(Instant::now() < deadline, "the certificate was not removed");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        storage.removed.lock().expect("lock").as_slice(),
        std::slice::from_ref(&old)
    );
    assert!(
        storage
            .certificates
            .lock()
            .expect("lock")
            .contains_key(&site)
    );
    assert!(certificates.issued(&site).is_some());
}

/// A change that reads an older certificate from storage leaves a newer one for the same names
/// installed, such as one that the manager installed meanwhile.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_newer_installed_certificates() {
    let storage = Memory::default();
    let site: Name = "site".parse().expect("name");
    storage
        .certificates
        .lock()
        .expect("lock")
        .insert(site.clone(), issued_until(&["site.test"], 2030));
    let text = "[certificates.site]\nacme = { domains = [\"site.test\"] }\n";
    let (server, certificates, _acme) = start(text, storage).await;
    let newer = issued_until(&["site.test"], 2031);
    let newer = certificates
        .read_issued(&newer.chain, &newer.key)
        .expect("certificate");
    certificates.install(&site, &newer);

    server.apply(config(text)).await.expect("apply");
    let installed = certificates.issued(&site).expect("installed");
    assert_eq!(installed.info().not_after, newer.info().not_after);
}

/// Waits until the report has a certificate that `found` accepts, and returns it.
async fn reported(
    server: &Server,
    found: impl Fn(&AcmeCertificateReport) -> bool,
) -> AcmeCertificateReport {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Some(report) = server.acme_certificates().into_iter().find(&found) {
            return report;
        }
        let reports = server.acme_certificates();
        assert!(Instant::now() < deadline, "not reported: {reports:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// How long after now the next order of `report` is placed.
fn retry_in(report: &AcmeCertificateReport) -> Duration {
    let retry_at = report.retry_at.expect("a time to try again");
    retry_at
        .duration_since(SystemTime::now())
        .expect("in the future")
}

/// The report tells how an order went: failed, why, and that the next one comes an hour later.
/// A renewal asked for orders again at once, and the wait after it is longer. Certificates
/// that ACME does not manage cannot be renewed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_failures_and_renews_on_request() {
    let text = "[certificates.site]\nacme = { domains = [\"site.test\"] }\n";
    let (server, _certificates, acme) = start(text, Memory::default()).await;
    let site: Name = "site".parse().expect("name");
    assert!(server.acme_certificates().is_empty());
    tokio::spawn(acme.run());

    let report = reported(&server, |report| report.failures == 1).await;
    assert_eq!(report.name, site);
    assert_eq!((report.renew_at, report.ordering), (None, false));
    let error = report.last_error.as_deref().expect("why it failed");
    let expected = format!("cannot create an ACME account at {DIRECTORY}: ");
    assert!(error.starts_with(&expected), "{error}");
    let wait = retry_in(&report);
    assert!(wait > Duration::from_secs(3500), "{wait:?}");

    assert!(server.renew_certificate(&site));
    let report = reported(&server, |report| report.failures == 2).await;
    let wait = retry_in(&report);
    assert!(wait > Duration::from_secs(7100), "{wait:?}");
    assert!(!server.renew_certificate(&"other".parse().expect("name")));
}

/// A certificate issued before is renewed when a third of its lifetime is left, as the report
/// tells; a renewal asked for orders it at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renews_issued_certificates_on_request() {
    let storage = Memory::default();
    let site: Name = "site".parse().expect("name");
    let stored = issued_within(&["site.test"], 2026, 2029);
    storage
        .certificates
        .lock()
        .expect("lock")
        .insert(site.clone(), stored);
    let text = "[certificates.site]\nacme = { domains = [\"site.test\"] }\n";
    let (server, _certificates, acme) = start(text, storage).await;
    tokio::spawn(acme.run());

    let report = reported(&server, |report| report.renew_at.is_some()).await;
    // A third of the three years, 365 days and 8 hours, before the end: 2028-01-01T16:00Z.
    let renew_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_830_355_200);
    assert_eq!(report.renew_at, Some(renew_at));
    assert_eq!((report.retry_at, report.failures), (None, 0));

    assert!(server.renew_certificate(&site));
    let report = reported(&server, |report| report.failures == 1).await;
    assert!(report.last_error.is_some());
}

/// While an order is in progress the report says so, and a renewal asked for meanwhile does not
/// order the certificate once more after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_orders_in_progress() {
    // A directory that takes connections and never answers, until `release` drops them.
    let silent = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let directory = format!(
        "https://{}/directory",
        silent.local_addr().expect("address")
    );
    let release = Arc::new(Notify::new());
    tokio::spawn({
        let release = release.clone();
        async move {
            let mut held = Vec::new();
            loop {
                tokio::select! {
                    accepted = silent.accept() => match accepted {
                        Ok((stream, _)) => held.push(stream),
                        Err(_) => return,
                    },
                    () = release.notified() => return,
                }
            }
        }
    });
    let text = "[certificates.site]\nacme = { domains = [\"site.test\"] }\n";
    let (server, _certificates, acme) =
        start_at(config_at(&directory, text), Memory::default()).await;
    let site: Name = "site".parse().expect("name");
    tokio::spawn(acme.run());

    let report = reported(&server, |report| report.ordering).await;
    assert_eq!((report.failures, report.last_error), (0, None));
    assert!(server.renew_certificate(&site));
    release.notify_one();
    let report = reported(&server, |report| report.failures == 1).await;
    assert!(!report.ordering);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let reports = server.acme_certificates();
    assert_eq!(reports[0].failures, 1, "ordered once more: {reports:?}");
}
