//! Integration tests of ACME that need no certificate authority: certificates issued before
//! come back from storage, the tokens of DNS providers must be readable, and certificates that
//! the configuration drops are removed.

mod common;

use std::time::Duration;

use rcgen::{CertificateParams, KeyPair};
use tokio::runtime::Handle;
use tokio::time::Instant;
use wormway_acme::{Acme, StoredCertificate};
use wormway_core::config::{Config, ConfigError, Name};
use wormway_runtime::{ApplyError, Server, Services};
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
    let key = KeyPair::generate().expect("key");
    let names: Vec<String> = domains.iter().map(|domain| (*domain).to_owned()).collect();
    let mut params = CertificateParams::new(names.clone()).expect("certificate parameters");
    params.not_after = rcgen::date_time_ymd(year, 1, 1);
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
    let text = format!(
        "version = 1\n[config]\nsource = \"file\"\n[acme]\ndirectory = \"{DIRECTORY}\"\n{text}"
    );
    Config::from_toml(&text).expect("configuration")
}

/// Starts a server with the certificates and ACME on `storage`, and returns it with them.
async fn start(text: &str, storage: Memory) -> (Server, Certificates, Acme) {
    let config = config(text);
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
