//! The engine of ACME: learns the certificates that each configuration gets through ACME, and
//! installs those issued before when the change commits.

use std::collections::BTreeMap;
use std::sync::Arc;

use wormway_core::config::{AcmeChallenge, Config, DnsProvider, Issue, Name, Protocol};
use wormway_runtime::{BoxFuture, Engine, Staged};
use wormway_tls::IssuedCertificate;

use crate::{Shared, secret};

/// The certificates that the configuration in effect gets through ACME.
#[derive(Default)]
pub(crate) struct Desired {
    /// What to order for each certificate.
    pub(crate) orders: BTreeMap<Name, Order>,
    /// Whether an HTTP listener listens on port 80, where HTTP-01 challenges arrive.
    pub(crate) port_80: bool,
}

/// What to order for one certificate.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Order {
    /// The host names, sorted, each once.
    pub(crate) domains: Vec<String>,
    /// How the certificate authority checks that the names are ours.
    pub(crate) challenge: AcmeChallenge,
    /// The DNS provider of `dns-01`, with its token read.
    pub(crate) dns: Option<Dns>,
}

/// A DNS provider with the token that the configuration refers to. Its token never goes to the
/// logs.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum Dns {
    /// Cloudflare, with its API token.
    Cloudflare {
        /// The API token.
        token: String,
    },
}

/// The engine of ACME.
pub(crate) struct AcmeEngine {
    /// What the engine and the manager share.
    shared: Arc<Shared>,
}

impl AcmeEngine {
    /// Creates the engine.
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        Self { shared }
    }
}

impl Engine for AcmeEngine {
    /// Reads the tokens of the DNS providers of `config`, which must be there, and the
    /// certificates issued before for the same host names.
    fn prepare<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<Box<dyn Staged>, Vec<Issue>>> {
        Box::pin(async move {
            let shared = &self.shared;
            let mut orders = BTreeMap::new();
            let mut stored = BTreeMap::new();
            let mut issues = Vec::new();
            for (name, certificate) in &config.certificates {
                let Some(acme) = &certificate.acme else {
                    continue;
                };
                let dns = match &acme.dns {
                    Some(DnsProvider::Cloudflare { api_token }) => {
                        match secret::read(api_token, &shared.base).await {
                            Ok(token) => Some(Dns::Cloudflare { token }),
                            Err(problem) => {
                                let at = format!("certificates.{name}.acme.dns.api_token");
                                issues.push(Issue::new(at, problem));
                                continue;
                            }
                        }
                    }
                    None => None,
                };
                let mut domains: Vec<String> = acme
                    .domains
                    .iter()
                    .map(|domain| domain.as_str().to_owned())
                    .collect();
                domains.sort();
                domains.dedup();
                if let Some(issued) = shared.stored(name, &domains).await {
                    stored.insert(name.clone(), issued);
                }
                let order = Order {
                    domains,
                    challenge: acme.challenge,
                    dns,
                };
                orders.insert(name.clone(), order);
            }
            if !issues.is_empty() {
                return Err(issues);
            }
            let port_80 = config.listeners.values().any(|listener| {
                listener.protocol == Protocol::Http
                    && listener.listen.iter().any(|addr| addr.port() == 80)
            });
            let staged: Box<dyn Staged> = Box::new(Commit {
                shared: shared.clone(),
                desired: Desired { orders, port_80 },
                stored,
            });
            Ok(staged)
        })
    }
}

/// The ACME certificates of a change, waiting for it to commit.
struct Commit {
    /// What the engine and the manager share.
    shared: Arc<Shared>,
    /// The certificates that the configuration gets through ACME.
    desired: Desired,
    /// The certificates issued before for the same host names.
    stored: BTreeMap<Name, IssuedCertificate>,
}

impl Staged for Commit {
    /// Installs the certificates issued before, unless a newer one for the same names is
    /// installed already, and hands the certificates to the manager.
    fn commit(self: Box<Self>) {
        let certificates = &self.shared.certificates;
        for (name, issued) in &self.stored {
            let Some(order) = self.desired.orders.get(name) else {
                continue;
            };
            let keep = certificates.issued(name).is_some_and(|installed| {
                covers(&installed, &order.domains)
                    && installed.info().not_after >= issued.info().not_after
            });
            if !keep {
                certificates.install(name, issued);
            }
        }
        self.shared.desired.send_replace(Arc::new(self.desired));
    }
}

/// Whether `certificate` covers exactly `domains`, which are sorted.
pub(crate) fn covers(certificate: &IssuedCertificate, domains: &[String]) -> bool {
    let mut names = certificate.info().names.clone();
    names.sort();
    names.dedup();
    names == domains
}
