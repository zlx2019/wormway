//! One order with the certificate authority: the answers to the challenges of every host name,
//! then the certificate and its private key.

use std::time::Duration;

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, Order as AcmeOrder,
    OrderStatus, RetryPolicy,
};
use wormway_core::config::AcmeChallenge;
use wormway_tls::Challenges;

use crate::cloudflare::{Cloudflare, Record};
use crate::engine::{Dns, Order};
use crate::reason;

/// How long the certificate authority may take to check the answers, and then to issue the
/// certificate.
const POLL: RetryPolicy = RetryPolicy::new()
    .initial_delay(Duration::from_secs(1))
    .backoff(1.5)
    .timeout(Duration::from_secs(120));
/// How long new DNS records may take to reach the name servers of the provider, which the
/// certificate authority asks.
const DNS_PROPAGATION: Duration = Duration::from_secs(10);

/// The answers published for the challenges of an order, withdrawn when it ends.
#[derive(Default)]
struct Published {
    /// Tokens answered by the HTTP listeners.
    tokens: Vec<String>,
    /// TXT records added for DNS-01.
    records: Vec<Record>,
}

/// Orders a certificate as `order` says with `account`, answering HTTP-01 challenges through
/// `challenges` and DNS-01 challenges through the DNS provider, and returns its chain and its
/// private key as PEM.
pub(crate) async fn issue(
    account: &Account,
    challenges: &Challenges,
    order: &Order,
) -> Result<(String, String), String> {
    let dns = match &order.dns {
        Some(Dns::Cloudflare { token }) => Some(Cloudflare::new(token)?),
        None => None,
    };
    let identifiers: Vec<Identifier> = order
        .domains
        .iter()
        .map(|domain| Identifier::Dns(domain.clone()))
        .collect();
    let mut acme = account
        .new_order(&NewOrder::new(&identifiers))
        .await
        .map_err(|error| format!("cannot place the order: {}", reason(&error)))?;
    let mut published = Published::default();
    let result = complete(
        &mut acme,
        challenges,
        order.challenge,
        dns.as_ref(),
        &mut published,
    )
    .await;
    for token in &published.tokens {
        challenges.remove(token);
    }
    if let Some(dns) = &dns {
        for record in &published.records {
            if let Err(error) = dns.remove(record).await {
                tracing::warn!("cannot remove a TXT record of DNS-01: {error}");
            }
        }
    }
    result
}

/// Answers the challenges of `acme`, of kind `kind`, then gets the certificate. Publishes
/// every answer before the certificate authority checks the first, since DNS records take a
/// while to spread; `published` collects them to withdraw.
async fn complete(
    acme: &mut AcmeOrder,
    challenges: &Challenges,
    kind: AcmeChallenge,
    dns: Option<&Cloudflare>,
    published: &mut Published,
) -> Result<(String, String), String> {
    let kind = match kind {
        AcmeChallenge::Http01 => ChallengeType::Http01,
        AcmeChallenge::Dns01 => ChallengeType::Dns01,
    };
    let mut authorizations = acme.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization
            .map_err(|error| format!("cannot read an authorization: {}", reason(&error)))?;
        match authorization.status {
            AuthorizationStatus::Valid => continue,
            AuthorizationStatus::Pending => {}
            status => {
                let identifier = authorization.identifier().to_string();
                return Err(format!("the authorization of {identifier} is {status:?}"));
            }
        }
        let identifier = authorization.identifier().to_string();
        let challenge = authorization
            .challenge(kind.clone())
            .ok_or_else(|| format!("no {kind:?} challenge offered for {identifier}"))?;
        let answer = challenge.key_authorization();
        match dns {
            None => {
                challenges.insert(&challenge.token, answer.as_str());
                published.tokens.push(challenge.token.clone());
            }
            Some(dns) => {
                let Identifier::Dns(domain) = challenge.identifier().identifier else {
                    return Err(format!("{identifier} is not a host name"));
                };
                let name = format!("_acme-challenge.{domain}");
                published
                    .records
                    .push(dns.add_txt(&name, &answer.dns_value()).await?);
            }
        }
    }
    if !published.records.is_empty() {
        tokio::time::sleep(DNS_PROPAGATION).await;
    }

    let mut authorizations = acme.authorizations();
    while let Some(authorization) = authorizations.next().await {
        let mut authorization = authorization
            .map_err(|error| format!("cannot read an authorization: {}", reason(&error)))?;
        if authorization.status != AuthorizationStatus::Pending {
            continue;
        }
        if let Some(mut challenge) = authorization.challenge(kind.clone()) {
            challenge
                .set_ready()
                .await
                .map_err(|error| format!("cannot start the check: {}", reason(&error)))?;
        }
    }
    let status = acme
        .poll_ready(&POLL)
        .await
        .map_err(|error| format!("the check failed: {}", reason(&error)))?;
    if status != OrderStatus::Ready {
        return Err(failures(acme).await);
    }
    let key = acme
        .finalize()
        .await
        .map_err(|error| format!("cannot finalize the order: {}", reason(&error)))?;
    let chain = acme
        .poll_certificate(&POLL)
        .await
        .map_err(|error| format!("cannot get the certificate: {}", reason(&error)))?;
    Ok((chain, key))
}

/// Returns why the challenges of `acme` failed, as the certificate authority tells.
async fn failures(acme: &mut AcmeOrder) -> String {
    let mut reasons = Vec::new();
    let mut authorizations = acme.authorizations();
    while let Some(Ok(authorization)) = authorizations.next().await {
        for challenge in &authorization.challenges {
            if let Some(error) = &challenge.error {
                reasons.push(format!("{}: {error}", authorization.identifier()));
            }
        }
    }
    if reasons.is_empty() {
        "the order became invalid".to_owned()
    } else {
        format!("the check failed: {}", reasons.join("; "))
    }
}
