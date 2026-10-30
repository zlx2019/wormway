//! The manager of the ACME certificates: orders the missing ones, renews the others before they
//! expire, one at a time, and keeps them installed and stored.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, BodyWrapper, CertificateIdentifier, Error,
    NewAccount,
};
use tokio::sync::watch;
use tracing::{info, warn};
use wormway_core::config::{AcmeChallenge, Name};
use wormway_core::time::rfc3339;
use wormway_tls::IssuedCertificate;

use crate::engine::{Desired, Order, covers};
use crate::{RENEWALS_TOTAL, Shared, StoredCertificate, https, issue, reason, schedule};

/// How often the renewal information of the certificate authority is looked at.
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);
/// The most that a look at the renewal information is moved, either way, so that instances do
/// not ask together.
const CHECK_SPREAD: Duration = Duration::from_secs(3600);

/// What the manager knows of one certificate.
struct Managed {
    /// What to order.
    order: Order,
    /// The certificate installed for it, if it covers the names of the order.
    current: Option<IssuedCertificate>,
    /// When to renew `current`; the start of time without one.
    renew_at: SystemTime,
    /// Failures in a row.
    failures: u32,
    /// When to try again after the last failure.
    retry_at: Option<SystemTime>,
    /// Why the last attempt failed.
    last_error: Option<String>,
}

impl Managed {
    /// Starts managing `order` for certificate `name`, from the certificate installed for it
    /// if that one covers the names of the order.
    fn new(shared: &Shared, name: &Name, order: &Order) -> Self {
        let current = shared
            .certificates
            .issued(name)
            .filter(|installed| covers(installed, &order.domains));
        Self {
            order: order.clone(),
            renew_at: current.as_ref().map_or(UNIX_EPOCH, schedule::renewal_time),
            current,
            failures: 0,
            retry_at: None,
            last_error: None,
        }
    }

    /// Returns when to order a certificate: at once without one, at the renewal time
    /// otherwise, but not before the wait after a failure is over.
    fn due_at(&self) -> SystemTime {
        self.retry_at
            .map_or(self.renew_at, |retry| retry.max(self.renew_at))
    }
}

/// Manages the certificates that `desired` hands over, for as long as the engine can hand
/// over more.
pub(crate) async fn run(shared: Arc<Shared>, mut desired: watch::Receiver<Arc<Desired>>) {
    let mut managed: BTreeMap<Name, Managed> = BTreeMap::new();
    let mut account: Option<Account> = None;
    let mut seen: Option<Arc<Desired>> = None;
    let mut next_check = SystemTime::now();
    let mut ari = true;
    loop {
        let current = desired.borrow_and_update().clone();
        let changed = seen
            .as_ref()
            .is_none_or(|seen| !Arc::ptr_eq(seen, &current));
        if changed {
            reconcile(&shared, &mut managed, &current).await;
            seen = Some(current.clone());
        }
        if SystemTime::now() >= next_check {
            if ari {
                ari = check_renewal_info(&shared, &mut managed).await;
            }
            next_check = SystemTime::now() + spread(CHECK_INTERVAL);
        }
        let now = SystemTime::now();
        let due: Vec<Name> = managed
            .iter()
            .filter(|(_, state)| state.due_at() <= now)
            .map(|(name, _)| name.clone())
            .collect();
        for name in due {
            if let Some(state) = managed.get_mut(&name) {
                renew(&shared, &mut account, &name, state, current.port_80).await;
            }
        }
        let wake = managed
            .values()
            .map(Managed::due_at)
            .fold(next_check, SystemTime::min);
        let wait = wake
            .duration_since(SystemTime::now())
            .unwrap_or(Duration::ZERO);
        tokio::select! {
            changed = desired.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Takes the certificates of a new configuration: stops managing those it no longer gets
/// through ACME, which are uninstalled and removed from storage, and starts afresh on the new
/// ones and on those whose order changed. The others keep their state, waits after failures
/// included, so that frequent changes do not run into the limits of the certificate authority.
/// Stored certificates that the configuration does not have are removed too, for names that
/// left it before the manager saw them, such as while Wormway was stopped.
async fn reconcile(shared: &Shared, managed: &mut BTreeMap<Name, Managed>, desired: &Desired) {
    let mut gone: BTreeSet<Name> = managed
        .keys()
        .filter(|name| !desired.orders.contains_key(*name))
        .cloned()
        .collect();
    match shared.storage.certificate_names().await {
        Ok(stored) => gone.extend(
            stored
                .into_iter()
                .filter(|name| !desired.orders.contains_key(name)),
        ),
        Err(error) => {
            warn!("cannot list the stored certificates: {}", reason(&*error));
        }
    }
    for name in gone {
        managed.remove(&name);
        shared.certificates.uninstall(&name);
        if let Err(error) = shared.storage.remove_certificate(&name).await {
            warn!(certificate = %name, "cannot remove the stored certificate: {}", reason(&*error));
        }
        info!(certificate = %name, "certificate no longer managed through ACME");
    }
    for (name, order) in &desired.orders {
        let unchanged = managed.get(name).is_some_and(|state| state.order == *order);
        if !unchanged {
            managed.insert(name.clone(), Managed::new(shared, name, order));
        }
    }
}

/// Orders a certificate for `state`, then stores and installs it, or waits longer after each
/// failure.
async fn renew(
    shared: &Shared,
    account: &mut Option<Account>,
    name: &Name,
    state: &mut Managed,
    port_80: bool,
) {
    let order = &state.order;
    if order.challenge == AcmeChallenge::Http01 && !port_80 {
        warn!(
            certificate = %name,
            "no HTTP listener listens on port 80, where the certificate authority sends HTTP-01 challenges"
        );
    }
    info!(certificate = %name, domains = ?order.domains, "ordering a certificate through ACME");
    let issued = async {
        let account = ready_account(shared, account).await?;
        let (chain, key) = issue::issue(account, shared.certificates.challenges(), order).await?;
        let issued = shared.certificates.read_issued(&chain, &key)?;
        Ok::<_, String>((issued, chain, key))
    }
    .await;
    match issued {
        Ok((issued, chain, key)) => {
            let stored = StoredCertificate {
                directory: shared.directory.clone(),
                domains: order.domains.clone(),
                chain,
                key,
            };
            if let Err(error) = shared.storage.save_certificate(name, &stored).await {
                warn!(certificate = %name, "cannot store the certificate, so it is ordered again after a restart: {}", reason(&*error));
            }
            shared.certificates.install(name, &issued);
            let expires = schedule::renewal_time(&issued);
            info!(
                certificate = %name,
                renew_after = %rfc3339(expires),
                "certificate issued through ACME"
            );
            state.renew_at = expires;
            state.current = Some(issued);
            state.failures = 0;
            state.retry_at = None;
            state.last_error = None;
            metrics::counter!(RENEWALS_TOTAL, "result" => "ok").increment(1);
        }
        Err(error) => {
            state.failures = state.failures.saturating_add(1);
            let wait = schedule::backoff(state.failures);
            state.retry_at = Some(SystemTime::now() + wait);
            let wait = wormway_core::config::Duration::from_secs(wait.as_secs());
            warn!(certificate = %name, "cannot get the certificate through ACME, trying again in {wait}: {error}");
            state.last_error = Some(error);
            metrics::counter!(RENEWALS_TOTAL, "result" => "error").increment(1);
        }
    }
}

/// Returns the ACME account, read from storage or created and stored the first time.
async fn ready_account<'a>(
    shared: &Shared,
    account: &'a mut Option<Account>,
) -> Result<&'a Account, String> {
    if account.is_none() {
        *account = Some(open_account(shared).await?);
    }
    account.as_ref().ok_or_else(|| "no ACME account".to_owned())
}

/// Returns a builder of accounts whose connections to the directory check its certificate
/// against the authorities of `[acme]`, or the way of the system.
fn account_builder(shared: &Shared) -> Result<AccountBuilder, String> {
    let authorities = match &shared.ca {
        Some(ca) => Some(
            shared
                .certificates
                .read_authorities(ca, "acme.ca")
                .map_err(|issue| issue.to_string())?,
        ),
        None => None,
    };
    let client = Client::builder(TokioExecutor::new())
        .build::<_, BodyWrapper<Bytes>>(https::connector(authorities, false)?);
    Ok(Account::builder_with_http(Box::new(client)))
}

/// Opens the account at the directory: the stored one, or a new one that agrees to the terms
/// of service of the certificate authority.
async fn open_account(shared: &Shared) -> Result<Account, String> {
    let builder = || account_builder(shared);
    let directory = &shared.directory;
    let stored = shared
        .storage
        .account(directory)
        .await
        .map_err(|error| format!("cannot read the ACME account: {}", reason(&*error)))?;
    if let Some(stored) = stored {
        let credentials: AccountCredentials = serde_json::from_str(&stored)
            .map_err(|error| format!("the stored ACME account is unreadable: {error}"))?;
        return builder()?
            .from_credentials(credentials)
            .await
            .map_err(|error| {
                format!(
                    "cannot reach the ACME directory {directory}: {}",
                    reason(&error)
                )
            });
    }
    let contact: Vec<&str> = shared.contact.iter().map(String::as_str).collect();
    let new = NewAccount {
        contact: &contact,
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (account, credentials) = builder()?
        .create(&new, directory.clone(), None)
        .await
        .map_err(|error| {
            format!(
                "cannot create an ACME account at {directory}: {}",
                reason(&error)
            )
        })?;
    let credentials = serde_json::to_string(&credentials)
        .map_err(|error| format!("cannot encode the ACME account: {error}"))?;
    if let Err(error) = shared
        .storage
        .save_account(&shared.directory, &credentials)
        .await
    {
        warn!(
            "cannot store the ACME account, so another is created after a restart: {}",
            reason(&*error)
        );
    }
    info!(
        directory = %shared.directory,
        "created an ACME account, which agrees to the terms of service of the certificate authority"
    );
    Ok(account)
}

/// Moves the renewal times of the installed certificates into the windows that the
/// certificate authority suggests, when they come earlier. Uses the stored account only.
/// Returns whether the authority offers renewal information.
async fn check_renewal_info(shared: &Shared, managed: &mut BTreeMap<Name, Managed>) -> bool {
    if managed.values().all(|state| state.current.is_none()) {
        return true;
    }
    let account = match shared.storage.account(&shared.directory).await {
        Ok(Some(_)) => match open_account(shared).await {
            Ok(account) => account,
            Err(error) => {
                tracing::debug!("cannot ask for renewal information: {error}");
                return true;
            }
        },
        _ => return true,
    };
    for (name, state) in managed.iter_mut() {
        let Some((authority, serial)) = state
            .current
            .as_ref()
            .and_then(IssuedCertificate::renewal_id)
        else {
            continue;
        };
        let id = CertificateIdentifier::new(authority.as_slice().into(), serial.as_slice().into());
        match account.renewal_info(&id).await {
            Ok((info, _)) => {
                let window = info.suggested_window;
                let at =
                    schedule::within(window.start.into(), window.end.into(), schedule::random());
                if at < state.renew_at {
                    info!(certificate = %name, renew_after = %rfc3339(at), "renewal moved earlier by the certificate authority");
                    state.renew_at = at;
                }
            }
            Err(Error::Unsupported(_)) => return false,
            Err(error) => {
                tracing::debug!(certificate = %name, "cannot get renewal information: {}", reason(&error));
            }
        }
    }
    true
}

/// Returns `interval` moved by up to [`CHECK_SPREAD`] either way.
fn spread(interval: Duration) -> Duration {
    let offset = schedule::within(
        UNIX_EPOCH,
        UNIX_EPOCH + CHECK_SPREAD * 2,
        schedule::random(),
    );
    let offset = offset.duration_since(UNIX_EPOCH).unwrap_or_default();
    interval + offset - CHECK_SPREAD
}
