//! Certificates: the ones presented, how ACME is doing with those it gets, and renewals on
//! request.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use serde::Serialize;
use wormway_core::config::Name;
use wormway_core::time::rfc3339;
use wormway_runtime::{AcmeCertificateReport, CertificateReport};

use super::Admin;
use super::error::ApiError;

/// What `GET /api/v1/status/certificates` reports.
#[derive(Serialize)]
pub(crate) struct CertificatesResponse {
    /// Every certificate of the configuration in effect, in name order.
    certificates: Vec<CertificateStatus>,
}

/// One certificate in the report.
#[derive(Serialize)]
struct CertificateStatus {
    /// Name of the certificate.
    name: Name,
    /// Where it comes from: `files` or `acme`.
    source: &'static str,
    /// The certificate presented; `null` while there is none, before ACME issued the first.
    current: Option<CurrentCertificate>,
    /// How ACME is doing with it; `null` for certificates from files, and until ACME looked at
    /// it.
    acme: Option<AcmeStatus>,
}

/// The certificate presented, from its leaf. Times are RFC 3339 timestamps in UTC.
#[derive(Serialize)]
struct CurrentCertificate {
    /// Host names it covers.
    names: Vec<String>,
    /// Distinguished name of its issuer.
    issuer: String,
    /// Start of its validity.
    not_before: String,
    /// End of its validity.
    not_after: String,
}

/// How ACME is doing with a certificate. Times are RFC 3339 timestamps in UTC.
#[derive(Serialize)]
struct AcmeStatus {
    /// When the certificate presented is renewed; `null` before one was issued.
    renew_at: Option<String>,
    /// When the next order is placed after the last one failed; `null` without failures.
    retry_at: Option<String>,
    /// Whether an order is in progress.
    ordering: bool,
    /// Orders that failed in a row.
    failures: u32,
    /// Why the last order failed; `null` without failures.
    last_error: Option<String>,
}

impl From<CertificateReport> for CurrentCertificate {
    /// Takes the report of the certificates.
    fn from(report: CertificateReport) -> Self {
        Self {
            names: report.names,
            issuer: report.issuer,
            not_before: rfc3339(report.not_before),
            not_after: rfc3339(report.not_after),
        }
    }
}

impl From<AcmeCertificateReport> for AcmeStatus {
    /// Takes the report of ACME.
    fn from(report: AcmeCertificateReport) -> Self {
        Self {
            renew_at: report.renew_at.map(rfc3339),
            retry_at: report.retry_at.map(rfc3339),
            ordering: report.ordering,
            failures: report.failures,
            last_error: report.last_error,
        }
    }
}

/// `GET /api/v1/status/certificates`: every certificate of the configuration in effect, with
/// the one presented and how ACME is doing with it.
pub(crate) async fn status(State(admin): State<Arc<Admin>>) -> Json<CertificatesResponse> {
    let snapshot = admin.server.snapshot();
    let mut presented: BTreeMap<Name, CertificateReport> = admin
        .server
        .certificates()
        .into_iter()
        .map(|report| (report.name.clone(), report))
        .collect();
    let mut acme: BTreeMap<Name, AcmeCertificateReport> = admin
        .server
        .acme_certificates()
        .into_iter()
        .map(|report| (report.name.clone(), report))
        .collect();
    let certificates = snapshot
        .config
        .certificates
        .iter()
        .map(|(name, certificate)| {
            let through_acme = certificate.acme.is_some();
            CertificateStatus {
                name: name.clone(),
                source: if through_acme { "acme" } else { "files" },
                current: presented.remove(name).map(Into::into),
                acme: acme.remove(name).filter(|_| through_acme).map(Into::into),
            }
        })
        .collect();
    Json(CertificatesResponse { certificates })
}

/// `POST /api/v1/certificates/{name}/renew`: orders a certificate that the configuration gets
/// through ACME again, without waiting for its renewal time or for the end of the wait after
/// failures. The order runs in the background; the report tells how it goes.
pub(crate) async fn renew(
    State(admin): State<Arc<Admin>>,
    name: Result<Path<Name>, PathRejection>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let Path(name) = name?;
    let snapshot = admin.server.snapshot();
    let certificate = snapshot
        .config
        .certificates
        .get(&name)
        .ok_or_else(|| ApiError::not_found(format!("certificates.{name}")))?;
    if certificate.acme.is_none() || !admin.server.renew_certificate(&name) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "not_acme",
            format!("certificates.{name} does not come through ACME"),
        ));
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "requested": true })),
    ))
}
