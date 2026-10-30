//! Metrics of the requests and of the attempts at the targets of the upstreams. They go to the
//! process-wide recorder, if one is installed.

use std::time::Duration;

use metrics::{counter, describe_counter, describe_histogram, histogram};
use wormway_core::config::Name;

/// Requests that ended, by listener, route and status.
const REQUESTS_TOTAL: &str = "wormway_http_requests_total";
/// Time from the request header to the end of the response, by route.
const REQUEST_DURATION: &str = "wormway_http_request_duration_seconds";
/// Attempts at the targets of the upstreams, by upstream and result.
const UPSTREAM_REQUESTS_TOTAL: &str = "wormway_upstream_requests_total";
/// Requests turned away by the rate limit of their route, by route.
const RATE_LIMITED_TOTAL: &str = "wormway_rate_limited_total";

/// Registers the help text of every gateway metric.
pub(crate) fn describe() {
    describe_counter!(
        REQUESTS_TOTAL,
        "HTTP requests that ended, by listener, route (empty without one) and status (499 when the client left before the response)."
    );
    describe_histogram!(
        REQUEST_DURATION,
        "Seconds from the request header to the end of the response, by route (empty without one)."
    );
    describe_counter!(
        UPSTREAM_REQUESTS_TOTAL,
        "Attempts at the targets of the upstreams, retries included, by upstream and result: ok, or timeout or error when the target failed."
    );
    describe_counter!(
        RATE_LIMITED_TOTAL,
        "Requests answered with 429 because the rate limit of their route was reached, by route."
    );
}

/// Counts a request of `listener` that ended with `status` after `duration`. `route` is `None`
/// for requests that matched no route.
pub(crate) fn request(listener: &Name, route: Option<&Name>, status: u16, duration: Duration) {
    let route = route.map(Name::to_string).unwrap_or_default();
    counter!(
        REQUESTS_TOTAL,
        "listener" => listener.to_string(),
        "route" => route.clone(),
        "status" => status.to_string()
    )
    .increment(1);
    histogram!(REQUEST_DURATION, "route" => route).record(duration.as_secs_f64());
}

/// Counts an attempt at a target of `upstream` that ended with `result`: `ok`, `timeout` or
/// `error`.
pub(crate) fn attempt(upstream: &Name, result: &'static str) {
    counter!(UPSTREAM_REQUESTS_TOTAL, "upstream" => upstream.to_string(), "result" => result)
        .increment(1);
}

/// Counts a request of `route` that its rate limit turned away.
pub(crate) fn rate_limited(route: &Name) {
    counter!(RATE_LIMITED_TOTAL, "route" => route.to_string()).increment(1);
}
