//! Rules that span fields. Each check appends to a list, so one run reports every problem.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::http::is_token;
use super::upstream::is_host_name;
use super::{
    AcmeChallenge, Balance, Config, ConfigSource, Duration, HashKey, HeaderName, HeaderRules,
    HealthCheckKind, Issue, Name, PathPattern, Redirect, Route, Target, Upstream, UpstreamProtocol,
};
use crate::routing::normalize_path;

/// Headers that frame a message or belong to one connection: routes may not change them.
const MANAGED_HEADERS: [&str; 8] = [
    "connection",
    "content-length",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Returns every rule violation in `config`.
pub(super) fn errors(config: &Config) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_listeners(config, &mut issues);
    check_address_conflicts(config, &mut issues);
    check_routes(config, &mut issues);
    check_upstreams(config, &mut issues);
    check_acme(config, &mut issues);
    check_certificates(config, &mut issues);
    issues
}

/// Returns settings that are accepted but have no effect.
pub(super) fn warnings(config: &Config) -> Vec<Issue> {
    if config.config.source != ConfigSource::Db {
        return Vec::new();
    }
    let tables = [
        ("listeners", config.listeners.is_empty()),
        ("routes", config.routes.is_empty()),
        ("upstreams", config.upstreams.is_empty()),
        ("certificates", config.certificates.is_empty()),
    ];
    tables
        .into_iter()
        .filter(|(_, empty)| !empty)
        .map(|(path, _)| {
            Issue::new(
                path,
                "ignored because config.source is \"db\": dynamic settings come from the database",
            )
        })
        .collect()
}

/// The ACME directory is one of Let's Encrypt or an HTTPS URL, and the email an address.
fn check_acme(config: &Config, issues: &mut Vec<Issue>) {
    let acme = &config.acme;
    let known = ["letsencrypt", "letsencrypt-staging"].contains(&acme.directory.as_str());
    if !known && !acme.directory.starts_with("https://") {
        issues.push(Issue::new(
            "acme.directory",
            "must be \"letsencrypt\", \"letsencrypt-staging\" or an https:// URL",
        ));
    }
    if let Some(email) = &acme.email
        && (!email.contains('@') || email.contains(char::is_whitespace))
    {
        issues.push(Issue::new("acme.email", "must be an email address"));
    }
}

/// Each certificate comes from files or through ACME, and its ACME settings fit together:
/// host names that a certificate authority accepts, each once, wildcards and a DNS provider
/// only with `dns-01`, which needs one.
fn check_certificates(config: &Config, issues: &mut Vec<Issue>) {
    for (name, certificate) in &config.certificates {
        let at = |field: &str| format!("certificates.{name}{field}");
        match (&certificate.acme, &certificate.cert, &certificate.key) {
            (Some(_), None, None) | (None, Some(_), Some(_)) => {}
            (Some(_), _, _) => issues.push(Issue::new(at(""), "set either cert and key, or acme")),
            (None, _, _) => issues.push(Issue::new(at(""), "set cert and key, or acme")),
        }
        let Some(acme) = &certificate.acme else {
            continue;
        };
        if acme.domains.is_empty() {
            issues.push(Issue::new(
                at(".acme.domains"),
                "must list at least one host name",
            ));
        }
        let mut seen = HashSet::new();
        for (index, domain) in acme.domains.iter().enumerate() {
            let at = at(&format!(".acme.domains[{index}]"));
            let host = domain.wildcard_suffix().unwrap_or(domain.as_str());
            if !is_host_name(host) || !host.contains('.') {
                issues.push(Issue::new(
                    &at,
                    "must be a host name with a dot, such as example.com, not an IP address",
                ));
            }
            if domain.wildcard_suffix().is_some() && acme.challenge != AcmeChallenge::Dns01 {
                issues.push(Issue::new(
                    &at,
                    "wildcard names need challenge = \"dns-01\"",
                ));
            }
            if !seen.insert(domain.as_str()) {
                issues.push(Issue::new(&at, "listed twice"));
            }
        }
        match (acme.challenge, &acme.dns) {
            (AcmeChallenge::Dns01, None) => issues.push(Issue::new(
                at(".acme.dns"),
                "needed by challenge = \"dns-01\"",
            )),
            (AcmeChallenge::Http01, Some(_)) => issues.push(Issue::new(
                at(".acme.dns"),
                "only for challenge = \"dns-01\"",
            )),
            _ => {}
        }
    }
}

/// Each listener has an address, and its TLS settings name existing certificates.
fn check_listeners(config: &Config, issues: &mut Vec<Issue>) {
    for (name, listener) in &config.listeners {
        if listener.listen.is_empty() {
            issues.push(Issue::new(
                format!("listeners.{name}.listen"),
                "must list at least one address",
            ));
        }
        let Some(tls) = &listener.tls else { continue };
        if listener.http.h2c() {
            issues.push(Issue::new(
                format!("listeners.{name}.http.h2c"),
                "only for listeners without TLS, which agree on HTTP/2 during the handshake",
            ));
        }
        if tls.certificates.is_empty() {
            issues.push(Issue::new(
                format!("listeners.{name}.tls.certificates"),
                "must list at least one certificate",
            ));
        }
        for (i, certificate) in tls.certificates.iter().enumerate() {
            if !config.certificates.contains_key(certificate) {
                issues.push(Issue::new(
                    format!("listeners.{name}.tls.certificates[{i}]"),
                    format!("unknown certificate \"{certificate}\""),
                ));
            }
        }
    }
}

/// No two sockets of the process, listeners and the Admin API included, claim the same address.
fn check_address_conflicts(config: &Config, issues: &mut Vec<Issue>) {
    // Addresses checked so far, with the path of the setting that claims each one.
    let mut claimed = vec![("admin.listen".to_owned(), config.admin.listen)];
    for (name, listener) in &config.listeners {
        for (i, addr) in listener.listen.iter().enumerate() {
            let path = format!("listeners.{name}.listen[{i}]");
            if let Some((other, taken)) = claimed.iter().find(|(_, taken)| overlaps(taken, addr)) {
                issues.push(Issue::new(
                    &path,
                    format!("{addr} overlaps {other} ({taken})"),
                ));
            }
            claimed.push((path, *addr));
        }
    }
}

/// Each route names existing listeners, can match, does exactly one thing, and changes only what
/// it may.
fn check_routes(config: &Config, issues: &mut Vec<Issue>) {
    for (name, route) in &config.routes {
        for (i, listener) in route.listeners.iter().enumerate() {
            if !config.listeners.contains_key(listener) {
                issues.push(Issue::new(
                    format!("routes.{name}.listeners[{i}]"),
                    format!("unknown listener \"{listener}\""),
                ));
            }
        }
        for (i, pattern) in route.r#match.paths.iter().enumerate() {
            let problem = match pattern {
                PathPattern::Prefix(path) => path_problem(path, false),
                PathPattern::Exact(path) => path_problem(path, true),
                PathPattern::Regex(_) => None,
            };
            if let Some(problem) = problem {
                issues.push(Issue::new(
                    format!("routes.{name}.match.paths[{i}]"),
                    problem,
                ));
            }
        }
        check_action(config, name, route, issues);
        check_modifiers(name, route, issues);
    }
}

/// The route does exactly one thing, and that thing is sound.
fn check_action(config: &Config, name: &Name, route: &Route, issues: &mut Vec<Issue>) {
    let actions = [
        route.upstream.is_some(),
        route.redirect.is_some(),
        route.respond.is_some(),
    ];
    match actions.into_iter().filter(|set| *set).count() {
        0 => issues.push(Issue::new(
            format!("routes.{name}"),
            "set one of upstream, redirect and respond",
        )),
        1 => {}
        _ => issues.push(Issue::new(
            format!("routes.{name}"),
            "set only one of upstream, redirect and respond",
        )),
    }
    if let Some(upstream) = &route.upstream
        && !config.upstreams.contains_key(upstream)
    {
        issues.push(Issue::new(
            format!("routes.{name}.upstream"),
            format!("unknown upstream \"{upstream}\""),
        ));
    }
    if let Some(redirect) = &route.redirect {
        if let Some(problem) = target_problem(redirect) {
            issues.push(Issue::new(format!("routes.{name}.redirect.to"), problem));
        }
        if !Redirect::STATUSES.contains(&redirect.status()) {
            issues.push(Issue::new(
                format!("routes.{name}.redirect.status"),
                "must be 301, 302, 303, 307 or 308",
            ));
        }
    }
    if let Some(respond) = &route.respond {
        if !(200..=599).contains(&respond.status) {
            issues.push(Issue::new(
                format!("routes.{name}.respond.status"),
                "must be between 200 and 599",
            ));
        } else if matches!(respond.status, 204 | 304) && !respond.body.is_empty() {
            issues.push(Issue::new(
                format!("routes.{name}.respond.body"),
                "must be empty for status 204 and 304",
            ));
        }
    }
}

/// Returns what is wrong with the target of a redirect, if anything.
fn target_problem(redirect: &Redirect) -> Option<String> {
    if redirect.to.is_empty() || !redirect.to.bytes().all(|b| b.is_ascii_graphic()) {
        return Some(
            "must be a URL or a path, in visible ASCII characters without spaces".to_owned(),
        );
    }
    redirect.parts().err()
}

/// The rewrite and the header rules of the route are sound, and the changes to upstream
/// requests come with an upstream.
fn check_modifiers(name: &Name, route: &Route, issues: &mut Vec<Issue>) {
    let only_upstream = "only for routes with an upstream";
    if let Some(rewrite) = &route.rewrite {
        let at = format!("routes.{name}.rewrite");
        if route.upstream.is_none() {
            issues.push(Issue::new(&at, only_upstream));
        }
        if rewrite.strip_prefix.is_none() && rewrite.add_prefix.is_none() {
            issues.push(Issue::new(&at, "set strip_prefix, add_prefix or both"));
        }
        // The prefix to strip is compared with the normalized path, as a path condition is.
        if let Some(prefix) = &rewrite.strip_prefix
            && let Some(problem) = path_problem(prefix, false)
        {
            issues.push(Issue::new(format!("{at}.strip_prefix"), problem));
        }
        if let Some(prefix) = &rewrite.add_prefix
            && !prefix.starts_with('/')
        {
            issues.push(Issue::new(
                format!("{at}.add_prefix"),
                "must start with \"/\"",
            ));
        }
    }
    let request_headers = format!("routes.{name}.request_headers");
    if route.upstream.is_none() && !route.request_headers.is_empty() {
        issues.push(Issue::new(&request_headers, only_upstream));
    }
    check_header_rules(&request_headers, &route.request_headers, issues);
    check_header_rules(
        &format!("routes.{name}.response_headers"),
        &route.response_headers,
        issues,
    );
    let timeouts = format!("routes.{name}.timeouts");
    if route.upstream.is_none() && !route.timeouts.is_default() {
        issues.push(Issue::new(&timeouts, only_upstream));
    }
    check_timeouts(
        &timeouts,
        [
            ("read", route.timeouts.read),
            ("write", route.timeouts.write),
        ],
        issues,
    );
}

/// Each time limit that is set is longer than zero.
fn check_timeouts<const N: usize>(
    at: &str,
    timeouts: [(&str, Option<Duration>); N],
    issues: &mut Vec<Issue>,
) {
    for (field, timeout) in timeouts {
        if timeout.is_some_and(|timeout| timeout.get().is_zero()) {
            issues.push(Issue::new(
                format!("{at}.{field}"),
                "must be longer than 0s",
            ));
        }
    }
}

/// The rules leave alone the headers that frame the message or belong to the connection.
fn check_header_rules(at: &str, rules: &HeaderRules, issues: &mut Vec<Issue>) {
    let managed = |name: &HeaderName| {
        MANAGED_HEADERS
            .iter()
            .any(|managed| name.as_str().eq_ignore_ascii_case(managed))
    };
    let problem = "cannot be changed: it frames the message or belongs to the connection";
    for (i, name) in rules.remove.iter().enumerate() {
        if managed(name) {
            issues.push(Issue::new(format!("{at}.remove[{i}]"), problem));
        }
    }
    for (field, values) in [("set", &rules.set), ("add", &rules.add)] {
        for name in values.keys().filter(|name| managed(name)) {
            issues.push(Issue::new(format!("{at}.{field}.{name}"), problem));
        }
    }
}

/// Returns why a prefix, or an exact path if `exact`, can never match, if it cannot: request
/// paths start with "/" and are compared after normalization, so they must be in normal form.
fn path_problem(path: &str, exact: bool) -> Option<String> {
    if !path.starts_with('/') {
        return Some("must start with \"/\"".to_owned());
    }
    // A prefix may end in the middle of a segment, such as "/." for "/.well-known/": a letter
    // after it keeps that part from reading as a "." or ".." segment.
    let written = if exact {
        path.to_owned()
    } else {
        format!("{path}x")
    };
    let normal = normalize_path(written.as_bytes());
    if *normal == *written.as_bytes() {
        return None;
    }
    let normal = String::from_utf8_lossy(&normal);
    let suggestion = if exact {
        &normal
    } else {
        normal.strip_suffix('x').unwrap_or(&normal)
    };
    Some(format!(
        "never matches: request paths are compared after decoding %XX, removing \".\" and \"..\" \
         segments and merging slashes, so write \"{suggestion}\""
    ))
}

/// Each upstream has targets, each listed once and with a weight in range, and sound balancing,
/// time limits and retries.
fn check_upstreams(config: &Config, issues: &mut Vec<Issue>) {
    for (name, upstream) in &config.upstreams {
        if upstream.targets.is_empty() {
            issues.push(Issue::new(
                format!("upstreams.{name}.targets"),
                "must list at least one target",
            ));
        }
        let mut seen = HashSet::new();
        for (i, target) in upstream.targets.iter().enumerate() {
            if !seen.insert(&target.address) {
                issues.push(Issue::new(
                    format!("upstreams.{name}.targets[{i}]"),
                    format!("{} is listed twice", target.address),
                ));
            }
            if !(1..=Target::MAX_WEIGHT).contains(&target.weight) {
                issues.push(Issue::new(
                    format!("upstreams.{name}.targets[{i}].weight"),
                    format!("must be between 1 and {}", Target::MAX_WEIGHT),
                ));
            }
        }
        check_balancing(name, upstream, issues);
        let timeouts = &upstream.timeouts;
        check_timeouts(
            &format!("upstreams.{name}.timeouts"),
            [
                ("connect", timeouts.connect),
                ("read", timeouts.read),
                ("write", timeouts.write),
                ("idle", timeouts.idle),
            ],
            issues,
        );
        if upstream.retries() > Upstream::MAX_RETRIES {
            issues.push(Issue::new(
                format!("upstreams.{name}.retries"),
                format!("must be at most {}", Upstream::MAX_RETRIES),
            ));
        }
        check_upstream_tls(name, upstream, issues);
        check_health(name, upstream, issues);
    }
}

/// The health checks have sound settings, and those of `"http"` come only with it.
fn check_health(name: &Name, upstream: &Upstream, issues: &mut Vec<Issue>) {
    if let Some(check) = &upstream.health_check {
        let at = format!("upstreams.{name}.health_check");
        if check.kind != HealthCheckKind::Http {
            let http_only = [
                ("path", check.path.is_some()),
                ("host", check.host.is_some()),
                ("status", check.status.is_some()),
            ];
            for (field, _) in http_only.into_iter().filter(|(_, set)| *set) {
                issues.push(Issue::new(
                    format!("{at}.{field}"),
                    "only for kind = \"http\"",
                ));
            }
        }
        if let Some(path) = &check.path
            && !is_request_path(path)
        {
            issues.push(Issue::new(
                format!("{at}.path"),
                "must start with \"/\" and hold only visible ASCII characters other than \"#\"",
            ));
        }
        if let Some(host) = &check.host
            && !is_authority(host)
        {
            issues.push(Issue::new(
                format!("{at}.host"),
                "must be a host name or an IP address, with an optional port",
            ));
        }
        if let Some(statuses) = &check.status {
            if statuses.is_empty() {
                issues.push(Issue::new(
                    format!("{at}.status"),
                    "must list at least one status",
                ));
            }
            for (i, status) in statuses.iter().enumerate() {
                if !(100..=599).contains(status) {
                    issues.push(Issue::new(
                        format!("{at}.status[{i}]"),
                        "must be between 100 and 599",
                    ));
                }
            }
        }
        check_timeouts(
            &at,
            [("interval", check.interval), ("timeout", check.timeout)],
            issues,
        );
        for (field, count) in [("healthy", check.healthy), ("unhealthy", check.unhealthy)] {
            if count == Some(0) {
                issues.push(Issue::new(format!("{at}.{field}"), "must be at least 1"));
            }
        }
    }
    if let Some(passive) = &upstream.passive {
        let at = format!("upstreams.{name}.passive");
        if passive.max_fails == Some(0) {
            issues.push(Issue::new(format!("{at}.max_fails"), "must be at least 1"));
        }
        check_timeouts(&at, [("fail_timeout", passive.fail_timeout)], issues);
    }
}

/// Whether `path` can be sent as the target of a request: it starts with "/" and holds visible
/// ASCII characters other than "#", which would start a fragment.
fn is_request_path(path: &str) -> bool {
    path.starts_with('/') && path.bytes().all(|b| b.is_ascii_graphic() && b != b'#')
}

/// Whether `authority` fits a `Host` header: a host name or an IP address, IPv6 in brackets,
/// with an optional port.
fn is_authority(authority: &str) -> bool {
    let host = match authority.rsplit_once(':') {
        // The colons of a bracketed IPv6 address without a port are not a port.
        Some((host, port)) if !port.contains(']') => {
            if port.parse::<u16>().is_err() {
                return false;
            }
            host
        }
        _ => authority,
    };
    if let Some(ip) = host.strip_prefix('[').and_then(|ip| ip.strip_suffix(']')) {
        return ip.parse::<Ipv6Addr>().is_ok();
    }
    is_host_name(host) || host.parse::<Ipv4Addr>().is_ok()
}

/// The protocol fits the TLS setting, and the TLS settings are complete and used.
fn check_upstream_tls(name: &Name, upstream: &Upstream, issues: &mut Vec<Issue>) {
    let protocol = match (upstream.protocol(), &upstream.tls) {
        (UpstreamProtocol::H2, None) => Some("h2 needs tls; h2c is HTTP/2 without TLS"),
        (UpstreamProtocol::H2c, Some(_)) => Some("h2c is HTTP/2 without TLS; use h2 with tls"),
        _ => None,
    };
    if let Some(problem) = protocol {
        issues.push(Issue::new(format!("upstreams.{name}.protocol"), problem));
    }
    let Some(tls) = &upstream.tls else {
        return;
    };
    let at = format!("upstreams.{name}.tls");
    if let Some(sni) = &tls.sni
        && !is_host_name(sni)
        && sni.parse::<IpAddr>().is_err()
    {
        issues.push(Issue::new(
            format!("{at}.sni"),
            "must be a host name or an IP address",
        ));
    }
    if tls.ca.is_some() && !tls.verify() {
        issues.push(Issue::new(
            format!("{at}.ca"),
            "unused while verify is false",
        ));
    }
    if tls.cert.is_some() != tls.key.is_some() {
        issues.push(Issue::new(&at, "set cert and key together"));
    }
}

/// The hash key comes with `consistent_hash`, and a cookie key names a cookie.
fn check_balancing(name: &Name, upstream: &Upstream, issues: &mut Vec<Issue>) {
    let Some(key) = &upstream.hash_key else {
        return;
    };
    let at = format!("upstreams.{name}.hash_key");
    if upstream.balance() != Balance::ConsistentHash {
        issues.push(Issue::new(&at, "only for balance = \"consistent_hash\""));
    }
    if let HashKey::Cookie(cookie) = key
        && !is_token(cookie)
    {
        issues.push(Issue::new(
            format!("{at}.cookie"),
            "must be a cookie name: letters, digits and !#$%&'*+-.^_`|~",
        ));
    }
}

/// Whether two addresses can not be bound at the same time: the same port, and the same IP or a
/// wildcard IP of the same family. Port 0 picks a free port, so it never overlaps.
fn overlaps(a: &SocketAddr, b: &SocketAddr) -> bool {
    a.port() == b.port()
        && a.port() != 0
        && a.is_ipv4() == b.is_ipv4()
        && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses TOML without the validation step.
    fn parse(text: &str) -> Config {
        toml::from_str(text).unwrap()
    }

    /// Paths of the issues, for compact assertions.
    fn paths(issues: &[Issue]) -> Vec<&str> {
        issues.iter().map(|issue| issue.path.as_str()).collect()
    }

    /// All problems come back from a single run, in a stable order.
    #[test]
    fn reports_every_problem() {
        let config = parse(
            r#"
            version = 1
            [listeners.a]
            listen = []
            protocol = "http"
            tls = { certificates = [] }
            [listeners.b]
            listen = ["127.0.0.1:9872"]
            protocol = "http"
            tls = { certificates = ["missing", "present"] }
            [certificates.present]
            cert = "a.crt"
            key = "a.key"
            "#,
        );
        let issues = errors(&config);
        assert_eq!(
            paths(&issues),
            [
                "listeners.a.listen",
                "listeners.a.tls.certificates",
                "listeners.b.tls.certificates[0]",
                "listeners.b.listen[0]",
            ]
        );
        assert_eq!(issues[2].message, "unknown certificate \"missing\"");
        assert_eq!(
            issues[3].message,
            "127.0.0.1:9872 overlaps admin.listen (127.0.0.1:9872)"
        );
    }

    /// Wildcards overlap specific addresses of the same family only, and port 0 never overlaps.
    #[test]
    fn detects_overlapping_addresses() {
        let addr = |s: &str| s.parse::<SocketAddr>().unwrap();
        assert!(overlaps(&addr("0.0.0.0:80"), &addr("127.0.0.1:80")));
        assert!(overlaps(&addr("[::1]:80"), &addr("[::]:80")));
        assert!(overlaps(&addr("10.0.0.1:80"), &addr("10.0.0.1:80")));
        assert!(!overlaps(&addr("10.0.0.1:80"), &addr("10.0.0.2:80")));
        assert!(!overlaps(&addr("0.0.0.0:80"), &addr("[::]:80")));
        assert!(!overlaps(&addr("0.0.0.0:80"), &addr("0.0.0.0:81")));
        assert!(!overlaps(&addr("0.0.0.0:0"), &addr("0.0.0.0:0")));
    }

    /// Duplicates inside one listener are caught too.
    #[test]
    fn detects_duplicates_within_a_listener() {
        let config = parse(
            r#"
            version = 1
            [listeners.web]
            listen = ["0.0.0.0:8080", "0.0.0.0:8080"]
            protocol = "http"
            "#,
        );
        assert_eq!(paths(&errors(&config)), ["listeners.web.listen[1]"]);
    }

    /// Routes must point at existing listeners and upstreams, and upstreams need sound targets.
    #[test]
    fn checks_routes_and_upstreams() {
        let config = parse(
            r#"
            version = 1
            [listeners.web]
            listen = ["127.0.0.1:8080"]
            protocol = "http"
            [routes.api]
            listeners = ["web", "missing"]
            match = { paths = ["/api/", "api/"] }
            upstream = "nowhere"
            [routes.site]
            upstream = "empty"
            [upstreams.empty]
            targets = []
            [upstreams.app]
            targets = ["10.0.0.1:80", { address = "10.0.0.1:80", weight = 2 }, { address = "10.0.0.2:80", weight = 0 }, { address = "10.0.0.3:80", weight = 257 }]
            "#,
        );
        let issues = errors(&config);
        assert_eq!(
            paths(&issues),
            [
                "routes.api.listeners[1]",
                "routes.api.match.paths[1]",
                "routes.api.upstream",
                "upstreams.app.targets[1]",
                "upstreams.app.targets[2].weight",
                "upstreams.app.targets[3].weight",
                "upstreams.empty.targets",
            ]
        );
        assert_eq!(issues[0].message, "unknown listener \"missing\"");
        assert_eq!(issues[2].message, "unknown upstream \"nowhere\"");
        assert_eq!(issues[3].message, "10.0.0.1:80 is listed twice");
        assert_eq!(issues[4].message, "must be between 1 and 256");
    }

    /// Prefixes and exact paths must be in the form that request paths take after
    /// normalization; regular expressions are not checked.
    #[test]
    fn rejects_paths_that_never_match() {
        let config = parse(
            r#"
            version = 1
            [routes.site]
            match = { paths = ["/", "/a/.", "/.well-known/", "/a/..b", "//a", "/a/./b", "/a%2Fb", { exact = "/a/" }, { exact = "/a/." }, { exact = "api" }, { regex = "//" }] }
            upstream = "app"
            [upstreams.app]
            targets = ["127.0.0.1:9000"]
            "#,
        );
        let issues = errors(&config);
        assert_eq!(
            paths(&issues),
            [
                "routes.site.match.paths[4]",
                "routes.site.match.paths[5]",
                "routes.site.match.paths[6]",
                "routes.site.match.paths[8]",
                "routes.site.match.paths[9]",
            ]
        );
        assert!(
            issues[0].message.ends_with("so write \"/a\""),
            "{}",
            issues[0]
        );
        assert!(
            issues[1].message.ends_with("so write \"/a/b\""),
            "{}",
            issues[1]
        );
        assert!(
            issues[2].message.ends_with("so write \"/a/b\""),
            "{}",
            issues[2]
        );
        assert!(
            issues[3].message.ends_with("so write \"/a/\""),
            "{}",
            issues[3]
        );
        assert_eq!(issues[4].message, "must start with \"/\"");
    }

    /// A route does exactly one thing, and redirects and fixed responses need sound settings.
    #[test]
    fn checks_route_actions() {
        let config = parse(
            r#"
            version = 1
            [routes.both]
            upstream = "app"
            respond = { status = 200 }
            [routes.early]
            respond = { status = 101 }
            [routes.empty]
            respond = { status = 204, body = "x" }
            [routes.fine]
            redirect = { to = "https://{host}:8443{uri}", status = 308 }
            [routes.lost]
            upstream = "missing"
            [routes.moved]
            redirect = { to = "https://{hots}{uri}", status = 300 }
            [routes.none]
            [routes.spaced]
            redirect = { to = "/a b" }
            [upstreams.app]
            targets = ["127.0.0.1:9000"]
            "#,
        );
        let issues = errors(&config);
        assert_eq!(
            paths(&issues),
            [
                "routes.both",
                "routes.early.respond.status",
                "routes.empty.respond.body",
                "routes.lost.upstream",
                "routes.moved.redirect.to",
                "routes.moved.redirect.status",
                "routes.none",
                "routes.spaced.redirect.to",
            ]
        );
        assert_eq!(
            issues[0].message,
            "set only one of upstream, redirect and respond"
        );
        assert_eq!(
            issues[4].message,
            "has an unknown placeholder {hots}, expected {host} or {uri}"
        );
        assert_eq!(
            issues[6].message,
            "set one of upstream, redirect and respond"
        );
    }

    /// Rewrites and request headers need an upstream, and header rules leave alone the headers
    /// that frame the message or belong to the connection.
    #[test]
    fn checks_route_modifiers() {
        let config = parse(
            r#"
            version = 1
            [routes.api]
            upstream = "app"
            rewrite = { strip_prefix = "/v1//", add_prefix = "api" }
            request_headers = { remove = ["X-Debug", "Connection"], set = { "Content-Length" = "1", "X-Env" = "prod" } }
            response_headers = { add = { "Transfer-Encoding" = "chunked", "X-Ok" = "1" } }
            [routes.moved]
            redirect = { to = "/" }
            rewrite = {}
            request_headers = { set = { "X-Env" = "prod" } }
            response_headers = { set = { "Cache-Control" = "no-store" } }
            [upstreams.app]
            targets = ["127.0.0.1:9000"]
            "#,
        );
        let issues = errors(&config);
        assert_eq!(
            paths(&issues),
            [
                "routes.api.rewrite.strip_prefix",
                "routes.api.rewrite.add_prefix",
                "routes.api.request_headers.remove[1]",
                "routes.api.request_headers.set.Content-Length",
                "routes.api.response_headers.add.Transfer-Encoding",
                "routes.moved.rewrite",
                "routes.moved.rewrite",
                "routes.moved.request_headers",
            ]
        );
        assert_eq!(
            issues[2].message,
            "cannot be changed: it frames the message or belongs to the connection"
        );
        assert_eq!(issues[5].message, "only for routes with an upstream");
        assert_eq!(issues[6].message, "set strip_prefix, add_prefix or both");
    }

    /// The hash key needs consistent hashing, time limits are longer than zero, retries are
    /// bounded, and only routes with an upstream have time limits.
    #[test]
    fn checks_upstream_settings() {
        let config = parse(
            r#"
            version = 1
            [routes.api]
            upstream = "app"
            timeouts = { read = "0s", write = "5m" }
            [routes.down]
            respond = { status = 503 }
            timeouts = { read = "5m" }
            [upstreams.app]
            targets = ["10.0.0.1:80", "api.internal:80", "API.internal:80"]
            hash_key = { cookie = "a b" }
            timeouts = { connect = "0ms", idle = "1s" }
            retries = 11
            [upstreams.sticky]
            targets = ["10.0.0.1:80"]
            balance = "consistent_hash"
            hash_key = { header = "X-User" }
            "#,
        );
        let issues = errors(&config);
        assert_eq!(
            paths(&issues),
            [
                "routes.api.timeouts.read",
                "routes.down.timeouts",
                "upstreams.app.targets[2]",
                "upstreams.app.hash_key",
                "upstreams.app.hash_key.cookie",
                "upstreams.app.timeouts.connect",
                "upstreams.app.retries",
            ]
        );
        assert_eq!(issues[0].message, "must be longer than 0s");
        assert_eq!(issues[2].message, "api.internal:80 is listed twice");
        assert_eq!(issues[3].message, "only for balance = \"consistent_hash\"");
        assert_eq!(issues[6].message, "must be at most 10");
    }

    /// HTTP/2 over TLS needs TLS and h2c goes without; TLS settings are complete and used.
    #[test]
    fn checks_upstream_protocols_and_tls() {
        let config = parse(
            r#"
            version = 1
            [upstreams.plain]
            targets = ["10.0.0.1:80"]
            protocol = "h2"
            [upstreams.mixed]
            targets = ["10.0.0.1:443"]
            protocol = "h2c"
            tls = { sni = "bad name", verify = false, ca = "ca.pem", cert = "wormway.crt" }
            [upstreams.fine]
            targets = ["10.0.0.1:443"]
            protocol = "h2"
            tls = { sni = "10.0.0.1", ca = "ca.pem", cert = "wormway.crt", key = "wormway.key" }
            "#,
        );
        let issues = errors(&config);
        assert_eq!(
            paths(&issues),
            [
                "upstreams.mixed.protocol",
                "upstreams.mixed.tls.sni",
                "upstreams.mixed.tls.ca",
                "upstreams.mixed.tls",
                "upstreams.plain.protocol",
            ]
        );
        assert_eq!(issues[3].message, "set cert and key together");
        assert_eq!(issues[4].message, "h2 needs tls; h2c is HTTP/2 without TLS");
    }

    /// Health checks have sound settings, the request settings only with "http", and passive
    /// checks count at least one failure for some time.
    #[test]
    fn checks_health_checks() {
        let config = parse(
            r#"
            version = 1
            [upstreams.tcp]
            targets = ["10.0.0.1:80"]
            health_check = { kind = "tcp", path = "/", status = [200], interval = "0s", healthy = 0 }
            passive = { max_fails = 0, fail_timeout = "0s" }
            [upstreams.http]
            targets = ["10.0.0.1:80"]
            health_check = { kind = "http", path = "health", host = "::1", status = [200, 99, 600] }
            [upstreams.empty]
            targets = ["10.0.0.1:80"]
            health_check = { kind = "http", path = "/a#b", host = "api:", status = [] }
            [upstreams.fine]
            targets = ["10.0.0.1:80"]
            health_check = { kind = "http", path = "/healthz?full=1", host = "[::1]:8080", status = [204], unhealthy = 1 }
            passive = {}
            "#,
        );
        let issues = errors(&config);
        assert_eq!(
            paths(&issues),
            [
                "upstreams.empty.health_check.path",
                "upstreams.empty.health_check.host",
                "upstreams.empty.health_check.status",
                "upstreams.http.health_check.path",
                "upstreams.http.health_check.host",
                "upstreams.http.health_check.status[1]",
                "upstreams.http.health_check.status[2]",
                "upstreams.tcp.health_check.path",
                "upstreams.tcp.health_check.status",
                "upstreams.tcp.health_check.interval",
                "upstreams.tcp.health_check.healthy",
                "upstreams.tcp.passive.max_fails",
                "upstreams.tcp.passive.fail_timeout",
            ]
        );
        assert_eq!(issues[2].message, "must list at least one status");
        assert_eq!(issues[5].message, "must be between 100 and 599");
        assert_eq!(issues[7].message, "only for kind = \"http\"");
        assert_eq!(issues[10].message, "must be at least 1");
    }

    /// Host headers take host names and IP addresses, IPv6 in brackets, with optional ports.
    #[test]
    fn recognizes_host_headers() {
        for host in [
            "api.internal",
            "api.internal:8080",
            "10.0.0.1",
            "10.0.0.1:80",
            "[::1]",
            "[::1]:8080",
        ] {
            assert!(is_authority(host), "{host}");
        }
        for host in [
            "",
            "::1",
            "api internal",
            "api:http",
            "http://api",
            "[api]",
            "10.0.0.1:70000",
        ] {
            assert!(!is_authority(host), "{host}");
        }
    }

    /// h2c is for listeners without TLS only.
    #[test]
    fn keeps_h2c_off_tls_listeners() {
        let config = parse(
            r#"
            version = 1
            [listeners.web]
            listen = ["127.0.0.1:8080"]
            protocol = "http"
            http = { h2c = true }
            [listeners.secure]
            listen = ["127.0.0.1:8443"]
            protocol = "http"
            tls = { certificates = ["site"], unknown_sni = "reject" }
            http = { h2c = true }
            [certificates.site]
            cert = "site.crt"
            key = "site.key"
            "#,
        );
        assert_eq!(paths(&errors(&config)), ["listeners.secure.http.h2c"]);
    }

    /// Dynamic tables in the file are flagged in db mode and used silently in file mode.
    #[test]
    fn warns_about_ignored_dynamic_settings() {
        let text = r#"
            version = 1
            [listeners.web]
            listen = ["0.0.0.0:8080"]
            protocol = "http"
            [routes.all]
            upstream = "app"
            [upstreams.app]
            targets = ["127.0.0.1:9000"]
            "#;
        assert_eq!(
            paths(&warnings(&parse(text))),
            ["listeners", "routes", "upstreams"]
        );

        let file_mode = format!("{text}\n[config]\nsource = \"file\"\n");
        assert!(warnings(&parse(&file_mode)).is_empty());
    }
}
