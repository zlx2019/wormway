//! Rules that span fields. Each check appends to a list, so one run reports every problem.

use std::net::SocketAddr;

use super::{Config, ConfigSource, Issue};

/// Returns every rule violation in `config`.
pub(super) fn errors(config: &Config) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_listeners(config, &mut issues);
    check_address_conflicts(config, &mut issues);
    issues
}

/// Returns settings that are accepted but have no effect.
pub(super) fn warnings(config: &Config) -> Vec<Issue> {
    if config.config.source != ConfigSource::Db {
        return Vec::new();
    }
    let tables = [
        ("listeners", config.listeners.is_empty()),
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

    /// Dynamic tables in the file are flagged in db mode and used silently in file mode.
    #[test]
    fn warns_about_ignored_dynamic_settings() {
        let text = r#"
            version = 1
            [listeners.web]
            listen = ["0.0.0.0:8080"]
            protocol = "http"
            "#;
        assert_eq!(paths(&warnings(&parse(text))), ["listeners"]);

        let file_mode = format!("{text}\n[config]\nsource = \"file\"\n");
        assert!(warnings(&parse(&file_mode)).is_empty());
    }
}
