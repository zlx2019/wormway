//! The path index under one host condition: the exact paths, regular expressions and prefixes
//! of the routes, each with its candidates in order of precedence.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};

use crate::config::{PathPattern, PathRegex};

/// The precedence of a candidate: lower ranks win. The fields compare in order, which is the
/// order of the rules in [`crate::config::Route`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Rank {
    /// Higher priorities first.
    pub(super) priority: Reverse<i32>,
    /// Exact hosts, then wildcard hosts, then any host.
    pub(super) host: HostKind,
    /// Exact paths, then regular expressions, then prefixes, longest first. Any path counts as
    /// the empty prefix.
    pub(super) path: (PathKind, Reverse<usize>),
    /// Routes with methods first: `false` sorts before `true`.
    pub(super) any_method: bool,
    /// Routes with more header conditions first.
    pub(super) headers: Reverse<usize>,
    /// Earlier routes first. Also the index of the route.
    pub(super) route: usize,
}

/// Kinds of host conditions, the most specific first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum HostKind {
    /// An exact host name.
    Exact,
    /// A wildcard first label.
    Wildcard,
    /// Any host.
    Any,
}

/// Kinds of path conditions, the most specific first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum PathKind {
    /// An exact path.
    Exact,
    /// A regular expression.
    Regex,
    /// A prefix.
    Prefix,
}

/// Collects the paths of the routes under one host condition.
#[derive(Default)]
pub(super) struct PathTableBuilder {
    /// Candidates by exact path.
    exact: HashMap<Box<[u8]>, Vec<Rank>>,
    /// Regular expressions with their candidates.
    regexes: Vec<(PathRegex, Rank)>,
    /// Candidates by prefix, in byte order.
    prefixes: BTreeMap<Box<[u8]>, Vec<Rank>>,
}

impl PathTableBuilder {
    /// Adds a candidate for `path`, or for any path if `None`. `rank` gets the kind of the path.
    pub(super) fn add(&mut self, path: Option<&PathPattern>, rank: Rank) {
        match path {
            None => self.add_prefix(b"", rank),
            Some(PathPattern::Prefix(prefix)) => self.add_prefix(prefix.as_bytes(), rank),
            Some(PathPattern::Exact(path)) => {
                let rank = Rank {
                    path: (PathKind::Exact, Reverse(0)),
                    ..rank
                };
                self.exact
                    .entry(path.as_bytes().into())
                    .or_default()
                    .push(rank);
            }
            Some(PathPattern::Regex(regex)) => {
                let rank = Rank {
                    path: (PathKind::Regex, Reverse(0)),
                    ..rank
                };
                self.regexes.push((regex.clone(), rank));
            }
        }
    }

    /// Adds a candidate for the paths that start with `prefix`.
    fn add_prefix(&mut self, prefix: &[u8], rank: Rank) {
        let rank = Rank {
            path: (PathKind::Prefix, Reverse(prefix.len())),
            ..rank
        };
        self.prefixes.entry(prefix.into()).or_default().push(rank);
    }

    /// Sorts the candidates and links every prefix to the longest other prefix in front of it.
    pub(super) fn build(mut self) -> PathTable {
        for ranks in self.exact.values_mut() {
            ranks.sort();
        }
        self.regexes.sort_by_key(|(_, rank)| *rank);
        let mut prefixes: Vec<Prefix> = Vec::with_capacity(self.prefixes.len());
        // The prefixes of the one added last, shortest first. In byte order, every prefix of a
        // string comes before it, so its parent is on this chain.
        let mut chain: Vec<usize> = Vec::new();
        for (bytes, mut ranks) in self.prefixes {
            ranks.sort();
            while let Some(&last) = chain.last()
                && !bytes.starts_with(&prefixes[last].bytes)
            {
                chain.pop();
            }
            prefixes.push(Prefix {
                parent: chain.last().copied(),
                bytes,
                ranks,
            });
            chain.push(prefixes.len() - 1);
        }
        PathTable {
            exact: self.exact,
            regexes: self.regexes,
            prefixes,
        }
    }
}

/// The paths of the routes under one host condition, ready for lookups.
pub(super) struct PathTable {
    /// Candidates by exact path, best first.
    exact: HashMap<Box<[u8]>, Vec<Rank>>,
    /// Regular expressions with their candidates, best first.
    regexes: Vec<(PathRegex, Rank)>,
    /// Prefixes in byte order.
    prefixes: Vec<Prefix>,
}

/// A prefix and its candidates.
struct Prefix {
    /// The prefix.
    bytes: Box<[u8]>,
    /// Index of the longest other prefix that this one starts with.
    parent: Option<usize>,
    /// Candidates, best first.
    ranks: Vec<Rank>,
}

impl PathTable {
    /// Replaces `best` with a candidate for `path` that ranks before it and that `accepts`
    /// takes, if there is one: the best such candidate of each kind of path. `accepts` checks
    /// the conditions that the table does not know, given the index of the route.
    pub(super) fn find(
        &self,
        path: &[u8],
        best: &mut Option<Rank>,
        accepts: &impl Fn(usize) -> bool,
    ) {
        if let Some(ranks) = self.exact.get(path) {
            offer(ranks.iter(), best, accepts, |_| true);
        }
        offer(
            self.regexes.iter().map(|(_, rank)| rank),
            best,
            accepts,
            |index| self.regexes[index].0.is_match(path),
        );
        for ranks in self.prefixes_of(path) {
            offer(ranks.iter(), best, accepts, |_| true);
        }
    }

    /// Returns the candidates of the prefixes that `path` starts with, longest prefix first.
    fn prefixes_of(&self, path: &[u8]) -> impl Iterator<Item = &[Rank]> {
        // Every prefix of `path` sorts between that prefix and `path`, so it is also a prefix
        // of the last entry not after `path`: one of its ancestors, or itself.
        let mut next = self
            .prefixes
            .partition_point(|prefix| *prefix.bytes <= *path)
            .checked_sub(1);
        if let Some(last) = next {
            let common = common_len(&self.prefixes[last].bytes, path);
            while let Some(index) = next
                && self.prefixes[index].bytes.len() > common
            {
                next = self.prefixes[index].parent;
            }
        }
        std::iter::from_fn(move || {
            let prefix = &self.prefixes[next?];
            next = prefix.parent;
            Some(&prefix.ranks[..])
        })
    }
}

/// Replaces `best` with the first of `ranks`, given best first, that ranks before it, that
/// `matches` takes by its position in `ranks`, and that `accepts` takes by its route.
fn offer<'a>(
    ranks: impl Iterator<Item = &'a Rank>,
    best: &mut Option<Rank>,
    accepts: &impl Fn(usize) -> bool,
    matches: impl Fn(usize) -> bool,
) {
    for (index, rank) in ranks.enumerate() {
        if best.is_some_and(|best| best <= *rank) {
            return;
        }
        if matches(index) && accepts(rank.route) {
            *best = Some(*rank);
            return;
        }
    }
}

/// Returns the length of the common start of `a` and `b`.
fn common_len(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(a, b)| a == b).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A rank for route `route`, with every other field equal.
    fn rank(route: usize) -> Rank {
        Rank {
            priority: Reverse(0),
            host: HostKind::Any,
            path: (PathKind::Prefix, Reverse(0)),
            any_method: true,
            headers: Reverse(0),
            route,
        }
    }

    /// The routes of the prefixes that `path` starts with, longest first.
    fn prefix_routes(table: &PathTable, path: &str) -> Vec<usize> {
        table
            .prefixes_of(path.as_bytes())
            .flat_map(|ranks| ranks.iter().map(|rank| rank.route))
            .collect()
    }

    /// Every prefix of a path is found through the chain of parents, also when the entries
    /// next to the path in byte order are not its prefixes.
    #[test]
    fn finds_every_prefix() {
        let mut builder = PathTableBuilder::default();
        let prefixes = ["", "/", "/a", "/ab", "/ac", "/b/", "/b/c/", "/b/d"];
        for (route, prefix) in prefixes.iter().enumerate() {
            builder.add(
                Some(&PathPattern::Prefix((*prefix).to_owned())),
                rank(route),
            );
        }
        let table = builder.build();
        assert_eq!(prefix_routes(&table, "/ab/x"), [3, 2, 1, 0]);
        assert_eq!(prefix_routes(&table, "/ad"), [2, 1, 0]);
        assert_eq!(prefix_routes(&table, "/a"), [2, 1, 0]);
        assert_eq!(prefix_routes(&table, "/b/c/x"), [6, 5, 1, 0]);
        assert_eq!(prefix_routes(&table, "/b/cc"), [5, 1, 0]);
        assert_eq!(prefix_routes(&table, "/b/e"), [5, 1, 0]);
        assert_eq!(prefix_routes(&table, "/z"), [1, 0]);
        assert_eq!(prefix_routes(&table, ""), [0]);
        assert_eq!(prefix_routes(&table, "*"), [0]);
    }

    /// Without a prefix of the path in the table, nothing is found.
    #[test]
    fn finds_no_prefix_when_there_is_none() {
        let mut builder = PathTableBuilder::default();
        for (route, prefix) in ["/b", "/c/"].iter().enumerate() {
            builder.add(
                Some(&PathPattern::Prefix((*prefix).to_owned())),
                rank(route),
            );
        }
        let table = builder.build();
        assert!(prefix_routes(&table, "/a").is_empty());
        assert!(prefix_routes(&table, "/c").is_empty());
        assert!(prefix_routes(&table, "/d").is_empty());
        assert!(
            PathTableBuilder::default()
                .build()
                .prefixes_of(b"/")
                .next()
                .is_none()
        );
    }
}
