//! Path normalization: the form in which routes compare request paths.

use std::borrow::Cow;

/// Returns `path` in the form that routes compare: every `%XX` decoded, `%2F` included, then
/// `.` and `..` segments resolved and repeated slashes merged, as Nginx does. A `..` above the
/// root stays at the root, and a `%` without two hex digits after it stays as it is.
///
/// Without this, `/public/../admin/` or `/admin%2Fusers` would escape the rules of a route for
/// `/admin/`. The result is bytes, since decoding may produce bytes that are not UTF-8. A path
/// that is in this form already, or that does not start with `/`, such as `*` in `OPTIONS *`,
/// comes back as it is, without copying.
pub fn normalize_path(path: &[u8]) -> Cow<'_, [u8]> {
    if !path.starts_with(b"/") || is_normal(path) {
        return Cow::Borrowed(path);
    }
    Cow::Owned(resolve(&decode(path)))
}

/// Whether `path`, which starts with `/`, needs no change: no `%`, no `.` or `..` segment and
/// no empty segment except the last one.
fn is_normal(path: &[u8]) -> bool {
    if path.contains(&b'%') {
        return false;
    }
    let mut segments = path[1..].split(|&b| b == b'/').peekable();
    while let Some(segment) = segments.next() {
        let last = segments.peek().is_none();
        if segment == b"." || segment == b".." || (segment.is_empty() && !last) {
            return false;
        }
    }
    true
}

/// Decodes every `%XX` of `path`; a `%` without two hex digits after it is kept.
fn decode(path: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        if path[i] == b'%'
            && let Some(high) = path.get(i + 1).and_then(hex_value)
            && let Some(low) = path.get(i + 2).and_then(hex_value)
        {
            decoded.push(high << 4 | low);
            i += 3;
        } else {
            decoded.push(path[i]);
            i += 1;
        }
    }
    decoded
}

/// Returns the value of a hex digit.
fn hex_value(digit: &u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Resolves the `.` and `..` segments of `path`, which starts with `/`, and drops its empty
/// segments. The result ends with `/` when `path` ends with `/` or with a `.` or `..` segment.
fn resolve(path: &[u8]) -> Vec<u8> {
    let mut resolved = Vec::with_capacity(path.len());
    // Whether the last segment stands for a directory, so that the result ends with "/".
    let mut directory = false;
    for segment in path[1..].split(|&b| b == b'/') {
        directory = matches!(segment, b"" | b"." | b"..");
        match segment {
            b"" | b"." => {}
            b".." => {
                let parent = resolved.iter().rposition(|&b| b == b'/').unwrap_or(0);
                resolved.truncate(parent);
            }
            _ => {
                resolved.push(b'/');
                resolved.extend_from_slice(segment);
            }
        }
    }
    if directory || resolved.is_empty() {
        resolved.push(b'/');
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Normalizes a path given as text.
    fn normal(path: &str) -> Cow<'_, [u8]> {
        normalize_path(path.as_bytes())
    }

    /// Paths in normal form, and paths that do not start with "/", are borrowed unchanged.
    #[test]
    fn leaves_normal_paths_alone() {
        for path in [
            "/",
            "/a",
            "/a/",
            "/a/b.c",
            "/.well-known/x",
            "/a/..b",
            "/a/...",
            "*",
            "",
        ] {
            assert!(
                matches!(normal(path), Cow::Borrowed(p) if p == path.as_bytes()),
                "{path:?}"
            );
        }
    }

    /// Dot segments resolve, never above the root, and repeated slashes merge.
    #[test]
    fn resolves_dot_segments_and_slashes() {
        for (path, expected) in [
            ("//", "/"),
            ("//a//b//", "/a/b/"),
            ("/a/./b", "/a/b"),
            ("/a/.", "/a/"),
            ("/a/b/..", "/a/"),
            ("/a/..", "/"),
            ("/..", "/"),
            ("/../../a", "/a"),
            ("/public/../admin/", "/admin/"),
            ("/a/b/../../c/./d/", "/c/d/"),
        ] {
            assert_eq!(*normal(path), *expected.as_bytes(), "{path:?}");
        }
    }

    /// Every escape decodes before the segments resolve, and broken escapes stay.
    #[test]
    fn decodes_escapes() {
        for (path, expected) in [
            ("/admin%2Fusers", &b"/admin/users"[..]),
            ("/admin%2fusers", b"/admin/users"),
            ("/%2e%2E/admin", b"/admin"),
            ("/a%2F..%2Fadmin", b"/admin"),
            ("/%C3%A9t%C3%A9", "/été".as_bytes()),
            ("/a%20b", b"/a b"),
            ("/a%25b", b"/a%b"),
            ("/%FF", b"/\xff"),
            ("/a%2", b"/a%2"),
            ("/a%zz", b"/a%zz"),
            ("/a%", b"/a%"),
        ] {
            assert_eq!(*normal(path), *expected, "{path:?}");
        }
    }
}
