//! Errors from loading a configuration.

use std::fmt;

/// Why a configuration was rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The text is not valid TOML or does not match the configuration structure. Parsing stops
    /// at the first such error.
    #[error(transparent)]
    Parse(#[from] ParseError),
    /// The configuration is well-formed but breaks rules that span fields. Every problem found is
    /// listed.
    #[error("invalid configuration: {}", join(.0))]
    Invalid(Vec<Issue>),
}

/// Joins issues into one line for the [`ConfigError`] message.
fn join(issues: &[Issue]) -> String {
    issues
        .iter()
        .map(Issue::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// A syntax or structure error, with its position in the source text when known.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub struct ParseError {
    /// Where the error is.
    pub position: Option<Position>,
    /// What went wrong.
    pub message: String,
}

impl ParseError {
    /// Converts a TOML error, locating its byte span in `text`.
    pub(crate) fn from_toml(error: &toml::de::Error, text: &str) -> Self {
        Self {
            position: error.span().map(|span| Position::locate(text, span.start)),
            message: error.message().to_owned(),
        }
    }
}

impl fmt::Display for ParseError {
    /// Writes `line L, column C: message`, or only the message when the position is unknown.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.position {
            Some(Position { line, column }) => {
                write!(f, "line {line}, column {column}: {}", self.message)
            }
            None => f.write_str(&self.message),
        }
    }
}

/// A position in the source text. Both numbers start at 1, and the column counts characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Position {
    /// Line number.
    pub line: usize,
    /// Column number.
    pub column: usize,
}

impl Position {
    /// Finds the line and column of the byte offset `offset` in `text`.
    fn locate(text: &str, offset: usize) -> Self {
        let before = &text[..text.floor_char_boundary(offset)];
        let line_start = before.rfind('\n').map_or(0, |i| i + 1);
        Self {
            line: before.matches('\n').count() + 1,
            column: before[line_start..].chars().count() + 1,
        }
    }
}

/// A problem with one setting, found by validation.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Issue {
    /// Path of the setting, such as `listeners.web.listen[0]`.
    pub path: String,
    /// What is wrong.
    pub message: String,
}

impl Issue {
    /// Creates an issue for the setting at `path`.
    pub(crate) fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Issue {
    /// Writes `path: message`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lines and columns start at 1, and columns count characters rather than bytes.
    #[test]
    fn locates_offsets() {
        let text = "ab\n名字 = 1\n";
        let at = |offset| {
            let p = Position::locate(text, offset);
            (p.line, p.column)
        };
        assert_eq!(at(0), (1, 1));
        assert_eq!(at(2), (1, 3));
        assert_eq!(at(3), (2, 1));
        // "名" and "字" take three bytes each.
        assert_eq!(at(9), (2, 3));
        // An offset inside a character or past the end does not panic.
        assert_eq!(at(4), (2, 1));
        assert_eq!(at(100), (3, 1));
    }
}
