//! Reading and checking the configuration file.

use std::path::Path;

use anyhow::Context;
use zora_core::config::{Config, ConfigError, Issue};

use crate::logging;

/// Reads and checks the configuration file at `path`. The outer error means the file could not
/// be read, the inner one that its contents are invalid.
pub fn load(path: &Path) -> anyhow::Result<Result<Config, ConfigError>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(Config::from_toml(&text).and_then(check_log_filter))
}

/// Checks `log.level`, which only the logging setup of the binary can parse.
fn check_log_filter(config: Config) -> Result<Config, ConfigError> {
    match logging::filter(&config.log) {
        Ok(_) => Ok(config),
        Err(error) => Err(ConfigError::Invalid(vec![Issue {
            path: "log.level".to_owned(),
            message: error.to_string(),
        }])),
    }
}

/// Prints why the file at `path` was rejected, one line per problem.
pub fn print_errors(path: &Path, error: &ConfigError) {
    let file = path.display();
    match error {
        // Editors and terminals turn `file:line:column` into a link to the error.
        ConfigError::Parse(error) => match error.position {
            Some(at) => eprintln!("{file}:{}:{}: error: {}", at.line, at.column, error.message),
            None => eprintln!("{file}: error: {}", error.message),
        },
        ConfigError::Invalid(issues) => {
            for issue in issues {
                eprintln!("{file}: error: {issue}");
            }
            eprintln!("{file}: {} error(s)", issues.len());
        }
    }
}
