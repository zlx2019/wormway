//! `wormway config`: exports and applies the dynamic settings of a running Wormway through its
//! Admin API.

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use serde::Deserialize;
use wormway_core::config::{ConfigError, DynamicConfig};

use crate::admin::{AdminClient, ApiError};
use crate::{ADMIN_TOKEN_ENV, load};

/// Answer of `GET /api/v1/config`; its other fields are not needed here.
#[derive(Deserialize)]
struct ConfigInEffect {
    /// The dynamic settings in effect.
    config: DynamicConfig,
}

/// Answer of `PUT /api/v1/config`.
#[derive(Deserialize)]
struct ChangeResult {
    /// Saved version in effect after the request.
    version: Option<i64>,
    /// Whether a new version was saved.
    changed: bool,
}

/// `wormway config export`: prints the dynamic settings in effect in the format of the
/// configuration file. `path` is the configuration file of the running Wormway.
pub fn export(path: &Path) -> anyhow::Result<ExitCode> {
    let Some(admin) = connect(path)? else {
        return Ok(ExitCode::FAILURE);
    };
    match block_on(admin.get::<ConfigInEffect>("/api/v1/config"))?? {
        Ok(answer) => {
            print!("{}", answer.config.to_toml()?);
            Ok(ExitCode::SUCCESS)
        }
        Err(error) => {
            print_api_error(None, error);
            Ok(ExitCode::FAILURE)
        }
    }
}

/// `wormway config apply`: applies the dynamic settings in `file` as a new version, with
/// `comment` saved along. Settings missing from the file are removed. The exit code is 0 only
/// if the settings are in effect.
pub fn apply(path: &Path, file: &Path, comment: &str) -> anyhow::Result<ExitCode> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("cannot read {}", file.display()))?;
    let dynamic = match DynamicConfig::from_toml(&text) {
        Ok(dynamic) => dynamic,
        Err(error) => {
            load::print_errors(file, &ConfigError::Parse(error));
            return Ok(ExitCode::FAILURE);
        }
    };
    let Some(admin) = connect(path)? else {
        return Ok(ExitCode::FAILURE);
    };
    let body = serde_json::json!({ "config": dynamic, "comment": comment });
    match block_on(admin.put::<ChangeResult>("/api/v1/config", &body))?? {
        Ok(ChangeResult {
            changed: true,
            version: Some(version),
        }) => println!("applied: version {version} is in effect"),
        Ok(_) => println!("no change: these settings are already in effect"),
        Err(error) => {
            print_api_error(Some(file), error);
            return Ok(ExitCode::FAILURE);
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Reads the configuration file at `path` to find the Admin API. Prints the problems and
/// returns `None` if the file is invalid.
fn connect(path: &Path) -> anyhow::Result<Option<AdminClient>> {
    match load::load(path)? {
        Ok(config) => Ok(Some(AdminClient::new(path, &config)?)),
        Err(error) => {
            load::print_errors(path, &error);
            Ok(None)
        }
    }
}

/// Runs `future` to completion on a small runtime of its own.
fn block_on<F: Future>(future: F) -> anyhow::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    Ok(runtime.block_on(future))
}

/// Prints an error answered by the Admin API. Problems with single settings are printed like
/// `wormway check` does, against `file` when the settings came from one.
fn print_api_error(file: Option<&Path>, error: ApiError) {
    match file {
        Some(file) if !error.details.is_empty() => {
            load::print_errors(file, &ConfigError::Invalid(error.details));
        }
        _ => eprintln!("error: {}", error.message),
    }
    if error.code == "unauthorized" {
        eprintln!("hint: set {ADMIN_TOKEN_ENV} to the token of the running Wormway");
    }
}
