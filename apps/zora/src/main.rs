//! The `zora` program: gateway, proxy protocols, reverse tunnels and dashboard in one binary.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use zora_core::config::{Config, ConfigError};

/// Environment variable that sets the configuration file path.
const CONFIG_ENV: &str = "ZORA_CONFIG";
/// Configuration file used when neither `--config` nor the environment variable is set.
const DEFAULT_CONFIG: &str = "zora.toml";

/// Gateway, proxy protocols, reverse tunnels and dashboard in one binary.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// What to do.
    #[command(subcommand)]
    command: Command,
}

/// Subcommands.
#[derive(Subcommand)]
enum Command {
    /// Validate a configuration file and report every problem found.
    Check(ConfigArgs),
    /// Print the JSON Schema of the configuration file.
    Schema,
}

/// Selects the configuration file.
#[derive(Args)]
struct ConfigArgs {
    /// Configuration file.
    #[arg(short, long, env = CONFIG_ENV, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
}

/// Runs the chosen subcommand.
fn main() -> anyhow::Result<ExitCode> {
    match Cli::parse().command {
        Command::Check(args) => check(&args.config),
        Command::Schema => {
            println!("{}", zora_core::config::json_schema());
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// `zora check`: prints the problems in the file. The exit code is 0 only if the file is valid.
fn check(path: &Path) -> anyhow::Result<ExitCode> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    let file = path.display().to_string();
    let config = match Config::from_toml(&text) {
        Ok(config) => config,
        Err(error) => {
            print_errors(&file, &error);
            return Ok(ExitCode::FAILURE);
        }
    };
    for warning in config.warnings() {
        eprintln!("{file}: warning: {warning}");
    }
    println!("{file}: ok");
    Ok(ExitCode::SUCCESS)
}

/// Prints why `file` was rejected, one line per problem.
fn print_errors(file: &str, error: &ConfigError) {
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
