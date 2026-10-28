//! The `zora` program: gateway, proxy protocols, reverse tunnels and dashboard in one binary.

mod load;
mod logging;
mod run;
mod signals;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

/// Environment variable that sets the configuration file path.
const CONFIG_ENV: &str = "ZORA_CONFIG";
/// Environment variable that sets the Admin API token instead of the token file.
const ADMIN_TOKEN_ENV: &str = "ZORA_ADMIN_TOKEN";
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
    /// Run until SIGINT or SIGTERM. SIGHUP reloads the configuration file.
    Run(ConfigArgs),
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
        Command::Run(args) => run::run(&args.config),
        Command::Check(args) => check(&args.config),
        Command::Schema => {
            println!("{}", zora_core::config::json_schema());
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// `zora check`: prints the problems in the file. The exit code is 0 only if the file is valid.
fn check(path: &Path) -> anyhow::Result<ExitCode> {
    let config = match load::load(path)? {
        Ok(config) => config,
        Err(error) => {
            load::print_errors(path, &error);
            return Ok(ExitCode::FAILURE);
        }
    };
    let file = path.display();
    for warning in config.warnings() {
        eprintln!("{file}: warning: {warning}");
    }
    println!("{file}: ok");
    Ok(ExitCode::SUCCESS)
}
