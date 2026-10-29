//! The `zora` program: gateway, proxy protocols, reverse tunnels and dashboard in one binary.

mod admin;
mod config;
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
    /// Export or apply the dynamic settings of a running zora through its Admin API.
    ///
    /// The address of the Admin API and the token file come from the configuration file of the
    /// running zora. ZORA_ADMIN_TOKEN replaces the token file.
    #[command(subcommand)]
    Config(ConfigCommand),
}

/// Subcommands of `zora config`.
#[derive(Subcommand)]
enum ConfigCommand {
    /// Print the dynamic settings in effect, in the format of the configuration file.
    Export(ConfigArgs),
    /// Apply the dynamic settings of a file as a new version. Settings missing from the file are
    /// removed; static settings in the file are ignored.
    Apply(ApplyArgs),
}

/// Selects the configuration file.
#[derive(Args)]
struct ConfigArgs {
    /// Configuration file.
    #[arg(short, long, env = CONFIG_ENV, default_value = DEFAULT_CONFIG)]
    config: PathBuf,
}

/// Arguments of `zora config apply`.
#[derive(Args)]
struct ApplyArgs {
    /// Configuration file of the running zora.
    #[command(flatten)]
    target: ConfigArgs,
    /// File with the dynamic settings, in the format of the configuration file.
    #[arg(short, long)]
    file: PathBuf,
    /// Note saved with the new version.
    #[arg(short = 'm', long)]
    comment: Option<String>,
}

/// Runs the chosen subcommand.
fn main() -> anyhow::Result<ExitCode> {
    install_crypto_provider()?;
    match Cli::parse().command {
        Command::Run(args) => run::run(&args.config),
        Command::Check(args) => check(&args.config),
        Command::Schema => {
            println!("{}", zora_core::config::json_schema());
            Ok(ExitCode::SUCCESS)
        }
        Command::Config(ConfigCommand::Export(args)) => config::export(&args.config),
        Command::Config(ConfigCommand::Apply(args)) => {
            let comment = args.comment.as_deref().unwrap_or_default();
            config::apply(&args.target.config, &args.file, comment)
        }
    }
}

/// Makes aws-lc-rs, with post-quantum key exchange first, the TLS crypto provider of the
/// process. It has to come first: with ring also compiled in for Pingora, rustls has no default
/// of its own, and Pingora would install ring the first time it needs TLS.
fn install_crypto_provider() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a TLS crypto provider is already installed"))
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
