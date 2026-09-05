//! Binary entry point for the `sito` DNS server CLI.

use clap::Parser;
use sito::cli::{Cli, Commands, run_backup, run_check_config, run_healthcheck, run_restore};
use sito::server::run_server_full;
use sito_core::config::Config;
use std::net::SocketAddr;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Handle subcommands
    if let Some(cmd) = cli.command {
        match cmd {
            Commands::CheckConfig { config } => {
                let config_path = config.unwrap_or(cli.config);
                if let Err(e) = run_check_config(&config_path) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            Commands::Healthcheck {
                address,
                timeout_ms,
            } => {
                let target_addr = if let Some(addr) = address {
                    addr
                } else if let Ok(content) = std::fs::read_to_string(&cli.config) {
                    if let Ok(cfg) = Config::from_toml_str(&content) {
                        SocketAddr::new("127.0.0.1".parse().unwrap(), cfg.dns.port)
                    } else {
                        "127.0.0.1:53".parse().unwrap()
                    }
                } else {
                    "127.0.0.1:53".parse().unwrap()
                };

                if let Err(e) = run_healthcheck(target_addr, timeout_ms).await {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            Commands::Backup { config, output } => {
                let config_path = config.unwrap_or(cli.config);
                if let Err(e) = run_backup(&config_path, output.as_deref()) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            Commands::Restore {
                input,
                config,
                force,
            } => {
                let config_path = config.unwrap_or(cli.config);
                if let Err(e) = run_restore(&input, &config_path, force) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            Commands::Ha { command } => match command {
                sito::cli::HaCommands::GenCerts { dir, master, slave } => {
                    if let Err(e) = sito::cli::run_ha_gen_certs(&dir, master, slave) {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                    return Ok(());
                }
            },
            Commands::Update { check, force, repo } => {
                if let Err(e) = sito::cli::run_update(check, force, repo.as_deref()).await {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
        }
    }

    // Server execution path
    let config_path = cli.config;
    let content = std::fs::read_to_string(&config_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to open configuration file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let config = Config::from_toml_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Invalid configuration in '{}': {}",
            config_path.display(),
            e
        )
    })?;

    // Initialize tracing subscriber per configuration
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.server.log_level));

    if config.server.log_format == "pretty" {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .pretty()
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .json()
            .init();
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        "Starting sito DNS server"
    );

    run_server_full(config, config_path, None).await
}
