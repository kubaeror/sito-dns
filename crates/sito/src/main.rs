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
            Commands::ResetAdmin { config, password } => {
                let config_path = config.unwrap_or(cli.config);
                if let Err(e) = sito::cli::run_reset_admin(&config_path, password.as_deref()) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
        }
    }

    // Server execution path
    let config_path = cli.config;
    let (config, setup_pending) = if config_path.exists() {
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
        (config, false)
    } else if cli.no_setup {
        (Config::default(), false)
    } else {
        (Config::default(), true)
    };

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

    if setup_pending {
        let web_cfg = config.get_web_config();
        let host_display = if web_cfg.bind.is_unspecified() {
            "localhost".to_string()
        } else {
            web_cfg.bind.to_string()
        };
        eprintln!("\n==================================================================");
        eprintln!(
            " First run detected: open http://{}:{} to complete setup",
            host_display, web_cfg.port
        );
        eprintln!("==================================================================\n");
        tracing::info!(
            "First run detected: open http://{}:{} to complete setup",
            host_display,
            web_cfg.port
        );
    } else if !config_path.exists() && cli.no_setup {
        tracing::info!(
            config = %config_path.display(),
            "Configuration file not found; running with built-in defaults (--no-setup)"
        );
    }

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        setup_pending,
        "Starting sito DNS server"
    );

    run_server_full(config, config_path, None, setup_pending).await
}
