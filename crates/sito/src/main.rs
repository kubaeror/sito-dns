//! Binary entry point for the `sito` DNS server CLI.

use clap::Parser;
use sito::cli::{Cli, Commands, run_backup, run_check_config, run_healthcheck_or_web, run_restore};
use sito::server::run_server_full;
use sito_core::config::Config;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

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
                setup_fallback,
            } => {
                let (dns_target, web_target) = if let Some(addr) = address {
                    (Some(addr), "127.0.0.1:8080".parse().unwrap())
                } else if let Ok(content) = std::fs::read_to_string(&cli.config) {
                    if let Ok(cfg) = Config::from_toml_str(&content) {
                        let (dns, web) = sito::cli::healthcheck_targets_from_config(&cfg);
                        (Some(dns), web)
                    } else {
                        (
                            Some("127.0.0.1:53".parse().unwrap()),
                            "127.0.0.1:8080".parse().unwrap(),
                        )
                    }
                } else {
                    // No configuration yet: the setup wizard web server is the
                    // only listener that should be up.
                    (None, "127.0.0.1:8080".parse().unwrap())
                };

                if let Err(e) =
                    run_healthcheck_or_web(dns_target, web_target, timeout_ms, setup_fallback).await
                {
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
                sito::cli::HaCommands::GenCerts {
                    dir,
                    master,
                    slave,
                    san,
                    uid,
                    gid,
                } => {
                    if let Err(e) = sito::cli::run_ha_gen_certs(&dir, master, slave, &san, uid, gid)
                    {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                    return Ok(());
                }
            },
            Commands::Update { check, force, repo } => {
                if let Err(e) =
                    sito::cli::run_update(check, force, repo.as_deref(), &cli.config).await
                {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            Commands::ResetAdmin {
                config,
                password,
                reset_all,
                force,
            } => {
                let config_path = config.unwrap_or(cli.config);
                if let Err(e) = sito::cli::run_reset_admin_with_options(
                    &config_path,
                    password.as_deref(),
                    reset_all,
                    force,
                ) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            Commands::ResetSessions { config, force } => {
                let config_path = config.unwrap_or(cli.config);
                if let Err(e) = sito::cli::run_reset_sessions_with_options(&config_path, force) {
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
        // No config file: the built-in defaults would bootstrap
        // `admin/adminadmin` on 0.0.0.0. Generate a random admin password and
        // bind the admin UI to loopback instead, printing the password once.
        let mut config = Config::default();
        match sito::cli::prepare_no_setup_bootstrap(&config_path, &mut config) {
            Ok(sito::cli::NoSetupBootstrap::GeneratedPassword(password)) => {
                eprintln!("\n==================================================================");
                eprintln!(" --no-setup without a configuration file detected.");
                eprintln!(" Admin UI bound to 127.0.0.1 with a randomly generated password.");
                eprintln!(" Username: admin");
                eprintln!(" Password: {password}");
                eprintln!(" Store this password now; it is never shown again.");
                eprintln!("==================================================================\n");
            }
            Ok(sito::cli::NoSetupBootstrap::KeptExistingUsers) => {
                eprintln!("\n==================================================================");
                eprintln!(" --no-setup without a configuration file detected.");
                eprintln!(" Existing credentials were found and kept; the admin UI is bound");
                eprintln!(" to 127.0.0.1. Use `sito reset-admin` to deliberately rotate them.");
                eprintln!("==================================================================\n");
            }
            Ok(sito::cli::NoSetupBootstrap::NotNeeded) => {}
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        (config, false)
    } else {
        (Config::default(), true)
    };

    // Initialize tracing subscriber per configuration. The filter layer is
    // installable via `sito::logging` so `server.log_level` hot-reloads.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.server.log_level));
    let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(env_filter);

    if config.server.log_format == "pretty" {
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(tracing_subscriber::fmt::layer().pretty())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter_layer)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    }

    if !sito::logging::install_reload_fn(move |level| {
        reload_handle
            .reload(tracing_subscriber::EnvFilter::new(level))
            .map_err(|e| e.to_string())
    }) {
        tracing::debug!("Log-level reload callback already installed");
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
        if config.server.data_dir.join("users.toml").exists() {
            eprintln!(
                " Note: '{}' already exists, so the wizard requires an admin login",
                config.server.data_dir.join("users.toml").display()
            );
            eprintln!(" instead of the first-boot setup token. Log in, then complete the wizard");
            eprintln!(" to restore the missing configuration.");
        }
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
