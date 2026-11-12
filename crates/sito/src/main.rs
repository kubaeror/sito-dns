//! Binary entry point for the `sito` DNS server CLI.

use clap::Parser;
use sito::cli::{Cli, Commands, run_backup, run_check_config, run_healthcheck_or_web, run_restore};
use sito::server::run_server_with_lease;
use sito_core::config::Config;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    // Resolve once before `cli.command` is moved out: an explicit --config
    // wins, otherwise use ./config.toml or /etc/sito/config.toml.
    let default_config_path = cli.config_path();

    // Handle subcommands
    if let Some(cmd) = cli.command {
        match cmd {
            Commands::CheckConfig { config } => {
                let config_path = config.unwrap_or(default_config_path.clone());
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
                // Read the configuration once: it provides both the probe
                // targets and whether HA replication is part of this role.
                let config_file = std::fs::read_to_string(&default_config_path).ok();
                let config = config_file
                    .as_ref()
                    .and_then(|content| Config::from_toml_str(content).ok());
                let (dns_target, web_target) = if let Some(addr) = address {
                    (Some(addr), "127.0.0.1:8080".parse().unwrap())
                } else if let Some(cfg) = &config {
                    let (dns, web) = sito::cli::healthcheck_targets_from_config(cfg);
                    (Some(dns), web)
                } else if config_file.is_some() {
                    // The file exists but does not parse: keep probing the
                    // conventional local defaults instead of the wizard only.
                    (
                        Some("127.0.0.1:53".parse().unwrap()),
                        "127.0.0.1:8080".parse().unwrap(),
                    )
                } else {
                    // No configuration yet: the setup wizard web server is the
                    // only listener that should be up.
                    (None, "127.0.0.1:8080".parse().unwrap())
                };
                // A parseable configuration decides whether HA replication is
                // part of this role. An explicit --address targets an
                // arbitrary server, so the local admin API is not a valid
                // readiness source for it. A missing or invalid config cannot
                // declare HA; the DNS probe remains the primary gate.
                let ha_required = address.is_none()
                    && config
                        .as_ref()
                        .is_some_and(sito::cli::ha_readiness_required);

                if let Err(e) = run_healthcheck_or_web(
                    dns_target,
                    web_target,
                    timeout_ms,
                    setup_fallback,
                    ha_required,
                )
                .await
                {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            Commands::Backup { config, output } => {
                let config_path = config.unwrap_or(default_config_path.clone());
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
                let config_path = config.unwrap_or(default_config_path.clone());
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
            Commands::Config { command } => match command {
                sito::cli::ConfigCommands::Migrate {
                    config,
                    from,
                    to,
                    backup,
                    adopt_safe_defaults,
                    ignore_unknown_keys,
                    json,
                } => {
                    // Accept both the global `--config` and the subcommand form.
                    let config_path = config.unwrap_or(default_config_path.clone());
                    if let Err(e) = sito::cli::run_config_migrate(
                        &config_path,
                        &from,
                        &to,
                        sito::cli::ConfigMigrateOptions {
                            backup,
                            adopt_safe_defaults,
                            ignore_unknown_keys,
                            json,
                        },
                    ) {
                        eprintln!("{e}");
                        std::process::exit(1);
                    }
                    return Ok(());
                }
            },
            Commands::Update {
                config,
                check,
                force,
                repo,
            } => {
                // Accept both the global `--config` (before the subcommand)
                // and the documented `sito update --config <path>` form.
                let config = config.or(cli.config);
                if let Err(e) =
                    sito::cli::run_update(check, force, repo.as_deref(), config.as_deref()).await
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
                let config_path = config.unwrap_or(default_config_path.clone());
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
                let config_path = config.unwrap_or(default_config_path.clone());
                if let Err(e) = sito::cli::run_reset_sessions_with_options(&config_path, force) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
            Commands::ClearQueryLog {
                config,
                keep_aggregates,
                force,
            } => {
                let config_path = config.unwrap_or(default_config_path.clone());
                if let Err(e) =
                    sito::cli::run_clear_query_log(&config_path, keep_aggregates, force).await
                {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
                return Ok(());
            }
        }
    }

    // Server execution path
    let config_path = default_config_path;
    let config_exists = config_path.exists();
    // Read/parse the configuration before acquiring the lease: this is a
    // read-only operation. Every mutation below runs under the lease.
    let (mut config, setup_pending) = if config_exists {
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
        // `admin/adminadmin` on 0.0.0.0. `prepare_no_setup_bootstrap` below
        // generates a random admin password and binds the admin UI to loopback;
        // it must run only while this process holds the service lease (P2-90).
        (Config::default(), false)
    } else {
        (Config::default(), true)
    };

    // P2-90: acquire the service lease before any bootstrap mutation. A second
    // process that cannot acquire it exits here without touching
    // `users.toml`/`config.toml` or printing a password it could never use.
    let data_dir = config.server.data_dir.clone();
    let (bootstrap, service_lease) = match sito::service_lock::with_service_lease(&data_dir, || {
        if !config_exists && cli.no_setup {
            sito::cli::prepare_no_setup_bootstrap(&config_path, &mut config)
        } else {
            Ok(sito::cli::NoSetupBootstrap::NotNeeded)
        }
    }) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };

    if !config_exists && cli.no_setup {
        match bootstrap {
            sito::cli::NoSetupBootstrap::GeneratedPassword(password) => {
                eprintln!("\n==================================================================");
                eprintln!(" --no-setup without a configuration file detected.");
                eprintln!(" Admin UI bound to 127.0.0.1 with a randomly generated password.");
                eprintln!(" Username: admin");
                eprintln!(" Password: {password}");
                eprintln!(" Store this password now; it is never shown again.");
                eprintln!("==================================================================\n");
            }
            sito::cli::NoSetupBootstrap::KeptExistingUsers => {
                eprintln!("\n==================================================================");
                eprintln!(" --no-setup without a configuration file detected.");
                eprintln!(" Existing credentials were found and kept; the admin UI is bound");
                eprintln!(" to 127.0.0.1. Use `sito reset-admin` to deliberately rotate them.");
                eprintln!("==================================================================\n");
            }
            sito::cli::NoSetupBootstrap::NotNeeded => {}
        }
    }

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

    run_server_with_lease(config, config_path, None, setup_pending, service_lease).await
}
