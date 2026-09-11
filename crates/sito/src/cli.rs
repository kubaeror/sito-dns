//! CLI arguments and subcommand execution for sito.

use clap::{Parser, Subcommand};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use sito_core::config::Config;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "sito",
    author,
    version,
    about = "High-performance, self-hosted, filtering DNS server"
)]
pub struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    pub config: PathBuf,

    /// Skip web-based setup wizard gating and start with defaults immediately
    #[arg(long)]
    pub no_setup: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Validate configuration file syntax and constraints without starting server
    CheckConfig {
        /// Optional path to configuration file to check (defaults to main --config)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
    /// Check server health via local DNS probe
    Healthcheck {
        /// Target server address to probe (default 127.0.0.1:53 or port from config)
        #[arg(short, long)]
        address: Option<SocketAddr>,
        /// Probe timeout in milliseconds
        #[arg(short, long, default_value = "2000")]
        timeout_ms: u64,
    },
    /// Create a tar.gz backup archive of configuration and metadata
    Backup {
        /// Optional path to configuration file to back up (defaults to main --config)
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Destination archive file path (.tar.gz)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Restore configuration from a backup archive (.tar.gz)
    Restore {
        /// Path to backup archive (.tar.gz) to restore
        #[arg(short, long)]
        input: PathBuf,
        /// Destination configuration file path (defaults to main --config)
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Overwrite destination configuration file if it already exists
        #[arg(short, long)]
        force: bool,
    },
    /// High Availability clustering management
    Ha {
        #[command(subcommand)]
        command: HaCommands,
    },
    /// Check for and install software updates
    Update {
        /// Only check for available updates without installing
        #[arg(short, long)]
        check: bool,
        /// Force update even if already running the latest version
        #[arg(short, long)]
        force: bool,
        /// Optional custom GitHub repository (e.g. kubaeror/sito-dns)
        #[arg(long)]
        repo: Option<String>,
    },
    /// Reset administrative credentials (re-bootstrap admin user)
    ResetAdmin {
        /// Optional path to configuration file (defaults to main --config)
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Optional new admin password (defaults to adminadmin)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Invalidate all persisted web sessions and API tokens (users are kept)
    ResetSessions {
        /// Optional path to configuration file (defaults to main --config)
        #[arg(short, long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum HaCommands {
    /// Generate self-signed CA and mTLS certificate/key pairs with BLAKE3 fingerprint pinning
    GenCerts {
        /// Destination directory to save generated certificates and private keys
        #[arg(short, long, default_value = "certs")]
        dir: PathBuf,
        /// Generate master server certificate
        #[arg(long)]
        master: bool,
        /// Generate slave client certificate
        #[arg(long)]
        slave: bool,
    },
}

/// Executes the `check-config` subcommand.
pub fn run_check_config(path: &Path) -> Result<(), anyhow::Error> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read configuration file '{}': {}",
            path.display(),
            e
        )
    })?;

    let config = Config::from_toml_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Configuration validation failed for '{}': {}",
            path.display(),
            e
        )
    })?;

    if let Some(ref clients_val) = config.clients {
        let _: sito_clients::ClientsConfig = clients_val.clone().try_into().map_err(|e| {
            anyhow::anyhow!(
                "Clients configuration validation failed for '{}': {}",
                path.display(),
                e
            )
        })?;
    }

    if let Some(ref rewrites_val) = config.rewrites {
        let _: sito_rewrites::RewritesConfig = rewrites_val.clone().try_into().map_err(|e| {
            anyhow::anyhow!(
                "Rewrites configuration validation failed for '{}': {}",
                path.display(),
                e
            )
        })?;
    }

    if let Some(tls) = config.get_tls_config() {
        if let (Some(cert_path), Some(key_path)) = (&tls.cert, &tls.key) {
            sito_transport::load_certificates(cert_path).map_err(|e| {
                anyhow::anyhow!(
                    "TLS certificate verification failed for '{}': {}",
                    cert_path.display(),
                    e
                )
            })?;
            sito_transport::load_private_key(key_path).map_err(|e| {
                anyhow::anyhow!(
                    "TLS private key verification failed for '{}': {}",
                    key_path.display(),
                    e
                )
            })?;
        }
        for sni in &tls.sni_certs {
            sito_transport::load_certificates(&sni.cert).map_err(|e| {
                anyhow::anyhow!(
                    "SNI TLS certificate verification failed for '{}' (domain '{}'): {}",
                    sni.cert.display(),
                    sni.domain,
                    e
                )
            })?;
            sito_transport::load_private_key(&sni.key).map_err(|e| {
                anyhow::anyhow!(
                    "SNI TLS private key verification failed for '{}' (domain '{}'): {}",
                    sni.key.display(),
                    sni.domain,
                    e
                )
            })?;
        }
    }

    println!(
        "Configuration file '{}' is valid (listening on port {}, {} upstreams, {} blocklists configured).",
        path.display(),
        config.dns.port,
        config.upstream.servers.len(),
        config.filtering.lists.len()
    );

    Ok(())
}

/// Executes the `healthcheck` subcommand by sending a test DNS query.
pub async fn run_healthcheck(addr: SocketAddr, timeout_ms: u64) -> Result<(), anyhow::Error> {
    probe_dns(addr, timeout_ms).await
}

/// Healthcheck that also accepts a reachable admin web interface as healthy.
///
/// This keeps container healthchecks green while the first-run setup wizard is
/// active (DNS listeners are intentionally unbound until setup completes).
pub async fn run_healthcheck_or_web(
    dns_addr: Option<SocketAddr>,
    web_addr: SocketAddr,
    timeout_ms: u64,
) -> Result<(), anyhow::Error> {
    let dns_error = if let Some(addr) = dns_addr {
        match probe_dns(addr, timeout_ms).await {
            Ok(()) => return Ok(()),
            Err(e) => Some(e),
        }
    } else {
        None
    };

    let connect = tokio::time::timeout(
        Duration::from_millis(timeout_ms),
        tokio::net::TcpStream::connect(web_addr),
    );
    if let Ok(Ok(_stream)) = connect.await {
        if let Some(e) = dns_error {
            println!(
                "Healthcheck OK: DNS probe failed ({e}), but admin web interface {web_addr} is reachable (likely setup wizard mode)"
            );
        } else {
            println!("Healthcheck OK: admin web interface {web_addr} is reachable");
        }
        return Ok(());
    }

    match dns_error {
        Some(e) => Err(e),
        None => Err(anyhow::anyhow!(
            "Healthcheck failed: neither DNS nor the admin web interface at {web_addr} responded within {timeout_ms}ms"
        )),
    }
}

async fn probe_dns(addr: SocketAddr, timeout_ms: u64) -> Result<(), anyhow::Error> {
    let bind_addr = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
    socket.connect(addr).await?;

    let mut query = Message::new(0x4242, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    let qname = Name::from_str("localhost.")?;
    query.queries.push(Query::query(qname, RecordType::A));

    let wire = sito_proto::encode_message(&query)?;
    let start = std::time::Instant::now();
    socket.send(&wire).await?;

    let mut buf = [0u8; 512];
    let len = tokio::time::timeout(Duration::from_millis(timeout_ms), socket.recv(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("Healthcheck timed out after {timeout_ms}ms"))??;

    let resp = sito_proto::decode_message(&buf[..len])?;
    let elapsed = start.elapsed();

    if resp.metadata.id != 0x4242 {
        anyhow::bail!(
            "Healthcheck failed: response ID mismatch (expected 0x4242, got {:#06x})",
            resp.metadata.id
        );
    }
    if resp.metadata.message_type != MessageType::Response {
        anyhow::bail!("Healthcheck failed: received a non-response DNS message");
    }
    match resp.metadata.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => {}
        other => {
            anyhow::bail!("Healthcheck failed: resolver returned {other:?}");
        }
    }

    println!(
        "Healthcheck OK: received response (id: {}, rcode: {:?}) in {:?}",
        resp.metadata.id, resp.metadata.response_code, elapsed
    );

    Ok(())
}

/// Executes the `backup` subcommand.
pub fn run_backup(config_path: &Path, output: Option<&Path>) -> Result<PathBuf, anyhow::Error> {
    let content = std::fs::read_to_string(config_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read configuration file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    // Pre-validate before backing up
    Config::from_toml_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Configuration validation failed for '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let archive_bytes = sito_api::handlers::config::create_backup_archive(&content)?;

    let out_path = if let Some(p) = output {
        p.to_path_buf()
    } else {
        PathBuf::from(format!(
            "sito-backup-{}.tar.gz",
            chrono::Utc::now().format("%Y%m%d%H%M%S")
        ))
    };

    std::fs::write(&out_path, archive_bytes)?;
    println!(
        "Backup successfully created at '{}' from '{}'",
        out_path.display(),
        config_path.display()
    );
    Ok(out_path)
}

/// Executes the `restore` subcommand.
pub fn run_restore(
    archive_path: &Path,
    target_config_path: &Path,
    force: bool,
) -> Result<(), anyhow::Error> {
    if target_config_path.exists() && !force {
        anyhow::bail!(
            "Target config file '{}' already exists. Use --force to overwrite.",
            target_config_path.display()
        );
    }

    let archive_bytes = std::fs::read(archive_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read backup archive '{}': {}",
            archive_path.display(),
            e
        )
    })?;

    let (config_toml, metadata) =
        sito_api::handlers::config::extract_backup_archive(&archive_bytes)?;

    // Atomic write to destination
    let tmp_path = target_config_path.with_extension("tmp");
    std::fs::write(&tmp_path, &config_toml)?;
    std::fs::rename(&tmp_path, target_config_path)?;

    println!(
        "Successfully restored configuration (sito version: {}, backup timestamp: {}) to '{}'",
        metadata.sito_version,
        metadata.timestamp,
        target_config_path.display()
    );
    Ok(())
}

/// Executes the `ha gen-certs` subcommand.
pub fn run_ha_gen_certs(dir: &Path, master: bool, slave: bool) -> Result<(), anyhow::Error> {
    let certs = sito_ha::generate_ha_certs(dir, master, slave)
        .map_err(|e| anyhow::anyhow!("Failed to generate HA certificates: {e}"))?;
    print!("{}", certs.summary());
    Ok(())
}

/// Executes the `update` subcommand.
pub async fn run_update(
    check: bool,
    force: bool,
    repo: Option<&str>,
    config_path: &Path,
) -> Result<(), anyhow::Error> {
    println!("Checking for updates...");
    let info = sito_api::updater::check_for_update(repo)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check for updates: {e}"))?;

    println!("Current version : v{}", info.current_version);
    println!("Latest version  : v{}", info.latest_version);

    if info.is_docker {
        println!("\nNotice: Running inside a Docker container.");
        if let Some(instructions) = &info.instructions {
            println!("{instructions}");
        }
        return Ok(());
    }

    if !info.update_available && !force {
        println!("\nsito is up to date.");
        return Ok(());
    }

    if check {
        if info.update_available {
            println!("\nA new version is available! Run 'sito update' to install.");
            println!("Release URL: {}", info.release_url);
            println!("\nRelease Notes:\n{}", info.release_notes);
        }
        return Ok(());
    }

    println!("\nApplying update to v{}...", info.latest_version);
    let require_signature = std::fs::read_to_string(config_path)
        .ok()
        .and_then(|content| Config::from_toml_str(&content).ok())
        .is_some_and(|cfg| cfg.server.update_require_signature);
    if require_signature {
        println!("Signature verification is required by configuration.");
    }
    let msg = sito_api::updater::apply_update(repo, force, require_signature)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to apply update: {e}"))?;

    println!("{msg}");
    Ok(())
}

/// Executes the `reset-admin` subcommand.
pub fn run_reset_admin(config_path: &Path, password: Option<&str>) -> Result<(), anyhow::Error> {
    let content = std::fs::read_to_string(config_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read configuration file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let config = Config::from_toml_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Configuration validation failed for '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let pass = password.unwrap_or("adminadmin");
    let users_path = sito_api::AuthManager::reset_admin_credentials(&config.server.data_dir, pass)
        .map_err(|e| anyhow::anyhow!("Failed to reset admin credentials: {e}"))?;

    println!(
        "Administrative credentials successfully reset in '{}'.\nUsername: admin",
        users_path.display()
    );
    if password.is_none() {
        println!(
            "Password: adminadmin (Warning: Please change this default password upon logging in!)"
        );
    } else {
        println!("Password: (custom password set)");
    }

    Ok(())
}

/// Executes the `reset-sessions` subcommand: removes persisted sessions and API tokens.
pub fn run_reset_sessions(config_path: &Path) -> Result<(), anyhow::Error> {
    let content = std::fs::read_to_string(config_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to read configuration file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let config = Config::from_toml_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Configuration validation failed for '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let data_dir = &config.server.data_dir;
    let mut removed = 0;
    for name in ["sessions.toml", "tokens.toml"] {
        let path = data_dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| anyhow::anyhow!("Failed to remove '{}': {e}", path.display()))?;
            removed += 1;
            println!("Removed {}", path.display());
        }
    }

    if removed == 0 {
        println!(
            "No persisted sessions or tokens found in '{}'.",
            data_dir.display()
        );
    } else {
        println!("All web sessions and API tokens have been invalidated.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_no_setup_flag() {
        let args_no_setup = vec!["sito", "--no-setup"];
        let cli = Cli::try_parse_from(args_no_setup).expect("parse args");
        assert!(cli.no_setup);
        assert_eq!(cli.config, PathBuf::from("config.toml"));

        let args_default = vec!["sito"];
        let cli_default = Cli::try_parse_from(args_default).expect("parse args");
        assert!(!cli_default.no_setup);

        let args_custom = vec!["sito", "--config", "/etc/sito/custom.toml", "--no-setup"];
        let cli_custom = Cli::try_parse_from(args_custom).expect("parse args");
        assert!(cli_custom.no_setup);
        assert_eq!(cli_custom.config, PathBuf::from("/etc/sito/custom.toml"));
    }
}
