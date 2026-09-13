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
        /// Accept the admin web interface as healthy only while the server
        /// reports first-boot setup pending (DNS listeners are not bound yet).
        /// Disabled by default: without a confirmed setup-pending status a
        /// failed DNS probe stays a failure.
        #[arg(long)]
        setup_fallback: bool,
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
        /// Additional subject alternative name for the generated certificates
        /// (hostname or IP address). Repeatable.
        #[arg(long = "san", value_name = "HOST_OR_IP", action = clap::ArgAction::Append)]
        san: Vec<String>,
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

    // Validate every remaining TOML-valued section (web/auth/stats/ha/
    // integrations) so check-config catches what startup would reject.
    crate::server::validate_typed_sections(&config).map_err(|e| {
        anyhow::anyhow!(
            "Configuration validation failed for '{}': {}",
            path.display(),
            e
        )
    })?;

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

/// Healthcheck that may accept the admin web interface while the server is
/// still in first-boot setup-pending mode.
///
/// The web fallback is only considered when `setup_fallback` is enabled and
/// the admin API explicitly reports that setup is pending. Once setup has
/// completed (or when the API cannot confirm setup-pending), a failing DNS
/// probe stays a healthcheck failure so a broken DNS listener is never masked.
pub async fn run_healthcheck_or_web(
    dns_addr: Option<SocketAddr>,
    web_addr: SocketAddr,
    timeout_ms: u64,
    setup_fallback: bool,
) -> Result<(), anyhow::Error> {
    let dns_error = if let Some(addr) = dns_addr {
        match probe_dns(addr, timeout_ms).await {
            Ok(()) => return Ok(()),
            Err(e) => Some(e),
        }
    } else {
        None
    };

    if !setup_fallback {
        return Err(dns_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "Healthcheck failed: no DNS target is configured and the setup web fallback is disabled"
            )
        }));
    }

    match probe_setup_pending(web_addr, timeout_ms).await {
        Ok(true) => {
            if let Some(e) = &dns_error {
                println!(
                    "Healthcheck OK: DNS probe failed ({e}), but admin web interface {web_addr} reports setup pending"
                );
            } else {
                println!("Healthcheck OK: admin web interface {web_addr} reports setup pending");
            }
            Ok(())
        }
        Ok(false) => Err(dns_error.unwrap_or_else(|| {
            anyhow::anyhow!(
                "Healthcheck failed: admin web interface {web_addr} is not reporting setup pending"
            )
        })),
        Err(status_error) => Err(match dns_error {
            Some(dns_err) => dns_err.context(format!(
                "setup status check against {web_addr} failed: {status_error}"
            )),
            None => status_error,
        }),
    }
}

/// Reports whether the admin API is in first-boot setup-pending mode.
///
/// `/health` and `/status` are preferred when they expose a JSON
/// `setup_pending` boolean. Otherwise the setup-gating middleware signal is
/// used: while setup is pending, `/api/v1/*` is short-circuited with
/// `503 Setup not completed`; once an admin account exists the normal auth
/// layer answers instead (typically `401`).
async fn probe_setup_pending(web_addr: SocketAddr, timeout_ms: u64) -> Result<bool, anyhow::Error> {
    for path in ["/health", "/status"] {
        if let Ok((200, body)) = http_get(web_addr, path, timeout_ms).await
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&body)
            && let Some(pending) = value
                .get("setup_pending")
                .and_then(serde_json::Value::as_bool)
        {
            return Ok(pending);
        }
    }

    match http_get(web_addr, "/api/v1/status", timeout_ms).await {
        Ok((503, body)) if body.contains("Setup not completed") => Ok(true),
        Ok(_) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Minimal HTTP/1.1 `GET` helper used only for setup-pending detection.
///
/// Uses a raw TCP stream to avoid adding a full HTTP client dependency to the
/// server binary. Responses are capped and parsed loosely; the caller only
/// relies on the status code and a substring of the body.
async fn http_get(
    addr: SocketAddr,
    path: &str,
    timeout_ms: u64,
) -> Result<(u16, String), anyhow::Error> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let timeout = Duration::from_millis(timeout_ms);
    let mut stream = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("timed out connecting to {addr}"))??;

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    tokio::time::timeout(timeout, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| anyhow::anyhow!("timed out sending request to {addr}"))??;

    let mut response = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    loop {
        let read = tokio::time::timeout(timeout, stream.read(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("timed out reading response from {addr}"))??;
        if read == 0 {
            break;
        }
        response.extend_from_slice(&buf[..read]);
        if response.len() > 64 * 1024 {
            break;
        }
    }

    let text = String::from_utf8_lossy(&response);
    let status_line = text
        .split("\r\n")
        .next()
        .ok_or_else(|| anyhow::anyhow!("empty HTTP response from {addr}"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP status line from {addr}: {status_line}"))?;
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or_default()
        .to_string();
    Ok((status, body))
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
    if resp.metadata.response_code != ResponseCode::NoError {
        anyhow::bail!(
            "Healthcheck failed: resolver returned {:?} (expected NOERROR)",
            resp.metadata.response_code
        );
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
pub fn run_ha_gen_certs(
    dir: &Path,
    master: bool,
    slave: bool,
    san: &[String],
) -> Result<(), anyhow::Error> {
    let certs = sito_ha::generate_ha_certs_with_sans(dir, master, slave, san)
        .map_err(|e| anyhow::anyhow!("Failed to generate HA certificates: {e}"))?;
    print!("{}", certs.summary());
    Ok(())
}

/// Reads the update signature policy from `config_path`.
///
/// Fails closed: an unreadable or invalid configuration is an error, because
/// falling back to `checksum-only` would silently disable signature
/// enforcement on a host that had it enabled.
fn update_signature_policy(config_path: &Path) -> Result<bool, anyhow::Error> {
    let content = std::fs::read_to_string(config_path).map_err(|e| {
        anyhow::anyhow!(
            "Refusing to update: cannot read configuration '{}' to determine the signature policy: {e}",
            config_path.display()
        )
    })?;
    let cfg = Config::from_toml_str(&content).map_err(|e| {
        anyhow::anyhow!(
            "Refusing to update: configuration '{}' is invalid: {e}",
            config_path.display()
        )
    })?;
    Ok(cfg.server.update_require_signature)
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
    // Fail closed: if the configuration cannot be read or parsed we cannot
    // know whether signatures are required, so refuse instead of silently
    // downgrading to checksum-only verification.
    let require_signature = update_signature_policy(config_path)?;
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

    #[test]
    fn test_update_signature_policy_fails_closed() {
        let dir = std::env::temp_dir().join(format!("sito_update_policy_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Missing config: refuse instead of silently disabling signatures.
        let missing = dir.join("missing.toml");
        assert!(update_signature_policy(&missing).is_err());

        // Invalid config: refuse.
        let invalid = dir.join("invalid.toml");
        std::fs::write(&invalid, "not = [valid").unwrap();
        assert!(update_signature_policy(&invalid).is_err());

        // Default config enables the requirement.
        let default_cfg = dir.join("default.toml");
        std::fs::write(&default_cfg, "config_version = 1\n").unwrap();
        assert!(update_signature_policy(&default_cfg).unwrap());

        // Explicit opt-out is honored.
        let opt_out = dir.join("opt_out.toml");
        std::fs::write(
            &opt_out,
            "config_version = 1\n[server]\nupdate_require_signature = false\n",
        )
        .unwrap();
        assert!(!update_signature_policy(&opt_out).unwrap());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cli_healthcheck_setup_fallback_defaults_off() {
        let cli = Cli::try_parse_from(["sito", "healthcheck"]).expect("parse args");
        match cli.command {
            Some(Commands::Healthcheck { setup_fallback, .. }) => assert!(!setup_fallback),
            other => panic!("expected healthcheck command, got {other:?}"),
        }

        let cli =
            Cli::try_parse_from(["sito", "healthcheck", "--setup-fallback"]).expect("parse args");
        match cli.command {
            Some(Commands::Healthcheck { setup_fallback, .. }) => assert!(setup_fallback),
            other => panic!("expected healthcheck command, got {other:?}"),
        }
    }

    /// Single-shot UDP responder that echoes a pre-built DNS message.
    async fn spawn_udp_responder(response: Message) -> SocketAddr {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind responder");
        let addr = socket.local_addr().expect("responder addr");
        let wire = sito_proto::encode_message(&response).expect("encode response");
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((_, peer)) = socket.recv_from(&mut buf).await {
                let _ = socket.send_to(&wire, peer).await;
            }
        });
        addr
    }

    fn dns_response(id: u16, rcode: ResponseCode) -> Message {
        let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
        resp.metadata.response_code = rcode;
        resp
    }

    /// Held-open UDP socket that never answers, forcing a deterministic timeout.
    async fn spawn_silent_udp() -> (SocketAddr, tokio::net::UdpSocket) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind silent socket");
        let addr = socket.local_addr().expect("silent addr");
        (addr, socket)
    }

    /// Minimal HTTP responder keyed by request path.
    async fn spawn_http_router(routes: Vec<(&'static str, u16, &'static str)>) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind http responder");
        let addr = listener.local_addr().expect("http responder addr");
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let Ok(read) = stream.read(&mut buf).await else {
                    continue;
                };
                let request = String::from_utf8_lossy(&buf[..read]);
                let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
                let (status, body) = routes
                    .iter()
                    .find(|(route, _, _)| *route == path)
                    .map_or((404, "Not Found"), |(_, status, body)| (*status, *body));
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_probe_dns_accepts_matching_noerror_response() {
        let addr = spawn_udp_responder(dns_response(0x4242, ResponseCode::NoError)).await;
        probe_dns(addr, 2_000)
            .await
            .expect("NOERROR response with matching ID must be accepted");
    }

    #[tokio::test]
    async fn test_probe_dns_rejects_message_id_mismatch() {
        let addr = spawn_udp_responder(dns_response(0x1337, ResponseCode::NoError)).await;
        let err = probe_dns(addr, 2_000)
            .await
            .expect_err("mismatched message ID must fail");
        assert!(
            err.to_string().contains("ID mismatch"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_probe_dns_rejects_servfail() {
        let addr = spawn_udp_responder(dns_response(0x4242, ResponseCode::ServFail)).await;
        let err = probe_dns(addr, 2_000)
            .await
            .expect_err("SERVFAIL must fail the healthcheck");
        assert!(
            err.to_string().contains("ServFail"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_probe_dns_rejects_refused() {
        let addr = spawn_udp_responder(dns_response(0x4242, ResponseCode::Refused)).await;
        let err = probe_dns(addr, 2_000)
            .await
            .expect_err("REFUSED must fail the healthcheck");
        assert!(
            err.to_string().contains("Refused"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_probe_dns_rejects_nxdomain() {
        let addr = spawn_udp_responder(dns_response(0x4242, ResponseCode::NXDomain)).await;
        let err = probe_dns(addr, 2_000)
            .await
            .expect_err("only NOERROR is a healthy response");
        assert!(
            err.to_string().contains("NXDomain"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_healthcheck_without_fallback_rejects_reachable_web_only() {
        let (dns_addr, _silent) = spawn_silent_udp().await;
        let web_addr =
            spawn_http_router(vec![("/api/v1/status", 503, "Setup not completed")]).await;
        let err = run_healthcheck_or_web(Some(dns_addr), web_addr, 200, false)
            .await
            .expect_err("web reachability must not mask a broken DNS listener by default");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_healthcheck_setup_fallback_accepts_pending_health_json() {
        let (dns_addr, _silent) = spawn_silent_udp().await;
        let web_addr = spawn_http_router(vec![("/health", 200, "{\"setup_pending\": true}")]).await;
        run_healthcheck_or_web(Some(dns_addr), web_addr, 200, true)
            .await
            .expect("setup-pending web interface must satisfy the setup fallback");
    }

    #[tokio::test]
    async fn test_healthcheck_setup_fallback_accepts_503_middleware_signal() {
        let (dns_addr, _silent) = spawn_silent_udp().await;
        let web_addr =
            spawn_http_router(vec![("/api/v1/status", 503, "Setup not completed")]).await;
        run_healthcheck_or_web(Some(dns_addr), web_addr, 200, true)
            .await
            .expect("503 setup-pending signal must satisfy the setup fallback");
    }

    #[tokio::test]
    async fn test_healthcheck_setup_fallback_rejects_completed_setup() {
        let (dns_addr, _silent) = spawn_silent_udp().await;
        let web_addr = spawn_http_router(vec![("/api/v1/status", 401, "Unauthorized")]).await;
        let err = run_healthcheck_or_web(Some(dns_addr), web_addr, 200, true)
            .await
            .expect_err("completed setup must not mask a broken DNS listener");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }
}
