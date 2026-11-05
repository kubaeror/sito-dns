//! CLI arguments and subcommand execution for sito.

use clap::{Parser, Subcommand};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use rand::RngExt;
use sito_core::config::Config;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

/// Conventional system-wide configuration path used by packages and the
/// systemd unit.
pub const SYSTEM_CONFIG_PATH: &str = "/etc/sito/config.toml";

/// Resolves the configuration path for server-side commands.
///
/// `--config` always wins. Otherwise an existing `./config.toml` (development
/// and manual installs) is preferred, then the system path. When neither
/// exists the relative default is returned so first-boot setup can create it;
/// commands that must fail closed use [`resolve_update_config_path`] instead.
pub fn resolve_config_path(explicit: Option<&Path>) -> PathBuf {
    resolve_config_path_from(
        explicit,
        Path::new("config.toml"),
        Path::new(SYSTEM_CONFIG_PATH),
    )
}

fn resolve_config_path_from(explicit: Option<&Path>, local: &Path, system: &Path) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if local.is_file() {
        return local.to_path_buf();
    }
    if system.is_file() {
        return system.to_path_buf();
    }
    local.to_path_buf()
}

/// Resolves the configuration path for `sito update`, which cannot run without
/// knowing the persisted signature policy.
///
/// An existing `/etc/sito/config.toml` is preferred over `./config.toml`
/// because updates are usually run as root from an arbitrary cwd.
pub fn resolve_update_config_path(explicit: Option<&Path>) -> Result<PathBuf, anyhow::Error> {
    resolve_update_config_path_from(
        explicit,
        Path::new("config.toml"),
        Path::new(SYSTEM_CONFIG_PATH),
    )
}

fn resolve_update_config_path_from(
    explicit: Option<&Path>,
    local: &Path,
    system: &Path,
) -> Result<PathBuf, anyhow::Error> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    // A system configuration wins over a relative file for updates: the
    // operator may run the command from any cwd after stopping the service,
    // and a stray ./config.toml must not silently change the signature policy.
    if system.is_file() {
        return Ok(system.to_path_buf());
    }
    if local.is_file() {
        return Ok(local.to_path_buf());
    }
    Err(anyhow::anyhow!(
        "Refusing to update: no configuration file found at '{}' or '{}'. Pass --config <path> to choose the configuration explicitly (system installs use {}).",
        system.display(),
        local.display(),
        SYSTEM_CONFIG_PATH
    ))
}

#[derive(Parser, Debug)]
#[command(
    name = "sito",
    author,
    version,
    about = "High-performance, self-hosted, filtering DNS server"
)]
pub struct Cli {
    /// Path to configuration file (default: ./config.toml when present, then
    /// /etc/sito/config.toml)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Skip web-based setup wizard gating and start with defaults immediately
    #[arg(long)]
    pub no_setup: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

impl Cli {
    /// Configuration path after applying an explicit `--config` or
    /// auto-detection (see [`resolve_config_path`]).
    pub fn config_path(&self) -> PathBuf {
        resolve_config_path(self.config.as_deref())
    }
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
        /// New admin password (a random one is generated and printed once when omitted)
        #[arg(short, long)]
        password: Option<String>,
        /// Also delete every non-admin account (full account-store replacement)
        #[arg(long = "reset-all", alias = "reset-users")]
        reset_all: bool,
        /// Allow the reset while sito is running. The running server keeps its
        /// in-memory credentials/sessions until it is restarted.
        #[arg(long)]
        force: bool,
    },
    /// Invalidate all persisted web sessions and API tokens (users are kept)
    ResetSessions {
        /// Optional path to configuration file (defaults to main --config)
        #[arg(short, long)]
        config: Option<PathBuf>,
        /// Allow the reset while sito is running. Live sessions and API tokens
        /// stay valid until the running server is restarted.
        #[arg(long)]
        force: bool,
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
        /// Transfer the generated certificates and private keys to this uid.
        /// Requires --gid. Use the runtime user (for example 65532 in the
        /// container image) so an unprivileged daemon can read its key.
        #[arg(long, requires = "gid", value_name = "UID")]
        uid: Option<u32>,
        /// Transfer the generated certificates and private keys to this gid.
        /// Requires --uid.
        #[arg(long, requires = "uid", value_name = "GID")]
        gid: Option<u32>,
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

/// Whether the configuration makes HA replication part of this node's role.
///
/// Mirrors the server's readiness gate so the healthcheck fails closed only
/// when `[ha]` is actually part of the deployment.
#[must_use]
pub fn ha_readiness_required(config: &Config) -> bool {
    sito_api::state::ha_readiness_required(config)
}

/// Healthcheck that may accept the admin web interface while the server is
/// still in first-boot setup-pending mode.
///
/// The web fallback is only considered when `setup_fallback` is enabled and
/// the admin API explicitly reports that setup is pending. Once setup has
/// completed (or when the API cannot confirm setup-pending), a failing DNS
/// probe stays a healthcheck failure so a broken DNS listener is never masked.
///
/// When `ha_required` is set, a successful DNS probe is not sufficient: the
/// `/health` endpoint must also report the HA role as ready. This keeps a
/// failed mTLS listener or a slave that never completed its handshake from
/// looking healthy just because DNS still answers.
pub async fn run_healthcheck_or_web(
    dns_addr: Option<SocketAddr>,
    web_addr: SocketAddr,
    timeout_ms: u64,
    setup_fallback: bool,
    ha_required: bool,
) -> Result<(), anyhow::Error> {
    let dns_error = if let Some(addr) = dns_addr {
        probe_dns(addr, timeout_ms).await.err()
    } else {
        Some(anyhow::anyhow!(
            "Healthcheck failed: no DNS target is configured and the setup web fallback is disabled"
        ))
    };

    let mut setup_pending_note = None;
    if let Some(dns_error) = dns_error {
        if !setup_fallback {
            return Err(dns_error);
        }

        match probe_setup_pending(web_addr, timeout_ms).await {
            Ok(true) => {
                setup_pending_note = Some(format!(
                    "Healthcheck OK: DNS probe failed ({dns_error}), but admin web interface {web_addr} reports setup pending"
                ));
            }
            Ok(false) => return Err(dns_error),
            Err(status_error) => {
                return Err(dns_error.context(format!(
                    "setup status check against {web_addr} failed: {status_error}"
                )));
            }
        }
    }

    if ha_required {
        probe_ha_readiness(web_addr, timeout_ms).await?;
    }
    if let Some(note) = setup_pending_note {
        println!("{note}");
    }
    Ok(())
}

/// Verifies the HA readiness reported by the public `/health` endpoint.
///
/// Any inability to obtain a definitive answer fails closed: an unreachable
/// web API or a payload without the `ha` object is an error, not a pass.
async fn probe_ha_readiness(web_addr: SocketAddr, timeout_ms: u64) -> Result<(), anyhow::Error> {
    let (status, body) = http_get(web_addr, "/health", timeout_ms)
        .await
        .map_err(|e| anyhow::anyhow!("cannot verify HA readiness from {web_addr}/health: {e}"))?;
    if status != 200 {
        return Err(anyhow::anyhow!(
            "cannot verify HA readiness: {web_addr}/health returned HTTP {status}"
        ));
    }
    let value: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
        anyhow::anyhow!("invalid HA readiness response from {web_addr}/health: {e}")
    })?;
    let ha = value.get("ha").ok_or_else(|| {
        anyhow::anyhow!(
            "cannot verify HA readiness: {web_addr}/health does not expose the HA readiness signal"
        )
    })?;
    if !ha
        .get("required")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(anyhow::anyhow!(
            "cannot verify HA readiness: {web_addr}/health does not report the configured HA role as required"
        ));
    }
    let ready = ha
        .get("ready")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot verify HA readiness: {web_addr}/health has no boolean `ha.ready` field"
            )
        })?;
    if ready {
        return Ok(());
    }
    // Deliberately ignore any server-provided detail: this message is printed
    // into container logs from a public probe. Operators get the detailed
    // cause from the authenticated `/api/v1/ha/status` endpoint or the logs.
    Err(anyhow::anyhow!(
        "Healthcheck failed: HA replication is not ready (see /api/v1/ha/status or the server logs for the reason)"
    ))
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

/// Creates or replaces a file with owner-only (0600) permissions and fsyncs it.
fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), anyhow::Error> {
    use std::io::Write;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    // `mode` only applies on creation: repair the permissions of a
    // pre-existing world-readable file we are overwriting.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

/// fsyncs the parent directory so a rename is durable.
fn fsync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
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

    // Backups contain configuration secrets (HA tokens, client secrets): the
    // file must never be group/world readable.
    write_private_file(&out_path, &archive_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to write backup '{}': {e}", out_path.display()))?;
    fsync_parent_dir(&out_path);
    println!(
        "Backup successfully created at '{}' from '{}' (mode 0600)",
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

    // Write a 0600 temporary sibling, fsync it, then atomically rename it into
    // place and fsync the directory.
    let tmp_path = target_config_path.with_extension("tmp");
    write_private_file(&tmp_path, config_toml.as_bytes()).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write temporary restore file '{}': {e}",
            tmp_path.display()
        )
    })?;
    std::fs::rename(&tmp_path, target_config_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ =
            std::fs::set_permissions(target_config_path, std::fs::Permissions::from_mode(0o600));
    }
    fsync_parent_dir(target_config_path);

    println!(
        "Successfully restored configuration (sito version: {}, backup timestamp: {}) to '{}' (mode 0600)",
        metadata.sito_version,
        metadata.timestamp,
        target_config_path.display()
    );
    Ok(())
}

/// Resolves the healthcheck DNS and web targets from a configuration.
///
/// A wildcard listener bind cannot be probed directly, so the target falls back
/// to loopback: `127.0.0.1` is preferred because it is the first loopback
/// address available on every dual-stack host, while `::1` is only used when
/// the configuration binds IPv6 addresses exclusively.
#[must_use]
pub fn healthcheck_targets_from_config(config: &Config) -> (SocketAddr, SocketAddr) {
    let bind_ip = config
        .dns
        .bind
        .iter()
        .find(|ip| !ip.is_unspecified())
        .copied()
        .unwrap_or_else(|| {
            if config.dns.bind.iter().any(std::net::IpAddr::is_ipv4) {
                "127.0.0.1".parse().expect("valid loopback")
            } else {
                "::1".parse().expect("valid ipv6 loopback")
            }
        });
    let web_cfg = config.get_web_config();
    let web_ip = if web_cfg.bind.is_unspecified() {
        "127.0.0.1".parse().expect("valid loopback")
    } else {
        web_cfg.bind
    };
    (
        SocketAddr::new(bind_ip, config.dns.port),
        SocketAddr::new(web_ip, web_cfg.port),
    )
}

/// Outcome of preparing the `--no-setup` first boot with no configuration file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoSetupBootstrap {
    /// A configuration file exists; nothing to prepare.
    NotNeeded,
    /// A random admin password was generated and must be shown exactly once.
    GeneratedPassword(String),
    /// Node-local credentials already exist and were deliberately kept; the
    /// admin UI is loopback-bound but no password was generated.
    KeptExistingUsers,
}

/// Prepares the insecure `--no-setup` first boot with no configuration file.
///
/// Without a config the built-in defaults would bootstrap `admin/adminadmin`
/// on `0.0.0.0`. Instead the admin UI is bound to loopback. When no users
/// exist, a random admin password is generated and written to `users.toml`
/// (0600) for the caller to print once. When `users.toml` already exists the
/// stored credentials are kept untouched (use `sito reset-admin` to rotate
/// them deliberately).
pub fn prepare_no_setup_bootstrap(
    config_path: &Path,
    config: &mut Config,
) -> Result<NoSetupBootstrap, anyhow::Error> {
    if config_path.exists() {
        return Ok(NoSetupBootstrap::NotNeeded);
    }

    // Bind the admin UI to loopback: the random password protects against
    // credential guessing, loopback binding against network exposure.
    let mut web = config.get_web_config();
    if web.bind.is_unspecified() {
        web.bind = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    }
    config.set_web_config(web);

    // Never silently rotate credentials that already exist on this node.
    if config.server.data_dir.join("users.toml").exists() {
        return Ok(NoSetupBootstrap::KeptExistingUsers);
    }

    let mut bytes = [0u8; 24];
    rand::rng().fill(&mut bytes);
    let mut password = String::with_capacity(48);
    for byte in &bytes {
        let _ = std::fmt::Write::write_fmt(&mut password, format_args!("{byte:02x}"));
    }
    sito_api::AuthManager::reset_admin_credentials(&config.server.data_dir, &password).map_err(
        |e| {
            anyhow::anyhow!(
                "Refusing to start with built-in defaults: failed to write the random admin \
                 credentials to '{}': {e}",
                config.server.data_dir.display()
            )
        },
    )?;
    Ok(NoSetupBootstrap::GeneratedPassword(password))
}

/// Executes the `ha gen-certs` subcommand.
///
/// `uid`/`gid` transfer every generated certificate and private key to the
/// unprivileged HA runtime user. They must be provided together; clap enforces
/// this for the CLI and the check below covers programmatic callers.
pub fn run_ha_gen_certs(
    dir: &Path,
    master: bool,
    slave: bool,
    san: &[String],
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), anyhow::Error> {
    let ownership = match (uid, gid) {
        (Some(uid), Some(gid)) => Some(sito_ha::CertOwnership { uid, gid }),
        (None, None) => None,
        _ => {
            return Err(anyhow::anyhow!(
                "--uid and --gid must be provided together so the generated keys are usable by exactly one runtime identity"
            ));
        }
    };

    let certs = sito_ha::generate_ha_certs_with_options(dir, master, slave, san, ownership)
        .map_err(|e| anyhow::anyhow!("Failed to generate HA certificates: {e}"))?;
    print!("{}", certs.summary());
    if let Some(owner) = ownership {
        println!(
            "Certificate files are owned by {}:{}; private keys remain mode 0600.",
            owner.uid, owner.gid
        );
    }
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
    config_path: Option<&Path>,
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

    // Fail closed: if the configuration cannot be found/read or parsed we
    // cannot know whether signatures are required, so refuse instead of
    // silently downgrading to checksum-only verification. Resolving here also
    // means `sudo sito update` works from any cwd after the service is stopped.
    let config_path = resolve_update_config_path(config_path)?;
    let require_signature = update_signature_policy(&config_path)?;

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
    if require_signature {
        println!("Signature verification is required by configuration.");
    }
    let msg = sito_api::updater::apply_update(repo, force, require_signature)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to apply update: {e}"))?;

    println!("{msg}");
    Ok(())
}

/// Formats the PID of the process currently holding the service lease.
fn lease_holder(pid: Option<u32>) -> String {
    pid.map_or_else(|| "a live process".to_string(), |pid| format!("pid {pid}"))
}

/// Data-directory access held for the whole duration of a reset.
///
/// When the service is stopped the CLI owns the service lease until this value
/// is dropped. That closes the check-then-write race: a server started by a
/// supervisor or by `systemctl start` cannot acquire the lease and start serving
/// stale in-memory state between the run check and the disk writes. When the
/// operator forced a reset on a live server, no exclusive lease is possible and
/// callers must print the persisted-only warning.
#[derive(Debug)]
enum ResetAccess {
    Stopped {
        _lease: crate::service_lock::ServiceLease,
    },
    Running {
        pid: Option<u32>,
    },
}

impl ResetAccess {
    fn is_running(&self) -> bool {
        matches!(self, Self::Running { .. })
    }
}

/// Acquires reset access, refusing a live service unless `--force` was given.
///
/// Acquisition *is* the run check. If the lease was free we hold it through the
/// reset; if it was held we know a server is live. `force_hint` is the
/// command-specific consequence of using `--force`, so the refusals do not
/// mention unrelated credentials.
fn begin_reset(
    data_dir: &Path,
    action: &str,
    force: bool,
    force_hint: &str,
) -> Result<ResetAccess, anyhow::Error> {
    match crate::service_lock::ServiceLease::acquire(data_dir) {
        Ok(lease) => Ok(ResetAccess::Stopped { _lease: lease }),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            // The lease is held, so a server was live. Read the PID only to
            // make the message useful; it cannot change the verdict.
            let pid = match crate::service_lock::status(data_dir) {
                Ok(crate::service_lock::ServiceStatus::Running { pid }) => pid,
                _ => None,
            };
            if force {
                Ok(ResetAccess::Running { pid })
            } else {
                Err(anyhow::anyhow!(
                    "Refusing to {action} while sito is running ({}).\n\
                     Stop the service first:\n  sudo systemctl stop sito\n\
                     Then run this command again and start it:\n  sudo systemctl start sito\n\
                     {force_hint}",
                    lease_holder(pid)
                ))
            }
        }
        Err(e) => Err(anyhow::anyhow!(
            "Refusing to {action}: cannot acquire the service lease in '{}': {e}",
            data_dir.display()
        )),
    }
}

const ADMIN_FORCE_HINT: &str = "Use --force only if you understand that existing web sessions and API \
     tokens remain valid until the service is restarted and that the new admin password is not \
     accepted until then.";
const SESSIONS_FORCE_HINT: &str = "Use --force only if you understand that existing web sessions and \
     API tokens remain valid until the service is restarted.";

const ADMIN_LIVE_STATE: &str = "Existing web sessions and API tokens remain valid, and the running \
     server still accepts the old admin password and rejects the new one";
const SESSIONS_LIVE_STATE: &str = "Existing web sessions and API tokens remain valid";

/// Warning printed by `--force` when the server is still running.
fn running_service_warning(pid: Option<u32>, live_state: &str) -> String {
    format!(
        "WARNING: sito is still running ({}). This command changed persisted files only; \
         the running server keeps its in-memory state. {live_state} until the service is \
         restarted. Restart it now:\n  sudo systemctl stop sito\n  sudo systemctl start sito",
        lease_holder(pid)
    )
}

/// Outcome of `reset-admin`, including a generated password so callers can
/// print it exactly once without persisting it anywhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetAdminOutcome {
    pub users_path: PathBuf,
    /// `Some` when the password was generated because none was supplied.
    pub generated_password: Option<String>,
    pub reset_all_users: bool,
}

/// Generates a 192-bit random hex password for `reset-admin`.
fn generate_reset_admin_password() -> String {
    let mut bytes = [0u8; 24];
    rand::rng().fill(&mut bytes);
    let mut password = String::with_capacity(48);
    for byte in &bytes {
        let _ = std::fmt::Write::write_fmt(&mut password, format_args!("{byte:02x}"));
    }
    password
}

/// Applies the shared API/wizard password policy to an operator-supplied
/// `reset-admin` password.
fn validate_reset_admin_password(password: &str) -> Result<(), anyhow::Error> {
    sito_api::handlers::auth_handlers::validate_password_policy(password)
        .map_err(|problem| anyhow::anyhow!("Invalid admin password: {}", problem.detail))
}

/// Executes the `reset-admin` subcommand, preserving non-admin accounts.
pub fn run_reset_admin(
    config_path: &Path,
    password: Option<&str>,
) -> Result<ResetAdminOutcome, anyhow::Error> {
    run_reset_admin_with_options(config_path, password, false, false)
}

/// Executes the `reset-admin` subcommand.
pub fn run_reset_admin_with_options(
    config_path: &Path,
    password: Option<&str>,
    reset_all_users: bool,
    force: bool,
) -> Result<ResetAdminOutcome, anyhow::Error> {
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

    // Keep the returned guard alive through the writes below.
    let access = begin_reset(
        &config.server.data_dir,
        "reset administrative credentials",
        force,
        ADMIN_FORCE_HINT,
    )?;

    let (pass, generated_password) = if let Some(password) = password {
        validate_reset_admin_password(password)?;
        (password.to_string(), None)
    } else {
        let generated = generate_reset_admin_password();
        (generated.clone(), Some(generated))
    };

    let users_path = if reset_all_users {
        sito_api::AuthManager::reset_admin_credentials_full(&config.server.data_dir, &pass)
    } else {
        sito_api::AuthManager::reset_admin_credentials(&config.server.data_dir, &pass)
    }
    .map_err(|e| anyhow::anyhow!("Failed to reset admin credentials: {e}"))?;

    if let ResetAccess::Running { pid } = &access {
        println!(
            "Administrative credentials were written to '{}'.\nUsername: admin",
            users_path.display()
        );
        println!("{}", running_service_warning(*pid, ADMIN_LIVE_STATE));
    } else {
        println!(
            "Administrative credentials successfully reset in '{}'.\nUsername: admin",
            users_path.display()
        );
    }
    if let Some(generated) = generated_password.as_deref() {
        println!("Password: {generated}");
        println!("Store this password now; it is not written anywhere else.");
    } else {
        println!("Password: (custom password set)");
    }
    if reset_all_users {
        println!("All non-admin accounts were removed (--reset-all).");
    } else {
        println!("Other user accounts were preserved.");
    }

    Ok(ResetAdminOutcome {
        users_path,
        generated_password,
        reset_all_users,
    })
}

/// Executes the `reset-sessions` subcommand: removes persisted sessions and API tokens.
pub fn run_reset_sessions(config_path: &Path) -> Result<(), anyhow::Error> {
    run_reset_sessions_with_options(config_path, false)
}

/// Executes `reset-sessions` with an explicit live-service override.
pub fn run_reset_sessions_with_options(
    config_path: &Path,
    force: bool,
) -> Result<(), anyhow::Error> {
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
    // Keep the returned guard alive through the writes below.
    let access = begin_reset(
        data_dir,
        "reset sessions and API tokens",
        force,
        SESSIONS_FORCE_HINT,
    )?;

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

    // Rotate the user-secret generation so a session/token copied out of the
    // deleted store can never be replayed, even if the files are restored.
    let generation = sito_api::auth::manager::rotate_auth_generation(data_dir)
        .map_err(|e| anyhow::anyhow!("Failed to rotate the auth generation: {e}"))?;
    println!("Auth generation rotated to {generation}.");

    if removed == 0 {
        println!(
            "No persisted sessions or tokens found in '{}'.",
            data_dir.display()
        );
    } else if access.is_running() {
        println!("Persisted web sessions and API tokens were removed.");
    } else {
        println!("All web sessions and API tokens have been invalidated.");
    }

    if let ResetAccess::Running { pid } = &access {
        println!("{}", running_service_warning(*pid, SESSIONS_LIVE_STATE));
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
        assert_eq!(cli.config, None);

        let args_default = vec!["sito"];
        let cli_default = Cli::try_parse_from(args_default).expect("parse args");
        assert!(!cli_default.no_setup);

        let args_custom = vec!["sito", "--config", "/etc/sito/custom.toml", "--no-setup"];
        let cli_custom = Cli::try_parse_from(args_custom).expect("parse args");
        assert!(cli_custom.no_setup);
        assert_eq!(
            cli_custom.config,
            Some(PathBuf::from("/etc/sito/custom.toml"))
        );
    }

    fn temp_config_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sito_config_path_{label}_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_server_config_path_resolution() {
        let dir = temp_config_dir("server");
        let local = dir.join("config.toml");
        let system = dir.join("etc/sito/config.toml");
        std::fs::create_dir_all(system.parent().unwrap()).unwrap();
        let explicit = dir.join("explicit.toml");

        // An explicit --config always wins, even when the file does not exist
        // yet (the setup wizard may create it).
        assert_eq!(
            resolve_config_path_from(Some(&explicit), &local, &system),
            explicit
        );

        // Neither location exists: keep the historical relative default so
        // first-boot setup can create ./config.toml.
        assert_eq!(resolve_config_path_from(None, &local, &system), local);

        // A local config takes precedence over the system path.
        std::fs::write(&local, "config_version = 1\n").unwrap();
        assert_eq!(resolve_config_path_from(None, &local, &system), local);

        // Without a local config, the system path is used.
        std::fs::remove_file(&local).unwrap();
        std::fs::write(&system, "config_version = 1\n").unwrap();
        assert_eq!(resolve_config_path_from(None, &local, &system), system);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_update_config_path_resolution_fails_closed() {
        let dir = temp_config_dir("update");
        let local = dir.join("config.toml");
        let system = dir.join("etc/sito/config.toml");
        std::fs::create_dir_all(system.parent().unwrap()).unwrap();
        let explicit = dir.join("explicit.toml");

        // Explicit path wins even if missing; the read error is reported when
        // the signature policy is loaded.
        assert_eq!(
            resolve_update_config_path_from(Some(&explicit), &local, &system).unwrap(),
            explicit
        );

        // Missing local and system config: refuse with actionable guidance.
        let err = resolve_update_config_path_from(None, &local, &system)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no configuration file found"),
            "unexpected error: {err}"
        );
        assert!(err.contains("--config"), "unexpected error: {err}");

        // A local config is used when the system path does not exist.
        std::fs::write(&local, "config_version = 1\n").unwrap();
        assert_eq!(
            resolve_update_config_path_from(None, &local, &system).unwrap(),
            local
        );

        // The system config wins when both exist, so a stray ./config.toml
        // cannot change the signature policy of a system install.
        std::fs::write(&system, "config_version = 1\n").unwrap();
        assert_eq!(
            resolve_update_config_path_from(None, &local, &system).unwrap(),
            system
        );

        // --config still overrides the system config.
        assert_eq!(
            resolve_update_config_path_from(Some(&explicit), &local, &system).unwrap(),
            explicit
        );

        let _ = std::fs::remove_dir_all(&dir);
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

    #[test]
    fn test_cli_ha_gen_certs_uid_gid() {
        let cli = Cli::try_parse_from([
            "sito",
            "ha",
            "gen-certs",
            "--dir",
            "/tmp/certs",
            "--uid",
            "65532",
            "--gid",
            "65532",
        ])
        .expect("parse args");
        match cli.command {
            Some(Commands::Ha {
                command: HaCommands::GenCerts { uid, gid, .. },
            }) => {
                assert_eq!(uid, Some(65532));
                assert_eq!(gid, Some(65532));
            }
            other => panic!("expected ha gen-certs command, got {other:?}"),
        }

        // --uid and --gid are a pair: half an ownership request must fail
        // instead of silently producing runtime-unreadable keys.
        let err = Cli::try_parse_from([
            "sito",
            "ha",
            "gen-certs",
            "--dir",
            "/tmp/certs",
            "--uid",
            "65532",
        ])
        .expect_err("--uid without --gid must be rejected");
        assert!(err.to_string().contains("--gid"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn test_run_ha_gen_certs_applies_uid_gid() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let dir = std::env::temp_dir().join(format!(
            "sito_ha_gen_certs_owner_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let probe = dir.join("probe");
        std::fs::write(&probe, b"x").unwrap();
        let meta = std::fs::metadata(&probe).unwrap();
        let (uid, gid) = (meta.uid(), meta.gid());

        run_ha_gen_certs(&dir, true, true, &[], Some(uid), Some(gid))
            .expect("gen-certs with the invoking uid/gid must succeed");
        for name in ["ca.key", "master.key", "slave.key"] {
            let meta = std::fs::metadata(dir.join(name)).unwrap();
            assert_eq!(meta.uid(), uid, "{name} uid");
            assert_eq!(meta.gid(), gid, "{name} gid");
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{name} mode");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: the healthcheck used to prefer `::1` whenever any bind was
    /// IPv6, which fails on hosts where the v6 loopback is disabled.
    #[test]
    fn test_healthcheck_targets_prefer_ipv4_loopback() {
        let cfg = Config::default();
        assert_eq!(
            cfg.dns.bind.len(),
            2,
            "default binds both wildcard families"
        );
        let (dns, web) = healthcheck_targets_from_config(&cfg);
        assert_eq!(dns.ip().to_string(), "127.0.0.1");
        assert_eq!(dns.port(), cfg.dns.port);
        assert_eq!(web.ip().to_string(), "127.0.0.1");

        // IPv6-only configuration still resolves to the v6 loopback.
        let mut v6_only = Config::default();
        v6_only.dns.bind = vec!["::".parse().unwrap()];
        let (dns, _) = healthcheck_targets_from_config(&v6_only);
        assert!(dns.ip().is_ipv6());

        // A concrete non-wildcard bind is probed directly.
        let mut concrete = Config::default();
        concrete.dns.bind = vec!["10.0.0.5".parse().unwrap()];
        let (dns, _) = healthcheck_targets_from_config(&concrete);
        assert_eq!(dns.ip().to_string(), "10.0.0.5");
    }

    /// Regression for WP-4.5: `--no-setup` without a config used to start the
    /// admin UI on 0.0.0.0 with `admin/adminadmin`.
    #[tokio::test]
    async fn test_no_setup_without_config_generates_random_password_on_loopback() {
        let dir = std::env::temp_dir().join(format!("sito_no_setup_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        let mut config = Config::default();
        config.server.data_dir = dir.clone();

        let password = match prepare_no_setup_bootstrap(&config_path, &mut config)
            .expect("bootstrap preparation")
        {
            NoSetupBootstrap::GeneratedPassword(password) => password,
            other => panic!("expected a generated password, got {other:?}"),
        };
        assert_eq!(password.len(), 48, "random password must be 192-bit hex");
        assert!(
            config.get_web_config().bind.is_loopback(),
            "admin UI must bind loopback when no config exists"
        );

        let users_file = dir.join("users.toml");
        assert!(users_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&users_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        let mgr =
            sito_api::AuthManager::with_storage_checked(&dir, 24, 5, false).expect("load users");
        assert!(matches!(
            mgr.login("admin", "adminadmin", "127.0.0.1").await,
            sito_api::auth::LoginResult::InvalidCredentials { .. }
        ));
        assert!(matches!(
            mgr.login("admin", &password, "127.0.0.1").await,
            sito_api::auth::LoginResult::Success(_)
        ));

        // Existing config: the credential must not be rotated again.
        std::fs::write(&config_path, "config_version = 1\n").unwrap();
        assert_eq!(
            prepare_no_setup_bootstrap(&config_path, &mut config).unwrap(),
            NoSetupBootstrap::NotNeeded
        );

        // No config but existing users: keep them untouched.
        std::fs::remove_file(&config_path).unwrap();
        let mut config = Config::default();
        config.server.data_dir = dir.clone();
        assert_eq!(
            prepare_no_setup_bootstrap(&config_path, &mut config).unwrap(),
            NoSetupBootstrap::KeptExistingUsers
        );
        let mgr =
            sito_api::AuthManager::with_storage_checked(&dir, 24, 5, false).expect("load users");
        assert!(matches!(
            mgr.login("admin", &password, "127.0.0.1").await,
            sito_api::auth::LoginResult::Success(_)
        ));

        let _ = std::fs::remove_dir_all(&dir);
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
        let err = run_healthcheck_or_web(Some(dns_addr), web_addr, 200, false, false)
            .await
            .expect_err("web reachability must not mask a broken DNS listener by default");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_healthcheck_fails_when_ha_is_not_ready() {
        let dns_addr = spawn_udp_responder(dns_response(0x4242, ResponseCode::NoError)).await;
        let web_addr = spawn_http_router(vec![(
            "/health",
            200,
            r#"{"status":"ok","setup_pending":false,"ha":{"required":true,"ready":false,"reason":"master mTLS initialization failed: Permission denied"}}"#,
        )])
        .await;

        let err = run_healthcheck_or_web(Some(dns_addr), web_addr, 2_000, false, true)
            .await
            .expect_err("a healthy DNS probe must not mask an unready HA node");
        let message = err.to_string();
        assert!(
            message.contains("HA replication is not ready"),
            "the healthcheck must report the unready HA role: {message}"
        );
        // `/health` is public; the healthcheck must not echo internal paths or
        // OS errors from the server's detailed readiness reason into logs.
        assert!(
            !message.contains("Permission denied") && !message.contains("mTLS initialization"),
            "the public healthcheck failure must stay generic: {message}"
        );
    }

    #[tokio::test]
    async fn test_healthcheck_passes_when_ha_is_ready() {
        let dns_addr = spawn_udp_responder(dns_response(0x4242, ResponseCode::NoError)).await;
        let web_addr = spawn_http_router(vec![(
            "/health",
            200,
            r#"{"status":"ok","setup_pending":false,"ha":{"required":true,"ready":true,"reason":null}}"#,
        )])
        .await;

        run_healthcheck_or_web(Some(dns_addr), web_addr, 2_000, false, true)
            .await
            .expect("a ready HA node must satisfy the healthcheck");
    }

    #[tokio::test]
    async fn test_healthcheck_ha_required_without_signal_fails_closed() {
        let dns_addr = spawn_udp_responder(dns_response(0x4242, ResponseCode::NoError)).await;
        let web_addr = spawn_http_router(vec![(
            "/health",
            200,
            r#"{"status":"ok","setup_pending":false}"#,
        )])
        .await;

        let err = run_healthcheck_or_web(Some(dns_addr), web_addr, 2_000, false, true)
            .await
            .expect_err("a missing HA readiness signal must fail closed");
        assert!(
            err.to_string().contains("HA readiness"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_healthcheck_ignores_ha_when_not_configured() {
        let dns_addr = spawn_udp_responder(dns_response(0x4242, ResponseCode::NoError)).await;
        // No web listener is required when HA is not part of the role.
        let web_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        run_healthcheck_or_web(Some(dns_addr), web_addr, 200, false, false)
            .await
            .expect("a DNS-only node must stay healthy without an HA check");
    }

    #[test]
    fn test_ha_readiness_required_from_config() {
        let mut cfg = Config::default();
        cfg.server.role = "master".to_string();
        assert!(
            !ha_readiness_required(&cfg),
            "no [ha] section means no HA readiness gate"
        );

        cfg.ha = Some(toml::from_str("replication_port = 8953").unwrap());
        assert!(ha_readiness_required(&cfg));

        cfg.ha = Some(toml::from_str("replication_port = 0").unwrap());
        assert!(
            !ha_readiness_required(&cfg),
            "an explicitly disabled master replication is not a gate"
        );

        cfg.server.role = "slave".to_string();
        cfg.ha = Some(toml::from_str("master_url = \"wss://10.0.0.1:8953\"").unwrap());
        assert!(ha_readiness_required(&cfg));

        cfg.ha = None;
        assert!(!ha_readiness_required(&cfg));
    }

    #[tokio::test]
    async fn test_healthcheck_setup_fallback_accepts_pending_health_json() {
        let (dns_addr, _silent) = spawn_silent_udp().await;
        let web_addr = spawn_http_router(vec![("/health", 200, "{\"setup_pending\": true}")]).await;
        run_healthcheck_or_web(Some(dns_addr), web_addr, 200, true, false)
            .await
            .expect("setup-pending web interface must satisfy the setup fallback");
    }

    #[tokio::test]
    async fn test_healthcheck_setup_fallback_accepts_503_middleware_signal() {
        let (dns_addr, _silent) = spawn_silent_udp().await;
        let web_addr =
            spawn_http_router(vec![("/api/v1/status", 503, "Setup not completed")]).await;
        run_healthcheck_or_web(Some(dns_addr), web_addr, 200, true, false)
            .await
            .expect("503 setup-pending signal must satisfy the setup fallback");
    }

    #[tokio::test]
    async fn test_healthcheck_setup_fallback_rejects_completed_setup() {
        let (dns_addr, _silent) = spawn_silent_udp().await;
        let web_addr = spawn_http_router(vec![("/api/v1/status", 401, "Unauthorized")]).await;
        let err = run_healthcheck_or_web(Some(dns_addr), web_addr, 200, true, false)
            .await
            .expect_err("completed setup must not mask a broken DNS listener");
        assert!(
            err.to_string().contains("timed out"),
            "unexpected error: {err}"
        );
    }

    /// WP-4.3: backups contain secrets (HA tokens, client secrets) and must be
    /// created 0600; restore must also repair the permissions of the config.
    #[test]
    fn test_backup_and_restore_files_are_private() {
        let dir = std::env::temp_dir().join(format!("sito_backup_perm_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            "config_version = 1\n[upstream]\nservers = [\"1.1.1.1\"]\n",
        )
        .unwrap();

        let archive = dir.join("backup.tar.gz");
        run_backup(&config_path, Some(&archive)).expect("backup");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "backup archive must be owner-only");
        }

        // Restore to a fresh path (and then over a world-readable file).
        let restored = dir.join("restored.toml");
        run_restore(&archive, &restored, false).expect("restore");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&restored).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "restored config must be owner-only");
        }
        let content = std::fs::read_to_string(&restored).unwrap();
        assert!(content.contains("1.1.1.1"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&restored, std::fs::Permissions::from_mode(0o644)).unwrap();
            run_restore(&archive, &restored, true).expect("forced restore");
            let mode = std::fs::metadata(&restored).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "restore must repair loose permissions");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn reset_admin_fixture() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("sito_reset_admin_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "config_version = 1\n[server]\ndata_dir = \"{}\"\n[upstream]\nservers = [\"1.1.1.1\"]\n",
                dir.display()
            ),
        )
        .unwrap();
        (dir, config_path)
    }

    #[test]
    fn test_cli_reset_admin_reset_all_flag() {
        for flag in ["--reset-all", "--reset-users"] {
            let cli = Cli::try_parse_from(["sito", "reset-admin", flag]).expect("parse args");
            assert!(matches!(
                cli.command,
                Some(Commands::ResetAdmin {
                    reset_all: true,
                    ..
                })
            ));
        }
    }

    #[test]
    fn test_cli_reset_force_flags() {
        let cli = Cli::try_parse_from(["sito", "reset-admin", "--force"]).expect("parse args");
        assert!(matches!(
            cli.command,
            Some(Commands::ResetAdmin { force: true, .. })
        ));

        let cli = Cli::try_parse_from(["sito", "reset-sessions", "--force"]).expect("parse args");
        assert!(matches!(
            cli.command,
            Some(Commands::ResetSessions { force: true, .. })
        ));

        let cli = Cli::try_parse_from(["sito", "reset-sessions"]).expect("parse args");
        assert!(matches!(
            cli.command,
            Some(Commands::ResetSessions { force: false, .. })
        ));
    }

    /// The reset must own the service lease for its whole duration, so a
    /// supervisor or `systemctl start` cannot slip a live server between the
    /// run check and the disk writes.
    #[test]
    fn test_reset_holds_service_lease_until_access_is_dropped() {
        let (dir, _config_path) = reset_admin_fixture();
        let access = begin_reset(&dir, "test reset", false, SESSIONS_FORCE_HINT)
            .expect("stopped service must be allowed");
        assert!(matches!(access, ResetAccess::Stopped { .. }));

        let err = crate::service_lock::ServiceLease::acquire(&dir)
            .expect_err("a server must not start while a reset holds the lease");
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);

        drop(access);
        drop(
            crate::service_lock::ServiceLease::acquire(&dir)
                .expect("lease must be released when the reset ends"),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_begin_reset_refuses_or_forces_live_service() {
        let (dir, _config_path) = reset_admin_fixture();
        let lease = crate::service_lock::ServiceLease::acquire(&dir).unwrap();

        let err = begin_reset(&dir, "test reset", false, SESSIONS_FORCE_HINT)
            .expect_err("a live service must be refused without --force");
        let message = err.to_string();
        assert!(message.contains("web sessions and API tokens remain valid"));
        assert!(!message.contains("admin password"));

        let access = begin_reset(&dir, "test reset", true, ADMIN_FORCE_HINT)
            .expect("--force must allow a live service");
        assert!(access.is_running());

        drop(access);
        drop(lease);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_reset_admin_rejects_weak_or_default_passwords() {
        let (dir, config_path) = reset_admin_fixture();
        let _ = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();

        for weak in ["adminadmin", "short", "has space 123"] {
            let err = run_reset_admin(&config_path, Some(weak))
                .expect_err("weak password must be rejected");
            assert!(
                !err.to_string().is_empty(),
                "rejection must explain the password policy"
            );
        }

        // The users file was not rotated by the rejected attempts.
        let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(matches!(
            mgr.login("admin", "adminadmin", "127.0.0.1").await,
            sito_api::auth::LoginResult::Success(_)
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_reset_admin_without_password_never_writes_default() {
        let (dir, config_path) = reset_admin_fixture();
        let _ = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();

        let outcome = run_reset_admin(&config_path, None).expect("generated-password reset");
        let generated = outcome
            .generated_password
            .expect("missing --password must generate one");
        assert_ne!(generated, "adminadmin");
        validate_reset_admin_password(&generated).expect("generated password meets policy");

        let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(matches!(
            mgr.login("admin", "adminadmin", "127.0.0.1").await,
            sito_api::auth::LoginResult::InvalidCredentials { .. }
        ));
        assert!(matches!(
            mgr.login("admin", &generated, "127.0.0.1").await,
            sito_api::auth::LoginResult::Success(_)
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_reset_admin_preserves_non_admin_users_by_default() {
        let (dir, config_path) = reset_admin_fixture();
        {
            let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
            mgr.update_user_password("admin", "OldAdminPassword1!")
                .await;
            mgr.create_user("alice", "AlicePassword1!", sito_api::auth::Role::Operator)
                .await;
        }

        run_reset_admin(&config_path, Some("NewAdminPassword1!")).expect("reset admin password");

        let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(
            mgr.has_user("alice"),
            "non-admin accounts must be preserved"
        );
        assert_eq!(mgr.role_of("alice"), Some(sito_api::auth::Role::Operator));
        assert!(matches!(
            mgr.login("admin", "NewAdminPassword1!", "127.0.0.1").await,
            sito_api::auth::LoginResult::Success(_)
        ));

        // The explicit full reset is the only path that removes other accounts.
        let outcome =
            run_reset_admin_with_options(&config_path, Some("NewAdminPassword2!"), true, false)
                .unwrap();
        assert!(outcome.reset_all_users);
        let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(!mgr.has_user("alice"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// WP-4.4: `reset-sessions` rotates the auth generation so a copied
    /// session/token cannot be replayed.
    #[test]
    fn test_reset_sessions_rotates_auth_generation() {
        let dir =
            std::env::temp_dir().join(format!("sito_reset_sessions_{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("config.toml");
        std::fs::write(
            &config_path,
            format!(
                "config_version = 1\n[server]\ndata_dir = \"{}\"\n[upstream]\nservers = [\"1.1.1.1\"]\n",
                dir.display()
            ),
        )
        .unwrap();

        // Seed a session and a token store plus a users file.
        std::fs::write(dir.join("sessions.toml"), "sessions = []\n").unwrap();
        std::fs::write(dir.join("tokens.toml"), "tokens = []\n").unwrap();

        run_reset_sessions(&config_path).expect("reset sessions");
        assert!(!dir.join("sessions.toml").exists());
        assert!(!dir.join("tokens.toml").exists());
        let generation = std::fs::read_to_string(dir.join("auth_generation")).unwrap();
        assert_eq!(generation.trim(), "1");

        // A second run bumps it again (monotonic).
        run_reset_sessions(&config_path).expect("reset sessions twice");
        let generation = std::fs::read_to_string(dir.join("auth_generation")).unwrap();
        assert_eq!(generation.trim(), "2");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
