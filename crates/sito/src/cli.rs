//! CLI arguments and subcommand execution for sito.

use clap::{Parser, Subcommand};
use hickory_proto::op::{Message, MessageType, OpCode, Query};
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

    println!(
        "Healthcheck OK: received response (id: {}, rcode: {:?}) in {:?}",
        resp.metadata.id, resp.metadata.response_code, elapsed
    );

    Ok(())
}
