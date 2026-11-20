#![cfg(test)]

use super::apply::apply_config_push;
use super::config_merge::{build_persisted_config, local_client_id_secrets};
use super::session::{
    CLEAN_CLOSE_RECONNECT_DELAY, connect_and_run, handle_master_message, mark_session_ended,
    parse_ws_url, record_master_liveness_loss,
};
use super::stats::build_stats_report;
use super::{SlaveAppHandles, SlaveConfigApplier, spawn_slave_worker};
use crate::bundle::{ConfigBundle, build_and_sign_push, push_payload_hash};
use crate::config::HaConfig;
use crate::error::HaError;
use crate::protocol::{AckConflict, HaMessage};
use crate::slave::state::{SlaveState, SlaveStatusTracker};
use crate::transport::{ExponentialBackoff, SLAVE_HANDSHAKE_TIMEOUT, ws_config};
use futures_util::SinkExt;
use sito_core::config::Config;
use sito_filter::HostsFilterEngine;
use sito_stats::MetricsRegistry;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Test-only applier used by the `sito-ha` unit and end-to-end tests.
///
/// Production implements [`SlaveConfigApplier`] in the `sito` binary on top of
/// `sito-api`. This stand-in mirrors the observable ordering that matters for
/// the worker tests: apply to the live handles, persist, and roll back when the
/// write fails.
pub(crate) mod test_support {
    use crate::slave::worker::SlaveConfigApplier;
    use sito_core::config::Config;
    use sito_filter::HostsFilterEngine;
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::sync::Arc;

    pub(crate) struct TestApplier {
        runtime: Arc<sito_runtime::RuntimeState>,
        filter: Arc<HostsFilterEngine>,
        config_path: Option<PathBuf>,
    }

    impl TestApplier {
        pub(crate) fn new(
            runtime: Arc<sito_runtime::RuntimeState>,
            filter: Arc<HostsFilterEngine>,
            config_path: Option<PathBuf>,
        ) -> Self {
            Self {
                runtime,
                filter,
                config_path,
            }
        }
    }

    impl SlaveConfigApplier for TestApplier {
        fn apply_and_persist<'a>(
            &'a self,
            cfg: &'a Config,
            document: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                let previous = self.runtime.snapshot();
                let previous_config = previous.config.clone();

                self.filter
                    .reload_with_config(&cfg.filtering)
                    .await
                    .map_err(|e| e.to_string())?;

                let clients: sito_clients::ClientsConfig = match cfg.clients.as_ref() {
                    Some(value) => value.clone().try_into().map_err(|e| format!("{e}"))?,
                    None => sito_clients::ClientsConfig::default(),
                };
                let rewrites: sito_rewrites::RewritesConfig = match cfg.rewrites.as_ref() {
                    Some(value) => value.clone().try_into().map_err(|e| format!("{e}"))?,
                    None => sito_rewrites::RewritesConfig::default(),
                };
                self.runtime.replace(sito_runtime::RuntimeSnapshot {
                    config: Arc::new(cfg.clone()),
                    clients: Arc::new(sito_clients::ClientRegistry::with_stores(
                        clients,
                        previous.clients.routeros_leases_store(),
                        previous.clients.unidentified_store(),
                    )),
                    rewrites: Arc::new(sito_rewrites::RewriteTable::new(rewrites)),
                    ..(*previous).clone()
                });

                if let Some(path) = self.config_path.as_deref()
                    && let Err(e) = tokio::fs::write(path, document).await
                {
                    // Persist failures must leave the live configuration
                    // untouched, exactly like the production applier.
                    self.runtime.replace((*previous).clone());
                    if let Err(reload_err) = self
                        .filter
                        .reload_with_config(&previous_config.filtering)
                        .await
                    {
                        tracing::error!(
                            error = %reload_err,
                            "Failed to restore the previous filter configuration after a persist failure"
                        );
                    }
                    return Err(e.to_string());
                }
                Ok(())
            })
        }
    }
}

use futures_util::StreamExt;

#[tokio::test]
async fn test_slave_missing_master_url_records_startup_noop() {
    let handles = test_handles(None).await;
    let metrics = handles.metrics.clone();
    let tracker = SlaveStatusTracker::new("slave-idle".to_string(), 0, None);
    let (_resync_tx, resync_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let worker = spawn_slave_worker(
        HaConfig {
            master_url: None,
            ..Default::default()
        },
        tracker,
        handles,
        resync_rx,
        shutdown_rx,
    );
    worker.await.unwrap();

    let rendered = metrics.render_prometheus();
    assert!(
        rendered
            .contains(r#"sito_ha_startup_noop_total{role="slave",reason="missing_master_url"} 1"#),
        "an idle slave worker must be observable: {rendered}"
    );
    let _ = shutdown_tx.send(true);
}

async fn test_handles(config_path: Option<PathBuf>) -> SlaveAppHandles {
    // Mirror production: the live runtime configuration is the parsed
    // on-disk configuration (when the test provides one).
    let base_config = match config_path.as_deref() {
        Some(path) => match tokio::fs::read_to_string(path).await {
            Ok(raw) => Config::from_toml_str(&raw).unwrap_or_default(),
            Err(_) => Config::default(),
        },
        None => Config::default(),
    };
    let config_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(base_config.clone())));
    let filter_engine = Arc::new(
        HostsFilterEngine::init(base_config.filtering.clone(), std::env::temp_dir()).await,
    );
    let rewrites_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(
        sito_rewrites::RewriteTable::new(Default::default()),
    )));
    let clients_arc = Arc::new(arc_swap::ArcSwap::new(Arc::new(
        sito_clients::ClientRegistry::new(Default::default()),
    )));
    let runtime = Arc::new(sito_runtime::RuntimeState::new(
        config_arc,
        clients_arc,
        rewrites_arc,
    ));
    let applier = Arc::new(crate::slave::worker::test_support::TestApplier::new(
        runtime.clone(),
        filter_engine.clone(),
        config_path.clone(),
    ));
    SlaveAppHandles {
        runtime,
        filter: filter_engine,
        metrics: MetricsRegistry::new("0.1.0", "slave"),
        config_path,
        applier,
    }
}

fn test_bundle(
    version: u64,
    config_toml: &str,
    clients: Option<toml::Value>,
    rewrites: Option<toml::Value>,
) -> ConfigBundle {
    ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        protocol_version: crate::protocol::PROTOCOL_VERSION,
        version,
        term: 0,
        timestamp: 1,
        config_toml: config_toml.to_string(),
        custom_rules: vec!["||pushed-rule.example^".to_string()],
        rewrites,
        clients,
        lists: vec![],
    }
}

#[derive(Debug, Clone)]
struct ApplierObservation {
    upstream_servers: Vec<String>,
    dnssec_validate: bool,
    dnssec_nta: Vec<String>,
    state: SlaveState,
    version: u64,
}

struct RecordingApplier {
    observation: Arc<std::sync::Mutex<Option<ApplierObservation>>>,
    tracker: SlaveStatusTracker,
}

impl SlaveConfigApplier for RecordingApplier {
    fn apply_and_persist<'a>(
        &'a self,
        cfg: &'a Config,
        _document: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            *self
                .observation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ApplierObservation {
                upstream_servers: cfg.upstream.servers.clone(),
                dnssec_validate: cfg.dns.dnssec.validate,
                dnssec_nta: cfg.dns.dnssec.nta.clone(),
                state: self.tracker.get_state(),
                version: self.tracker.get_version(),
            });
            Ok(())
        })
    }
}

struct FailingApplier;

impl SlaveConfigApplier for FailingApplier {
    fn apply_and_persist<'a>(
        &'a self,
        _cfg: &'a Config,
        _document: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async { Err("listener rebind failed".to_string()) })
    }
}

/// Reads the next slave ACK from the peer end of an in-memory WebSocket.
async fn read_ack<S>(peer: &mut tokio_tungstenite::WebSocketStream<S>) -> HaMessage
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt as _;
    let message = peer.next().await.unwrap().unwrap();
    HaMessage::from_json(&message.into_text().unwrap()).unwrap()
}

/// D-01: every component must be applied before the push is acknowledged.
/// The recording applier sees the new upstream/DNSSEC configuration, the
/// tracker is still `Applying`, and the applied-version watermark is still
/// the old one inside the callback.
#[tokio::test]
async fn test_push_applies_all_components_before_ack() {
    use tokio_tungstenite::tungstenite::protocol::Role;

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let tracker = SlaveStatusTracker::new("slave-before-ack".to_string(), 4, None);
    let observation = Arc::new(std::sync::Mutex::new(None));
    let mut handles = test_handles(None).await;
    handles.applier = Arc::new(RecordingApplier {
        observation: observation.clone(),
        tracker: tracker.clone(),
    });

    let config_toml = r#"
config_version = 2

[server]
role = "slave"

[upstream]
servers = ["9.9.9.9"]

[dns.dnssec]
validate = true
mode = "validate"
nta = ["internal.example"]
"#;
    let push = build_and_sign_push(&test_bundle(5, config_toml, None, None), &signing_key).unwrap();

    let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        slave_socket,
        Role::Client,
        Some(ws_config()),
    )
    .await;
    let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        peer_socket,
        Role::Server,
        Some(ws_config()),
    )
    .await;

    tracker.set_state(SlaveState::HelloSent);
    handle_master_message(
        &push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();

    let observation = observation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .expect("the applier must run before the ACK");
    assert_eq!(
        observation.state,
        SlaveState::Applying,
        "the push must still be in flight while components are applied"
    );
    assert_eq!(
        observation.version, 4,
        "the watermark must not advance before the apply succeeds"
    );
    assert_eq!(observation.upstream_servers, vec!["9.9.9.9".to_string()]);
    assert!(observation.dnssec_validate);
    assert_eq!(observation.dnssec_nta, vec!["internal.example".to_string()]);

    assert!(matches!(
        read_ack(&mut peer).await,
        HaMessage::Ack {
            version: 5,
            term: 0,
            conflict: None,
            applied: true,
            ..
        }
    ));
    assert_eq!(tracker.get_state(), SlaveState::Synced);
    assert_eq!(tracker.get_version(), 5);
}

/// D-01: a component failure is an apply failure: the watermark stays put,
/// the state becomes `Degraded`, and the ACK says `applied: false`.
#[tokio::test]
async fn test_component_failure_is_apply_failure() {
    use tokio_tungstenite::tungstenite::protocol::Role;

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let tracker = SlaveStatusTracker::new("slave-apply-fail".to_string(), 4, None);
    let mut handles = test_handles(None).await;
    let before_config = handles.runtime.snapshot().config.clone();
    handles.applier = Arc::new(FailingApplier);

    let push = build_and_sign_push(
        &test_bundle(
            5,
            "config_version = 2\n[server]\nrole = \"slave\"\n",
            None,
            None,
        ),
        &signing_key,
    )
    .unwrap();

    let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        slave_socket,
        Role::Client,
        Some(ws_config()),
    )
    .await;
    let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        peer_socket,
        Role::Server,
        Some(ws_config()),
    )
    .await;

    tracker.set_state(SlaveState::HelloSent);
    handle_master_message(
        &push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();

    assert_eq!(tracker.get_state(), SlaveState::Degraded);
    assert_eq!(
        tracker.get_version(),
        4,
        "a failed component apply must not advance the watermark"
    );
    assert!(
        Arc::ptr_eq(&before_config, &handles.runtime.snapshot().config),
        "the live runtime must not be replaced by a failed apply"
    );
    match read_ack(&mut peer).await {
        HaMessage::Ack {
            version,
            applied,
            error,
            ..
        } => {
            assert_eq!(version, 5);
            assert!(!applied);
            assert!(
                error.unwrap_or_default().contains("listener rebind failed"),
                "the ACK must carry the apply failure"
            );
        }
        other => panic!("expected an ACK, got {other:?}"),
    }
}

#[tokio::test]
async fn test_persisted_config_preserves_ha_and_identity() {
    let dir = std::env::temp_dir().join(format!("sito_ha_merge_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join("config.toml");

    let local = r#"
config_version = 2

[server]
role = "slave"
instance_name = "slave-1"
data_dir = "/var/lib/sito"

[ha]
master_url = "wss://master.example:8953"
master_pubkey = "abc123"
cert = "/etc/sito/slave.crt"
key = "/etc/sito/slave.key"

[clients]
client_id_secrets = { "kids-tablet" = "s3cret-value" }

[integrations.mikrotik]
url = "https://192.168.1.1"
password = "routeros-password"
"#;
    tokio::fs::write(&path, local).await.unwrap();

    // Sanitized bundle from the master: no [ha], no instance_name, no
    // client secrets and no RouterOS password.
    let pushed = r#"
config_version = 2

[server]
role = "slave"
data_dir = "/var/lib/sito-master"

[clients]

[integrations.mikrotik]
url = "https://192.168.1.1"
"#;

    let mut sanitized_clients = toml::Table::new();
    sanitized_clients.insert(
        "client_id_secrets".to_string(),
        toml::Value::Table({
            let mut t = toml::Table::new();
            t.insert(
                "kids-tablet".to_string(),
                toml::Value::String("s3cret-value".to_string()),
            );
            t
        }),
    );

    let bundle = test_bundle(2, pushed, Some(toml::Value::Table(sanitized_clients)), None);
    let live = Config::from_toml_str(local).expect("node-local config");
    let merged =
        build_persisted_config(pushed, &bundle, Some(&path), &live, bundle.clients.clone())
            .await
            .expect("build persisted config");
    let table: toml::Table = merged.parse().unwrap();

    let ha = table.get("ha").expect("[ha] must be preserved");
    assert_eq!(
        ha.get("master_url").and_then(toml::Value::as_str),
        Some("wss://master.example:8953")
    );
    let server = table.get("server").unwrap();
    assert_eq!(
        server.get("instance_name").and_then(toml::Value::as_str),
        Some("slave-1")
    );
    assert_eq!(
        server.get("data_dir").and_then(toml::Value::as_str),
        Some("/var/lib/sito")
    );
    assert_eq!(
        server.get("role").and_then(toml::Value::as_str),
        Some("slave")
    );
    assert_eq!(
        table
            .get("clients")
            .and_then(|c| c.get("client_id_secrets"))
            .and_then(|s| s.get("kids-tablet"))
            .and_then(toml::Value::as_str),
        Some("s3cret-value"),
        "node-local client secrets must survive a push"
    );
    assert_eq!(
        table
            .get("integrations")
            .and_then(|i| i.get("mikrotik"))
            .and_then(|m| m.get("password"))
            .and_then(toml::Value::as_str),
        Some("routeros-password"),
        "node-local RouterOS credentials must survive a push"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn test_local_client_id_secrets_read_from_live_config() {
    let live = Config::from_toml_str(
        "config_version = 2\n[clients]\nclient_id_secrets = { \"phone\" = \"abc\" }\n",
    )
    .expect("live config");
    let secrets = local_client_id_secrets(&live);
    assert_eq!(secrets.get("phone").map(String::as_str), Some("abc"));
    assert!(
        local_client_id_secrets(&Config::default()).is_empty(),
        "a node without client secrets must yield no client id secrets"
    );
}

/// I4: without a local path there is nothing to protect, so the pushed
/// sections survive and only the forced node-local fields are merged.
#[tokio::test]
async fn test_persisted_config_without_local_file_keeps_pushed_sections() {
    let pushed = "config_version = 2\n[server]\nrole = \"slave\"\n";
    let mut bundle = test_bundle(1, pushed, None, None);
    bundle.custom_rules = vec![];
    let live = Config::default();
    let merged = build_persisted_config(pushed, &bundle, None, &live, None)
        .await
        .expect("build persisted config");
    let table: toml::Table = merged.parse().unwrap();
    assert_eq!(
        table
            .get("server")
            .and_then(|server| server.get("role"))
            .and_then(toml::Value::as_str),
        Some("slave")
    );
    assert_eq!(
        table
            .get("server")
            .and_then(|server| server.get("instance_name"))
            .and_then(toml::Value::as_str),
        Some(live.server.instance_name.as_str()),
        "node identity must come from the live configuration"
    );
    let expected_data_dir = live.server.data_dir.to_string_lossy();
    assert_eq!(
        table
            .get("server")
            .and_then(|server| server.get("data_dir"))
            .and_then(toml::Value::as_str),
        Some(expected_data_dir.as_ref()),
        "the node data directory must come from the live configuration"
    );
}

/// Node-local listener, TLS, ACME and RouterOS identity must never be
/// replaced by the master's values: a master bound to `192.168.1.10` must
/// not make a slave at `.11` fail to bind, and certificate paths that only
/// exist on the master must not reach the slave's persisted file.
#[tokio::test]
async fn test_persisted_config_preserves_node_local_listener_tls_and_web() {
    let local = r#"
config_version = 2

[server]
role = "slave"
instance_name = "slave-1"
data_dir = "/var/lib/sito-slave"

[dns]
bind = ["192.168.1.11"]

[dns.tls]
cert = "/etc/sito/slave-dns.crt"
key = "/etc/sito/slave-dns.key"

[tls]
cert = "/etc/sito/slave.crt"
key = "/etc/sito/slave.key"

[acme]
enabled = true
email = "slave@example.com"
domains = ["slave.example"]
cache_dir = "/var/lib/sito/acme"

[web]
bind = "127.0.0.1"
port = 8081

[integrations.mikrotik]
url = "https://192.168.1.7"
password = "local-routeros-password"
"#;
    let pushed = r#"
config_version = 2

[server]
role = "slave"
data_dir = "/var/lib/sito-master"

[dns]
bind = ["192.168.1.10", "::"]

[dns.tls]
cert = "/etc/sito/master-dns.crt"
key = "/etc/sito/master-dns.key"

[tls]
cert = "/etc/sito/master.crt"
key = "/etc/sito/master.key"

[acme]
enabled = true
email = "master@example.com"
domains = ["master.example"]
cache_dir = "/var/lib/sito-master/acme"

[web]
bind = "192.168.1.10"
port = 80

[integrations.mikrotik]
url = "https://192.168.9.9"
"#;

    let live = Config::from_toml_str(local).expect("node-local config");
    let bundle = test_bundle(2, pushed, None, None);
    let merged = build_persisted_config(pushed, &bundle, None, &live, None)
        .await
        .expect("build persisted config");
    let table: toml::Table = merged.parse().unwrap();

    assert_eq!(
        table
            .get("dns")
            .and_then(|dns| dns.get("bind"))
            .and_then(toml::Value::as_array)
            .map(|bind| bind
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()),
        Some(vec!["192.168.1.11"]),
        "the slave must keep its own bind list, not the master's: {merged}"
    );
    assert_eq!(
        table
            .get("dns")
            .and_then(|dns| dns.get("tls"))
            .and_then(|tls| tls.get("cert"))
            .and_then(toml::Value::as_str),
        Some("/etc/sito/slave-dns.crt"),
        "the slave must keep its own [dns.tls] certificate path"
    );
    assert_eq!(
        table
            .get("tls")
            .and_then(|tls| tls.get("cert"))
            .and_then(toml::Value::as_str),
        Some("/etc/sito/slave.crt"),
        "the slave must keep its own [tls] certificate path"
    );
    assert_eq!(
        table
            .get("tls")
            .and_then(|tls| tls.get("key"))
            .and_then(toml::Value::as_str),
        Some("/etc/sito/slave.key"),
        "the slave must keep its own [tls] key path"
    );
    assert_eq!(
        table
            .get("acme")
            .and_then(|acme| acme.get("email"))
            .and_then(toml::Value::as_str),
        Some("slave@example.com"),
        "the slave must keep its own [acme] identity"
    );
    assert_eq!(
        table
            .get("acme")
            .and_then(|acme| acme.get("cache_dir"))
            .and_then(toml::Value::as_str),
        Some("/var/lib/sito/acme"),
        "the slave must keep its own [acme] cache directory"
    );
    assert_eq!(
        table
            .get("web")
            .and_then(|web| web.get("bind"))
            .and_then(toml::Value::as_str),
        Some("127.0.0.1"),
        "the slave must keep its own web bind address"
    );
    assert_eq!(
        table
            .get("web")
            .and_then(|web| web.get("port"))
            .and_then(toml::Value::as_integer),
        Some(8081),
        "the slave must keep its own web port"
    );
    assert_eq!(
        table
            .get("integrations")
            .and_then(|integrations| integrations.get("mikrotik"))
            .and_then(|mikrotik| mikrotik.get("url"))
            .and_then(toml::Value::as_str),
        Some("https://192.168.1.7"),
        "the RouterOS URL is node-local and must come from the slave"
    );
    assert_eq!(
        table
            .get("integrations")
            .and_then(|integrations| integrations.get("mikrotik"))
            .and_then(|mikrotik| mikrotik.get("password"))
            .and_then(toml::Value::as_str),
        Some("local-routeros-password"),
        "the RouterOS password must survive a push"
    );
}

/// Regression: a slave that disables the admin listener must not receive
/// the master's `web.enabled = true`. That false difference made the push
/// fail with `restart_required: web`, so the slave stayed `Degraded` and
/// replication never converged. The complete node-local web identity must
/// survive; only cluster-shared `[web]` keys (legacy ACME) follow the
/// master.
#[tokio::test]
async fn test_persisted_config_preserves_node_local_web_identity() {
    let local = r#"
config_version = 2

[server]
role = "slave"

[web]
enabled = false
bind = "127.0.0.1"
port = 8081
trusted_proxies = ["10.0.0.2"]
metrics_auth = false
public_url = "https://slave.example"
tls_terminated_by_proxy = true
acme_enabled = true
acme_email = "slave@example.com"
acme_domains = ["slave.example"]
"#;
    let pushed = r#"
config_version = 2

[server]
role = "slave"

[web]
enabled = true
bind = "192.168.1.10"
port = 80
trusted_proxies = ["10.0.0.1"]
metrics_auth = true
public_url = "https://master.example"
tls_terminated_by_proxy = false
acme_enabled = false
"#;

    let live = Config::from_toml_str(local).expect("node-local config");
    let bundle = test_bundle(2, pushed, None, None);
    let merged = build_persisted_config(pushed, &bundle, None, &live, None)
        .await
        .expect("build persisted config");
    let table: toml::Table = merged.parse().unwrap();
    let web = table
        .get("web")
        .and_then(toml::Value::as_table)
        .expect("[web] must be persisted");

    assert_eq!(
        web.get("enabled").and_then(toml::Value::as_bool),
        Some(false),
        "the slave must keep its own web.enabled: {merged}"
    );
    assert_eq!(
        web.get("bind").and_then(toml::Value::as_str),
        Some("127.0.0.1"),
        "the slave must keep its own web.bind"
    );
    assert_eq!(
        web.get("port").and_then(toml::Value::as_integer),
        Some(8081),
        "the slave must keep its own web.port"
    );
    assert_eq!(
        web.get("trusted_proxies")
            .and_then(toml::Value::as_array)
            .map(|proxies| proxies
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()),
        Some(vec!["10.0.0.2"]),
        "the slave must keep its own web.trusted_proxies"
    );
    assert_eq!(
        web.get("metrics_auth").and_then(toml::Value::as_bool),
        Some(false),
        "the slave must keep its own web.metrics_auth"
    );
    assert_eq!(
        web.get("public_url").and_then(toml::Value::as_str),
        Some("https://slave.example"),
        "the slave must keep its own web.public_url"
    );
    assert_eq!(
        web.get("tls_terminated_by_proxy")
            .and_then(toml::Value::as_bool),
        Some(true),
        "the slave must keep its own web.tls_terminated_by_proxy"
    );
    assert_eq!(
        web.get("acme_enabled").and_then(toml::Value::as_bool),
        Some(false),
        "cluster-shared [web] keys must still come from the master"
    );

    // The restart-only check compares the effective typed listener
    // fields. `config_apply`'s regression test asserts the same pair does
    // not report `web`.
    let applied = Config::from_toml_str(&merged).expect("merged config");
    let applied_web = applied.get_web_config();
    let live_web = live.get_web_config();
    // The full WebConfig now also carries deprecated [web] acme_* aliases,
    // which are cluster-shared and intentionally follow the master. The
    // node-local listener identity must match exactly.
    assert_eq!(applied_web.enabled, live_web.enabled);
    assert_eq!(applied_web.bind, live_web.bind);
    assert_eq!(applied_web.port, live_web.port);
    assert_eq!(applied_web.trusted_proxies, live_web.trusted_proxies);
    assert_eq!(applied_web.metrics_auth, live_web.metrics_auth);
    assert_eq!(applied_web.public_url, live_web.public_url);
    assert_eq!(
        applied_web.tls_terminated_by_proxy,
        live_web.tls_terminated_by_proxy
    );
}

/// A slave without certificate material must not inherit the master's TLS
/// and ACME paths: they are local to the master and a restart on the slave
/// would fail to load them.
#[tokio::test]
async fn test_pushed_tls_and_acme_are_removed_when_slave_has_none() {
    let pushed = r#"
config_version = 2

[server]
role = "slave"

[dns]
bind = ["192.168.1.10"]
[dns.tls]
cert = "/etc/sito/master-dns.crt"
key = "/etc/sito/master-dns.key"

[tls]
cert = "/etc/sito/master.crt"
key = "/etc/sito/master.key"

[acme]
enabled = true
email = "master@example.com"
domains = ["master.example"]
"#;
    let live = Config::default();
    let bundle = test_bundle(2, pushed, None, None);
    let merged = build_persisted_config(pushed, &bundle, None, &live, None)
        .await
        .expect("build persisted config");
    let table: toml::Table = merged.parse().unwrap();

    assert!(
        table.get("tls").is_none(),
        "the master's [tls] section must not be persisted on a slave without one: {merged}"
    );
    assert!(
        table.get("acme").is_none(),
        "the master's [acme] section must not be persisted on a slave without one: {merged}"
    );
    assert!(
        table.get("dns").and_then(|dns| dns.get("tls")).is_none(),
        "the master's [dns.tls] section must not be persisted on a slave: {merged}"
    );
    let expected_bind: Vec<String> = live.dns.bind.iter().map(ToString::to_string).collect();
    assert_eq!(
        table
            .get("dns")
            .and_then(|dns| dns.get("bind"))
            .and_then(toml::Value::as_array)
            .map(|bind| bind
                .iter()
                .filter_map(toml::Value::as_str)
                .collect::<Vec<_>>()),
        Some(expected_bind.iter().map(String::as_str).collect()),
        "the slave's default bind list must be preserved"
    );
}

/// I4 regression: the local file is expected but unreadable/unparseable.
/// The push must fail (applied:false) and the file must stay untouched.
#[tokio::test]
async fn test_unparseable_local_config_rejects_push_and_keeps_file() {
    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!("sito_ha_corrupt_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join("config.toml");
    let corrupt = "[server\nrole = \"slave\"\n";
    tokio::fs::write(&path, corrupt).await.unwrap();

    let mut handles = test_handles(None).await;
    handles.config_path = Some(path.clone());
    let tracker = SlaveStatusTracker::new("slave-corrupt".to_string(), 0, None);
    let config_toml = "config_version = 2\n[server]\nrole = \"slave\"\n";
    let push = build_and_sign_push(&test_bundle(1, config_toml, None, None), &signing_key).unwrap();

    let err = apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
        .await
        .expect_err("an unparseable local config must reject the push");
    assert!(matches!(err, HaError::Rollback(_)));
    assert_eq!(tracker.get_state(), SlaveState::Degraded);
    assert_eq!(tracker.get_version(), 0);
    assert_eq!(
        tokio::fs::read_to_string(&path).await.unwrap(),
        corrupt,
        "the push must not overwrite the node-local configuration"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// Absent `clients`/`rewrites` in the bundle are authoritative removals:
/// the runtime snapshot and the persisted file must agree (a restart must
/// observe what was applied).
#[tokio::test]
async fn test_absent_clients_and_rewrites_are_removed_consistently() {
    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!("sito_ha_absent_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join("config.toml");
    tokio::fs::write(
            &path,
            "config_version = 2\n[server]\nrole = \"slave\"\ninstance_name = \"slave-absent\"\n\n[clients]\nentries = []\n\n[rewrites]\nttl = 60\n",
        )
        .await
        .unwrap();

    let tracker = SlaveStatusTracker::new("slave-absent".to_string(), 0, None);
    let handles = test_handles(Some(path.clone())).await;
    let before = handles.runtime.snapshot();

    let config_toml = r#"
config_version = 2

[server]
role = "slave"

[clients]
entries = []

[rewrites]
ttl = 60
"#;
    let push = build_and_sign_push(&test_bundle(1, config_toml, None, None), &signing_key).unwrap();
    let applied = apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
        .await
        .unwrap();
    assert_eq!(applied, 1);
    assert_eq!(tracker.get_state(), SlaveState::Synced);

    // Runtime: the components were replaced (authoritative removal), not
    // kept from the previous snapshot, and the snapshot config no longer
    // carries the structured sections.
    let snapshot = handles.runtime.snapshot();
    assert!(!Arc::ptr_eq(&snapshot.clients, &before.clients));
    assert!(!Arc::ptr_eq(&snapshot.rewrites, &before.rewrites));
    assert!(snapshot.config.clients.is_none());
    assert!(snapshot.config.rewrites.is_none());
    assert_eq!(snapshot.config.filtering.custom_rules.len(), 1);

    // Disk: a restart loads the same (absent) sections.
    let persisted: toml::Table = tokio::fs::read_to_string(&path)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        persisted.get("clients").is_none(),
        "absent clients must be removed from the persisted file"
    );
    assert!(
        persisted.get("rewrites").is_none(),
        "absent rewrites must be removed from the persisted file"
    );
    assert_eq!(
        persisted
            .get("server")
            .and_then(|s| s.get("instance_name"))
            .and_then(toml::Value::as_str),
        Some("slave-absent"),
        "node identity survives"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// A failed persist must not advance the version or ACK as applied; a
/// later successful attempt applies the same push.
#[tokio::test]
async fn test_persist_failure_is_apply_failure_and_retry_succeeds() {
    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!("sito_ha_persist_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    // Point at a path whose parent directory does not exist: the atomic
    // write must fail.
    let path = dir.join("missing").join("config.toml");

    let tracker = SlaveStatusTracker::new("slave-persist".to_string(), 0, None);
    tracker.set_state(SlaveState::Synced);
    let handles = test_handles(Some(path.clone())).await;

    let config_toml = "config_version = 2\n[server]\nrole = \"slave\"\n";
    let bundle = test_bundle(2, config_toml, None, None);
    let push = build_and_sign_push(&bundle, &signing_key).unwrap();

    let err = apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
        .await
        .expect_err("persist failure must be reported as an apply failure");
    assert!(matches!(err, HaError::Rollback(_)));
    assert_eq!(tracker.get_state(), SlaveState::Degraded);
    assert_eq!(
        tracker.get_version(),
        0,
        "the applied-version watermark must not advance without a durable write"
    );
    assert!(
        handles
            .runtime
            .snapshot()
            .config
            .filtering
            .custom_rules
            .is_empty(),
        "runtime configuration must not be replaced when persistence fails"
    );
    assert_eq!(
        handles.filter.rule_count(),
        0,
        "the live filter snapshot must be rolled back when persistence fails"
    );

    // Repair the path and re-apply: the same push succeeds. The local file
    // must exist and parse because a push never overwrites node-local
    // state it could not read.
    tokio::fs::create_dir_all(path.parent().unwrap())
        .await
        .unwrap();
    tokio::fs::write(&path, "config_version = 2\n[server]\nrole = \"slave\"\n")
        .await
        .unwrap();
    let applied = apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
        .await
        .unwrap();
    assert_eq!(applied, 2);
    assert_eq!(tracker.get_state(), SlaveState::Synced);
    assert_eq!(tracker.get_version(), 2);
    assert_eq!(
        handles
            .runtime
            .snapshot()
            .config
            .filtering
            .custom_rules
            .len(),
        1
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// A restart restores the applied watermark and rejects both an older
/// signed bundle and a same-version bundle with different content.
#[tokio::test]
async fn test_restart_rejects_replay_and_same_version_content_swap() {
    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_watermark_worker_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let watermark_path = dir.join("ha_watermark.toml");
    let config_toml = "config_version = 2\n[server]\nrole = \"slave\"\n";

    let first = SlaveStatusTracker::new("slave-restart".to_string(), 0, None)
        .with_watermark_path(watermark_path.clone())
        .unwrap();
    let handles = test_handles(None).await;
    let push_v2 =
        build_and_sign_push(&test_bundle(2, config_toml, None, None), &signing_key).unwrap();
    assert_eq!(
        apply_config_push(&push_v2, &first, &handles, &signing_key.public_key())
            .await
            .unwrap(),
        2
    );

    // Simulate a process restart: only the on-disk watermark survives.
    let restarted = SlaveStatusTracker::new("slave-restart".to_string(), 0, None)
        .with_watermark_path(watermark_path.clone())
        .unwrap();
    assert_eq!(restarted.get_version(), 2);
    let restarted_handles = test_handles(None).await;

    let old_push =
        build_and_sign_push(&test_bundle(1, config_toml, None, None), &signing_key).unwrap();
    assert!(
        apply_config_push(
            &old_push,
            &restarted,
            &restarted_handles,
            &signing_key.public_key()
        )
        .await
        .is_err(),
        "an older signed bundle must be rejected after restart"
    );
    assert_eq!(
        restarted.get_version(),
        2,
        "a rejected replay must not advance the watermark"
    );

    let mut swapped = test_bundle(2, config_toml, None, None);
    swapped.custom_rules = vec!["||content-swap.example^".to_string()];
    let swapped_push = build_and_sign_push(&swapped, &signing_key).unwrap();
    assert!(
        apply_config_push(
            &swapped_push,
            &restarted,
            &restarted_handles,
            &signing_key.public_key()
        )
        .await
        .is_err(),
        "same-version content replay must be rejected"
    );
    assert!(
        restarted_handles
            .runtime
            .snapshot()
            .config
            .filtering
            .custom_rules
            .is_empty(),
        "rejected replays must not change the live configuration"
    );

    // Forward progress still works after the restart.
    let push_v3 =
        build_and_sign_push(&test_bundle(3, config_toml, None, None), &signing_key).unwrap();
    assert_eq!(
        apply_config_push(
            &push_v3,
            &restarted,
            &restarted_handles,
            &signing_key.public_key()
        )
        .await
        .unwrap(),
        3
    );
    let persisted = restarted.get_watermark().expect("watermark");
    assert_eq!(persisted.version, 3);

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// The watermark is durable before the push is acknowledged.
#[tokio::test]
async fn test_watermark_is_persisted_before_ack() {
    use tokio_tungstenite::tungstenite::protocol::Role;

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_watermark_ack_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let watermark_path = dir.join("ha_watermark.toml");
    let tracker = SlaveStatusTracker::new("slave-ack".to_string(), 0, None)
        .with_watermark_path(watermark_path.clone())
        .unwrap();
    let handles = test_handles(None).await;
    let push = build_and_sign_push(
        &test_bundle(
            1,
            "config_version = 2\n[server]\nrole = \"slave\"\n",
            None,
            None,
        ),
        &signing_key,
    )
    .unwrap();

    let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        slave_socket,
        Role::Client,
        Some(ws_config()),
    )
    .await;
    let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        peer_socket,
        Role::Server,
        Some(ws_config()),
    )
    .await;

    tracker.set_state(SlaveState::HelloSent);
    handle_master_message(
        &push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();

    assert!(matches!(
        read_ack(&mut peer).await,
        HaMessage::Ack {
            version: 1,
            term: 0,
            conflict: None,
            applied: true,
            ..
        }
    ));
    let persisted: crate::bundle::AppliedWatermark =
        serde_json::from_str(&tokio::fs::read_to_string(&watermark_path).await.unwrap()).unwrap();
    assert_eq!(persisted.version, 1);
    assert_eq!(
        persisted.payload_hash,
        push_payload_hash(&push).unwrap(),
        "the ACK must only be sent after the exact signed payload is on disk"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// A same-version payload fork latches the slave: every further push in the
/// same term is rejected until an explicit higher-term promotion arrives.
#[tokio::test]
async fn test_same_version_fork_latches_and_blocks_same_term_versions() {
    use tokio_tungstenite::tungstenite::protocol::Role;

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_fork_latch_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let watermark_path = dir.join("ha_watermark.toml");
    let tracker = SlaveStatusTracker::new("slave-fork".to_string(), 0, None)
        .with_watermark_path(watermark_path.clone())
        .unwrap();
    let handles = test_handles(None).await;
    let config_toml = "config_version = 2\n[server]\nrole = \"slave\"\n";

    // Applied state: term 0, version 50, payload B.
    let applied = ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        term: 0,
        ..test_bundle(50, config_toml, None, None)
    };
    let applied_push = build_and_sign_push(&applied, &signing_key).unwrap();
    assert_eq!(
        apply_config_push(&applied_push, &tracker, &handles, &signing_key.public_key())
            .await
            .unwrap(),
        50
    );
    assert!(!tracker.is_forked());

    let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        slave_socket,
        Role::Client,
        Some(ws_config()),
    )
    .await;
    let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        peer_socket,
        Role::Server,
        Some(ws_config()),
    )
    .await;

    // Same term and version, different content: fork signal.
    let mut forked = test_bundle(50, config_toml, None, None);
    forked.term = 0;
    forked.custom_rules = vec!["||fork-a.example^".to_string()];
    let forked_push = build_and_sign_push(&forked, &signing_key).unwrap();
    tracker.set_state(SlaveState::Synced);
    handle_master_message(
        &forked_push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();

    match read_ack(&mut peer).await {
        HaMessage::Ack {
            version,
            term,
            applied,
            conflict,
            ..
        } => {
            assert_eq!(version, 50);
            assert_eq!(term, 0);
            assert!(!applied);
            assert_eq!(conflict, Some(AckConflict::SameVersionFork));
        }
        other => panic!("expected an ACK, got {other:?}"),
    }
    assert!(tracker.is_forked(), "the fork must be latched");
    assert_eq!(
        tracker.get_state(),
        SlaveState::Degraded,
        "a fork must degrade the slave immediately"
    );
    let persisted: crate::bundle::AppliedWatermark =
        serde_json::from_str(&tokio::fs::read_to_string(&watermark_path).await.unwrap()).unwrap();
    assert!(persisted.forked, "the latch must be durable");
    assert_eq!(persisted.version, 50);

    // The forked master's next version in the same term is refused.
    let forked_next = ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        term: 0,
        ..test_bundle(51, config_toml, None, None)
    };
    let forked_next_push = build_and_sign_push(&forked_next, &signing_key).unwrap();
    handle_master_message(
        &forked_next_push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();
    match read_ack(&mut peer).await {
        HaMessage::Ack {
            version,
            applied,
            conflict,
            ..
        } => {
            assert_eq!(version, 50);
            assert!(!applied);
            assert_eq!(conflict, Some(AckConflict::SameVersionFork));
        }
        other => panic!("expected an ACK, got {other:?}"),
    }
    assert_eq!(tracker.get_version(), 50);
    let live_rules = &handles.runtime.snapshot().config.filtering.custom_rules;
    assert!(
        !live_rules
            .iter()
            .any(|rule| rule.contains("fork-a.example")),
        "the forked configuration must never become live: {live_rules:?}"
    );

    // An explicit higher-term promotion (with a higher version) resumes
    // replication and clears the latch.
    let promoted = ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        term: 1,
        ..test_bundle(51, config_toml, None, None)
    };
    let promoted_push = build_and_sign_push(&promoted, &signing_key).unwrap();
    handle_master_message(
        &promoted_push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();
    match read_ack(&mut peer).await {
        HaMessage::Ack {
            version,
            term,
            applied,
            conflict,
            ..
        } => {
            assert_eq!(version, 51);
            assert_eq!(term, 1);
            assert!(applied);
            assert_eq!(conflict, None);
        }
        other => panic!("expected an ACK, got {other:?}"),
    }
    assert_eq!(tracker.get_version(), 51);
    assert_eq!(tracker.get_term(), 1);
    assert!(!tracker.is_forked(), "a higher term clears the latch");
    assert!(!tracker.get_watermark().unwrap().forked);

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// A failed durable fork-latch write must still keep the in-memory latch and
/// refuse the next same-term version; it must not proceed as if unlatched.
#[tokio::test]
async fn test_fork_latch_write_failure_still_refuses_same_term_push() {
    use tokio_tungstenite::tungstenite::protocol::Role;

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_fork_latch_fail_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let tracker = SlaveStatusTracker::new("slave-fork-fail".to_string(), 0, None)
        .with_watermark_path(dir.join("ha_watermark.toml"))
        .unwrap();
    let handles = test_handles(None).await;
    let config_toml = "config_version = 2\n[server]\nrole = \"slave\"\n";

    let applied = ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        term: 0,
        ..test_bundle(50, config_toml, None, None)
    };
    let applied_push = build_and_sign_push(&applied, &signing_key).unwrap();
    assert_eq!(
        apply_config_push(&applied_push, &tracker, &handles, &signing_key.public_key())
            .await
            .unwrap(),
        50
    );

    // Sabotage the watermark path: its parent becomes a regular file, so
    // the next atomic latch write fails.
    tokio::fs::remove_dir_all(&dir).await.unwrap();
    tokio::fs::write(&dir, b"not-a-directory").await.unwrap();

    let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        slave_socket,
        Role::Client,
        Some(ws_config()),
    )
    .await;
    let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        peer_socket,
        Role::Server,
        Some(ws_config()),
    )
    .await;

    let mut forked = test_bundle(50, config_toml, None, None);
    forked.term = 0;
    forked.custom_rules = vec!["||fork-write-fail.example^".to_string()];
    let forked_push = build_and_sign_push(&forked, &signing_key).unwrap();
    tracker.set_state(SlaveState::Synced);
    handle_master_message(
        &forked_push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();

    match read_ack(&mut peer).await {
        HaMessage::Ack {
            applied,
            conflict,
            error,
            ..
        } => {
            assert!(!applied);
            assert_eq!(conflict, Some(AckConflict::SameVersionFork));
            assert!(
                error.unwrap_or_default().contains("could not be persisted"),
                "the ACK must surface the latch write failure"
            );
        }
        other => panic!("expected an ACK, got {other:?}"),
    }
    assert!(
        tracker.is_forked(),
        "the in-memory latch must survive a failed durable write"
    );
    assert_eq!(tracker.get_state(), SlaveState::Degraded);

    let forked_next = ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        term: 0,
        ..test_bundle(51, config_toml, None, None)
    };
    let forked_next_push = build_and_sign_push(&forked_next, &signing_key).unwrap();
    handle_master_message(
        &forked_next_push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();
    match read_ack(&mut peer).await {
        HaMessage::Ack {
            version,
            applied,
            conflict,
            ..
        } => {
            assert_eq!(version, 50);
            assert!(!applied);
            assert_eq!(conflict, Some(AckConflict::SameVersionFork));
        }
        other => panic!("expected an ACK, got {other:?}"),
    }
    assert_eq!(tracker.get_version(), 50);
    assert!(
        !handles
            .runtime
            .snapshot()
            .config
            .filtering
            .custom_rules
            .iter()
            .any(|rule| rule.contains("fork-write-fail")),
        "the forked configuration must not become live"
    );

    let _ = tokio::fs::remove_file(&dir).await;
}

/// A stale master from an older term must not overwrite a newer slave,
/// even when its version counter is higher.
#[tokio::test]
async fn test_stale_master_push_is_rejected_without_overwriting() {
    use tokio_tungstenite::tungstenite::protocol::Role;

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "sito_ha_stale_master_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let tracker = SlaveStatusTracker::new("slave-epoch".to_string(), 0, None)
        .with_watermark_path(dir.join("ha_watermark.toml"))
        .unwrap();
    let handles = test_handles(None).await;

    // The slave has applied an epoch-1, version-5 bundle.
    let current = ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        term: 1,
        ..test_bundle(
            5,
            "config_version = 2\n[server]\nrole = \"slave\"\n",
            None,
            None,
        )
    };
    let current_push = build_and_sign_push(&current, &signing_key).unwrap();
    assert_eq!(
        apply_config_push(&current_push, &tracker, &handles, &signing_key.public_key())
            .await
            .unwrap(),
        5
    );
    assert_eq!(tracker.get_term(), 1);

    // A stale epoch-0 master offers a higher version.
    let stale = ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        term: 0,
        ..test_bundle(
            6,
            "config_version = 2\n[server]\nrole = \"slave\"\n",
            None,
            None,
        )
    };
    let stale_push = build_and_sign_push(&stale, &signing_key).unwrap();

    let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        slave_socket,
        Role::Client,
        Some(ws_config()),
    )
    .await;
    let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        peer_socket,
        Role::Server,
        Some(ws_config()),
    )
    .await;

    tracker.set_state(SlaveState::Synced);
    handle_master_message(
        &stale_push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .unwrap();

    match read_ack(&mut peer).await {
        HaMessage::Ack {
            version,
            term,
            applied,
            error,
            ..
        } => {
            assert_eq!(version, 5);
            assert_eq!(term, 1);
            assert!(!applied);
            assert!(
                error.unwrap_or_default().contains("stale master/epoch"),
                "the ACK must explain the rejected epoch"
            );
        }
        other => panic!("expected an ACK, got {other:?}"),
    }
    assert_eq!(tracker.get_version(), 5);
    assert_eq!(tracker.get_term(), 1);
    assert_eq!(
        tracker.get_watermark().unwrap().version,
        5,
        "the stale push must not advance the watermark"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// A v1 master must be rejected before its first push is applied, and the
/// rejection must not latch: the next valid v2 push on a later session applies.
#[tokio::test]
async fn test_slave_rejects_v1_master_and_accepts_next_valid_push() {
    use tokio_tungstenite::tungstenite::protocol::Role;

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let tracker = SlaveStatusTracker::new("slave-v1-master".to_string(), 4, None);
    let handles = test_handles(None).await;

    let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        slave_socket,
        Role::Client,
        Some(ws_config()),
    )
    .await;
    let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        peer_socket,
        Role::Server,
        Some(ws_config()),
    )
    .await;

    // A v1 master's ConfigPush has no protocol_version (deserialized as 0).
    let v1_text = r#"{"type":"config_push","version":5,"term":0,"hash_blake3":"h","signature_ed25519":"s","payload_b64":"p","payload_hash_blake3":"h"}"#;
    tracker.set_state(SlaveState::HelloSent);
    let err = handle_master_message(v1_text, &mut ws, &tracker, &handles, None)
        .await
        .expect_err("a v1 master must be rejected before applying its push");
    assert!(
        err.to_string().contains("protocol_mismatch"),
        "rejection must be actionable: {err}"
    );
    assert_eq!(
        tracker.get_version(),
        4,
        "a rejected v1 push must not advance the applied version"
    );
    assert_ne!(
        tracker.get_state(),
        SlaveState::Synced,
        "a rejected master must not leave the slave synced"
    );
    let readiness = tracker.readiness();
    assert!(!readiness.ready);
    assert!(
        readiness
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("protocol_mismatch"),
        "readiness must expose the protocol mismatch: {readiness:?}"
    );
    assert!(matches!(
        read_ack(&mut peer).await,
        HaMessage::Ack {
            applied: false,
            error: Some(ref error),
            ..
        } if error.contains("protocol_mismatch")
    ));

    // A later v2 connection (represented here by the next push on the same
    // socket) is still accepted: the rejection is per-peer, not sticky.
    let push = build_and_sign_push(
        &test_bundle(
            5,
            "config_version = 2\n[server]\nrole = \"slave\"\n",
            None,
            None,
        ),
        &signing_key,
    )
    .unwrap();
    tracker.set_state(SlaveState::HelloSent);
    handle_master_message(
        &push.to_json().unwrap(),
        &mut ws,
        &tracker,
        &handles,
        Some(&signing_key.public_key()),
    )
    .await
    .expect("a subsequent v2 push must be accepted");
    assert_eq!(tracker.get_version(), 5);
    assert_eq!(tracker.get_state(), SlaveState::Synced);
    assert!(tracker.readiness().ready);
    assert!(matches!(
        read_ack(&mut peer).await,
        HaMessage::Ack {
            version: 5,
            applied: true,
            ..
        }
    ));
}

/// The early-ACK path must reach `Synced`, but it must never clear a
/// `Degraded` state without a successful apply.
#[tokio::test]
async fn test_early_ack_marks_synced_but_keeps_degraded() {
    use tokio_tungstenite::tungstenite::protocol::Role;

    // Two raw WebSocket ends over a duplex pipe: the slave writes its ACK
    // on one end and the test reads it on the other.
    let (slave_socket, peer_socket) = tokio::io::duplex(64 * 1024);
    let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        slave_socket,
        Role::Client,
        Some(ws_config()),
    )
    .await;
    let mut peer = tokio_tungstenite::WebSocketStream::from_raw_socket(
        peer_socket,
        Role::Server,
        Some(ws_config()),
    )
    .await;
    let tracker = SlaveStatusTracker::new("slave-early".to_string(), 5, None);
    let handles = test_handles(None).await;
    let push = HaMessage::ConfigPush {
        protocol_version: crate::protocol::PROTOCOL_VERSION,
        version: 5,
        term: 0,
        hash_blake3: "hash".to_string(),
        signature_ed25519: "sig".to_string(),
        payload_b64: "payload".to_string(),
        payload_hash_blake3: "hash".to_string(),
    };
    let text = push.to_json().unwrap();

    tracker.set_state(SlaveState::HelloSent);
    handle_master_message(&text, &mut ws, &tracker, &handles, None)
        .await
        .unwrap();
    assert_eq!(tracker.get_state(), SlaveState::Synced);
    assert_eq!(tracker.get_version(), 5);
    let ack = peer.next().await.unwrap().unwrap();
    let ack = HaMessage::from_json(&ack.into_text().unwrap()).unwrap();
    assert!(matches!(
        ack,
        HaMessage::Ack {
            version: 5,
            term: 0,
            conflict: None,
            applied: true,
            ..
        }
    ));

    // Degraded is preserved by an early ACK (nothing was applied).
    tracker.mark_degraded("previous apply failed".to_string());
    handle_master_message(&text, &mut ws, &tracker, &handles, None)
        .await
        .unwrap();
    assert_eq!(tracker.get_state(), SlaveState::Degraded);
    assert_eq!(
        tracker.degraded_reason.lock().unwrap().as_deref(),
        Some("previous apply failed")
    );
}

/// Bracketed IPv6 master URLs must be parsed into a host/port pair (not a
/// formatted socket address), and malformed forms must fail loudly.
#[test]
fn test_parse_ws_url_ipv6_and_invalid_forms() {
    assert_eq!(
        parse_ws_url("wss://[::1]").unwrap(),
        (true, "::1".to_string(), 8953)
    );
    assert_eq!(
        parse_ws_url("wss://[2001:db8::1]:8953").unwrap(),
        (true, "2001:db8::1".to_string(), 8953)
    );
    assert_eq!(
        parse_ws_url("ws://[::1]:9000/path").unwrap(),
        (false, "::1".to_string(), 9000)
    );

    let err = parse_ws_url("wss://[::1").expect_err("unclosed bracket must fail");
    assert!(err.to_string().contains("Unclosed IPv6 bracket"));

    let err = parse_ws_url("wss://[::1]:not-a-port").expect_err("invalid port must fail");
    assert!(err.to_string().contains("Invalid port"));

    let err = parse_ws_url("wss://[::1]:99999").expect_err("out-of-range port must fail");
    assert!(err.to_string().contains("Invalid port"));
}

/// A clean master close uses a fixed 1 s reconnect delay and resets the error
/// backoff, while error paths keep growing exponentially.
#[test]
fn test_clean_close_reconnect_is_fixed_and_resets_error_backoff() {
    assert_eq!(CLEAN_CLOSE_RECONNECT_DELAY, Duration::from_secs(1));

    let mut backoff = ExponentialBackoff::default();
    let first = backoff.next_delay();
    let second = backoff.next_delay();
    assert!(
        second > first,
        "error backoff must grow: {first:?} then {second:?}"
    );

    // A clean close resets the generator, so the next failure starts at the
    // minimum delay instead of inheriting the clean-close loop.
    backoff.reset();
    let after_clean_close = backoff.next_delay();
    assert!(
        after_clean_close <= Duration::from_millis(1300),
        "a clean close must reset the error backoff: {after_clean_close:?}"
    );
}

/// A stalled peer must not pin the slave: the plaintext WebSocket
/// handshake is bounded by `SLAVE_HANDSHAKE_TIMEOUT`.
#[tokio::test(start_paused = true)]
async fn test_stalled_websocket_handshake_times_out() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    // Accept and send nothing: the HTTP upgrade never completes.
    let stall = tokio::spawn(async move {
        let _conn = listener.accept().await;
        tokio::time::sleep(Duration::from_secs(3600)).await;
    });

    let ha_config = HaConfig {
        master_url: Some(format!("ws://127.0.0.1:{port}")),
        allow_insecure_ws: true,
        ..Default::default()
    };
    let tracker = SlaveStatusTracker::new("slave-stall".to_string(), 0, None);
    let handles = test_handles(None).await;
    let mut resync_rx = {
        let (_tx, rx) = mpsc::channel(1);
        rx
    };
    let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

    let started = tokio::time::Instant::now();
    let err = connect_and_run(
        ha_config.master_url.as_deref().unwrap(),
        &ha_config,
        &tracker,
        &handles,
        None,
        &mut resync_rx,
        &mut shutdown_rx,
    )
    .await
    .expect_err("stalled handshake must time out");
    assert!(
        matches!(err, HaError::Timeout(_)),
        "expected a timeout error, got {err:?}"
    );
    assert!(started.elapsed() >= SLAVE_HANDSHAKE_TIMEOUT);
    stall.abort();
}

/// Regression (deferred D2): the liveness-timeout branch used to set
/// `Connecting` unconditionally, erasing the `Degraded` reason recorded by
/// a failed apply. It must mirror the reconnect loop's guard.
#[test]
fn test_master_liveness_loss_preserves_degraded_reason() {
    let tracker = SlaveStatusTracker::new("slave-degraded".to_string(), 4, None);
    tracker.mark_degraded("previous apply failed".to_string());

    record_master_liveness_loss(&tracker, "master heartbeat timed out".to_string());

    assert_eq!(
        tracker.get_state(),
        SlaveState::Degraded,
        "a liveness timeout must not clear a failed-apply state"
    );
    assert_eq!(
        tracker.degraded_reason.lock().unwrap().as_deref(),
        Some("previous apply failed"),
        "the operator must keep the apply-failure reason"
    );
    let readiness = tracker.readiness();
    assert!(
        !readiness.ready,
        "the transport failure must still be reported as not ready: {readiness:?}"
    );
    assert!(
        readiness
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("heartbeat timed out")),
        "the transport failure must remain visible: {readiness:?}"
    );
}

/// A healthy session that loses the master must drop out of `Synced`.
#[test]
fn test_master_liveness_loss_marks_connecting_when_not_degraded() {
    let tracker = SlaveStatusTracker::new("slave-synced".to_string(), 4, None);
    tracker.mark_synced(4);

    record_master_liveness_loss(&tracker, "master heartbeat timed out".to_string());

    assert_eq!(tracker.get_state(), SlaveState::Connecting);
    assert!(
        !tracker.readiness().ready,
        "a master-liveness loss must not report replication ready"
    );
}

/// A clean session end must not erase a failed-apply reason either.
#[test]
fn test_clean_session_end_preserves_degraded_reason() {
    let degraded = SlaveStatusTracker::new("slave-degraded".to_string(), 4, None);
    degraded.mark_degraded("previous apply failed".to_string());
    mark_session_ended(&degraded);
    assert_eq!(
        degraded.get_state(),
        SlaveState::Degraded,
        "a clean disconnect must not clear a failed-apply state"
    );
    assert_eq!(
        degraded.degraded_reason.lock().unwrap().as_deref(),
        Some("previous apply failed")
    );

    let synced = SlaveStatusTracker::new("slave-synced".to_string(), 4, None);
    synced.mark_synced(4);
    mark_session_ended(&synced);
    assert_eq!(synced.get_state(), SlaveState::Connecting);
}

/// A failed apply must survive reconnects: `Degraded` is not cleared by a
/// new connection attempt, only by a successful apply.
#[tokio::test]
async fn test_degraded_state_survives_reconnect_attempts() {
    let port = sito_test_support::reserve_port_number().unwrap();
    let ha_config = HaConfig {
        master_url: Some(format!("ws://127.0.0.1:{port}")),
        allow_insecure_ws: true,
        ..Default::default()
    };
    let tracker = SlaveStatusTracker::new("slave-degraded".to_string(), 4, None);
    tracker.mark_degraded("previous apply failed".to_string());
    let handles = test_handles(None).await;
    let (_resync_tx, resync_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = spawn_slave_worker(ha_config, tracker.clone(), handles, resync_rx, shutdown_rx);

    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        tracker.get_state(),
        SlaveState::Degraded,
        "reconnecting must not clear a Degraded state"
    );
    assert_eq!(
        tracker.degraded_reason.lock().unwrap().as_deref(),
        Some("previous apply failed")
    );

    let _ = shutdown_tx.send(true);
    worker.abort();
}

/// The WebSocket codec cap applies to the slave too: an oversized push is
/// rejected before it is parsed, not applied or ACKed.
#[tokio::test]
async fn test_slave_rejects_oversized_push() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let fake_master = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        // Read the Hello, then send a valid but oversized push.
        let _ = ws.next().await;
        let big = HaMessage::ConfigPush {
            protocol_version: crate::protocol::PROTOCOL_VERSION,
            version: 99,
            term: 0,
            hash_blake3: "h".to_string(),
            signature_ed25519: "s".to_string(),
            payload_b64: "x".repeat(2 * 1024 * 1024),
            payload_hash_blake3: "h".to_string(),
        };
        let _ = ws
            .send(WsMessage::Text(big.to_json().unwrap().into()))
            .await;
        tokio::time::sleep(Duration::from_secs(5)).await;
    });

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let ha_config = HaConfig {
        master_url: Some(format!("ws://127.0.0.1:{port}")),
        master_pubkey: Some(signing_key.public_key_hex()),
        allow_insecure_ws: true,
        ..Default::default()
    };
    let tracker = SlaveStatusTracker::new("slave-oversize".to_string(), 0, None);
    let handles = test_handles(None).await;
    let (_resync_tx, resync_rx) = mpsc::channel(1);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let worker = spawn_slave_worker(ha_config, tracker.clone(), handles, resync_rx, shutdown_rx);

    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        !matches!(
            tracker.get_state(),
            SlaveState::Degraded | SlaveState::Synced
        ),
        "an oversized push must be rejected by the codec, not processed (state: {:?})",
        tracker.get_state()
    );
    assert_eq!(tracker.get_version(), 0);

    let _ = shutdown_tx.send(true);
    worker.abort();
    fake_master.abort();
}

/// The WP-5.1 end-to-end scenario: a realistic master config with a
/// `[tls] key` path and structured `client_id_secrets` must replicate
/// successfully (no unresolvable `${SECRET:tls_key}` placeholder).
/// Certificate paths are node-local: the slave keeps its own `[tls]`
/// paths and the wire bundle must not carry the client secret.
#[tokio::test]
async fn test_push_with_tls_path_and_client_secrets_applies() {
    use crate::bundle::sanitize_config_for_bundle;

    let master_toml = r#"
config_version = 2

[server]
role = "master"
instance_name = "master-prod"

[ha]
replication_port = 8953

[tls]
cert = "/etc/sito/cert.pem"
key = "/etc/sito/tls.key"

[clients]
client_id_secrets = { "kids-tablet" = "client_shared_secret_9876" }
"#;
    let sanitized = sanitize_config_for_bundle(master_toml).unwrap();
    assert!(
        sanitized.contains("key = \"/etc/sito/tls.key\""),
        "the TLS key path must survive sanitization: {sanitized}"
    );
    assert!(!sanitized.contains("${SECRET:"));

    let mut secrets = toml::Table::new();
    secrets.insert(
        "kids-tablet".to_string(),
        toml::Value::String("client_shared_secret_9876".to_string()),
    );
    let mut clients = toml::Table::new();
    clients.insert("client_id_secrets".to_string(), toml::Value::Table(secrets));

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let bundle = ConfigBundle {
        config_digest: String::new(),
        signing_key_fingerprint: String::new(),
        clients: Some(toml::Value::Table(clients)),
        ..test_bundle(2, &sanitized, None, None)
    };
    let push = build_and_sign_push(&bundle, &signing_key).unwrap();

    let dir = std::env::temp_dir().join(format!("sito_ha_tls_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join("config.toml");
    // The slave keeps its node-local secret and TLS paths.
    tokio::fs::write(
            &path,
            "config_version = 2\n[server]\nrole = \"slave\"\ninstance_name = \"slave-tls\"\n\n[tls]\ncert = \"/etc/sito/slave.crt\"\nkey = \"/etc/sito/slave.key\"\n\n[clients]\nclient_id_secrets = { \"kids-tablet\" = \"client_shared_secret_9876\" }\n",
        )
        .await
        .unwrap();

    let tracker = SlaveStatusTracker::new("slave-tls".to_string(), 0, None);
    let handles = test_handles(Some(path.clone())).await;
    apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
        .await
        .expect("a config with a TLS key path and client secrets must replicate");
    assert_eq!(tracker.get_state(), SlaveState::Synced);

    // The persisted configuration keeps the node-local secret and the
    // slave's own TLS paths, and a restart can parse it.
    let persisted: toml::Table = tokio::fs::read_to_string(&path)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        persisted
            .get("tls")
            .and_then(|t| t.get("key"))
            .and_then(toml::Value::as_str),
        Some("/etc/sito/slave.key"),
        "the master's certificate path must not replace the slave's"
    );
    assert_eq!(
        persisted
            .get("clients")
            .and_then(|c| c.get("client_id_secrets"))
            .and_then(|s| s.get("kids-tablet"))
            .and_then(toml::Value::as_str),
        Some("client_shared_secret_9876"),
        "the node-local secret must be restored on the slave"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// `bundle.lists` is authoritative: the runtime filter engine and the
/// persisted file both get the metadata carried by the bundle.
#[tokio::test]
async fn test_bundle_list_metadata_is_authoritative() {
    use crate::bundle::FilterListMetadata;

    let signing_key = crate::crypto::Ed25519SigningKey::generate().unwrap();
    let dir = std::env::temp_dir().join(format!("sito_ha_lists_{}", rand::random::<u64>()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let path = dir.join("config.toml");
    // The local/pushed TOML has no lists at all.
    tokio::fs::write(&path, "[server]\nrole = \"slave\"\n")
        .await
        .unwrap();

    let tracker = SlaveStatusTracker::new("slave-lists".to_string(), 0, None);
    let handles = test_handles(Some(path.clone())).await;

    let mut bundle = test_bundle(
        1,
        "config_version = 2\n[server]\nrole = \"slave\"\n",
        None,
        None,
    );
    bundle.lists = vec![FilterListMetadata {
        name: "bundle-list".to_string(),
        url: "https://lists.example/hosts.txt".to_string(),
        enabled: true,
        refresh_hours: Some(12),
    }];
    let push = build_and_sign_push(&bundle, &signing_key).unwrap();
    apply_config_push(&push, &tracker, &handles, &signing_key.public_key())
        .await
        .unwrap();

    let snapshot = handles.runtime.snapshot();
    assert_eq!(snapshot.config.filtering.lists.len(), 1);
    assert_eq!(snapshot.config.filtering.lists[0].name, "bundle-list");
    assert_eq!(snapshot.config.filtering.lists[0].refresh_hours, Some(12));

    let persisted: toml::Table = tokio::fs::read_to_string(&path)
        .await
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        persisted
            .get("filtering")
            .and_then(|f| f.get("lists"))
            .and_then(toml::Value::as_array)
            .and_then(|lists| lists.first())
            .and_then(|list| list.get("name"))
            .and_then(toml::Value::as_str),
        Some("bundle-list"),
        "the persisted file must expose the bundle's list metadata"
    );

    let _ = tokio::fs::remove_dir_all(&dir).await;
}

/// Regression for audit WP-7.3: the metrics registry only holds lifetime
/// counters and lifetime upstream RTT accumulators, so a report labelled
/// with `window_s` must carry deltas since the previous report instead of
/// those lifetime values. Before the fix, `upstreams[*].rtt_ms`/`errors`
/// were the lifetime mean/total, so the idle second window below would
/// repeat them instead of reporting zero.
#[test]
fn test_stats_report_carries_window_deltas_not_lifetime_totals() {
    let metrics = MetricsRegistry::new("0.1.0", "test");

    // Activity before the first snapshot is outside every report window.
    metrics.inc_queries("udp", 1, "allowed");
    metrics.inc_queries("udp", 1, "blocked");
    metrics.observe_upstream_rtt("1.1.1.1:53", 0.020);
    metrics.inc_upstream_errors("1.1.1.1:53", "timeout");
    let initial = metrics.snapshot();

    // Window 1: three queries (one blocked), one 30 ms RTT sample, one error.
    metrics.inc_queries("udp", 1, "allowed");
    metrics.inc_queries("udp", 28, "allowed");
    metrics.inc_queries("udp", 1, "blocked");
    metrics.observe_upstream_rtt("1.1.1.1:53", 0.030);
    metrics.inc_upstream_errors("1.1.1.1:53", "timeout");

    let (report, snapshot) = build_stats_report(&metrics, &initial, 30);
    match &report {
        HaMessage::StatsReport {
            window_s,
            queries,
            blocked,
            upstreams,
        } => {
            assert_eq!(*window_s, 30);
            assert_eq!(
                *queries, 3,
                "only queries since the previous snapshot belong to the window"
            );
            assert_eq!(*blocked, 1);
            let upstream = upstreams.get("1.1.1.1:53").expect("upstream report");
            assert!(
                (upstream.rtt_ms - 30.0).abs() < 1e-6,
                "window mean must not mix in pre-window samples: {}",
                upstream.rtt_ms
            );
            assert_eq!(upstream.errors, 1);
        }
        other => panic!("expected a StatsReport, got {other:?}"),
    }

    // Window 2: no new activity. The lifetime totals are still non-zero, so
    // a report built from them would fail every assertion below.
    let (report, _snapshot) = build_stats_report(&metrics, &snapshot, 30);
    match &report {
        HaMessage::StatsReport {
            queries,
            blocked,
            upstreams,
            ..
        } => {
            assert_eq!(*queries, 0);
            assert_eq!(*blocked, 0);
            let upstream = upstreams.get("1.1.1.1:53").expect("upstream report");
            assert!(
                upstream.rtt_ms.abs() < f64::EPSILON,
                "an idle window must report no RTT samples, got {}",
                upstream.rtt_ms
            );
            assert_eq!(upstream.errors, 0);
        }
        other => panic!("expected a StatsReport, got {other:?}"),
    }
}
