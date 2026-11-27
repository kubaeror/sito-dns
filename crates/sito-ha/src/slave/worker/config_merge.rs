//! Merge of node-local settings back into a pushed configuration document.

use std::collections::HashMap;

use tracing::warn;

use sito_core::config::Config;

use crate::bundle::{ConfigBundle, NODE_LOCAL_WEB_KEYS};
use crate::error::HaError;

/// Builds the TOML document that is persisted after a successful push.
///
/// Merges slave-local state back into the pushed configuration:
///
/// * `[ha]` (master URL, certificates, pins, token) is slave-local and is
///   removed by `sanitize_config_for_bundle` on the master.
/// * `server.role` is forced to `slave`; `server.instance_name`,
///   `server.data_dir`, `server.log_level` and `server.log_format` identify
///   this node and must not be replaced by the master's values. Logging is
///   part of the same node-local projection the edit-time shared gate uses, so
///   a local log edit survives every push and does not count as shared drift.
/// * `[integrations.mikrotik]` credentials are stripped from the replicated
///   configuration and restored from the live node-local configuration.
///
/// The node-local values come from the running configuration, not a fresh disk
/// read: a transient read error or a mid-edit file must not silently drop
/// `[ha]`/identity/credentials. When `local_path` is set, the file is still
/// read once to fail the push if it is unreadable or unparseable, because
/// persisting over it would destroy the only copy of that node-local state.
///
/// The structured bundle fields (`clients`, `rewrites`, `lists`,
/// `custom_rules`) are authoritative: a missing field removes the
/// corresponding configuration instead of keeping the previous copy, so the
/// persisted file matches the runtime snapshot exactly.
pub(super) async fn build_persisted_config(
    pushed_toml: &str,
    bundle: &ConfigBundle,
    local_path: Option<&std::path::Path>,
    live: &Config,
    clients_value: Option<toml::Value>,
) -> Result<String, HaError> {
    let mut pushed = pushed_toml
        .parse::<toml::Table>()
        .map_err(|e| HaError::Validation {
            field: "config".to_string(),
            reason: format!("Pushed configuration is not valid TOML: {e}"),
        })?;

    if let Some(path) = local_path {
        let raw = tokio::fs::read_to_string(path).await.map_err(HaError::Io)?;
        raw.parse::<toml::Table>()
            .map_err(|e| HaError::Validation {
                field: "config".to_string(),
                reason: format!(
                    "Cannot parse node-local configuration '{}': {e}",
                    path.display()
                ),
            })?;
    }

    // `[ha]` is node-local. If the live configuration has none, never leave
    // the master's copy in place.
    match live.ha {
        Some(ref ha) => {
            pushed.insert("ha".to_string(), ha.clone());
        }
        None => {
            pushed.remove("ha");
        }
    }

    let server = pushed
        .entry("server".to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| HaError::Validation {
            field: "server".to_string(),
            reason: "Pushed [server] section is not a table".to_string(),
        })?;
    server.insert("role".to_string(), toml::Value::String("slave".to_string()));
    server.insert(
        "instance_name".to_string(),
        toml::Value::String(live.server.instance_name.clone()),
    );
    server.insert(
        "data_dir".to_string(),
        toml::Value::String(live.server.data_dir.to_string_lossy().into_owned()),
    );
    // Logging is node-local (`shared_config_diff` and `shared_config_digest`
    // exclude it), so the local values must be preserved here too: otherwise a
    // local log-level edit would be silently reverted by the next push and the
    // digest would no longer flag that revert as drift.
    server.insert(
        "log_level".to_string(),
        toml::Value::String(live.server.log_level.clone()),
    );
    server.insert(
        "log_format".to_string(),
        toml::Value::String(live.server.log_format.clone()),
    );

    // Node-local listener, TLS and ACME identity. The master's bind addresses
    // may not exist on this node (or may already be in use) and its
    // certificate paths are local to the master, so the live node-local values
    // are authoritative for the persisted document.
    preserve_node_local_listener_config(&mut pushed, live)?;

    // `[integrations.mikrotik]` describes the router on this node's LAN and
    // carries per-node credentials. None of it is shared cluster state.
    preserve_node_local_mikrotik(&mut pushed, live)?;

    // Authoritative removal: the bundle's structured fields decide whether the
    // section exists at all. `clients_value` already includes the node-local
    // `client_id_secrets` merged back in.
    match clients_value {
        Some(value) => {
            pushed.insert("clients".to_string(), value);
        }
        None => {
            pushed.remove("clients");
        }
    }
    match bundle.rewrites {
        Some(ref value) => {
            pushed.insert("rewrites".to_string(), value.clone());
        }
        None => {
            pushed.remove("rewrites");
        }
    }
    if pushed.contains_key("filtering")
        || !bundle.custom_rules.is_empty()
        || !bundle.lists.is_empty()
    {
        let filtering = pushed
            .entry("filtering".to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if let toml::Value::Table(filtering) = filtering {
            filtering.insert(
                "custom_rules".to_string(),
                toml::Value::Array(
                    bundle
                        .custom_rules
                        .iter()
                        .map(|r| toml::Value::String(r.clone()))
                        .collect(),
                ),
            );
            match toml::Value::try_from(&bundle.lists) {
                Ok(lists) => {
                    filtering.insert("lists".to_string(), lists);
                }
                Err(e) => {
                    warn!(error = %e, "Failed to serialize bundle list metadata; keeping pushed lists");
                }
            }
        }
    }

    toml::to_string_pretty(&pushed).map_err(|e| HaError::Serialization(e.to_string()))
}

/// Encodes a serializable configuration section as a TOML value.
fn section_value<T: serde::Serialize>(value: &T) -> Result<toml::Value, HaError> {
    toml::Value::try_from(value).map_err(|e| HaError::Serialization(e.to_string()))
}

/// Returns `table[key]` as a mutable table, creating it when absent.
fn ensure_section<'a>(
    table: &'a mut toml::Table,
    key: &str,
) -> Result<&'a mut toml::Table, HaError> {
    table
        .entry(key.to_string())
        .or_insert_with(|| toml::Value::Table(toml::Table::new()))
        .as_table_mut()
        .ok_or_else(|| HaError::Validation {
            field: key.to_string(),
            reason: format!("Pushed [{key}] section is not a table"),
        })
}

/// Restores the node-local listener, TLS and ACME identity into `pushed`.
///
/// The master's `dns.bind` addresses, the complete `[web]` identity,
/// certificate paths and ACME account/cache settings are local to the master
/// node. A slave with different addresses would fail to bind (or expose the
/// admin UI on the wrong interface) and its TLS material lives at different
/// paths.
fn preserve_node_local_listener_config(
    pushed: &mut toml::Table,
    live: &Config,
) -> Result<(), HaError> {
    {
        let dns = ensure_section(pushed, "dns")?;
        dns.insert(
            "bind".to_string(),
            toml::Value::Array(
                live.dns
                    .bind
                    .iter()
                    .map(|addr| toml::Value::String(addr.to_string()))
                    .collect(),
            ),
        );
        match live.dns.tls.as_ref() {
            Some(tls) => {
                dns.insert("tls".to_string(), section_value(tls)?);
            }
            None => {
                dns.remove("tls");
            }
        }
    }

    match live.tls.as_ref() {
        Some(tls) => {
            pushed.insert("tls".to_string(), section_value(tls)?);
        }
        None => {
            pushed.remove("tls");
        }
    }

    match live.acme.as_ref() {
        Some(acme) => {
            pushed.insert("acme".to_string(), section_value(acme)?);
        }
        None => {
            pushed.remove("acme");
        }
    }

    // Only materialize `[web]` when either side declares it; a node that never
    // configured it keeps using the built-in defaults. Read the raw local
    // table so keys that only exist in raw form (`public_url`,
    // `tls_terminated_by_proxy`) survive as well. A key absent locally is
    // removed instead of inherited so the slave's effective default applies;
    // cluster-shared `[web]` keys (legacy `acme_*`) still come from the push.
    if pushed.contains_key("web") || live.web.is_some() {
        let local_web = live
            .web
            .as_ref()
            .and_then(toml::Value::as_table)
            .cloned()
            .unwrap_or_default();
        let web = ensure_section(pushed, "web")?;
        for key in NODE_LOCAL_WEB_KEYS {
            match local_web.get(key) {
                Some(value) => {
                    web.insert(key.to_string(), value.clone());
                }
                None => {
                    web.remove(key);
                }
            }
        }
    }

    Ok(())
}

/// Restores the node-local `[integrations.mikrotik]` section into `pushed`.
///
/// The router lives on this node's LAN and carries per-node credentials, so
/// the whole section is node-local rather than only `token`/`password`.
fn preserve_node_local_mikrotik(pushed: &mut toml::Table, live: &Config) -> Result<(), HaError> {
    let local = live
        .integrations
        .as_ref()
        .and_then(|integrations| integrations.get("mikrotik"))
        .cloned();
    match local {
        Some(value) => {
            let integrations = ensure_section(pushed, "integrations")?;
            integrations.insert("mikrotik".to_string(), value);
        }
        None => {
            if let Some(integrations) = pushed
                .get_mut("integrations")
                .and_then(toml::Value::as_table_mut)
            {
                integrations.remove("mikrotik");
            }
        }
    }

    // An empty `[integrations]` left over from removing the master's MikroTik
    // section would look like a restart-only `integrations` change on the next
    // apply, so drop it entirely.
    if pushed
        .get("integrations")
        .and_then(toml::Value::as_table)
        .is_some_and(toml::Table::is_empty)
    {
        pushed.remove("integrations");
    }

    Ok(())
}

/// Reads the node-local `[clients] client_id_secrets` table (name -> secret)
/// from the live configuration.
pub(super) fn local_client_id_secrets(config: &Config) -> HashMap<String, String> {
    config
        .clients
        .as_ref()
        .and_then(|clients| clients.get("client_id_secrets"))
        .and_then(toml::Value::as_table)
        .map(|secrets| {
            secrets
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .as_str()
                        .map(|secret| (name.clone(), secret.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}
