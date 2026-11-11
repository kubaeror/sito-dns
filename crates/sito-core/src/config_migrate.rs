//! Config v1 → v2 migration (D4, WP-1.3).
//!
//! Migration is **behavior-preserving** by default: every known v1 key/value
//! is copied, even when the 2.0 default differs. `--adopt-safe-defaults` opts
//! into the documented 2.0 safe defaults; `--ignore-unknown-keys` is the only
//! path that drops unknown keys, and it reports each drop.

use crate::config::{CONFIG_VERSION, CONFIG_VERSION_V1, Config};
use crate::config_schema::{FieldStatus, schema};
use crate::error::ConfigError;
use serde::{Deserialize, Serialize};

/// Options for [`Config::migrate_v1_to_v2`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MigrationOptions {
    /// Replace the documented safety defaults with their 2.0 values instead
    /// of preserving the v1 effective behavior.
    pub adopt_safe_defaults: bool,
    /// Drop unknown keys instead of failing. Each drop is listed in
    /// [`MigrationReport::unknown_dropped`].
    pub ignore_unknown_keys: bool,
}

/// One moved, removed or dead key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationChange {
    /// v1 dotted path.
    pub from: String,
    /// v2 dotted path, when the key was moved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// Why the key changed.
    pub reason: String,
}

/// Machine-readable migration report (also printed by the CLI).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MigrationReport {
    pub from_version: u32,
    pub to_version: u32,
    /// Keys moved to a canonical v2 path (`[dns.tls]`, `[web] acme_*`,
    /// legacy aliases).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub moved: Vec<MigrationChange>,
    /// Keys removed because config v2 no longer accepts them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<MigrationChange>,
    /// Unknown keys dropped because `--ignore-unknown-keys` was passed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_dropped: Vec<String>,
    /// v1 defaults written explicitly so the effective v1 behavior survives
    /// the config v2 default change (for example `web.bind = "0.0.0.0"`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub defaults_materialized: Vec<String>,
    /// Safe 2.0 defaults adopted because `--adopt-safe-defaults` was passed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_defaults_applied: Vec<String>,
    /// Non-fatal notes (for example, both a legacy alias and its canonical
    /// key were present and the canonical value won).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Result of a successful migration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationOutcome {
    /// The migrated, validated v2 TOML document.
    pub document: String,
    pub report: MigrationReport,
}

/// Migrates a v1 TOML document to config v2.
pub(crate) fn migrate(
    source: &str,
    options: MigrationOptions,
) -> Result<MigrationOutcome, ConfigError> {
    let mut table: toml::Table =
        toml::from_str(source).map_err(|e| ConfigError::Parse(e.to_string()))?;

    let found = table
        .get("config_version")
        .and_then(toml::Value::as_integer)
        .map_or(CONFIG_VERSION_V1, |value| {
            u32::try_from(value).unwrap_or(u32::MAX)
        });
    if found != CONFIG_VERSION_V1 {
        return Err(ConfigError::UnsupportedVersion {
            found,
            supported: CONFIG_VERSION,
        });
    }

    let mut report = MigrationReport {
        from_version: CONFIG_VERSION_V1,
        to_version: CONFIG_VERSION,
        ..MigrationReport::default()
    };

    let mut unknown = schema().unknown_keys(&table);
    unknown.sort();
    if !unknown.is_empty() {
        if !options.ignore_unknown_keys {
            let first = unknown.first().cloned().unwrap_or_default();
            return Err(ConfigError::UnknownKey {
                section: first.split('.').next().unwrap_or_default().to_string(),
                key: first,
            });
        }
        report.unknown_dropped = schema().remove_unknown_keys(&mut table);
        report.unknown_dropped.sort();
        report.unknown_dropped.dedup();
    }

    // 1. Resolve table-level v1 precedence before moving individual aliases.
    //
    // v1 selected either the whole `[acme]` table or the whole `[web] acme_*`
    // block, and either the whole `[dns.tls]` table or the whole `[tls]`
    // table. Merging the loser's fields would change the effective
    // configuration (enable issuance, resurrect ignored SNI certificates).
    if table.get("acme").is_some() {
        for alias in [
            "acme_enabled",
            "acme_email",
            "acme_domains",
            "acme_staging",
            "acme_cache_dir",
        ] {
            let path = format!("web.{alias}");
            if remove_path(&mut table, &path).is_some() {
                report.removed.push(MigrationChange {
                    from: path,
                    to: None,
                    reason: "v1 ignored this alias because the [acme] table exists; it was dropped"
                        .to_string(),
                });
            }
        }
    }

    if let Some(dns_tls) = remove_path(&mut table, "dns.tls") {
        let child_keys: Vec<String> = dns_tls
            .as_table()
            .map(|table| table.keys().cloned().collect())
            .unwrap_or_default();
        if table.contains_key("tls") {
            report.warnings.push(
                "both [dns.tls] and [tls] were present; v1 preferred [dns.tls], so the whole [tls] table was replaced"
                    .to_string(),
            );
        }
        if child_keys.is_empty() {
            report.moved.push(MigrationChange {
                from: "dns.tls".to_string(),
                to: Some("tls".to_string()),
                reason: "deprecated v1 alias rewritten to its config v2 path".to_string(),
            });
        } else {
            for key in child_keys {
                report.moved.push(MigrationChange {
                    from: format!("dns.tls.{key}"),
                    to: Some(format!("tls.{key}")),
                    reason: "deprecated v1 alias rewritten to its config v2 path".to_string(),
                });
            }
        }
        table.insert("tls".to_string(), dns_tls);
    }

    // 2. Rewrite deprecated aliases to their canonical v2 paths. The schema
    //    map is the single source of truth for the movement.
    let deprecated: Vec<(String, String)> = schema()
        .fields()
        .iter()
        .filter(|field| field.status == FieldStatus::Deprecated)
        .filter_map(|field| field.to.as_ref().map(|to| (field.path.clone(), to.clone())))
        .collect();
    for (from, to) in deprecated {
        let Some(value) = remove_path(&mut table, &from) else {
            continue;
        };
        if get_path(&table, &to).is_some() {
            // v1 precedence: get_tls_config prefers `[dns.tls]` over `[tls]`,
            // while get_acme_config prefers typed `[acme]` over `[web]
            // acme_*`. Preserve the effective v1 value in both conflicts.
            if from.starts_with("dns.tls.") {
                report.warnings.push(format!(
                    "'{from}' and '{to}' were both present; v1 preferred [dns.tls], so the alias value was kept"
                ));
                insert_path(&mut table, &to, value);
            } else {
                report.warnings.push(format!(
                    "'{from}' and its canonical replacement '{to}' were both present; the canonical value was kept and '{from}' was dropped"
                ));
            }
            report.moved.push(MigrationChange {
                from,
                to: Some(to),
                reason: "deprecated v1 alias rewritten to its config v2 path".to_string(),
            });
            continue;
        }
        insert_path(&mut table, &to, value);
        report.moved.push(MigrationChange {
            from,
            to: Some(to),
            reason: "deprecated v1 alias rewritten to its config v2 path".to_string(),
        });
    }
    // Removing every alias can leave an empty `[dns.tls]`/`[web]` shell.
    remove_empty_table(&mut table, "dns", "tls");

    // 3. Remove keys config v2 no longer accepts. They are reported so an
    //    operator can audit what happened even though the values were inert.
    let removed: Vec<String> = schema()
        .fields()
        .iter()
        .filter(|field| matches!(field.status, FieldStatus::Removed | FieldStatus::Dead))
        .map(|field| field.path.clone())
        .collect();
    for path in removed {
        if let Some(_value) = remove_path(&mut table, &path) {
            report.removed.push(MigrationChange {
                from: path,
                to: None,
                reason: "removed from config v2; it was not part of the runtime configuration"
                    .to_string(),
            });
        }
    }

    table.insert(
        "config_version".to_string(),
        toml::Value::Integer(i64::from(CONFIG_VERSION)),
    );

    // 4. Preserve the v1 effective admin bind. `web.bind` was optional in
    //    1.9 and defaulted to 0.0.0.0; silently inheriting the v2 loopback
    //    default would make the admin UI unreachable after an upgrade.
    if options.adopt_safe_defaults {
        report.safe_defaults_applied = adopt_safe_defaults(&mut table);
    } else if get_path(&table, "web.bind").is_none() {
        insert_path(
            &mut table,
            "web.bind",
            toml::Value::String("0.0.0.0".to_string()),
        );
        report.defaults_materialized.push("web.bind".to_string());
    }

    let document =
        toml::to_string_pretty(&table).map_err(|e| ConfigError::Migration(e.to_string()))?;

    // The migrated document must be loadable by the normal v2 parser. This is
    // the same fail-closed path startup uses.
    Config::from_toml_str(&document).map_err(|e| {
        ConfigError::Migration(format!("the migrated document is not valid config v2: {e}"))
    })?;

    Ok(MigrationOutcome { document, report })
}

/// The documented 2.0 safe defaults. Only settings whose v1 effective value
/// differs from the 2.0 default are rewritten and reported.
fn adopt_safe_defaults(table: &mut toml::Table) -> Vec<String> {
    let mut applied = Vec::new();

    // Loopback admin UI (plain HTTP). Materialize it even when the v1 file
    // omitted web.bind, otherwise the requested safe default would not take
    // effect.
    set_if_different(
        table,
        "web.bind",
        toml::Value::String("127.0.0.1".to_string()),
        true,
        &mut applied,
    );
    // Fail closed when every filter source fails at first boot.
    set_if_different(
        table,
        "filtering.fail_closed",
        toml::Value::Boolean(true),
        false,
        &mut applied,
    );
    // Require authentication for /metrics.
    set_if_different(
        table,
        "web.metrics_auth",
        toml::Value::Boolean(true),
        false,
        &mut applied,
    );
    // No self-signed bootstrap certificate on encrypted listeners.
    if get_path(table, "acme").is_some() {
        set_if_different(
            table,
            "acme.allow_bootstrap_cert",
            toml::Value::Boolean(false),
            false,
            &mut applied,
        );
    }
    // Hostname upstreams may not resolve to private/reserved addresses.
    set_if_different(
        table,
        "upstream.allow_private_targets",
        toml::Value::Boolean(false),
        false,
        &mut applied,
    );
    // API tokens expire by default.
    set_if_different(
        table,
        "auth.token_default_ttl_days",
        toml::Value::Integer(90),
        false,
        &mut applied,
    );
    // Rollups do not retain device labels.
    set_if_different(
        table,
        "stats.rollup_client_names",
        toml::Value::Boolean(false),
        false,
        &mut applied,
    );
    // Release signatures required for in-app updates.
    set_if_different(
        table,
        "server.update_require_signature",
        toml::Value::Boolean(true),
        false,
        &mut applied,
    );
    applied
}

fn set_if_different(
    table: &mut toml::Table,
    path: &str,
    value: toml::Value,
    materialize_if_absent: bool,
    applied: &mut Vec<String>,
) {
    if get_path(table, path).is_none() {
        // Most absent keys already resolve to the 2.0 default; only a setting
        // whose 2.0 default changed from v1 needs an explicit value.
        if materialize_if_absent {
            insert_path(table, path, value);
            applied.push(path.to_string());
        }
        return;
    }
    if get_path(table, path) == Some(&value) {
        return;
    }
    insert_path(table, path, value);
    applied.push(path.to_string());
}

fn get_path<'a>(table: &'a toml::Table, path: &str) -> Option<&'a toml::Value> {
    let mut parts = path.split('.');
    let first = parts.next()?;
    let mut current = table.get(first)?;
    for part in parts {
        current = current.as_table()?.get(part)?;
    }
    Some(current)
}

fn insert_path(table: &mut toml::Table, path: &str, value: toml::Value) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let leaf = parts.pop().expect("a path has at least one segment");
    let mut current = table;
    for part in parts {
        let entry = current
            .entry(part.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if !entry.is_table() {
            *entry = toml::Value::Table(toml::Table::new());
        }
        current = entry.as_table_mut().expect("inserted a table");
    }
    current.insert(leaf.to_string(), value);
}

fn remove_path(table: &mut toml::Table, path: &str) -> Option<toml::Value> {
    let mut parts: Vec<&str> = path.split('.').collect();
    let leaf = parts.pop()?;
    let mut current = table;
    for part in parts {
        current = current.get_mut(part)?.as_table_mut()?;
    }
    current.remove(leaf)
}

fn remove_empty_table(table: &mut toml::Table, parent: &str, child: &str) {
    let Some(parent_table) = table.get_mut(parent).and_then(toml::Value::as_table_mut) else {
        return;
    };
    if parent_table
        .get(child)
        .and_then(toml::Value::as_table)
        .is_some_and(toml::Table::is_empty)
    {
        parent_table.remove(child);
    }
}
