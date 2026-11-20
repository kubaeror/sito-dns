//! Application of a master configuration push to the local server.

use std::collections::HashMap;

use tracing::{error, info};

use sito_clients::ClientsConfig;
use sito_core::config::{Config, FilterListConfig};
use sito_rewrites::RewritesConfig;

use crate::bundle::{
    push_payload_hash, shared_config_digest, substitute_secrets,
    verify_and_unpack_push_with_watermark,
};
use crate::error::HaError;
use crate::protocol::HaMessage;
use crate::slave::state::SlaveStatusTracker;

use super::SlaveAppHandles;
use super::config_merge::{build_persisted_config, local_client_id_secrets};

/// Applies a configuration push to the local server handles.
///
/// Implements rollback safety: if staging verification, validation or the
/// atomic persist fails, the previous configuration stays live, the state
/// transitions to `Degraded`, and an error is returned (the caller then ACKs
/// `applied: false`). Persisting happens before the push is acknowledged, so a
/// push is never reported as applied when it is not durable.
pub async fn apply_config_push(
    push: &HaMessage,
    tracker: &SlaveStatusTracker,
    handles: &SlaveAppHandles,
    master_pubkey: &[u8],
) -> Result<u64, HaError> {
    let watermark = tracker.get_watermark();

    // 1. Verify cryptographic signature, checksum, term and monotonicity
    //    against the persisted watermark (not only the in-memory counter, so a
    //    process restart cannot lose the replay guard).
    let bundle =
        match verify_and_unpack_push_with_watermark(push, watermark.as_ref(), master_pubkey) {
            Ok(b) => b,
            Err(e) => {
                tracker.mark_degraded(format!("Validation/Signature verification failed: {e}"));
                return Err(e);
            }
        };
    let payload_hash = match push_payload_hash(push) {
        Ok(hash) => hash,
        Err(e) => {
            tracker.mark_degraded(format!("Validation/Signature verification failed: {e}"));
            return Err(e);
        }
    };

    // Before the first watermark exists (fresh node or a test harness), fall
    // back to the in-memory applied version so the monotonicity guard is not
    // weakened by the watermark refactor.
    if watermark.is_none() && bundle.version <= tracker.get_version() {
        let err = HaError::Validation {
            field: "version".to_string(),
            reason: format!(
                "Push version {} is not greater than the current applied version {} (monotonicity violation/replay rejected)",
                bundle.version,
                tracker.get_version()
            ),
        };
        tracker.mark_degraded(format!("Validation/Signature verification failed: {err}"));
        return Err(err);
    }

    // An identical re-delivery of the already-applied bundle needs no work and
    // must not rewrite local configuration; acknowledge it as synced. A newer
    // term with the same payload only records the promoted epoch. A locally
    // drifted configuration (or a legacy watermark without a digest) must not
    // take this shortcut: it has to apply the bundle so the on-disk document
    // matches the shared state and a digest is recorded.
    if let Some(ref applied) = watermark
        && bundle.version == applied.version
        && payload_hash == applied.normalized_hash()
        && !tracker.requires_full_apply()
    {
        if bundle.term > applied.term {
            tracker.persist_watermark_with_identity(
                bundle.version,
                bundle.term,
                &payload_hash,
                applied.applied_config_digest.as_deref(),
                Some(&bundle.signing_key_fingerprint),
            )?;
        }
        tracker.mark_synced_with_term(bundle.version, bundle.term);
        return Ok(bundle.version);
    }

    // 2. Secret substitution. Placeholders resolve from the process
    // environment only (`DNSD_SECRET_<NAME>`, then `<NAME>`); there is no
    // on-disk local secret store. Fail closed: a push referencing a secret
    // this slave does not have must be rejected rather than silently replacing
    // credentials with empty strings.
    let substituted_toml = match substitute_secrets(&bundle.config_toml, &HashMap::new(), false) {
        Ok(s) => s,
        Err(e) => {
            tracker.mark_degraded(format!("Secret substitution failed: {e}"));
            return Err(e);
        }
    };

    // 3. Staging configuration validation
    let mut staging_config = match Config::from_toml_str(&substituted_toml) {
        Ok(cfg) => cfg,
        Err(e) => {
            let reason = format!("Staging configuration validation failed: {e}");
            tracker.mark_degraded(reason.clone());
            return Err(HaError::Validation {
                field: "config".to_string(),
                reason,
            });
        }
    };

    // The structured bundle fields are authoritative: a `null` `rewrites`
    // value means "remove the local rewrites", not "keep the previous ones".
    // Validate the typed rewrites here; the raw value is copied verbatim into
    // the applied/persisted configuration below so a restart observes exactly
    // what was applied.
    let _staging_rewrites: Option<RewritesConfig> = match bundle.rewrites {
        Some(ref r_val) => match r_val.clone().try_into() {
            Ok(rc) => Some(rc),
            Err(e) => {
                let reason = format!("Staging rewrites parsing failed: {e}");
                tracker.mark_degraded(reason.clone());
                return Err(HaError::Validation {
                    field: "rewrites".to_string(),
                    reason,
                });
            }
        },
        None => None,
    };

    // Staging clients validation if present. Per-client shared secrets are
    // stripped from replicated configuration; keep the node-local values.
    let mut staging_clients: Option<ClientsConfig> = match bundle.clients {
        Some(ref c_val) => match c_val.clone().try_into() {
            Ok(cc) => Some(cc),
            Err(e) => {
                let reason = format!("Staging clients parsing failed: {e}");
                tracker.mark_degraded(reason.clone());
                return Err(HaError::Validation {
                    field: "clients".to_string(),
                    reason,
                });
            }
        },
        None => None,
    };
    // Node-local state is read from the live runtime snapshot, not re-read
    // from disk: the file may be unreadable or mid-edit, and the running
    // configuration is the authoritative node-local state.
    let live_config = handles.runtime.config_handle().load_full();
    if let Some(ref mut clients) = staging_clients {
        for (name, secret) in local_client_id_secrets(&live_config) {
            clients.client_id_secrets.entry(name).or_insert(secret);
        }
    }

    // Mirror the authoritative fields into the parsed Config so the snapshot,
    // the filter engine and the persisted file cannot disagree.
    staging_config.clients = match staging_clients {
        Some(ref clients) => {
            Some(
                toml::Value::try_from(clients).map_err(|e| HaError::Validation {
                    field: "clients".to_string(),
                    reason: format!("Failed to serialize staged clients configuration: {e}"),
                })?,
            )
        }
        None => None,
    };
    staging_config.rewrites.clone_from(&bundle.rewrites);
    staging_config
        .filtering
        .custom_rules
        .clone_from(&bundle.custom_rules);
    staging_config.filtering.lists = bundle
        .lists
        .iter()
        .map(|meta| FilterListConfig {
            name: meta.name.clone(),
            url: meta.url.clone(),
            enabled: meta.enabled,
            refresh_hours: meta.refresh_hours,
        })
        .collect();

    // 4. Build the document that will be persisted. Node-local settings
    //    (`[ha]`, instance identity, RouterOS credentials) are merged back in,
    //    and the bundle's structured clients/rewrites/lists remain
    //    authoritative. Applying exactly this document guarantees the running
    //    configuration and the file a restart loads cannot diverge.
    let document = match build_persisted_config(
        &substituted_toml,
        &bundle,
        handles.config_path.as_deref(),
        &live_config,
        staging_config.clients.clone(),
    )
    .await
    {
        Ok(document) => document,
        Err(e) => {
            let reason = format!(
                "Refusing to persist pushed configuration without the node-local configuration: {e}"
            );
            error!(error = %e, "Refusing to apply pushed configuration");
            tracker.mark_degraded(reason.clone());
            return Err(HaError::Rollback(reason));
        }
    };
    let apply_config = match Config::from_toml_str(&document) {
        Ok(cfg) => cfg,
        Err(e) => {
            let reason = format!("Merged pushed configuration is invalid: {e}");
            tracker.mark_degraded(reason.clone());
            return Err(HaError::Validation {
                field: "config".to_string(),
                reason,
            });
        }
    };

    // 5. Single apply/persist path. The applier applies every component
    //    (including the hook-owned DNSSEC/listener/scoped-upstream pieces) and
    //    persists the document atomically. It rolls the in-memory apply back
    //    when the persist fails, so on `Err` nothing has changed durably or
    //    live, the version does not advance, and the caller ACKs
    //    `applied: false`.
    if let Err(e) = handles
        .applier
        .apply_and_persist(&apply_config, &document)
        .await
    {
        let reason = format!("Failed to apply pushed configuration: {e}");
        error!(
            error = %e,
            "Failed to apply pushed configuration; refusing to acknowledge the push"
        );
        tracker.mark_degraded(reason.clone());
        return Err(HaError::Rollback(reason));
    }

    // Persist the applied-version watermark and the digest of the shared
    // projection of the document that was applied before acknowledging: a
    // crash between apply and ACK must still leave a restart able to reject
    // replays and detect a shared-field edit, while node-local edits (identity,
    // listener/TLS, secrets) do not force a spurious full apply.
    let applied_config_digest = shared_config_digest(&document);
    if let Err(e) = tracker.persist_watermark_with_identity(
        bundle.version,
        bundle.term,
        &payload_hash,
        Some(&applied_config_digest),
        Some(&bundle.signing_key_fingerprint),
    ) {
        let reason = format!("Failed to persist the applied-version watermark: {e}");
        error!(
            error = %e,
            version = bundle.version,
            "Configuration was applied but the watermark could not be persisted; refusing to acknowledge"
        );
        tracker.mark_degraded(reason.clone());
        return Err(HaError::Rollback(reason));
    }

    // Mark tracker as synced (a successful apply is the only path that clears
    // a `Degraded` state).
    tracker.mark_synced_with_term(bundle.version, bundle.term);
    #[allow(clippy::cast_precision_loss)]
    handles
        .metrics
        .set_ha_config_version(&tracker.instance_name, bundle.version as f64);

    info!(
        instance = %tracker.instance_name,
        version = bundle.version,
        "Successfully applied and synchronized configuration bundle from master"
    );

    Ok(bundle.version)
}
