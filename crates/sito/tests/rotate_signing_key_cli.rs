//! Real-binary acceptance for `sito ha rotate-signing-key`.
//!
//! The unit tests exercise the rotation algorithm and the CLI function; this
//! test proves the shipped command refuses without `--confirm`, refuses while a
//! live service owns the data directory, rotates offline, prints the new
//! `master_pubkey`, and releases its temporary service lease.

#![cfg(feature = "ha")]

use std::fmt::Write as _;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sito_ha::{
    ConfigBundle, Ed25519SigningKey, HaStateStore, PROTOCOL_VERSION, build_and_sign_push,
    push_payload_hash, seal_bundle_identity,
};

fn fixture(label: &str) -> (PathBuf, PathBuf, PathBuf, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "sito_rotate_cli_{label}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let data_dir = dir.join("state");
    std::fs::create_dir_all(&data_dir).unwrap();
    let key = Ed25519SigningKey::load_or_create(&data_dir.join("ha_signing.key")).unwrap();
    let mut bundle = ConfigBundle {
        version: 4,
        term: 2,
        timestamp: 1,
        config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
        ..ConfigBundle::default()
    };
    seal_bundle_identity(&mut bundle, &key.public_key());
    let push = build_and_sign_push(&bundle, &key).unwrap();
    let hash = push_payload_hash(&push).unwrap();
    let state = serde_json::json!({
        "protocol_version": PROTOCOL_VERSION,
        "bundle": bundle,
        "signing_key_pubkey": key.public_key_hex(),
        "publication_state": "published",
        "published_version": 4,
        "published_hash": hash.clone(),
    });
    std::fs::write(
        data_dir.join("ha_state.toml"),
        serde_json::to_vec_pretty(&state).unwrap(),
    )
    .unwrap();

    let config_path = dir.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "config_version = 2\n\
             [server]\n\
             role = \"master\"\n\
             data_dir = \"{}\"\n\
             [upstream]\n\
             servers = [\"1.1.1.1\"]\n\
             [ha]\n\
             replication_port = 0\n",
            data_dir.display()
        ),
    )
    .unwrap();
    (dir, config_path, data_dir, key.public_key_hex(), hash)
}

/// Acquires the same advisory lease a running server holds.
fn hold_service_lease(data_dir: &Path) -> File {
    let path = data_dir.join("sito.pid");
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.lock().unwrap();
    file.set_len(0).unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    writeln!(file, "{}", std::process::id()).unwrap();
    file.sync_all().unwrap();
    file
}

fn sito() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sito"))
}

fn stderr_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_of(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn rotate_signing_key_cli_refuses_without_confirm_and_while_running() {
    let (dir, config_path, data_dir, old_pubkey, _) = fixture("refusals");
    let old_key = std::fs::read(data_dir.join("ha_signing.key")).unwrap();
    let old_state = std::fs::read(data_dir.join("ha_state.toml")).unwrap();

    // Missing --confirm: refused before any read/mutation.
    let output = sito()
        .args(["ha", "rotate-signing-key", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(stderr_of(&output).contains("--confirm"));
    assert_eq!(
        std::fs::read(data_dir.join("ha_signing.key")).unwrap(),
        old_key
    );
    assert_eq!(
        std::fs::read(data_dir.join("ha_state.toml")).unwrap(),
        old_state
    );

    // Live service lease: refused and nothing changed.
    let lease = hold_service_lease(&data_dir);
    let output = sito()
        .args(["ha", "rotate-signing-key", "--config"])
        .arg(&config_path)
        .arg("--confirm")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(stderr.contains("service lease"), "{stderr}");
    assert!(stderr.contains("systemctl stop sito"), "{stderr}");
    assert_eq!(
        std::fs::read(data_dir.join("ha_signing.key")).unwrap(),
        old_key
    );
    assert_eq!(
        std::fs::read(data_dir.join("ha_state.toml")).unwrap(),
        old_state
    );
    drop(lease);

    // Stopped service with --confirm succeeds and prints the exact operator
    // instructions for every slave.
    let output = sito()
        .args(["ha", "rotate-signing-key", "--config"])
        .arg(&config_path)
        .args(["--confirm", "--term", "9", "--version", "20"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rotation failed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    let new_key =
        Ed25519SigningKey::from_pkcs8(&std::fs::read(data_dir.join("ha_signing.key")).unwrap())
            .unwrap();
    let new_pubkey = new_key.public_key_hex();
    assert_ne!(new_pubkey, old_pubkey);
    assert!(
        stdout.contains("New master_pubkey"),
        "missing pubkey heading: {stdout}"
    );
    assert!(stdout.contains(&new_pubkey), "missing new pubkey: {stdout}");
    assert!(
        stdout.contains(&format!("master_pubkey = \"{new_pubkey}\"")),
        "missing slave config line: {stdout}"
    );
    assert!(stdout.contains("systemctl restart sito"), "{stdout}");
    assert!(stdout.contains("version 20"), "{stdout}");
    assert!(
        stdout.contains("No witness request, witness lease or bundle publish"),
        "{stdout}"
    );

    // The service lease used for the mutation is released.
    assert!(
        !data_dir.join("sito.pid").exists(),
        "the CLI must release the temporary service lease"
    );

    // Backups exist at 0600 and the state was re-sealed.
    let entries: Vec<_> = std::fs::read_dir(&data_dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    let key_backups: Vec<_> = entries
        .iter()
        .filter(|name| name.starts_with("ha_signing.key.bak."))
        .collect();
    let state_backups: Vec<_> = entries
        .iter()
        .filter(|name| name.starts_with("ha_state.toml.bak."))
        .collect();
    assert_eq!(key_backups.len(), 1, "{entries:?}");
    assert_eq!(state_backups.len(), 1, "{entries:?}");
    let loaded = HaStateStore::new(data_dir.join("ha_state.toml"))
        .load()
        .unwrap();
    let bundle = loaded.bundle().unwrap();
    assert_eq!(bundle.version, 20);
    assert_eq!(bundle.term, 9);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for name in [key_backups[0].as_str(), state_backups[0].as_str()] {
            let mode = std::fs::metadata(data_dir.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name} must be 0600");
        }
        let mode = std::fs::metadata(data_dir.join("ha_signing.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rotate_signing_key_cli_prints_witness_term_floor_and_published_baseline() {
    let (dir, config_path, data_dir, old_pubkey, published_hash) = fixture("promotion_output");
    let mut document = std::fs::read_to_string(&config_path).unwrap();
    write!(
        document,
        "master_pubkey = \"{old_pubkey}\"\n\
         [ha.promotion]\n\
         enabled = true\n\
         cluster_id = \"home-dns\"\n\
         node_id = \"node-a\"\n\
         backend = \"witness\"\n\
         [ha.promotion.witness]\n\
         url = \"https://witness.lan:8954\"\n\
         ca = \"/etc/sito/witness-ca.crt\"\n\
         token_file = \"/etc/sito/witness.token\"\n"
    )
    .unwrap();
    std::fs::write(&config_path, document).unwrap();

    let output = sito()
        .args(["ha", "rotate-signing-key", "--config"])
        .arg(&config_path)
        .args(["--confirm", "--term", "9", "--version", "20"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rotation failed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);

    // The witness term floor is the rotated state term, not merely "above the
    // previous applied term".
    assert!(
        stdout.contains("record term must be at least 9"),
        "{stdout}"
    );
    assert!(stdout.contains("--term <TERM >= 9>"), "{stdout}");

    // The witness update uses the preserved published baseline, never the
    // rotated pending version/hash.
    assert!(stdout.contains("--version 4"), "{stdout}");
    assert!(
        stdout.contains(&format!("--bundle-hash {published_hash}")),
        "{stdout}"
    );
    assert!(
        stdout.contains("--allow-equal-version --confirm"),
        "the printed term-only witness command must be operable at the preserved baseline: {stdout}"
    );
    assert!(
        stdout.contains("never the staged pending version 20"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("--version 20"),
        "the pending version must not be suggested to the witness: {stdout}"
    );

    // The master's own stale [ha] master_pubkey is called out.
    assert!(
        stdout.contains("WARNING: this master's own [ha] master_pubkey"),
        "{stdout}"
    );
    assert!(stdout.contains(&old_pubkey), "{stdout}");

    assert!(!data_dir.join("sito.pid").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rotate_signing_key_cli_term_only_witness_command_works_on_a_fixture_witness() {
    let (dir, _config_path, _data_dir, _old_pubkey, published_hash) = fixture("witness_term_only");
    let witness_dir = dir.join("witness");
    std::fs::create_dir_all(&witness_dir).unwrap();
    // Steady state: the witness record version equals the cluster's published
    // baseline, which is exactly the state a rotation preserves.
    let record = sito_ha::LeaseRecord {
        schema: sito_ha::witness::LEASE_SCHEMA,
        cluster_id: "home-dns".to_string(),
        holder: "node-a/boot".to_string(),
        node_id: "node-a".to_string(),
        term: 3,
        revision: 5,
        version: 4,
        bundle_hash: published_hash.clone(),
        acquired_unix_ms: 1,
        expires_unix_ms: 1,
    };
    std::fs::write(
        witness_dir.join("lease.json"),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .unwrap();

    // The old strict path refuses the unchanged published version.
    let strict = sito()
        .args(["ha", "lease-admin", "set", "--state-dir"])
        .arg(&witness_dir)
        .args([
            "--term",
            "9",
            "--version",
            "4",
            "--bundle-hash",
            &published_hash,
            "--confirm",
        ])
        .output()
        .unwrap();
    assert!(!strict.status.success());
    assert!(
        stderr_of(&strict).contains("version_not_raised"),
        "{}",
        stderr_of(&strict)
    );

    // The term-only mode the rotation CLI prints succeeds on the same record.
    let output = sito()
        .args(["ha", "lease-admin", "set", "--state-dir"])
        .arg(&witness_dir)
        .args([
            "--term",
            "9",
            "--version",
            "4",
            "--bundle-hash",
            &published_hash,
            "--allow-equal-version",
            "--confirm",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "term-only bump failed: {}",
        stderr_of(&output)
    );
    let updated: sito_ha::LeaseRecord =
        serde_json::from_slice(&std::fs::read(witness_dir.join("lease.json")).unwrap()).unwrap();
    assert_eq!(updated.term, 9);
    assert_eq!(updated.version, 4);
    assert_eq!(updated.bundle_hash, published_hash);
    assert_eq!(updated.revision, record.revision + 1);
    assert_eq!(updated.expires_unix_ms, 0);

    let _ = std::fs::remove_dir_all(&dir);
}
