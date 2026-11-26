//! Real-binary acceptance for `sito ha rotate-signing-key`.
//!
//! The unit tests exercise the rotation algorithm and the CLI function; this
//! test proves the shipped command refuses without `--confirm`, refuses while a
//! live service owns the data directory, rotates offline, prints the new
//! `master_pubkey`, and releases its temporary service lease.

#![cfg(feature = "ha")]

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use sito_ha::{
    ConfigBundle, Ed25519SigningKey, HaStateStore, PROTOCOL_VERSION, build_and_sign_push,
    push_payload_hash, seal_bundle_identity,
};

fn fixture(label: &str) -> (PathBuf, PathBuf, PathBuf, String) {
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
        "published_hash": hash,
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
    (dir, config_path, data_dir, key.public_key_hex())
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
    let (dir, config_path, data_dir, old_pubkey) = fixture("refusals");
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
