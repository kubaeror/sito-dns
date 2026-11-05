//! Regression tests for live-service semantics of `reset-admin`/`reset-sessions`.
//!
//! These tests exercise the real CLI binary and simulate a running server by
//! holding the same advisory service lease the server uses. The lease is the
//! authoritative stop/run signal: a stale file without a lock does not block a
//! reset, but a live holder does.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture(label: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "sito_reset_service_{label}_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
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

/// Acquires the lease a running server holds for `data_dir`.
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
fn reset_sessions_refuses_while_service_running() {
    let (dir, config_path) = fixture("sessions_refuse");
    std::fs::write(dir.join("sessions.toml"), "sessions = []\n").unwrap();
    std::fs::write(dir.join("tokens.toml"), "tokens = []\n").unwrap();
    let _lease = hold_service_lease(&dir);

    let output = sito()
        .args(["reset-sessions", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "reset-sessions must fail closed while the service is running"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("systemctl stop sito"),
        "error must tell the operator how to stop the service: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "error must mention the explicit override: {stderr}"
    );
    assert!(
        dir.join("sessions.toml").exists() && dir.join("tokens.toml").exists(),
        "a refused reset must not delete the persisted stores"
    );
    assert!(
        !dir.join("auth_generation").exists(),
        "a refused reset must not rotate the auth generation"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reset_sessions_force_warns_and_only_removes_persisted_state() {
    let (dir, config_path) = fixture("sessions_force");
    std::fs::write(dir.join("sessions.toml"), "sessions = []\n").unwrap();
    std::fs::write(dir.join("tokens.toml"), "tokens = []\n").unwrap();
    let _lease = hold_service_lease(&dir);

    let output = sito()
        .args(["reset-sessions", "--force", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "--force must be allowed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("restart"),
        "--force must warn that a restart is required: {stdout}"
    );
    assert!(
        !stdout.contains("All web sessions and API tokens have been invalidated"),
        "--force must not claim live sessions were invalidated: {stdout}"
    );
    assert!(!dir.join("sessions.toml").exists());
    assert!(!dir.join("tokens.toml").exists());
    assert_eq!(
        std::fs::read_to_string(dir.join("auth_generation"))
            .unwrap()
            .trim(),
        "1"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn reset_admin_refuses_while_service_running() {
    let (dir, config_path) = fixture("admin_refuse");
    {
        let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.update_user_password("admin", "OldAdminPassword1!")
            .await;
    }
    let _lease = hold_service_lease(&dir);
    let users_before = std::fs::read(dir.join("users.toml")).unwrap();
    let generation_before = std::fs::read_to_string(dir.join("auth_generation")).ok();

    let output = sito()
        .args([
            "reset-admin",
            "--password",
            "NewAdminPassword1!",
            "--config",
        ])
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "reset-admin must fail closed while the service is running"
    );
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("systemctl stop sito"),
        "error must tell the operator how to stop the service: {stderr}"
    );
    assert!(
        stderr.contains("--force"),
        "error must mention the explicit override: {stderr}"
    );
    assert_eq!(
        std::fs::read(dir.join("users.toml")).unwrap(),
        users_before,
        "a refused reset must not rewrite users.toml"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("auth_generation")).ok(),
        generation_before,
        "a refused reset must not rotate the auth generation"
    );
    assert!(
        !stdout_of(&output).contains("successfully reset"),
        "a refused reset must not claim success: {}",
        stdout_of(&output)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn reset_admin_force_warns_and_applies_only_after_restart() {
    let (dir, config_path) = fixture("admin_force");
    {
        let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.update_user_password("admin", "OldAdminPassword1!")
            .await;
    }
    let _lease = hold_service_lease(&dir);

    let output = sito()
        .args([
            "reset-admin",
            "--force",
            "--password",
            "NewAdminPassword1!",
            "--config",
        ])
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "--force must be allowed: {}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    assert!(
        stdout.contains("restart"),
        "--force must warn that the new password needs a restart: {stdout}"
    );
    assert!(
        !stdout.contains("will take effect immediately"),
        "--force must not claim the live server picked up the password: {stdout}"
    );

    // A fresh manager (what a restarted server loads) sees the new password.
    let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(matches!(
        mgr.login("admin", "NewAdminPassword1!", "127.0.0.1").await,
        sito_api::auth::LoginResult::Success(_)
    ));
    assert!(matches!(
        mgr.login("admin", "OldAdminPassword1!", "127.0.0.1").await,
        sito_api::auth::LoginResult::InvalidCredentials { .. }
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn reset_admin_without_running_service_keeps_deterministic_recovery() {
    let (dir, config_path) = fixture("admin_stopped");
    {
        let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.update_user_password("admin", "OldAdminPassword1!")
            .await;
        mgr.create_user("alice", "AlicePassword1!", sito_api::auth::Role::Operator)
            .await;
    }

    let output = sito()
        .args([
            "reset-admin",
            "--password",
            "NewAdminPassword1!",
            "--config",
        ])
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "reset-admin must succeed while stopped: {}",
        stderr_of(&output)
    );
    assert!(stdout_of(&output).contains("successfully reset"));

    let mgr = sito_api::AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        mgr.has_user("alice"),
        "non-admin accounts must be preserved"
    );
    assert!(matches!(
        mgr.login("admin", "NewAdminPassword1!", "127.0.0.1").await,
        sito_api::auth::LoginResult::Success(_)
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reset_sessions_without_running_service_reports_accurate_success() {
    let (dir, config_path) = fixture("sessions_stopped");
    std::fs::write(dir.join("sessions.toml"), "sessions = []\n").unwrap();
    std::fs::write(dir.join("tokens.toml"), "tokens = []\n").unwrap();

    let output = sito()
        .args(["reset-sessions", "--config"])
        .arg(&config_path)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "reset-sessions must succeed while stopped: {}",
        stderr_of(&output)
    );
    assert!(
        stdout_of(&output).contains("All web sessions and API tokens have been invalidated"),
        "stopped-service success text is accurate: {}",
        stdout_of(&output)
    );
    assert!(!dir.join("sessions.toml").exists());
    assert!(!dir.join("tokens.toml").exists());

    let _ = std::fs::remove_dir_all(&dir);
}
