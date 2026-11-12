#![cfg(test)]

use super::*;

fn auth_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sito_auth_{label}_{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn in_memory_totp_secret(mgr: &AuthManager, username: &str) -> String {
    lock(&mgr.users)
        .get(username)
        .and_then(|u| u.totp.as_ref())
        .map(|t| t.secret.clone())
        .expect("user has TOTP configured")
}

async fn enable_totp(mgr: &AuthManager, username: &str) -> TotpSetupResponse {
    let setup = mgr.init_totp_setup(username).await.expect("totp setup");
    assert!(
        mgr.confirm_totp_setup(username, &setup.backup_codes[0])
            .await,
        "TOTP setup must be confirmed"
    );
    setup
}

#[tokio::test]
async fn test_auth_manager_login_and_session() {
    let mgr = AuthManager::new();
    // Login with default admin
    match mgr.login("admin", "adminadmin", "127.0.0.1").await {
        LoginResult::Success(session) => {
            assert_eq!(session.username, "admin");
            assert_eq!(session.role, Role::Admin);
            assert!(mgr.validate_session(&session.id).is_some());
            mgr.logout(&session.id).await;
            assert!(mgr.validate_session(&session.id).is_none());
        }
        _ => panic!("Expected successful login"),
    }
}

#[tokio::test]
async fn test_unknown_user_and_wrong_password_are_rejected() {
    let mgr = AuthManager::new();
    assert!(matches!(
        mgr.login("ghost", "whatever", "127.0.0.1").await,
        LoginResult::InvalidCredentials { .. }
    ));
    assert!(matches!(
        mgr.login("admin", "wrongpassword", "127.0.0.1").await,
        LoginResult::InvalidCredentials { .. }
    ));
}

/// WP-0.7 (P1-20): pre-auth inputs are bounded before lockout bookkeeping
/// and Argon2, and the lockout map never stores the raw username.
#[tokio::test]
async fn test_login_rejects_oversized_credentials_before_lockout() {
    let mgr = AuthManager::new();

    let long_username = "u".repeat(MAX_LOGIN_USERNAME_BYTES + 1);
    assert!(matches!(
        mgr.login(&long_username, "whatever", "127.0.0.1").await,
        LoginResult::InvalidCredentials { .. }
    ));
    assert_eq!(
        mgr.lockout.attempts_len(),
        0,
        "oversized usernames must not create lockout entries"
    );

    let long_password = "p".repeat(MAX_LOGIN_PASSWORD_BYTES + 1);
    assert!(matches!(
        mgr.login("admin", &long_password, "127.0.0.1").await,
        LoginResult::InvalidCredentials { .. }
    ));
    assert_eq!(
        mgr.lockout.attempts_len(),
        0,
        "oversized passwords must be rejected before the lockout/Argon2 path"
    );
}

#[tokio::test]
async fn test_login_lockout_key_is_a_digest() {
    let mgr = AuthManager::new();
    for _ in 0..5 {
        let _ = mgr.login("admin", "wrongpassword", "127.0.0.1").await;
    }
    let keys = mgr.lockout.attempt_keys();
    assert_eq!(keys.len(), 1);
    assert!(
        !keys[0].contains("admin"),
        "the raw username must never be a lockout-map key: {keys:?}"
    );
    assert_eq!(keys[0], lockout_key("admin"));
}

/// Deferred D4b: re-auth must report the threshold-crossing failure as a
/// lockout (matching login), not return 401 once more and 429 only on the
/// following attempt.
#[tokio::test]
async fn test_reauth_lockout_triggers_on_the_fifth_failure() {
    let mgr = AuthManager::new();
    let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await else {
        panic!("login failed");
    };

    for attempt in 1..crate::auth::lockout::MAX_FAILED_ATTEMPTS {
        assert!(
            matches!(
                mgr.reauth("admin", "wrongpassword", None, &session.id, "")
                    .await,
                Err(ReauthError::InvalidCredentials)
            ),
            "attempt {attempt} must stay a 401"
        );
    }
    assert!(
        matches!(
            mgr.reauth("admin", "wrongpassword", None, &session.id, "")
                .await,
            Err(ReauthError::LockedOut { .. })
        ),
        "the fifth failure must be the 429 lockout, like login"
    );
}

/// Deferred D4b: oversized re-auth credentials are rejected before the
/// lockout check and Argon2 (matching login), including while locked out.
#[tokio::test]
async fn test_reauth_rejects_oversized_credentials_before_lockout() {
    let mgr = AuthManager::new();
    let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await else {
        panic!("login failed");
    };
    for _ in 0..crate::auth::lockout::MAX_FAILED_ATTEMPTS {
        let _ = mgr
            .reauth("admin", "wrongpassword", None, &session.id, "")
            .await;
    }
    assert!(mgr.lockout.check_lockout(&lockout_key("admin")).is_some());

    let long_username = "u".repeat(MAX_LOGIN_USERNAME_BYTES + 1);
    assert!(matches!(
        mgr.reauth(&long_username, "whatever", None, &session.id, "")
            .await,
        Err(ReauthError::InvalidCredentials)
    ));
    let long_password = "p".repeat(MAX_LOGIN_PASSWORD_BYTES + 1);
    assert!(matches!(
        mgr.reauth("admin", &long_password, None, &session.id, "")
            .await,
        Err(ReauthError::InvalidCredentials)
    ));
    assert_eq!(
        mgr.lockout.attempts_len(),
        1,
        "oversized inputs must not create or extend lockout entries"
    );
}

#[tokio::test]
async fn test_auth_manager_totp_flow() {
    let mgr = AuthManager::new();
    let setup = mgr.init_totp_setup("admin").await.expect("setup");

    // Use backup code to confirm setup
    assert!(
        mgr.confirm_totp_setup("admin", &setup.backup_codes[0])
            .await
    );

    // Login now requires TOTP
    match mgr.login("admin", "adminadmin", "127.0.0.1").await {
        LoginResult::TotpRequired { partial_token } => {
            // Invalid code fails
            assert!(matches!(
                mgr.verify_totp(&partial_token, "000000", "127.0.0.1").await,
                TotpVerifyResult::Invalid
            ));
            // Valid backup code succeeds
            let session = match mgr
                .verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1")
                .await
            {
                TotpVerifyResult::Success(session) => session,
                other => panic!("expected TOTP success, got {other:?}"),
            };
            assert_eq!(session.role, Role::Admin);
        }
        _ => panic!("Expected TOTP required"),
    }
}

#[tokio::test]
async fn test_totp_bruteforce_attempt_limit() {
    // High IP rate limit so the per-account lockout/attempt cap is exercised.
    let mgr = AuthManager::with_config(24, 1000);
    let setup = mgr.init_totp_setup("admin").await.expect("setup");
    assert!(
        mgr.confirm_totp_setup("admin", &setup.backup_codes[0])
            .await
    );

    let LoginResult::TotpRequired { partial_token } =
        mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("Expected TOTP required");
    };

    let mut saw_terminal = false;
    for _ in 0..MAX_TOTP_ATTEMPTS {
        match mgr.verify_totp(&partial_token, "000000", "127.0.0.1").await {
            TotpVerifyResult::Invalid => {}
            TotpVerifyResult::LockedOut { .. } => {
                saw_terminal = true;
                break;
            }
            other => panic!("unexpected TOTP result: {other:?}"),
        }
    }
    assert!(
        saw_terminal,
        "repeated wrong TOTP codes must eventually lock the account"
    );

    // The partial token is consumed and cannot be used with a valid code.
    assert!(matches!(
        mgr.verify_totp(&partial_token, &setup.backup_codes[1], "127.0.0.1")
            .await,
        TotpVerifyResult::TokenExpired | TotpVerifyResult::LockedOut { .. }
    ));
}

#[tokio::test]
async fn test_totp_backup_code_is_single_use_under_concurrency() {
    let mgr = Arc::new(AuthManager::new());
    let setup = mgr.init_totp_setup("admin").await.expect("setup");
    assert!(
        mgr.confirm_totp_setup("admin", &setup.backup_codes[0])
            .await
    );

    let LoginResult::TotpRequired { partial_token: t1 } =
        mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("Expected TOTP required");
    };
    let LoginResult::TotpRequired { partial_token: t2 } =
        mgr.login("admin", "adminadmin", "127.0.0.2").await
    else {
        panic!("Expected TOTP required");
    };

    // Both requests race on the same unused backup code.
    let code = setup.backup_codes[1].clone();
    let code_2 = code.clone();
    let mgr_2 = Arc::clone(&mgr);
    let (r1, r2) = tokio::join!(mgr.verify_totp(&t1, &code, "127.0.0.1"), async move {
        mgr_2.verify_totp(&t2, &code_2, "127.0.0.2").await
    },);

    let successes = [&r1, &r2]
        .iter()
        .filter(|r| matches!(r, TotpVerifyResult::Success(_)))
        .count();
    assert_eq!(
        successes, 1,
        "a backup code must be consumed exactly once: {r1:?} / {r2:?}"
    );
}

#[tokio::test]
async fn test_delete_user_revokes_sessions() {
    let mgr = AuthManager::new();
    let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await else {
        panic!("expected direct login");
    };
    assert!(mgr.validate_session(&session.id).is_some());

    assert!(mgr.delete_user("admin").await);
    assert!(
        mgr.validate_session(&session.id).is_none(),
        "a deleted account's sessions must be invalidated"
    );
}

#[tokio::test]
async fn test_auth_manager_api_tokens() {
    let mgr = AuthManager::new();
    let (meta, resp) = mgr
        .create_token("grafana", Role::Viewer, Some("admin"))
        .await
        .expect("token");

    assert_eq!(mgr.list_tokens().len(), 1);
    let validated = mgr.validate_token(&resp.token).expect("valid token");
    assert_eq!(validated.id, meta.id);
    assert_eq!(validated.scope, Role::Viewer);
    assert_eq!(validated.owner.as_deref(), Some("admin"));

    assert!(mgr.delete_token(&meta.id).await);
    assert!(mgr.validate_token(&resp.token).is_none());
    assert_eq!(mgr.list_tokens().len(), 0);
}

#[tokio::test]
async fn test_api_token_cap_evicts() {
    let mgr = AuthManager::new();
    for i in 0..(MAX_API_TOKENS + 5) {
        mgr.create_token(&format!("tok-{i}"), Role::Viewer, None)
            .await
            .expect("token");
    }
    assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);
}

#[tokio::test]
async fn test_api_token_capacity_never_evicts_another_owners_token() {
    let mgr = AuthManager::new();
    // Fill the global store to MAX_API_TOKENS with owned tokens only:
    // 15 owners at the per-owner quota plus a 16th owner.
    for owner in 0..(MAX_API_TOKENS / MAX_API_TOKENS_PER_OWNER - 1) {
        let owner = format!("owner-{owner}");
        for i in 0..MAX_API_TOKENS_PER_OWNER {
            create_owned_token(&mgr, &owner, &format!("{owner}-{i}")).await;
        }
    }
    for i in 0..MAX_API_TOKENS_PER_OWNER {
        create_owned_token(&mgr, "admin", &format!("admin-{i}")).await;
    }
    assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);

    let err = mgr
        .create_token("viewer-new", Role::Viewer, Some("viewer"))
        .await
        .expect_err("full store must not evict another owner's token");
    assert_eq!(err, CreateTokenError::CapacityReached);
    assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);
    assert!(
        mgr.list_tokens().iter().all(|token| token.owner.is_some()),
        "the failed create must not have evicted another owner's token"
    );

    // The same owner can still rotate its oldest token at the global cap.
    mgr.create_token("admin-new", Role::Admin, Some("admin"))
        .await
        .expect("same-owner rotation");
    assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);
    assert!(
        mgr.list_tokens()
            .iter()
            .any(|token| token.name == "admin-new")
    );
    assert_eq!(
        mgr.list_tokens()
            .iter()
            .filter(|token| token.owner.as_deref() == Some("owner-0"))
            .count(),
        MAX_API_TOKENS_PER_OWNER,
        "another owner's tokens must be untouched"
    );
}

#[tokio::test]
async fn test_global_cap_evicts_only_same_owner_below_per_owner_quota() {
    let mgr = AuthManager::new();
    // 15 owners at the per-owner quota => 240 tokens.
    for owner in 0..(MAX_API_TOKENS / MAX_API_TOKENS_PER_OWNER - 1) {
        let owner = format!("owner-{owner}");
        for i in 0..MAX_API_TOKENS_PER_OWNER {
            create_owned_token(&mgr, &owner, &format!("{owner}-{i}")).await;
        }
    }
    // A 16th owner with 15 tokens => 255, leaving one free global slot.
    let partial_owner = "owner-partial";
    for i in 0..(MAX_API_TOKENS_PER_OWNER - 1) {
        create_owned_token(&mgr, partial_owner, &format!("partial-{i}")).await;
    }
    assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS - 1);

    // The requester owns exactly one token and is below the per-owner
    // quota, so only the global same-owner branch can make room.
    create_owned_token(&mgr, "solo", "solo-old").await;
    assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);

    create_owned_token(&mgr, "solo", "solo-new").await;

    assert_eq!(mgr.list_tokens().len(), MAX_API_TOKENS);
    assert_eq!(
        owned_token_names(&mgr, "solo"),
        vec!["solo-new".to_string()],
        "the global cap must evict the requester's own oldest token"
    );
    assert_eq!(
        owned_token_names(&mgr, partial_owner).len(),
        MAX_API_TOKENS_PER_OWNER - 1,
        "other owners' tokens must survive the global same-owner eviction"
    );
    assert_eq!(
        owned_token_names(&mgr, "owner-0").len(),
        MAX_API_TOKENS_PER_OWNER,
        "other owners' tokens must survive the global same-owner eviction"
    );
}

#[tokio::test]
async fn test_delete_user_revokes_owned_tokens() {
    let mgr = AuthManager::new();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let (alice_token, _) = mgr
        .create_token("alice-token", Role::Operator, Some("alice"))
        .await
        .expect("alice token");
    let (admin_token, _) = mgr
        .create_token("admin-token", Role::Admin, Some("admin"))
        .await
        .expect("admin token");
    mgr.create_token("legacy", Role::Viewer, None)
        .await
        .expect("legacy token");

    assert!(mgr.delete_user("alice").await);

    let ids: Vec<String> = mgr
        .list_tokens()
        .into_iter()
        .map(|token| token.id)
        .collect();
    assert!(
        !ids.contains(&alice_token.id),
        "deleting a user must revoke their API tokens"
    );
    assert!(ids.contains(&admin_token.id));
    assert_eq!(ids.len(), 2, "admin-owned and legacy tokens must survive");
}

#[tokio::test]
async fn test_token_owner_persists_and_delete_user_removes_it_from_disk() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_token_owner_persist_{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();

    {
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        mgr.create_token("alice-persisted", Role::Operator, Some("alice"))
            .await
            .expect("alice token");
    }

    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    let reloaded = mgr
        .list_tokens()
        .into_iter()
        .find(|token| token.name == "alice-persisted")
        .expect("token must survive reload");
    assert_eq!(reloaded.owner.as_deref(), Some("alice"));

    assert!(mgr.delete_user("alice").await);
    assert!(
        !mgr.list_tokens()
            .iter()
            .any(|token| token.name == "alice-persisted")
    );
    drop(mgr);

    let tokens_toml = std::fs::read_to_string(temp_dir.join("tokens.toml")).unwrap();
    assert!(
        !tokens_toml.contains("alice-persisted"),
        "deletion must rewrite tokens.toml without the owned token"
    );

    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert!(
        !mgr.list_tokens()
            .iter()
            .any(|token| token.name == "alice-persisted"),
        "the deletion must survive a reload"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

fn owned_token_names(mgr: &AuthManager, owner: &str) -> Vec<String> {
    let mut names: Vec<String> = mgr
        .list_tokens()
        .into_iter()
        .filter(|token| token.owner.as_deref() == Some(owner))
        .map(|token| token.name)
        .collect();
    names.sort();
    names
}

async fn create_owned_token(mgr: &AuthManager, owner: &str, name: &str) {
    mgr.create_token(name, Role::Viewer, Some(owner))
        .await
        .expect("owned token");
}

#[tokio::test]
async fn test_password_change_revokes_owned_tokens() {
    let dir = auth_temp_dir("pw_revokes_tokens");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        create_owned_token(&mgr, "alice", "alice-token").await;
        create_owned_token(&mgr, "admin", "admin-token").await;
        mgr.create_token("legacy", Role::Viewer, None)
            .await
            .expect("legacy token");

        assert!(mgr.update_user_password("alice", "AlicePassword2").await);
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "a password change must revoke the account's API tokens"
        );
        assert_eq!(
            owned_token_names(&mgr, "admin"),
            vec!["admin-token".to_string()]
        );
        assert!(
            mgr.list_tokens().iter().any(|token| token.name == "legacy"),
            "legacy ownerless tokens stay Admin-managed"
        );
    }

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        owned_token_names(&mgr, "alice").is_empty(),
        "password-change token revocation must survive a reload"
    );
    assert!(
        mgr.list_tokens()
            .iter()
            .any(|token| token.name == "admin-token")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_disable_totp_revokes_owned_tokens() {
    let dir = auth_temp_dir("totp_revokes_tokens");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        enable_totp(&mgr, "alice").await;
        create_owned_token(&mgr, "alice", "alice-token").await;
        create_owned_token(&mgr, "admin", "admin-token").await;

        assert!(mgr.disable_totp("alice").await);
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "disabling TOTP must revoke the account's API tokens"
        );
        assert_eq!(
            owned_token_names(&mgr, "admin"),
            vec!["admin-token".to_string()]
        );
    }

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        owned_token_names(&mgr, "alice").is_empty(),
        "TOTP-disable token revocation must survive a reload"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_role_change_revokes_owned_tokens() {
    let dir = auth_temp_dir("role_revokes_tokens");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        create_owned_token(&mgr, "alice", "before-demotion").await;
        create_owned_token(&mgr, "admin", "admin-token").await;
        mgr.create_token("legacy", Role::Viewer, None)
            .await
            .expect("legacy token");

        // Exercise the handler-facing checked path.
        assert_eq!(
            mgr.set_user_role_checked("alice", Role::Viewer).await,
            Ok(true)
        );
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "demotion must revoke existing tokens so the old scope cannot survive"
        );
        assert_eq!(
            owned_token_names(&mgr, "admin"),
            vec!["admin-token".to_string()]
        );
        assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));
    }

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        owned_token_names(&mgr, "alice").is_empty(),
        "demotion token revocation must survive a reload"
    );
    assert_eq!(
        owned_token_names(&mgr, "admin"),
        vec!["admin-token".to_string()]
    );
    assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));

    // Promotion also revokes, and must persist.
    create_owned_token(&mgr, "alice", "before-promotion").await;
    assert_eq!(
        mgr.set_user_role_checked("alice", Role::Admin).await,
        Ok(true)
    );
    assert!(
        owned_token_names(&mgr, "alice").is_empty(),
        "promotion also revokes existing tokens"
    );
    drop(mgr);

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        owned_token_names(&mgr, "alice").is_empty(),
        "promotion token revocation must survive a reload"
    );
    assert_eq!(
        owned_token_names(&mgr, "admin"),
        vec!["admin-token".to_string()]
    );
    assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));

    // A no-op role update must not revoke anything, before or after reload.
    create_owned_token(&mgr, "alice", "unchanged-role").await;
    assert_eq!(
        mgr.set_user_role_checked("alice", Role::Admin).await,
        Ok(false)
    );
    assert!(
        mgr.list_tokens()
            .iter()
            .any(|token| token.name == "unchanged-role"),
        "setting the same role must not revoke tokens"
    );
    drop(mgr);

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        mgr.list_tokens()
            .iter()
            .any(|token| token.name == "unchanged-role"),
        "a no-op role update must not revoke tokens across reload"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_overwriting_user_revokes_owned_tokens() {
    let dir = auth_temp_dir("overwrite_revokes_tokens");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        create_owned_token(&mgr, "alice", "alice-old").await;
        create_owned_token(&mgr, "admin", "admin-token").await;
        mgr.create_token("legacy", Role::Viewer, None)
            .await
            .expect("legacy token");

        mgr.create_user("alice", "AlicePassword2", Role::Viewer)
            .await;
        assert!(
            owned_token_names(&mgr, "alice").is_empty(),
            "overwriting a user account must revoke its API tokens"
        );
        assert_eq!(
            owned_token_names(&mgr, "admin"),
            vec!["admin-token".to_string()]
        );
        assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));
    }

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        owned_token_names(&mgr, "alice").is_empty(),
        "overwrite token revocation must survive a reload"
    );
    assert_eq!(
        owned_token_names(&mgr, "admin"),
        vec!["admin-token".to_string()]
    );
    assert!(mgr.list_tokens().iter().any(|token| token.name == "legacy"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_per_owner_token_quota_evicts_only_that_owner() {
    let mgr = AuthManager::new();
    let (bob_token, _) = mgr
        .create_token("bob-keep", Role::Viewer, Some("bob"))
        .await
        .expect("bob token");

    for i in 0..MAX_API_TOKENS_PER_OWNER {
        create_owned_token(&mgr, "alice", &format!("alice-{i}")).await;
        // Keep created_at strictly increasing so "oldest" is unambiguous.
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let alice_before = owned_token_names(&mgr, "alice");
    assert_eq!(alice_before.len(), MAX_API_TOKENS_PER_OWNER);

    create_owned_token(&mgr, "alice", "alice-new").await;

    let alice_after = owned_token_names(&mgr, "alice");
    assert_eq!(
        alice_after.len(),
        MAX_API_TOKENS_PER_OWNER,
        "one owner must never exceed the per-owner quota"
    );
    assert!(
        !alice_after.iter().any(|name| name == "alice-0"),
        "the owner's oldest token must be evicted: {alice_after:?}"
    );
    assert!(alice_after.iter().any(|name| name == "alice-new"));
    assert!(
        mgr.list_tokens()
            .iter()
            .any(|token| token.id == bob_token.id),
        "another owner's token must never be evicted"
    );
}

#[tokio::test]
async fn test_per_owner_token_quota_trims_persisted_overflow() {
    let mgr = AuthManager::new();
    // Simulate a tokens.toml written before the per-owner quota existed.
    {
        let mut tokens = lock(&mgr.tokens);
        for i in 0..20 {
            let (mut meta, _) = generate_token(&format!("legacy-{i}"), Role::Viewer);
            meta.owner = Some("alice".to_string());
            meta.created_at = i;
            tokens.insert(meta.hash.clone(), meta);
        }
    }

    create_owned_token(&mgr, "alice", "new").await;

    let names = owned_token_names(&mgr, "alice");
    assert_eq!(
        names.len(),
        MAX_API_TOKENS_PER_OWNER,
        "legacy overflow must be trimmed to the per-owner quota"
    );
    assert!(names.iter().any(|name| name == "new"));
    assert!(
        !names.iter().any(|name| name == "legacy-0"),
        "the oldest overflow token must be trimmed first"
    );
}

#[test]
fn test_setup_token_lifecycle_and_rate_limit() {
    let mgr = AuthManager::with_storage(
        std::env::temp_dir().join(format!("sito_setup_tok_{}", rand::random::<u64>())),
        24,
        5,
    )
    .unwrap();
    assert!(mgr.setup_token_required());

    // Unknown tokens are rejected and throttled.
    assert_eq!(
        mgr.validate_setup_token(Some("wrong"), "198.51.100.7"),
        SetupTokenStatus::Invalid
    );
    for _ in 0..MAX_SETUP_TOKEN_FAILURES {
        let _ = mgr.validate_setup_token(Some("wrong"), "198.51.100.7");
    }
    assert_eq!(
        mgr.validate_setup_token(Some("wrong"), "198.51.100.7"),
        SetupTokenStatus::RateLimited
    );

    // The actual token is valid (need to read it from state in tests).
    let token = lock(&mgr.setup_token)
        .as_ref()
        .map(|t| t.token.clone())
        .expect("token provisioned");
    assert_eq!(
        mgr.validate_setup_token(Some(&token), "198.51.100.8"),
        SetupTokenStatus::Valid
    );

    // Consuming invalidates it.
    mgr.consume_setup_token();
    assert!(!mgr.setup_token_required());
    assert_eq!(
        mgr.validate_setup_token(Some(&token), "198.51.100.8"),
        SetupTokenStatus::Missing
    );
}

#[tokio::test]
async fn test_setup_token_does_not_expire_before_setup_completes() {
    let mgr = AuthManager::with_storage(
        std::env::temp_dir().join(format!("sito_setup_tok_age_{}", rand::random::<u64>())),
        24,
        5,
    )
    .unwrap();
    let token = mgr.setup_token().expect("token provisioned");

    // Regression: a server left in setup mode longer than the old 24 h
    // expiry must still require the token; an expired token previously
    // enabled unauthenticated `/ui/wizard/complete`.
    mgr.age_setup_token_for_test(Duration::from_hours(72));
    mgr.prune().await;

    assert!(
        mgr.setup_token_required(),
        "setup token must survive while setup is pending"
    );
    assert_eq!(
        mgr.validate_setup_token(Some(&token), "198.51.100.9"),
        SetupTokenStatus::Valid
    );

    // Once setup is complete the residual token is cleared.
    mgr.mark_setup_complete();
    mgr.prune().await;
    assert!(!mgr.setup_token_required());
}

#[tokio::test]
async fn test_user_persistence_across_restart() {
    let temp_dir = std::env::temp_dir().join(format!("sito_auth_test_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    {
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(mgr.is_first_run());

        // Change admin password
        assert!(mgr.update_user_password("admin", "newsecret123").await);
        assert!(!mgr.is_first_run());

        // Create operator user
        mgr.create_user("operator1", "oppassword", Role::Operator)
            .await;

        // Setup TOTP for operator1
        let setup = mgr.init_totp_setup("operator1").await.expect("totp setup");
        assert!(
            mgr.confirm_totp_setup("operator1", &setup.backup_codes[0])
                .await
        );
    }

    // Simulate server restart by creating a new AuthManager pointing to same directory
    {
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        assert!(!mgr.is_first_run());

        // Old default credentials must FAIL
        match mgr.login("admin", "adminadmin", "127.0.0.1").await {
            LoginResult::InvalidCredentials { .. } => {}
            other => panic!("expected invalid credentials, got {other:?}"),
        }

        // New password must SUCCEED
        match mgr.login("admin", "newsecret123", "127.0.0.1").await {
            LoginResult::Success(session) => {
                assert_eq!(session.username, "admin");
                assert_eq!(session.role, Role::Admin);
            }
            other => panic!("expected success, got {other:?}"),
        }

        // Operator must exist and require TOTP
        match mgr.login("operator1", "oppassword", "127.0.0.1").await {
            LoginResult::TotpRequired { .. } => {}
            other => panic!("expected TotpRequired, got {other:?}"),
        }

        // Verify file permissions (0600 on Unix)
        let users_file = temp_dir.join("users.toml");
        assert!(users_file.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&users_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_corrupt_users_file_is_not_backed_up_and_refuses_to_start() {
    let temp_dir = auth_temp_dir("corrupt");
    let users_file = temp_dir.join("users.toml");
    let plaintext = "JBSWY3DPEHPK3PXP";
    let corrupt_content = format!(
        "[[users]]\nusername = 'admin'\npassword_hash = invalid_syntax\n\
             [users.totp]\nenabled = true\nsecret = '{plaintext}'\n\
             backup_code_hashes = []\nbroken = [\n"
    );
    std::fs::write(&users_file, &corrupt_content).unwrap();

    match AuthManager::with_storage(&temp_dir, 24, 5) {
        Err(AuthStorageError::CorruptUsersFile { path, source: _ }) => {
            assert_eq!(path, users_file);
        }
        Ok(_) => panic!("Expected Err(CorruptUsersFile), got Ok"),
        Err(other) => panic!("Expected CorruptUsersFile, got {other:?}"),
    }

    // A corrupt file may still contain legacy plaintext TOTP secrets, so
    // it must never be retained as a raw backup.
    let backups: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".corrupt."))
        .collect();
    assert!(
        backups.is_empty(),
        "corrupt users files must not be backed up raw"
    );
    for entry in std::fs::read_dir(&temp_dir).unwrap().filter_map(Result::ok) {
        if entry.path() == users_file {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(entry.path()) {
            assert!(
                !text.contains(plaintext),
                "recovery file {} leaked the legacy TOTP secret",
                entry.path().display()
            );
        }
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_reset_admin_backup_seals_legacy_plaintext() {
    let dir = auth_temp_dir("reset_backup_plaintext");
    let plaintext;
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        enable_totp(&mgr, "admin").await;
        plaintext = in_memory_totp_secret(&mgr, "admin");
    }

    // Restore a pre-1.9 plaintext secret without starting the manager, so
    // the reset itself is the first code path to see this file.
    let users_file = dir.join("users.toml");
    let raw = std::fs::read_to_string(&users_file).unwrap();
    let parsed: UsersFile = toml::from_str(&raw).unwrap();
    let sealed = parsed
        .users
        .iter()
        .find(|u| u.username == "admin")
        .and_then(|u| u.totp.as_ref())
        .expect("stored TOTP config")
        .secret
        .clone();
    let legacy = raw.replace(&sealed, &plaintext);
    assert!(legacy.contains(&plaintext));
    std::fs::write(&users_file, &legacy).unwrap();

    AuthManager::reset_admin_credentials(&dir, "resetpassword1").unwrap();

    let backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            name.starts_with("users.toml.reset.") && name.ends_with(".bak")
        })
        .collect();
    assert_eq!(backups.len(), 1, "reset must retain one sanitized backup");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&backups[0]).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "recovery backup must be owner-only");
    }
    let backup_raw = std::fs::read_to_string(&backups[0]).unwrap();
    assert!(
        !backup_raw.contains(&plaintext),
        "reset backup leaked the legacy plaintext TOTP secret"
    );
    let backup: UsersFile = toml::from_str(&backup_raw).unwrap();
    let backup_secret = backup
        .users
        .iter()
        .find(|u| u.username == "admin")
        .and_then(|u| u.totp.as_ref())
        .expect("backup keeps the TOTP config")
        .secret
        .clone();
    assert!(backup_secret.starts_with("enc:v1:"));

    // The live store is the freshly reset account and contains no TOTP.
    let current = std::fs::read_to_string(&users_file).unwrap();
    assert!(!current.contains(&plaintext));
    assert!(!current.contains("enc:v1:"));

    // No temporary files left by either atomic write.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("users.tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left behind");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_reset_admin_skips_backup_for_unparseable_users_file() {
    let dir = auth_temp_dir("reset_backup_corrupt");
    let plaintext = "JBSWY3DPEHPK3PXP";
    let corrupt_content = format!(
        "[[users]]\nusername = 'admin'\npassword_hash = invalid_syntax\n\
             [users.totp]\nenabled = true\nsecret = '{plaintext}'\n\
             backup_code_hashes = []\nbroken = [\n"
    );
    std::fs::write(dir.join("users.toml"), corrupt_content).unwrap();

    // Replacing an unparseable store requires the explicit full reset.
    AuthManager::reset_admin_credentials_full(&dir, "resetpassword1").unwrap();

    let backups: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            name.starts_with("users.toml.reset.") && name.ends_with(".bak")
        })
        .collect();
    assert!(
        backups.is_empty(),
        "unparseable users file must not be retained as a backup"
    );
    let current = std::fs::read_to_string(dir.join("users.toml")).unwrap();
    assert!(!current.contains(plaintext));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_empty_users_file_refuses_to_start() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_auth_empty_test_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);
    let users_file = temp_dir.join("users.toml");
    std::fs::write(&users_file, "users = []\n").unwrap();

    let res = AuthManager::with_storage(&temp_dir, 24, 5);
    match res {
        Err(AuthStorageError::EmptyUsersFile { path }) => {
            assert_eq!(path, users_file);
        }
        Ok(_) => panic!("Expected Err(EmptyUsersFile), got Ok"),
        Err(other) => panic!("Expected EmptyUsersFile, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Minor: `reset-admin` is the recovery path and must still work when the
/// existing `totp.key` is malformed.
#[tokio::test]
async fn test_reset_admin_credentials_recovers_from_corrupt_totp_key() {
    let temp_dir = std::env::temp_dir().join(format!(
        "sito_auth_reset_corrupt_key_{}",
        rand::random::<u64>()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    {
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        mgr.update_user_password("admin", "firstpassword").await;
    }
    let key_path = temp_dir.join("totp.key");
    std::fs::write(&key_path, b"not-a-valid-key").unwrap();

    let reset_path = AuthManager::reset_admin_credentials(&temp_dir, "newpassword_reset")
        .expect("admin reset must recover from a malformed TOTP key");
    assert_eq!(reset_path, temp_dir.join("users.toml"));
    let backups: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("totp.corrupt.")
        })
        .collect();
    assert_eq!(backups.len(), 1, "the unusable key must be moved aside");
    assert!(
        AuthManager::with_storage(&temp_dir, 24, 5).is_ok(),
        "the fresh key and reset credentials must load"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_reset_admin_credentials() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_auth_reset_test_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // First bootstrap
    {
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        mgr.update_user_password("admin", "firstpassword").await;
    }

    // Corrupt the users file
    let users_file = temp_dir.join("users.toml");
    std::fs::write(&users_file, "corrupt garbage").unwrap();
    assert!(AuthManager::with_storage(&temp_dir, 24, 5).is_err());

    // Perform admin credentials reset (a corrupt store needs a full reset)
    let reset_path =
        AuthManager::reset_admin_credentials_full(&temp_dir, "newpassword_reset").unwrap();
    assert_eq!(reset_path, users_file);

    // Now loading with_storage must succeed
    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    match mgr.login("admin", "newpassword_reset", "127.0.0.1").await {
        LoginResult::Success(session) => {
            assert_eq!(session.username, "admin");
            assert_eq!(session.role, Role::Admin);
        }
        other => panic!("Expected login success after reset, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// Regression: a custom-named Admin (or deletion of the literal `admin`
/// while another Admin exists) must survive restart without re-entering
/// setup-token mode.
#[tokio::test]
async fn test_custom_admin_survives_restart_without_setup_token() {
    let dir = auth_temp_dir("custom_admin_restart");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("owner", "OwnerPassword123!", Role::Admin)
            .await;
        assert!(mgr.delete_user_checked("admin").await.is_ok());
    }

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(mgr.has_user("owner"));
    assert!(!mgr.has_user("admin"));
    assert!(!mgr.setup_token_required());
    assert!(!mgr.is_default_admin_active());
    assert!(!mgr.is_first_run());
    assert!(matches!(
        mgr.login("owner", "OwnerPassword123!", "127.0.0.1").await,
        LoginResult::Success(_)
    ));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A store with only non-admin accounts has no usable Admin, so it must
/// stay recoverable through the setup token even though no default admin
/// exists.
#[tokio::test]
async fn test_no_admin_account_still_provisions_setup_token() {
    let dir = auth_temp_dir("no_admin_token");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("viewer", "ViewerPassword123!", Role::Viewer)
            .await;
        assert!(mgr.delete_user("admin").await);
    }

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(!mgr.has_user("admin"));
    assert!(!mgr.is_first_run());
    assert!(mgr.setup_token_required());

    let _ = std::fs::remove_dir_all(&dir);
}

/// Regression: a valid but wrong 32-byte `totp.key` must not leave the
/// server unable to start after `reset-admin` preserved TOTP accounts.
#[tokio::test]
async fn test_reset_admin_drops_totp_unreadable_by_current_key() {
    let dir = auth_temp_dir("reset_wrong_totp_key");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword123!", Role::Operator)
            .await;
        let setup = mgr.init_totp_setup("alice").await.expect("totp setup");
        assert!(
            mgr.confirm_totp_setup("alice", &setup.backup_codes[0])
                .await
        );
        assert!(mgr.totp_enabled("alice"));
    }
    // Replace the key with a structurally valid but different 32-byte key.
    std::fs::write(dir.join("totp.key"), [0x5Au8; 32]).unwrap();

    AuthManager::reset_admin_credentials(&dir, "NewAdminPassword123!").unwrap();

    let mgr = AuthManager::with_storage(&dir, 24, 5)
        .expect("preserved accounts must not make startup fail after reset");
    assert!(mgr.has_user("alice"));
    assert!(!mgr.totp_enabled("alice"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed users-file write during deletion must restore the account and
/// surface an error instead of reporting a successful deletion.
#[tokio::test]
async fn test_delete_user_rolls_back_when_persistence_fails() {
    let dir = auth_temp_dir("delete_persist_failure");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    mgr.create_user("owner", "OwnerPassword123!", Role::Admin)
        .await;
    let users_path = dir.join("users.toml");
    SECRET_WRITE_FAIL_AFTER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((users_path.clone(), 0));

    let err = mgr
        .delete_user_checked("admin")
        .await
        .expect_err("failed users write must not report success");
    assert!(matches!(err, UserMutationError::Persistence(_)));
    assert!(mgr.has_user("admin"));
    assert!(mgr.has_user("owner"));
    assert!(mgr.is_default_admin_active());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_prune_expired_entries() {
    let mgr = Arc::new(AuthManager::new());
    // 1. Create a session and expire it
    let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await else {
        panic!("login failed");
    };
    assert_eq!(mgr.sessions_len(), 1);
    mgr.expire_session_for_test(&session.id);

    // 2. Create pending totp and expire it
    mgr.init_totp_setup("admin").await;
    assert_eq!(mgr.pending_totp_len(), 1);
    mgr.expire_pending_totp_for_test();

    // 3. Prune
    mgr.prune().await;
    assert_eq!(mgr.sessions_len(), 0);
    assert_eq!(mgr.pending_totp_len(), 0);

    // Test pruner task shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = mgr.spawn_pruner(shutdown_rx);
    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_millis(500), handle)
        .await
        .expect("pruner should shutdown cleanly")
        .unwrap();
}

#[tokio::test]
async fn test_session_persistence_across_restart() {
    let temp_dir = std::env::temp_dir().join(format!("sito_sess_test_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let session_id = {
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("login failed");
        };
        session.id
    };

    // Restart: session must still validate and the file must be 0600.
    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    let restored = mgr.validate_session(&session_id).expect("session restored");
    assert!(
        !restored.csrf_token.is_empty(),
        "legacy sessions get a CSRF token on load"
    );

    let sessions_file = temp_dir.join("sessions.toml");
    assert!(sessions_file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&sessions_file).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    // Logout must persist the revocation across another restart.
    mgr.logout(&session_id).await;
    let mgr2 = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert!(mgr2.validate_session(&session_id).is_none());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_token_persistence_and_expiry() {
    let temp_dir = std::env::temp_dir().join(format!("sito_tok_test_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let plaintext = {
        let mgr = AuthManager::with_config_and_storage_full(
            Some(temp_dir.join("users.toml")),
            24,
            5,
            true,
            true,
            30, // 30-day token TTL
        )
        .unwrap();
        let (meta, resp) = mgr
            .create_token("ci", Role::Operator, None)
            .await
            .expect("token");
        assert!(meta.expires_at.is_some(), "default TTL must be applied");
        resp.token
    };

    // Restart: the token still authenticates and the hash is persisted.
    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    let meta = mgr
        .validate_token(&plaintext)
        .expect("token survives restart");
    assert_eq!(meta.scope, Role::Operator);

    let tokens_file = temp_dir.join("tokens.toml");
    assert!(tokens_file.exists());
    let content = std::fs::read_to_string(&tokens_file).unwrap();
    assert!(
        !content.contains(&plaintext),
        "plaintext token must never be persisted"
    );

    // Revocation persists.
    assert!(mgr.delete_token(&meta.id).await);
    let mgr2 = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert!(mgr2.validate_token(&plaintext).is_none());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_expired_token_rejected_on_load() {
    let temp_dir = std::env::temp_dir().join(format!("sito_tokexp_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    let (mut meta, resp) = mgr
        .create_token("expired", Role::Viewer, None)
        .await
        .expect("token");
    meta.expires_at = Some(chrono::Utc::now().timestamp() - 10);
    lock(&mgr.tokens).insert(meta.hash.clone(), meta);
    mgr.save_tokens_async().await;
    drop(mgr);

    let mgr2 = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert!(mgr2.validate_token(&resp.token).is_none());

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_corrupt_session_store_backed_up_and_empty() {
    let temp_dir = std::env::temp_dir().join(format!("sito_sesscor_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    // Bootstrap a valid manager, then corrupt the sessions file.
    {
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        drop(mgr);
    }
    std::fs::write(temp_dir.join("sessions.toml"), "not = [valid toml").unwrap();

    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert_eq!(mgr.sessions_len(), 0, "corrupt store starts empty");
    let backups: Vec<_> = std::fs::read_dir(&temp_dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".corrupt."))
        .collect();
    assert_eq!(backups.len(), 1, "corrupt file must be backed up");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_session_persistence_can_be_disabled() {
    let temp_dir = std::env::temp_dir().join(format!("sito_nopersist_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let mgr = AuthManager::with_config_and_storage_full(
        Some(temp_dir.join("users.toml")),
        24,
        5,
        true,
        false, // session_persist disabled
        0,
    )
    .unwrap();
    assert!(!temp_dir.join("sessions.toml").exists());
    drop(mgr);

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_lock_recovery_after_poisoning() {
    let mgr = AuthManager::new();
    let users = mgr.users.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = users.lock().unwrap();
        panic!("poison the users lock");
    }));
    // The manager must keep working instead of panicking.
    assert!(mgr.has_user("admin"));
    let (meta, resp) = mgr
        .create_token("post-poison", Role::Viewer, None)
        .await
        .expect("token");
    assert!(mgr.validate_token(&resp.token).is_some());
    assert!(mgr.delete_token(&meta.id).await);
}

/// WP-4.4: `reset-admin` must invalidate every live session and API token,
/// not just replace the password.
#[tokio::test]
async fn test_reset_admin_credentials_invalidates_sessions_and_tokens() {
    let temp_dir =
        std::env::temp_dir().join(format!("sito_auth_reset_revoke_{}", rand::random::<u64>()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let (session_id, token_plaintext, token_hash) = {
        let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
        let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await
        else {
            panic!("login failed");
        };
        let (_meta, resp) = mgr
            .create_token("ci", Role::Operator, None)
            .await
            .expect("token");
        assert!(mgr.validate_session(&session.id).is_some());
        assert!(mgr.validate_token(&resp.token).is_some());
        let token_hash = hash_token(&resp.token);
        (session.id, resp.token, token_hash)
    };

    AuthManager::reset_admin_credentials(&temp_dir, "resetpassword1").unwrap();

    // The persisted stores are removed on reset.
    assert!(!temp_dir.join("sessions.toml").exists());
    assert!(!temp_dir.join("tokens.toml").exists());

    // Even if an attacker restores stale stores, the rotated generation
    // rejects them.
    std::fs::write(
            temp_dir.join("sessions.toml"),
            format!(
                "[[sessions]]\nid = \"{session_id}\"\nusername = \"admin\"\nrole = \"admin\"\ncreated_at = 0\nexpires_at = {}\ncsrf_token = \"deadbeef\"\ngeneration = 0\n",
                i64::MAX
            ),
        )
        .unwrap();
    std::fs::write(
            temp_dir.join("tokens.toml"),
            format!(
                "[[tokens]]\nid = \"tok_stale\"\nname = \"ci\"\nhash = \"{token_hash}\"\nscope = \"operator\"\ncreated_at = 0\ngeneration = 0\n"
            ),
        )
        .unwrap();

    let mgr = AuthManager::with_storage(&temp_dir, 24, 5).unwrap();
    assert!(
        mgr.validate_session(&session_id).is_none(),
        "a session from the previous generation must be rejected"
    );
    assert!(
        mgr.validate_token(&token_plaintext).is_none(),
        "a token from the previous generation must be rejected"
    );
    // The new credentials work.
    assert!(matches!(
        mgr.login("admin", "resetpassword1", "127.0.0.1").await,
        LoginResult::Success(_)
    ));

    let _ = std::fs::remove_dir_all(&temp_dir);
}

/// WP-4.4: changing a password revokes that user's sessions (already) and
/// role changes take effect immediately.
#[tokio::test]
async fn test_role_change_and_admin_guards() {
    let mgr = AuthManager::new();
    mgr.create_user("ops", "OperatorPass1", Role::Operator)
        .await;
    assert_eq!(mgr.admin_count(), 1);
    assert_eq!(mgr.role_of("ops"), Some(Role::Operator));

    let LoginResult::Success(session) = mgr.login("ops", "OperatorPass1", "127.0.0.1").await else {
        panic!("login failed");
    };
    assert!(mgr.set_user_role("ops", Role::Viewer).await);
    assert_eq!(mgr.role_of("ops"), Some(Role::Viewer));
    assert!(
        mgr.validate_session(&session.id).is_none(),
        "a role change must revoke existing sessions"
    );

    // Unknown user.
    assert!(!mgr.set_user_role("ghost", Role::Admin).await);
    assert_eq!(
        mgr.set_user_role_checked("ghost", Role::Admin).await,
        Err(UserMutationError::NotFound)
    );
    assert_eq!(
        mgr.delete_user_checked("ghost").await,
        Err(UserMutationError::NotFound)
    );
    assert_eq!(mgr.list_users().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_demotions_keep_at_least_one_admin() {
    let mgr = AuthManager::new();
    mgr.create_user("admin2", "Admin2Password1", Role::Admin)
        .await;
    assert_eq!(mgr.admin_count(), 2);

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let demote = |username: &'static str| {
        let mgr = mgr.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            mgr.set_user_role_checked(username, Role::Viewer).await
        })
    };
    let (first, second) = tokio::join!(demote("admin"), demote("admin2"));
    let first = first.expect("demotion task");
    let second = second.expect("demotion task");

    let successes = [&first, &second]
        .iter()
        .filter(|result| matches!(result, Ok(true)))
        .count();
    let blocked = [&first, &second]
        .iter()
        .filter(|result| matches!(result, Err(UserMutationError::LastAdmin)))
        .count();
    assert_eq!(
        successes, 1,
        "exactly one concurrent demotion may succeed: {first:?} / {second:?}"
    );
    assert_eq!(
        blocked, 1,
        "the losing demotion must return LastAdmin: {first:?} / {second:?}"
    );
    assert_eq!(
        mgr.admin_count(),
        1,
        "concurrent demotions must leave at least one Admin"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent_demote_and_delete_keep_at_least_one_admin() {
    let mgr = AuthManager::new();
    mgr.create_user("admin2", "Admin2Password1", Role::Admin)
        .await;
    assert_eq!(mgr.admin_count(), 2);

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let demote = {
        let mgr = mgr.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            mgr.set_user_role_checked("admin", Role::Viewer).await
        })
    };
    let delete = {
        let mgr = mgr.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            mgr.delete_user_checked("admin2").await
        })
    };
    let (demote, delete) = tokio::join!(demote, delete);
    let demote = demote.expect("demotion task");
    let delete = delete.expect("deletion task");

    match (&demote, &delete) {
        (Ok(true), Ok(())) => panic!("both operations removed an Admin"),
        (Ok(true), Err(UserMutationError::LastAdmin))
        | (Err(UserMutationError::LastAdmin), Ok(())) => {}
        other => panic!("unexpected concurrent results: {other:?}"),
    }
    assert_eq!(
        mgr.admin_count(),
        1,
        "concurrent demote/delete must leave at least one Admin"
    );
}

/// Overwriting an existing account must not be able to remove the sole
/// remaining Admin, even through the internal (non-handler) path.
#[tokio::test]
async fn test_create_user_cannot_overwrite_sole_admin_with_non_admin_role() {
    for role in [Role::Viewer, Role::Operator] {
        let mgr = AuthManager::new();
        assert_eq!(mgr.admin_count(), 1);
        assert!(mgr.is_default_admin_active());

        mgr.create_user("admin", "ReplacementPass1", role).await;

        assert_eq!(
            mgr.role_of("admin"),
            Some(Role::Admin),
            "a blocked overwrite must leave the Admin role unchanged ({role:?})"
        );
        assert_eq!(
            mgr.admin_count(),
            1,
            "a blocked overwrite must leave exactly one Admin ({role:?})"
        );
        assert!(
            mgr.is_default_admin_active(),
            "a blocked overwrite must not change the default-admin flag ({role:?})"
        );
        assert!(
            matches!(
                mgr.login("admin", "adminadmin", "127.0.0.1").await,
                LoginResult::Success(_)
            ),
            "a blocked overwrite must not change the password ({role:?})"
        );
    }
}

/// Concurrent create/delete writes must not let an older snapshot land
/// after a newer one: the persisted file must match the final in-memory
/// state (no resurrected deletions, no lost creations).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_concurrent_token_mutations_persist_final_state() {
    const MUTATIONS: usize = 30;
    let dir = auth_temp_dir("concurrent_token_persist");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();

    let mut seeded = Vec::with_capacity(MUTATIONS);
    for i in 0..MUTATIONS {
        let (meta, _resp) = mgr
            .create_token(&format!("seed-{i}"), Role::Viewer, None)
            .await
            .expect("seed token");
        seeded.push(meta.id);
    }

    let barrier = Arc::new(tokio::sync::Barrier::new(MUTATIONS * 2));
    // Model a slow disk for the first concurrent write so an older
    // snapshot can complete after newer ones if writes are not serialized.
    SECRET_WRITE_DELAYS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((dir.join("tokens.toml"), Duration::from_millis(300)));
    let mut tasks = Vec::with_capacity(MUTATIONS * 2);
    for id in seeded {
        let mgr = mgr.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            assert!(mgr.delete_token(&id).await, "seeded token must be deleted");
        }));
    }
    for i in 0..MUTATIONS {
        let mgr = mgr.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            mgr.create_token(&format!("new-{i}"), Role::Viewer, None)
                .await
                .expect("new token");
        }));
    }
    for task in tasks {
        task.await.expect("token mutation task");
    }

    let mut expected: Vec<(String, String)> = mgr
        .list_tokens()
        .into_iter()
        .map(|token| (token.id, token.name))
        .collect();
    expected.sort();
    assert_eq!(
        expected.len(),
        MUTATIONS,
        "only the newly created tokens should remain"
    );
    assert!(
        expected.iter().all(|(_, name)| name.starts_with("new-")),
        "no deleted seed token may remain in memory: {expected:?}"
    );

    // Read the file directly instead of relying on a reload's filtering.
    let raw = std::fs::read_to_string(dir.join("tokens.toml")).unwrap();
    let persisted_file: TokensFile = toml::from_str(&raw).unwrap();
    let mut persisted: Vec<(String, String)> = persisted_file
        .tokens
        .into_iter()
        .map(|token| (token.id, token.name))
        .collect();
    persisted.sort();
    assert_eq!(
        persisted, expected,
        "tokens.toml must reflect the final in-memory state after concurrent mutations"
    );

    drop(mgr);
    let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
    let mut after_reload: Vec<(String, String)> = reloaded
        .list_tokens()
        .into_iter()
        .map(|token| (token.id, token.name))
        .collect();
    after_reload.sort();
    assert_eq!(
        after_reload, expected,
        "a reload must reproduce the final in-memory token state"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cancelling the future that awaits a persistence write must not release
/// the persist lock early: the detached blocking write owns the lock until
/// it finishes, so a newer save cannot be overwritten by the orphan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cancelled_token_save_keeps_lock_until_write_finishes() {
    let dir = auth_temp_dir("cancelled_token_save");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    let (meta, _resp) = mgr
        .create_token("doomed", Role::Viewer, None)
        .await
        .expect("token");
    let tokens_path = dir.join("tokens.toml");

    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    SECRET_WRITE_START_SIGNALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((tokens_path.clone(), started_tx));
    SECRET_WRITE_DELAYS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((tokens_path.clone(), Duration::from_millis(500)));

    let save_mgr = mgr.clone();
    let save = tokio::spawn(async move {
        save_mgr.save_tokens_async().await;
    });

    // Wait until the blocking write has started and is sleeping. The signal
    // is path-scoped and one-shot, so parallel tests cannot consume it.
    tokio::time::timeout(Duration::from_secs(5), started_rx)
        .await
        .expect("timed out waiting for the delayed write to start")
        .expect("write-start signal was dropped");

    // Cancel the caller while the orphaned blocking write is still running.
    save.abort();
    let _ = save.await;

    // The newer revocation must persist after (not before) the orphan write.
    assert!(mgr.delete_token(&meta.id).await);
    // Give a broken implementation time to let the orphan land afterwards.
    tokio::time::sleep(Duration::from_millis(700)).await;

    let raw = std::fs::read_to_string(&tokens_path).unwrap();
    let persisted: TokensFile = toml::from_str(&raw).unwrap();
    assert!(
        !persisted.tokens.iter().any(|token| token.id == meta.id),
        "a cancelled stale write must not resurrect a deleted token: {raw}"
    );

    drop(mgr);
    let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        !reloaded
            .list_tokens()
            .iter()
            .any(|token| token.id == meta.id),
        "a reload must not resurrect a deleted token"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sync reader (`validate_token`) that removes an expired token while a
/// save is in flight must leave the token store dirty: the old snapshot on
/// disk still contains the removal, and the next prune must rewrite it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_validate_token_expiry_retries_persist() {
    let dir = auth_temp_dir("validate_token_retry");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    let (meta, resp) = mgr
        .create_token("expiring-retry", Role::Viewer, None)
        .await
        .expect("token");
    // Expire the token in memory only: the next snapshot will include it.
    lock(&mgr.tokens)
        .get_mut(&meta.hash)
        .expect("token in memory")
        .expires_at = Some(chrono::Utc::now().timestamp() - 10);

    let tokens_path = dir.join("tokens.toml");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    SECRET_WRITE_START_SIGNALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((tokens_path.clone(), started_tx));
    SECRET_WRITE_DELAYS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((tokens_path.clone(), Duration::from_millis(400)));

    let save_mgr = mgr.clone();
    let save = tokio::spawn(async move { save_mgr.save_tokens_async().await });
    tokio::time::timeout(Duration::from_secs(5), started_rx)
        .await
        .expect("timed out waiting for the delayed token write to start")
        .expect("write-start signal was dropped");

    // Remove the expired token while the snapshot write is in flight.
    assert!(mgr.validate_token(&resp.token).is_none());
    save.await.expect("token save task");

    // Without the dirty flag the prune below would see no in-memory change
    // and skip rewriting, leaving the removed token on disk.
    mgr.prune().await;

    let raw = std::fs::read_to_string(&tokens_path).unwrap();
    assert!(
        !raw.contains("expiring-retry"),
        "prune must persist a removal made by validate_token: {raw}"
    );

    drop(mgr);
    let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        !reloaded
            .list_tokens()
            .iter()
            .any(|token| token.id == meta.id),
        "a reload must not resurrect a token removed by validate_token"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Same contract as [`test_validate_token_expiry_retries_persist`] for
/// sessions: a sync `validate_session` removal must mark the store dirty so
/// the pruner rewrites the stale snapshot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_validate_session_expiry_retries_persist() {
    let dir = auth_temp_dir("validate_session_retry");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await else {
        panic!("login failed");
    };
    mgr.expire_session_for_test(&session.id);

    let sessions_path = dir.join("sessions.toml");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    SECRET_WRITE_START_SIGNALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((sessions_path.clone(), started_tx));
    SECRET_WRITE_DELAYS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((sessions_path.clone(), Duration::from_millis(400)));

    let save_mgr = mgr.clone();
    let save = tokio::spawn(async move { save_mgr.save_sessions_async().await });
    tokio::time::timeout(Duration::from_secs(5), started_rx)
        .await
        .expect("timed out waiting for the delayed session write to start")
        .expect("write-start signal was dropped");

    assert!(mgr.validate_session(&session.id).is_none());
    save.await.expect("session save task");

    mgr.prune().await;

    let raw = std::fs::read_to_string(&sessions_path).unwrap();
    assert!(
        !raw.contains(&session.id),
        "prune must persist a removal made by validate_session: {raw}"
    );

    drop(mgr);
    let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(reloaded.validate_session(&session.id).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Enabling TOTP is a credential change exactly like disabling it: tokens
/// owned by the account must not outlive the new second factor.
#[tokio::test]
async fn test_totp_enable_revokes_owned_tokens() {
    let dir = auth_temp_dir("totp_enable_revokes");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let (admin_token, admin_resp) = mgr
        .create_token("admin-before-totp", Role::Operator, Some("admin"))
        .await
        .expect("admin token");
    let (alice_token, _) = mgr
        .create_token("alice-unaffected", Role::Operator, Some("alice"))
        .await
        .expect("alice token");

    enable_totp(&mgr, "admin").await;

    assert!(
        mgr.validate_token(&admin_resp.token).is_none(),
        "enabling TOTP must revoke owned tokens in memory"
    );
    assert!(
        !mgr.list_tokens()
            .iter()
            .any(|token| token.id == admin_token.id)
    );
    assert!(
        mgr.list_tokens()
            .iter()
            .any(|token| token.id == alice_token.id),
        "another account's tokens must survive"
    );

    let raw = std::fs::read_to_string(dir.join("tokens.toml")).unwrap();
    assert!(
        !raw.contains("admin-before-totp"),
        "the revocation must be persisted: {raw}"
    );
    assert!(raw.contains("alice-unaffected"));

    drop(mgr);
    let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        !reloaded
            .list_tokens()
            .iter()
            .any(|token| token.id == admin_token.id),
        "a reload must not resurrect a token revoked by TOTP enable"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `save_users_initial` bypasses `persist_lock` and is only safe from the
/// constructors. Runtime mutations must go through `save_users_async`.
#[test]
fn test_save_users_is_constructor_only() {
    let manager_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/auth/manager");
    let mut files: Vec<_> = std::fs::read_dir(&manager_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect();
    files.sort();
    let source: String = files
        .iter()
        .map(|path| std::fs::read_to_string(path).unwrap())
        .collect();
    // Build needles at runtime so this test's own source cannot match them.
    let private_initial_fn = format!(
        "{}{}",
        "fn save_users", "_initial(&self) -> Result<(), AuthStorageError> {"
    );
    assert!(
        source.lines().any(|line| {
            line.trim_end().ends_with(&private_initial_fn) && !line.trim_start().starts_with("pub ")
        }),
        "the synchronous constructor-only writer must exist with restricted visibility"
    );
    let public_initial_fn = format!("pub {private_initial_fn}");
    assert!(
        !source
            .lines()
            .any(|line| line.trim_start().starts_with(&public_initial_fn)),
        "save_users_initial must stay private"
    );
    let constructor_calls = format!("{}{}", "mgr.save_users", "_initial()");
    assert_eq!(
        source.matches(&constructor_calls).count(),
        2,
        "only the two constructors may call save_users_initial"
    );
}

#[tokio::test]
async fn test_user_mutations_persist_across_restart() {
    // Each mutation is the last write in its own store so a missing async
    // save cannot be masked by a later unrelated save.
    let role_dir = auth_temp_dir("async_role");
    {
        let mgr = AuthManager::with_storage(&role_dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        assert!(mgr.set_user_role("alice", Role::Viewer).await);
    }
    let mgr = AuthManager::with_storage(&role_dir, 24, 5).unwrap();
    assert_eq!(
        mgr.role_of("alice"),
        Some(Role::Viewer),
        "a role change must be persisted"
    );
    drop(mgr);
    let _ = std::fs::remove_dir_all(&role_dir);

    let totp_dir = auth_temp_dir("async_totp");
    {
        let mgr = AuthManager::with_storage(&totp_dir, 24, 5).unwrap();
        mgr.create_user("alice", "AlicePassword1", Role::Operator)
            .await;
        enable_totp(&mgr, "alice").await;
        assert!(mgr.disable_totp("alice").await);
    }
    let mgr = AuthManager::with_storage(&totp_dir, 24, 5).unwrap();
    assert!(
        !mgr.totp_enabled("alice"),
        "disabling TOTP must be persisted"
    );
    drop(mgr);
    let _ = std::fs::remove_dir_all(&totp_dir);

    let delete_dir = auth_temp_dir("async_delete");
    {
        let mgr = AuthManager::with_storage(&delete_dir, 24, 5).unwrap();
        mgr.create_user("bob", "BobPassword01", Role::Operator)
            .await;
        assert!(mgr.delete_user("bob").await);
    }
    let mgr = AuthManager::with_storage(&delete_dir, 24, 5).unwrap();
    assert!(!mgr.has_user("bob"), "deleting a user must be persisted");
    drop(mgr);
    let _ = std::fs::remove_dir_all(&delete_dir);
}

/// Blocking persistence (users, sessions, tokens) must run on the blocking
/// pool, never inline on the async runtime thread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_auth_writes_run_off_runtime_thread() {
    let dir = auth_temp_dir("off_runtime");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();

    // Ignore the synchronous bootstrap write performed by the constructor.
    SECRET_WRITE_THREADS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clear();

    let caller_thread = std::thread::current().id();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let (meta, _resp) = mgr
        .create_token("ci", Role::Viewer, None)
        .await
        .expect("token");
    let LoginResult::Success(session) = mgr.login("admin", "adminadmin", "127.0.0.1").await else {
        panic!("expected direct login");
    };
    mgr.logout(&session.id).await;
    assert!(mgr.delete_token(&meta.id).await);

    let writes: Vec<(PathBuf, std::thread::ThreadId)> = SECRET_WRITE_THREADS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(path, _)| path.starts_with(&dir))
        .cloned()
        .collect();
    for name in ["users.toml", "sessions.toml", "tokens.toml"] {
        let matching: Vec<_> = writes
            .iter()
            .filter(|(path, _)| path.ends_with(name))
            .collect();
        assert!(
            !matching.is_empty(),
            "expected a persisted {name} write from the async path"
        );
        assert!(
            matching.iter().all(|(_, tid)| *tid != caller_thread),
            "{name} persistence must not run on the calling async thread"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_users_file_encrypts_totp_secret() {
    let dir = auth_temp_dir("totp_encrypt");
    let plaintext;
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let _setup = enable_totp(&mgr, "admin").await;
        plaintext = in_memory_totp_secret(&mgr, "admin");
        assert_ne!(plaintext, "");
    }

    let users_file = dir.join("users.toml");
    let raw = std::fs::read_to_string(&users_file).unwrap();
    assert!(
        raw.contains("enc:v1:"),
        "TOTP secret must be sealed in users.toml: {raw}"
    );
    assert!(
        !raw.contains(&plaintext),
        "users.toml must not contain the recoverable TOTP secret: {raw}"
    );

    let parsed: UsersFile = toml::from_str(&raw).unwrap();
    let stored = parsed
        .users
        .iter()
        .find(|u| u.username == "admin")
        .and_then(|u| u.totp.as_ref())
        .expect("stored TOTP config");
    assert!(stored.secret.starts_with("enc:v1:"));
    assert_ne!(stored.secret, plaintext);

    // The atomic rewrite must not leave temporary files behind.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("users.tmp"))
        .collect();
    assert!(leftovers.is_empty(), "temporary files left behind");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_plaintext_totp_secret_migrates_on_load() {
    let dir = auth_temp_dir("totp_migrate");
    let plaintext;
    let backup_code;
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let setup = enable_totp(&mgr, "admin").await;
        plaintext = in_memory_totp_secret(&mgr, "admin");
        backup_code = setup.backup_codes[1].clone();
    }

    // Rewrite the file as a pre-1.9 plaintext store.
    let users_file = dir.join("users.toml");
    let raw = std::fs::read_to_string(&users_file).unwrap();
    let parsed: UsersFile = toml::from_str(&raw).unwrap();
    let sealed = parsed
        .users
        .iter()
        .find(|u| u.username == "admin")
        .and_then(|u| u.totp.as_ref())
        .expect("stored TOTP config")
        .secret
        .clone();
    assert!(sealed.starts_with("enc:v1:"));
    let legacy = raw.replace(&sealed, &plaintext);
    assert_ne!(legacy, raw);
    assert!(legacy.contains(&plaintext));
    std::fs::write(&users_file, &legacy).unwrap();

    // Startup migrates the legacy value and rewrites the file once.
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    let migrated = std::fs::read_to_string(&users_file).unwrap();
    assert!(
        migrated.contains("enc:v1:"),
        "migration must seal the plaintext secret"
    );
    assert!(
        !migrated.contains(&plaintext),
        "migration must not leave the plaintext secret behind"
    );

    // The migration's atomic rewrite must not leave a temp file behind.
    let leftovers: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("users.tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "migration left temporary files behind"
    );

    // The account still logs in with its remaining backup code.
    let LoginResult::TotpRequired { partial_token } =
        mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("expected TOTP required after migration");
    };
    match mgr
        .verify_totp(&partial_token, &backup_code, "127.0.0.1")
        .await
    {
        TotpVerifyResult::Success(session) => assert_eq!(session.username, "admin"),
        other => panic!("expected successful login after migration, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_encrypted_totp_login_survives_restart() {
    let dir = auth_temp_dir("totp_restart");
    let backup_code;
    let plaintext;
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        let setup = enable_totp(&mgr, "admin").await;
        backup_code = setup.backup_codes[1].clone();
        plaintext = in_memory_totp_secret(&mgr, "admin");
    }

    let raw = std::fs::read_to_string(dir.join("users.toml")).unwrap();
    assert!(raw.contains("enc:v1:"));
    assert!(!raw.contains(&plaintext));

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    let LoginResult::TotpRequired { partial_token } =
        mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("expected TOTP required after restart");
    };
    match mgr
        .verify_totp(&partial_token, &backup_code, "127.0.0.1")
        .await
    {
        TotpVerifyResult::Success(session) => assert_eq!(session.username, "admin"),
        other => panic!("expected successful login after restart, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_missing_totp_key_refuses_start() {
    let dir = auth_temp_dir("totp_missing_key");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        enable_totp(&mgr, "admin").await;
    }

    let key_path = dir.join("totp.key");
    let users_path = dir.join("users.toml");
    std::fs::remove_file(&key_path).unwrap();

    match AuthManager::with_storage(&dir, 24, 5) {
        Err(AuthStorageError::MissingTotpKey {
            key_path: actual_key,
            users_path: actual_users,
        }) => {
            assert_eq!(actual_key, key_path);
            assert_eq!(actual_users, users_path);
        }
        Ok(_) => panic!("startup must fail closed when the TOTP key is missing"),
        Err(other) => panic!("expected MissingTotpKey, got {other:?}"),
    }
    assert!(users_path.exists(), "the users file must not be rewritten");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_wrong_totp_key_refuses_start() {
    let dir = auth_temp_dir("totp_wrong_key");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        enable_totp(&mgr, "admin").await;
    }

    std::fs::write(dir.join("totp.key"), [0x5au8; 32]).unwrap();

    match AuthManager::with_storage(&dir, 24, 5) {
        Err(AuthStorageError::TotpSecretDecrypt { username, .. }) => {
            assert_eq!(username, "admin");
        }
        Ok(_) => panic!("startup must fail closed with the wrong TOTP key"),
        Err(other) => panic!("expected TotpSecretDecrypt, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_totp_key_file_is_0600() {
    let dir = auth_temp_dir("totp_key_0600");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    enable_totp(&mgr, "admin").await;
    drop(mgr);

    let key_path = dir.join("totp.key");
    assert!(key_path.exists());
    assert_eq!(std::fs::metadata(&key_path).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_totp_secret_not_in_list_users_or_debug() {
    let mgr = AuthManager::new();
    enable_totp(&mgr, "admin").await;
    let secret = in_memory_totp_secret(&mgr, "admin");
    assert_ne!(secret, "");

    let json = serde_json::to_string(&mgr.list_users()).unwrap();
    assert!(!json.contains(&secret), "list_users leaked the TOTP secret");
    assert!(!json.contains("secret"));

    let user_debug = {
        let users = lock(&mgr.users);
        format!("{:?}", users.get("admin").unwrap())
    };
    assert!(!user_debug.contains(&secret));
    assert!(user_debug.contains("<redacted>"));

    let totp_debug = {
        let users = lock(&mgr.users);
        format!("{:?}", users.get("admin").unwrap().totp.as_ref().unwrap())
    };
    assert!(!totp_debug.contains(&secret));
    assert!(totp_debug.contains("<redacted>"));
}

// ------------------------------------------------------------------
// Credential epoch / revocation races
// ------------------------------------------------------------------

fn install_login_gate(mgr: &AuthManager) -> (Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>) {
    let reached = Arc::new(tokio::sync::Notify::new());
    let resume = Arc::new(tokio::sync::Notify::new());
    *lock(&mgr.login_gate) = Some(LoginGate {
        reached: reached.clone(),
        resume: resume.clone(),
    });
    (reached, resume)
}

/// A password change that lands after the password was verified but before
/// the session insert must invalidate the in-flight login.
#[tokio::test]
async fn test_password_change_during_login_cannot_create_session() {
    let mgr = AuthManager::new();
    let (reached, resume) = install_login_gate(&mgr);
    let login_mgr = mgr.clone();
    let login =
        tokio::spawn(async move { login_mgr.login("admin", "adminadmin", "127.0.0.1").await });

    reached.notified().await;
    assert!(mgr.update_user_password("admin", "NewAdminPassword1").await);
    resume.notify_one();

    let result = login.await.expect("login task");
    assert!(
        !matches!(result, LoginResult::Success(_)),
        "an in-flight login must not outlive the password it verified: {result:?}"
    );
    assert_eq!(mgr.sessions_len(), 0);
}

/// Demoting an account while its login is in flight must not issue a
/// session carrying the old (higher) role.
#[tokio::test]
async fn test_demotion_during_login_cannot_create_session() {
    let mgr = AuthManager::new();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let (reached, resume) = install_login_gate(&mgr);
    let login_mgr = mgr.clone();
    let login = tokio::spawn(async move {
        login_mgr
            .login("alice", "AlicePassword1", "127.0.0.1")
            .await
    });

    reached.notified().await;
    assert!(mgr.set_user_role("alice", Role::Viewer).await);
    resume.notify_one();

    let result = login.await.expect("login task");
    assert!(
        !matches!(result, LoginResult::Success(_)),
        "a demoted account must not receive a session with its old role: {result:?}"
    );
    assert_eq!(mgr.sessions_len(), 0);
}

/// Deleting an account while its login is in flight must not create a
/// session for the removed account.
#[tokio::test]
async fn test_deletion_during_login_cannot_create_session() {
    let mgr = AuthManager::new();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let (reached, resume) = install_login_gate(&mgr);
    let login_mgr = mgr.clone();
    let login = tokio::spawn(async move {
        login_mgr
            .login("alice", "AlicePassword1", "127.0.0.1")
            .await
    });

    reached.notified().await;
    assert!(mgr.delete_user("alice").await);
    resume.notify_one();

    let result = login.await.expect("login task");
    assert!(
        !matches!(result, LoginResult::Success(_)),
        "a deleted account must not receive a session: {result:?}"
    );
    assert_eq!(mgr.sessions_len(), 0);
}

/// Enabling TOTP while a password-only login is in flight must force the
/// second factor instead of issuing a session that bypasses it.
#[tokio::test]
async fn test_totp_enable_during_login_cannot_bypass_second_factor() {
    let mgr = AuthManager::new();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let (reached, resume) = install_login_gate(&mgr);
    let login_mgr = mgr.clone();
    let login = tokio::spawn(async move {
        login_mgr
            .login("alice", "AlicePassword1", "127.0.0.1")
            .await
    });

    reached.notified().await;
    enable_totp(&mgr, "alice").await;
    resume.notify_one();

    let result = login.await.expect("login task");
    assert!(
        !matches!(result, LoginResult::Success(_)),
        "TOTP enablement must not be bypassed by an in-flight login: {result:?}"
    );
    assert_eq!(mgr.sessions_len(), 0);
}

/// Disabling TOTP while the second factor is being verified must not let
/// the in-flight verification re-enable the factor or issue a session.
#[tokio::test]
async fn test_totp_disable_during_verification_cannot_create_session() {
    let mgr = AuthManager::new();
    let setup = enable_totp(&mgr, "admin").await;
    let LoginResult::TotpRequired { partial_token } =
        mgr.login("admin", "adminadmin", "127.0.0.1").await
    else {
        panic!("expected TOTP challenge");
    };
    let code = setup.backup_codes[1].clone();

    let (reached, resume) = install_login_gate(&mgr);
    let verify_mgr = mgr.clone();
    let verify = tokio::spawn(async move {
        verify_mgr
            .verify_totp(&partial_token, &code, "127.0.0.1")
            .await
    });

    reached.notified().await;
    assert!(mgr.disable_totp("admin").await);
    resume.notify_one();

    let result = verify.await.expect("verify task");
    assert!(
        !matches!(result, TotpVerifyResult::Success(_)),
        "a disabled second factor must not authenticate an in-flight verification: {result:?}"
    );
    assert!(!mgr.totp_enabled("admin"), "disable must win the race");
    assert_eq!(mgr.sessions_len(), 0);
}

/// Even when the session/token revocation writes fail, a restart must not
/// resurrect credentials issued before a password change.
#[tokio::test]
async fn test_restart_rejects_credentials_older_than_password_change() {
    let dir = auth_temp_dir("epoch_restart");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let LoginResult::Success(session) = mgr.login("alice", "AlicePassword1", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    let (_meta, token) = mgr
        .create_token("stale", Role::Viewer, Some("alice"))
        .await
        .expect("token");
    assert!(dir.join("sessions.toml").exists());
    assert!(dir.join("tokens.toml").exists());

    // The users write succeeds, but the revocation writes fail: this is
    // the crash window where the old session/token files survive.
    {
        let mut rules = SECRET_WRITE_FAIL_AFTER
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        rules.push((dir.join("sessions.toml"), 0));
        rules.push((dir.join("tokens.toml"), 0));
    }
    assert!(mgr.update_user_password("alice", "AlicePassword2").await);
    drop(mgr);

    let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        reloaded.validate_session(&session.id).is_none(),
        "a persisted session must not survive a password change"
    );
    assert!(
        reloaded.validate_token(&token.token).is_none(),
        "a persisted API token must not survive a password change"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Sessions and tokens written before the credential epoch existed must be
/// rejected after upgrade (forced re-login / re-issue).
#[tokio::test]
async fn test_epochless_persisted_credentials_are_rejected() {
    let dir = auth_temp_dir("epoch_legacy");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        drop(mgr);
    }

    let legacy_session = r#"
[[sessions]]
id = "legacy-session"
username = "admin"
role = "admin"
created_at = 0
expires_at = 9999999999
csrf_token = ""
generation = 0
"#;
    std::fs::write(dir.join("sessions.toml"), legacy_session).unwrap();

    let plaintext = "sito_legacy_epochless_token";
    let legacy_token = format!(
        r#"
[[tokens]]
id = "tok_legacy"
name = "legacy"
hash = "{}"
scope = "viewer"
created_at = 1
generation = 0
owner = "admin"
"#,
        hash_token(plaintext)
    );
    std::fs::write(dir.join("tokens.toml"), legacy_token).unwrap();

    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        mgr.validate_session("legacy-session").is_none(),
        "an epochless persisted session must force re-login after upgrade"
    );
    assert!(
        mgr.validate_token(plaintext).is_none(),
        "an epochless persisted token must be rejected after upgrade"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// ------------------------------------------------------------------
// Fail-closed user persistence
// ------------------------------------------------------------------

/// A failed role write must roll the role back and leave existing sessions
/// valid instead of reporting success.
#[tokio::test]
async fn test_role_change_rolls_back_when_persistence_fails() {
    let dir = auth_temp_dir("role_persist_failure");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let LoginResult::Success(session) = mgr.login("alice", "AlicePassword1", "127.0.0.1").await
    else {
        panic!("login failed");
    };
    SECRET_WRITE_FAIL_AFTER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((dir.join("users.toml"), 0));

    let err = mgr
        .set_user_role_checked("alice", Role::Viewer)
        .await
        .expect_err("a failed users write must not report success");
    assert!(matches!(err, UserMutationError::Persistence(_)));
    assert_eq!(mgr.role_of("alice"), Some(Role::Operator));
    assert!(
        mgr.validate_session(&session.id).is_some(),
        "a rolled-back role change must not revoke the account's session"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed mutation's rollback must not clobber a concurrent mutation
/// that committed while the first write was in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_failed_rollback_does_not_clobber_concurrent_role_change() {
    let dir = auth_temp_dir("mutation_rollback_role");
    let mgr = Arc::new(AuthManager::with_storage(&dir, 24, 5).unwrap());
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;

    let users_path = dir.join("users.toml");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    SECRET_WRITE_START_SIGNALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((users_path.clone(), started_tx));
    SECRET_WRITE_DELAYS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((users_path.clone(), Duration::from_millis(500)));
    SECRET_WRITE_FAIL_AFTER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((users_path, 0));

    // First mutation: role change whose users write fails.
    let first_mgr = mgr.clone();
    let first =
        tokio::spawn(async move { first_mgr.set_user_role_checked("alice", Role::Viewer).await });
    started_rx.await.expect("first users write started");

    // Second mutation: promote while the first write is still sleeping.
    // Without a mutation lock it changes memory before the first rollback.
    let second_mgr = mgr.clone();
    let second =
        tokio::spawn(async move { second_mgr.set_user_role_checked("alice", Role::Admin).await });

    let first_result = first.await.expect("first task");
    assert!(
        matches!(first_result, Err(UserMutationError::Persistence(_))),
        "the first mutation must fail: {first_result:?}"
    );
    let second_result = second
        .await
        .expect("second task")
        .expect("the second mutation must succeed");
    assert!(second_result, "the promotion must report a change");
    assert_eq!(
        mgr.role_of("alice"),
        Some(Role::Admin),
        "the failed mutation's rollback must not clobber the committed promotion"
    );

    drop(mgr);
    let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert_eq!(
        reloaded.role_of("alice"),
        Some(Role::Admin),
        "the committed promotion must be the persisted state"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed mutation's rollback must not resurrect an account that a
/// concurrent mutation deleted successfully.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_failed_rollback_does_not_resurrect_deleted_account() {
    let dir = auth_temp_dir("mutation_rollback_delete");
    let mgr = Arc::new(AuthManager::with_storage(&dir, 24, 5).unwrap());
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;

    let users_path = dir.join("users.toml");
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    SECRET_WRITE_START_SIGNALS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((users_path.clone(), started_tx));
    SECRET_WRITE_DELAYS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((users_path.clone(), Duration::from_millis(500)));
    SECRET_WRITE_FAIL_AFTER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((users_path, 0));

    // First mutation: role change whose users write fails.
    let first_mgr = mgr.clone();
    let first =
        tokio::spawn(async move { first_mgr.set_user_role_checked("alice", Role::Viewer).await });
    started_rx.await.expect("first users write started");

    // Second mutation: delete the account while the first write sleeps.
    let second_mgr = mgr.clone();
    let second = tokio::spawn(async move { second_mgr.delete_user_checked("alice").await });

    let first_result = first.await.expect("first task");
    assert!(
        matches!(first_result, Err(UserMutationError::Persistence(_))),
        "the first mutation must fail: {first_result:?}"
    );
    second
        .await
        .expect("second task")
        .expect("the deletion must succeed");
    assert!(
        !mgr.has_user("alice"),
        "the failed mutation's rollback must not resurrect the deleted account"
    );

    drop(mgr);
    let reloaded = AuthManager::with_storage(&dir, 24, 5).unwrap();
    assert!(
        !reloaded.has_user("alice"),
        "the deletion must be the persisted state"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed TOTP enable write must not report success or leave the factor
/// enabled in memory.
#[tokio::test]
async fn test_totp_enable_rolls_back_when_persistence_fails() {
    let dir = auth_temp_dir("totp_enable_persist_failure");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    let setup = mgr.init_totp_setup("alice").await.expect("setup");
    SECRET_WRITE_FAIL_AFTER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((dir.join("users.toml"), 0));

    assert!(
        !mgr.confirm_totp_setup("alice", &setup.backup_codes[0])
            .await,
        "a failed write must not report TOTP enabled"
    );
    assert!(!mgr.totp_enabled("alice"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// A failed TOTP disable write must leave the factor enabled and report a
/// failure.
#[tokio::test]
async fn test_totp_disable_rolls_back_when_persistence_fails() {
    let dir = auth_temp_dir("totp_disable_persist_failure");
    let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
    mgr.create_user("alice", "AlicePassword1", Role::Operator)
        .await;
    enable_totp(&mgr, "alice").await;
    SECRET_WRITE_FAIL_AFTER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((dir.join("users.toml"), 0));

    assert!(
        !mgr.disable_totp("alice").await,
        "a failed write must not report TOTP disabled"
    );
    assert!(
        mgr.totp_enabled("alice"),
        "the second factor must remain enabled when its removal did not land"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `reset-admin` must report a users-file write failure instead of
/// claiming the new credentials are installed.
#[tokio::test]
async fn test_reset_admin_reports_users_write_failure() {
    let dir = auth_temp_dir("reset_persist_failure");
    {
        let mgr = AuthManager::with_storage(&dir, 24, 5).unwrap();
        assert!(mgr.update_user_password("admin", "OldAdminPassword1").await);
    }
    SECRET_WRITE_FAIL_AFTER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((dir.join("users.toml"), 0));

    let result = AuthManager::reset_admin_credentials(&dir, "NewAdminPassword1");
    assert!(
        result.is_err(),
        "reset-admin must not report success when users.toml was not written"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

mod send_checks {
    use super::*;

    #[test]
    fn test_auth_futures_are_send() {
        fn assert_send<F: std::future::Future + Send>(_f: F) {}
        let mgr = AuthManager::new();
        assert_send(mgr.update_user_password("admin", "x"));
        assert_send(mgr.verify_second_factor("admin", "x"));
        assert_send(mgr.confirm_totp_setup("admin", "x"));
        assert_send(mgr.create_user("a", "b", Role::Viewer));
        assert_send(mgr.login("a", "b", "c"));
        assert_send(mgr.verify_totp("a", "b", "c"));
        assert_send(mgr.set_user_role("a", Role::Viewer));
        assert_send(mgr.delete_user("a"));
        assert_send(mgr.disable_totp("a"));
        assert_send(mgr.logout("a"));
        assert_send(mgr.create_token("a", Role::Viewer, None));
        assert_send(mgr.delete_token("a"));
        assert_send(mgr.prune());
    }
}
