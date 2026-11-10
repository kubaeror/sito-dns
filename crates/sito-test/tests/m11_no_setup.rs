//! Regression for the `--no-setup` fresh-boot path (final review Important #4).
//!
//! `--no-setup` without a config used to keep `filtering.enabled = true` with
//! zero sources. Since the P2-95 fail-closed change that SERVFAILed every
//! query until the operator added a list. The bootstrap path now disables
//! filtering explicitly; this test starts that configuration and resolves a
//! real query.

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};
use sito::cli::{NoSetupBootstrap, prepare_no_setup_bootstrap};
use sito_core::config::Config;
use sito_proto::rdata::A;
use sito_test::{MockDnsServer, TestServerInstance};
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_no_setup_fresh_boot_resolves_a_query() {
    let mock_upstream = MockDnsServer::spawn().await.unwrap();
    mock_upstream.add_a_record("no-setup.example", Ipv4Addr::new(192, 0, 2, 80), 300);

    let dir = std::env::temp_dir().join(format!(
        "sito_no_setup_e2e_{}_{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.toml");

    let mut config = Config::default();
    config.server.data_dir = dir.clone();
    config.dns.dnssec.validate = false;
    config.upstream.servers = vec![mock_upstream.addr().to_string()];

    match prepare_no_setup_bootstrap(&config_path, &mut config).expect("bootstrap") {
        NoSetupBootstrap::GeneratedPassword(password) => {
            assert_eq!(password.len(), 48);
        }
        other => panic!("expected a generated password, got {other:?}"),
    }
    assert!(
        !config.filtering.enabled,
        "a fresh --no-setup boot has no filter sources and must not fail closed"
    );

    let server = TestServerInstance::spawn(config).await.unwrap();
    let response = server
        .client()
        .query_udp("no-setup.example", RecordType::A)
        .await
        .unwrap();

    assert_eq!(
        response.metadata.response_code,
        ResponseCode::NoError,
        "a fresh --no-setup install must resolve instead of SERVFAIL"
    );
    assert_eq!(response.answers.len(), 1);
    assert!(
        matches!(response.answers[0].data, RData::A(A(ip)) if ip == Ipv4Addr::new(192, 0, 2, 80))
    );

    server.shutdown().await.unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}
