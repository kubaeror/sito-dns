//! Regression tests for listener binding defaults (audit 6, WP-0.3).
//!
//! The shipped default `dns.bind = ["0.0.0.0", "::"]` must start on a
//! dual-stack Linux host. Before the explicit `IPV6_V6ONLY` socket handling,
//! the `::` TCP bind failed with `EADDRINUSE` after `0.0.0.0`, so the server
//! never started with the default (or wizard-generated) configuration.

#![allow(clippy::pedantic)]

use sito_core::config::Config;
use sito_test::harness::{HarnessOptions, TestServerInstance};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

#[tokio::test]
async fn test_default_dual_stack_bind_starts_and_accepts_both_families() {
    let mut config = Config::default();
    // Keep the test fully offline: no upstream traffic is expected anyway,
    // but point the resolver at a closed local port.
    config.upstream.servers = vec!["127.0.0.1:1".to_string()];

    let server = TestServerInstance::spawn_with_options(
        config,
        HarnessOptions {
            dns_bind: Some(vec![
                IpAddr::from_str("0.0.0.0").expect("valid v4 wildcard"),
                IpAddr::from_str("::").expect("valid v6 wildcard"),
            ]),
        },
    )
    .await
    .expect("default dual-stack bind must start the server");

    // IPv4 readiness is asserted by the harness itself; require that the IPv6
    // listener also accepts connections.
    let v6 = SocketAddr::new(IpAddr::from_str("::1").expect("valid ::1"), server.port());
    let accepted =
        tokio::time::timeout(Duration::from_secs(3), tokio::net::TcpStream::connect(v6)).await;
    assert!(
        matches!(accepted, Ok(Ok(_))),
        "IPv6 TCP listener must accept on ::1 (got {accepted:?})"
    );

    server.shutdown().await.expect("clean shutdown");
}
