//! Client tests against the in-process witness server (ADR-0010 test plan A/C
//! foundation rows). Expiry uses the server's `ManualClock`; TLS and auth use
//! real files and a real handshake. No plaintext or mock transport is used.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use sito_ha_types::config::{PromotionConfig, WitnessClientConfig};

use super::WitnessClient;
use super::WitnessClientError;
use crate::witness::clock::ManualClock;
use crate::witness::record::LEASE_PROTOCOL_VERSION;
use crate::witness::server::{WitnessConfig, WitnessHandle, start_witness_server};
use crate::witness::{AcquireRequest, RenewRequest};

const CLUSTER: &str = "home-dns";
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const START_MS: i64 = 1_760_000_000_000;
const TTL: u64 = 30;

struct Fixture {
    dir: PathBuf,
    ca: PathBuf,
    token_file: PathBuf,
    pin: String,
    cert: PathBuf,
    key: PathBuf,
    addr: std::net::SocketAddr,
    clock: Arc<ManualClock>,
    handle: Option<WitnessHandle>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.take();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Fixture {
    async fn start() -> Self {
        let dir = unique_dir("witness_client");
        std::fs::create_dir_all(&dir).unwrap();
        let certs = crate::crypto::generate_ha_certs(&dir.join("certs"), true, false).unwrap();
        let cert = certs.master_cert_path.clone().unwrap();
        let key = certs.master_key_path.clone().unwrap();
        let pin = certs.master_fingerprint.clone().unwrap();
        let ca = certs.ca_cert_path.clone();
        let cert_for_mock = cert.clone();
        let key_for_mock = key.clone();
        let token_file = dir.join("witness.token");
        write_secret(&token_file, TOKEN.as_bytes());
        let state_dir = dir.join("state");
        let clock = Arc::new(ManualClock::new(START_MS));
        let witness_clock: Arc<dyn crate::witness::clock::Clock> = clock.clone();
        let handle = start_witness_server(
            WitnessConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                cluster_id: CLUSTER.to_string(),
                cert,
                key,
                token_file: token_file.clone(),
                state_dir,
            },
            witness_clock,
        )
        .await
        .unwrap();
        let addr = handle.local_addr();
        Self {
            dir,
            ca,
            token_file,
            pin,
            cert: cert_for_mock,
            key: key_for_mock,
            addr,
            clock,
            handle: Some(handle),
        }
    }

    fn config(&self) -> PromotionConfig {
        PromotionConfig {
            enabled: true,
            candidate: true,
            cluster_id: Some(CLUSTER.to_string()),
            node_id: Some("node-a".to_string()),
            witness: WitnessClientConfig {
                url: Some(format!("https://127.0.0.1:{}", self.addr.port())),
                ca: Some(self.ca.clone()),
                server_name: None,
                fingerprint: None,
                token_file: Some(self.token_file.clone()),
            },
            ..Default::default()
        }
    }

    fn client(&self) -> WitnessClient {
        WitnessClient::new(&self.config()).expect("client configuration")
    }

    fn config_for_addr(&self, addr: SocketAddr) -> PromotionConfig {
        let mut config = self.config();
        config.witness.url = Some(format!("https://127.0.0.1:{}", addr.port()));
        config
    }
}

/// Serves one TLS request with a fixed JSON body; used to exercise response
/// validation that the real witness cannot produce on demand.
async fn spawn_static_info(
    cert: &Path,
    key: &Path,
    body: String,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        crate::transport::load_certs_pem(cert).unwrap(),
        crate::transport::load_key_pem(key).unwrap(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let handle = tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = acceptor.accept(stream).await else {
            return;
        };
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    (addr, handle)
}

fn holder(node: &str) -> String {
    format!("{node}/00000000-0000-0000-0000-000000000001")
}

fn hash(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn acquire(term: u64, version: u64, bundle_hash: &str) -> AcquireRequest {
    AcquireRequest {
        holder: holder("node-a"),
        node_id: "node-a".to_string(),
        expected_term: None,
        expected_revision: None,
        term,
        version,
        bundle_hash: bundle_hash.to_string(),
        ttl_secs: TTL,
    }
}

fn unique_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sito_{label}_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ))
}

fn write_secret(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

#[tokio::test]
async fn info_and_empty_lease_roundtrip() {
    let fixture = Fixture::start().await;
    let client = fixture.client();

    let info = client.info().await.expect("info");
    assert_eq!(info.lease_protocol_version, LEASE_PROTOCOL_VERSION);
    assert_eq!(info.cluster_id, CLUSTER);
    assert_eq!(info.now_unix_ms, START_MS);

    assert_eq!(client.lease().await.expect("empty lease"), None);
}

#[tokio::test]
async fn acquire_and_renew_use_the_server_dtos() {
    let fixture = Fixture::start().await;
    let client = fixture.client();

    let acquired = client
        .acquire(&acquire(1, 0, "none"))
        .await
        .expect("first acquire");
    assert_eq!(acquired.term, 1);
    assert_eq!(acquired.revision, 1);
    assert_eq!(acquired.version, 0);
    assert_eq!(acquired.bundle_hash, "none");

    let current = client.lease().await.expect("lease").expect("record");
    assert_eq!(current, acquired);

    let renewed = client
        .renew(&RenewRequest {
            holder: holder("node-a"),
            term: 1,
            expected_revision: 1,
            version: 0,
            bundle_hash: "none".to_string(),
            ttl_secs: TTL,
        })
        .await
        .expect("renew");
    assert_eq!(renewed.term, 1);
    assert_eq!(renewed.revision, 2);
}

#[tokio::test]
async fn acquire_normalizes_prefixed_and_uppercase_hashes() {
    let fixture = Fixture::start().await;
    let client = fixture.client();
    let bare = hash(7);

    let acquired = client
        .acquire(&acquire(1, 1, &format!("blake3:{}", bare.to_uppercase())))
        .await
        .expect("normalized acquire");
    assert_eq!(acquired.version, 1);
    assert_eq!(acquired.bundle_hash, bare);
    assert!(!acquired.bundle_hash.contains("blake3:"));
}

#[tokio::test]
async fn malformed_hashes_fail_before_any_request() {
    let fixture = Fixture::start().await;
    let client = fixture.client();

    let bad_zero = client.acquire(&acquire(1, 0, &hash(1))).await;
    assert!(matches!(
        bad_zero,
        Err(WitnessClientError::InvalidHash { .. })
    ));

    let bad_positive = client.acquire(&acquire(1, 1, "none")).await;
    assert!(matches!(
        bad_positive,
        Err(WitnessClientError::InvalidHash { .. })
    ));

    let bad_renew = client
        .renew(&RenewRequest {
            holder: holder("node-a"),
            term: 1,
            expected_revision: 1,
            version: 0,
            bundle_hash: "garbage".to_string(),
            ttl_secs: TTL,
        })
        .await;
    assert!(matches!(
        bad_renew,
        Err(WitnessClientError::InvalidHash { .. })
    ));

    // Nothing was written by the rejected requests.
    assert_eq!(client.lease().await.expect("lease"), None);
}

#[tokio::test]
async fn conflict_reports_the_current_record() {
    let fixture = Fixture::start().await;
    let client = fixture.client();
    client.acquire(&acquire(1, 0, "none")).await.unwrap();

    let mut second = acquire(2, 0, "none");
    second.expected_term = Some(1);
    second.expected_revision = Some(1);
    // The lease is still live, so the CAS must refuse the takeover.
    let error = client.acquire(&second).await.expect_err("live lease");
    match error {
        WitnessClientError::Conflict {
            reason,
            current: Some(current),
            ..
        } => {
            assert_eq!(reason.as_deref(), Some("lease_held"));
            assert_eq!(current.term, 1);
            assert_eq!(current.holder, holder("node-a"));
        }
        other => panic!("expected a 409 with the current record, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_or_wrong_token_is_an_auth_failure() {
    let fixture = Fixture::start().await;
    let mut config = fixture.config();
    let wrong = fixture.dir.join("wrong.token");
    write_secret(&wrong, b"not-the-token");
    config.witness.token_file = Some(wrong);
    let client = WitnessClient::new(&config).unwrap();

    let error = client.info().await.expect_err("401");
    assert!(matches!(error, WitnessClientError::Auth { .. }));
    assert_eq!(error.reason_code(), "witness_auth_failed");
}

#[tokio::test]
async fn token_file_must_be_mode_0600() {
    use std::os::unix::fs::PermissionsExt as _;

    let fixture = Fixture::start().await;
    let path = fixture.dir.join("open.token");
    std::fs::write(&path, TOKEN).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut config = fixture.config();
    config.witness.token_file = Some(path);

    let error = WitnessClient::new(&config).expect_err("0644 token must be refused");
    assert!(matches!(error, WitnessClientError::Auth { .. }));
}

#[tokio::test]
async fn cluster_mismatch_is_explicit() {
    let fixture = Fixture::start().await;
    let mut config = fixture.config();
    config.cluster_id = Some("other-cluster".to_string());
    let client = WitnessClient::new(&config).unwrap();

    let error = client.info().await.expect_err("403");
    assert!(matches!(error, WitnessClientError::ClusterMismatch { .. }));
    assert_eq!(error.reason_code(), "witness_cluster_mismatch");
}

#[tokio::test]
async fn wrong_ca_wrong_pin_and_wrong_san_fail_closed() {
    let fixture = Fixture::start().await;

    // A foreign CA must not verify the witness certificate.
    let foreign_dir = unique_dir("witness_client_foreign");
    std::fs::create_dir_all(&foreign_dir).unwrap();
    let foreign =
        crate::crypto::generate_ha_certs(&foreign_dir.join("certs"), true, false).unwrap();
    let mut wrong_ca = fixture.config();
    wrong_ca.witness.ca = Some(foreign.ca_cert_path.clone());
    let client = WitnessClient::new(&wrong_ca).unwrap();
    let error = client.info().await.expect_err("wrong CA");
    assert!(matches!(error, WitnessClientError::Tls { .. }), "{error:?}");
    assert_eq!(error.reason_code(), "witness_tls_failed");

    // A pin is additive: a wrong pin fails even with the correct CA.
    let mut wrong_pin = fixture.config();
    wrong_pin.witness.fingerprint = Some(hash(0xaa));
    let client = WitnessClient::new(&wrong_pin).unwrap();
    let error = client.info().await.expect_err("wrong pin");
    assert!(matches!(error, WitnessClientError::Tls { .. }), "{error:?}");

    // A matching pin with the correct CA succeeds.
    let mut pinned = fixture.config();
    pinned.witness.fingerprint = Some(fixture.pin.clone());
    WitnessClient::new(&pinned)
        .unwrap()
        .info()
        .await
        .expect("matching pin");

    // The SAN is always validated; a pin does not replace it.
    let mut wrong_name = fixture.config();
    wrong_name.witness.server_name = Some("wrong.example".to_string());
    wrong_name.witness.fingerprint = Some(fixture.pin.clone());
    let client = WitnessClient::new(&wrong_name).unwrap();
    let error = client.info().await.expect_err("wrong SAN");
    assert!(matches!(error, WitnessClientError::Tls { .. }), "{error:?}");

    let _ = std::fs::remove_dir_all(&foreign_dir);
}

#[tokio::test]
async fn plaintext_and_invalid_urls_are_rejected() {
    let fixture = Fixture::start().await;
    let mut config = fixture.config();
    config.witness.url = Some("http://127.0.0.1:8954".to_string());
    let error = WitnessClient::new(&config).expect_err("plaintext must be rejected");
    assert!(matches!(
        error,
        WitnessClientError::InvalidConfig {
            field: "ha.promotion.witness.url",
            ..
        }
    ));

    let mut disabled = fixture.config();
    disabled.enabled = false;
    assert!(matches!(
        WitnessClient::new(&disabled),
        Err(WitnessClientError::Disabled)
    ));
}

#[tokio::test]
async fn unreachable_witness_is_a_typed_unavailable_error() {
    let fixture = Fixture::start().await;
    let config = fixture.config();
    let client = WitnessClient::new(&config).unwrap();

    // Stop the witness and use its now-closed port.
    let mut fixture = fixture;
    fixture.handle.take().unwrap().shutdown().await;
    let error = client.info().await.expect_err("unreachable");
    assert!(
        matches!(error, WitnessClientError::Unavailable { .. }),
        "{error:?}"
    );
    assert!(error.is_retryable());
}

#[tokio::test]
async fn lease_returns_expired_record_and_acquire_takes_next_term() {
    let fixture = Fixture::start().await;
    let client = fixture.client();
    let first = client.acquire(&acquire(1, 0, "none")).await.unwrap();

    fixture.clock.advance(i64::try_from(TTL * 1000).unwrap());
    let expired = client
        .lease()
        .await
        .expect("expired record is still returned")
        .expect("record");
    assert_eq!(expired.holder, first.holder);
    assert!(expired.is_expired(START_MS + 30_000));

    let mut takeover = acquire(2, 0, "none");
    takeover.expected_term = Some(1);
    takeover.expected_revision = Some(1);
    let second = client.acquire(&takeover).await.expect("expired takeover");
    assert_eq!(second.term, 2);
    assert_eq!(second.revision, 2);
    assert_eq!(second.expires_unix_ms, START_MS + 60_000);
}

#[tokio::test]
async fn renew_after_expiry_is_a_409_conflict() {
    let fixture = Fixture::start().await;
    let client = fixture.client();
    let first = client.acquire(&acquire(1, 0, "none")).await.unwrap();
    fixture.clock.advance(i64::try_from(TTL * 1000).unwrap());

    let error = client
        .renew(&RenewRequest {
            holder: first.holder.clone(),
            term: first.term,
            expected_revision: first.revision,
            version: 0,
            bundle_hash: "none".to_string(),
            ttl_secs: TTL,
        })
        .await
        .expect_err("expired renew");
    match error {
        WitnessClientError::Conflict {
            reason,
            current: Some(current),
            ..
        } => {
            assert_eq!(reason.as_deref(), Some("lease_expired"));
            assert_eq!(current.term, 1);
        }
        other => panic!("expected lease_expired conflict, got {other:?}"),
    }
}

#[tokio::test]
async fn ttl_outside_the_adr_bounds_maps_to_non_retryable_server_error() {
    let fixture = Fixture::start().await;
    let client = fixture.client();

    for ttl in [4, 301] {
        let mut request = acquire(1, 0, "none");
        request.ttl_secs = ttl;
        let error = client.acquire(&request).await.expect_err("invalid ttl");
        match error {
            WitnessClientError::Server { status, .. } => assert_eq!(status, 400),
            other => panic!("expected HTTP 400 for ttl {ttl}, got {other:?}"),
        }
        assert!(!error.is_retryable(), "400 must not be retried");
    }
    assert_eq!(client.lease().await.expect("no state change"), None);
}

#[tokio::test]
async fn missing_ca_or_token_is_invalid_config() {
    let fixture = Fixture::start().await;

    let mut no_ca = fixture.config();
    no_ca.witness.ca = None;
    assert!(matches!(
        WitnessClient::new(&no_ca),
        Err(WitnessClientError::InvalidConfig {
            field: "ha.promotion.witness.ca",
            ..
        })
    ));

    let mut no_token = fixture.config();
    no_token.witness.token_file = None;
    assert!(matches!(
        WitnessClient::new(&no_token),
        Err(WitnessClientError::InvalidConfig {
            field: "ha.promotion.witness.token_file",
            ..
        })
    ));
}

#[tokio::test]
async fn wrong_ca_and_wrong_pin_together_fail_closed() {
    let fixture = Fixture::start().await;
    let foreign_dir = unique_dir("witness_client_foreign_pin");
    std::fs::create_dir_all(&foreign_dir).unwrap();
    let foreign =
        crate::crypto::generate_ha_certs(&foreign_dir.join("certs"), true, false).unwrap();

    let mut config = fixture.config();
    config.witness.ca = Some(foreign.ca_cert_path.clone());
    config.witness.fingerprint = Some(hash(0xbb));
    let client = WitnessClient::new(&config).unwrap();
    let error = client.info().await.expect_err("wrong CA and pin");
    assert!(matches!(error, WitnessClientError::Tls { .. }), "{error:?}");

    let _ = std::fs::remove_dir_all(&foreign_dir);
}

#[tokio::test]
async fn info_rejects_protocol_and_cluster_mismatches() {
    let fixture = Fixture::start().await;

    let (addr, handle) = spawn_static_info(
        &fixture.cert,
        &fixture.key,
        format!(r#"{{"lease_protocol_version":2,"cluster_id":"{CLUSTER}","now_unix_ms":1}}"#),
    )
    .await;
    let client = WitnessClient::new(&fixture.config_for_addr(addr)).unwrap();
    let error = client.info().await.expect_err("protocol mismatch");
    assert!(matches!(
        error,
        WitnessClientError::ProtocolMismatch {
            found: 2,
            expected: 1
        }
    ));
    handle.await.unwrap();

    let (addr, handle) = spawn_static_info(
        &fixture.cert,
        &fixture.key,
        r#"{"lease_protocol_version":1,"cluster_id":"other-cluster","now_unix_ms":1}"#.to_string(),
    )
    .await;
    let client = WitnessClient::new(&fixture.config_for_addr(addr)).unwrap();
    let error = client.info().await.expect_err("cluster mismatch");
    assert!(matches!(error, WitnessClientError::ClusterMismatch { .. }));
    handle.await.unwrap();
}
