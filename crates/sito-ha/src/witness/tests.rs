//! Witness server tests from ADR-0010 test plan B, using real TLS and state
//! directories. Expiry is driven by a `ManualClock` so the CAS/expiry rules are
//! exercised exactly as in production without weakening them for speed.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::admin::{lease_admin_set_term_only_with_clock, lease_admin_set_with_clock};
use super::clock::{Clock, ManualClock};
use super::normalize_hash;
use super::record::{LEASE_PROTOCOL_VERSION, LeaseRecord};
use super::server::{WitnessConfig, start_witness_server};
use super::store::{INITIALIZED_FILE, LEASE_FILE, LeaseStore};

const CLUSTER: &str = "home-dns";
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const START_MS: i64 = 1_760_000_000_000;
const TTL: u64 = 30;

struct TestWitness {
    dir: PathBuf,
    cert: PathBuf,
    key: PathBuf,
    token_file: PathBuf,
    state_dir: PathBuf,
    ca: PathBuf,
    clock: Arc<ManualClock>,
    handle: Option<super::server::WitnessHandle>,
}

impl Drop for TestWitness {
    fn drop(&mut self) {
        self.handle.take();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl TestWitness {
    async fn start() -> Self {
        Self::start_at(START_MS).await
    }

    async fn start_at(initial_ms: i64) -> Self {
        let dir = unique_dir("witness");
        std::fs::create_dir_all(&dir).unwrap();
        let certs = crate::crypto::generate_ha_certs(&dir.join("certs"), true, false).unwrap();
        let cert = certs.master_cert_path.clone().unwrap();
        let key = certs.master_key_path.clone().unwrap();
        let ca = certs.ca_cert_path.clone();
        let token_file = dir.join("witness.token");
        write_secret(&token_file, TOKEN.as_bytes());
        let state_dir = dir.join("state");
        let clock = Arc::new(ManualClock::new(initial_ms));
        let config = WitnessConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cluster_id: CLUSTER.to_string(),
            cert: cert.clone(),
            key: key.clone(),
            token_file: token_file.clone(),
            state_dir: state_dir.clone(),
        };
        let handle = start_witness_server(config, clock.clone()).await.unwrap();
        Self {
            dir,
            cert,
            key,
            token_file,
            state_dir,
            ca,
            clock,
            handle: Some(handle),
        }
    }

    async fn restart(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown().await;
        }
        let config = WitnessConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cluster_id: CLUSTER.to_string(),
            cert: self.cert.clone(),
            key: self.key.clone(),
            token_file: self.token_file.clone(),
            state_dir: self.state_dir.clone(),
        };
        self.handle = Some(
            start_witness_server(config, self.clock.clone())
                .await
                .unwrap(),
        );
    }

    async fn stop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.shutdown().await;
        }
    }

    fn addr(&self) -> SocketAddr {
        self.handle.as_ref().unwrap().local_addr()
    }

    async fn get(&self, path: &str) -> HttpResponse {
        self.request_with(path, Some(TOKEN), Some(CLUSTER), None, "GET")
            .await
    }

    async fn post(&self, path: &str, body: &Value) -> HttpResponse {
        let bytes = serde_json::to_vec(body).unwrap();
        self.request_with(path, Some(TOKEN), Some(CLUSTER), Some(&bytes), "POST")
            .await
    }

    async fn request_with(
        &self,
        path: &str,
        token: Option<&str>,
        cluster: Option<&str>,
        body: Option<&[u8]>,
        method: &str,
    ) -> HttpResponse {
        let mut stream = self
            .connect(Some(&self.ca), "127.0.0.1", None)
            .await
            .expect("TLS handshake with the witness");
        write_request(&mut stream, method, path, token, cluster, body).await;
        read_response(&mut stream).await
    }

    async fn connect(
        &self,
        ca: Option<&Path>,
        server_name: &str,
        pin: Option<&str>,
    ) -> Result<TlsStream<TcpStream>, String> {
        let config = crate::transport::build_client_tls_config(None, None, pin, false, ca)
            .map_err(|error| error.to_string())?;
        let connector = TlsConnector::from(config);
        let tcp = TcpStream::connect(self.addr())
            .await
            .map_err(|error| error.to_string())?;
        let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|error| error.to_string())?;
        connector
            .connect(name, tcp)
            .await
            .map_err(|error| error.to_string())
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    fn record(&self) -> LeaseRecord {
        serde_json::from_slice(&self.body).expect("lease record response")
    }
}

async fn write_request(
    stream: &mut TlsStream<TcpStream>,
    method: &str,
    path: &str,
    token: Option<&str>,
    cluster: Option<&str>,
    body: Option<&[u8]>,
) {
    use std::fmt::Write as _;

    let body = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\nContent-Type: application/json\r\n",
        body.len()
    );
    if let Some(token) = token {
        let _ = write!(request, "Authorization: Bearer {token}\r\n");
    }
    if let Some(cluster) = cluster {
        let _ = write!(request, "X-Sito-Cluster: {cluster}\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.flush().await.unwrap();
}

async fn read_response(stream: &mut TlsStream<TcpStream>) -> HttpResponse {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.unwrap();
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("HTTP response header terminator");
    let head = std::str::from_utf8(&bytes[..split]).unwrap();
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .expect("HTTP status code");
    HttpResponse {
        status,
        body: bytes[split + 4..].to_vec(),
    }
}

fn acquire(
    holder: &str,
    node_id: &str,
    expected: Option<(u64, u64)>,
    term: u64,
    version: u64,
    hash: &str,
    ttl: u64,
) -> Value {
    json!({
        "holder": holder,
        "node_id": node_id,
        "expected_term": expected.map(|(term, _)| term),
        "expected_revision": expected.map(|(_, revision)| revision),
        "term": term,
        "version": version,
        "bundle_hash": hash,
        "ttl_secs": ttl,
    })
}

fn renew(holder: &str, term: u64, revision: u64, version: u64, hash: &str, ttl: u64) -> Value {
    json!({
        "holder": holder,
        "term": term,
        "expected_revision": revision,
        "version": version,
        "bundle_hash": hash,
        "ttl_secs": ttl,
    })
}

fn holder(node: &str) -> String {
    format!("{node}/00000000-0000-0000-0000-000000000001")
}

fn hash(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn unique_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sito_witness_{label}_{}_{}",
        std::process::id(),
        rand::random::<u64>()
    ))
}

fn write_secret(path: &Path, bytes: &[u8]) {
    #[cfg(unix)]
    {
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
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes).unwrap();
    }
}

async fn first_grant(witness: &TestWitness) -> LeaseRecord {
    let response = witness
        .post(
            "/v1/lease/acquire",
            &acquire(&holder("node-a"), "node-a", None, 1, 0, "none", TTL),
        )
        .await;
    assert_eq!(response.status, 200, "first acquire: {:?}", response.body);
    response.record()
}

// --- health, info and first acquire ---------------------------------------

#[tokio::test]
async fn healthz_needs_no_auth_and_info_reports_protocol_and_clock() {
    let witness = TestWitness::start().await;
    let health = witness
        .request_with("/healthz", None, None, None, "GET")
        .await;
    assert_eq!(health.status, 200);

    let info = witness.get("/v1/info").await;
    assert_eq!(info.status, 200);
    let info = info.json();
    assert_eq!(info["lease_protocol_version"], LEASE_PROTOCOL_VERSION);
    assert_eq!(info["cluster_id"], CLUSTER);
    assert_eq!(info["now_unix_ms"], START_MS);
}

#[tokio::test]
async fn acquire_on_empty_state_grants_term_one_and_persists_files() {
    let witness = TestWitness::start().await;
    let empty = witness.get("/v1/lease").await;
    assert_eq!(empty.status, 204);
    assert_eq!(empty.body, Vec::<u8>::new());

    let record = first_grant(&witness).await;
    assert_eq!(record.schema, 1);
    assert_eq!(record.cluster_id, CLUSTER);
    assert_eq!(record.term, 1);
    assert_eq!(record.revision, 1);
    assert_eq!(record.version, 0);
    assert_eq!(record.bundle_hash, "none");
    assert_eq!(record.acquired_unix_ms, START_MS);
    assert_eq!(record.expires_unix_ms, START_MS + 30_000);
    assert!(witness.state_dir.join(LEASE_FILE).is_file());
    assert!(witness.state_dir.join(INITIALIZED_FILE).is_file());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for name in [LEASE_FILE, INITIALIZED_FILE] {
            let mode = std::fs::metadata(witness.state_dir.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name} must be 0600");
        }
        let dir_mode = std::fs::metadata(&witness.state_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "state dir must be 0700");
    }
}

#[tokio::test]
async fn version_zero_requires_none_and_positive_version_rejects_none() {
    let witness = TestWitness::start().await;
    let bad_zero = witness
        .post(
            "/v1/lease/acquire",
            &acquire(&holder("node-a"), "node-a", None, 1, 0, &hash(1), TTL),
        )
        .await;
    assert_eq!(bad_zero.status, 400);

    let bad_positive = witness
        .post(
            "/v1/lease/acquire",
            &acquire(&holder("node-a"), "node-a", None, 1, 1, "none", TTL),
        )
        .await;
    assert_eq!(bad_positive.status, 400);

    let ok = first_grant(&witness).await;
    assert_eq!(ok.term, 1);
}

// --- renew ----------------------------------------------------------------

#[tokio::test]
async fn renew_keeps_term_increments_revision_and_extends_expiry() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    witness.clock.advance(10_000);

    let response = witness
        .post(
            "/v1/lease/renew",
            &renew(&first.holder, 1, first.revision, 0, "none", TTL),
        )
        .await;
    assert_eq!(response.status, 200);
    let renewed = response.record();
    assert_eq!(renewed.term, 1);
    assert_eq!(renewed.revision, 2);
    assert_eq!(renewed.expires_unix_ms, START_MS + 40_000);
}

#[tokio::test]
async fn renew_rejects_stale_revision_foreign_holder_and_wrong_term() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    witness.clock.advance(1_000);

    for (body, reason) in [
        (
            renew(&first.holder, 1, first.revision + 1, 0, "none", TTL),
            "revision_mismatch",
        ),
        (
            renew(&holder("node-b"), 1, first.revision, 0, "none", TTL),
            "holder_mismatch",
        ),
        (
            renew(&first.holder, 2, first.revision, 0, "none", TTL),
            "term_mismatch",
        ),
    ] {
        let response = witness.post("/v1/lease/renew", &body).await;
        assert_eq!(response.status, 409, "{body}");
        assert_eq!(response.json()["reason"], reason);
        assert_eq!(
            response.json()["current"]["revision"],
            first.revision,
            "409 must carry the current record"
        );
    }

    let current = witness.get("/v1/lease").await.record();
    assert_eq!(current, first, "no failed renewal may change the record");
}

#[tokio::test]
async fn renew_after_expiry_fails_and_acquire_moves_to_next_term() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    witness.clock.advance(30_000);

    let expired = witness
        .post(
            "/v1/lease/renew",
            &renew(&first.holder, 1, first.revision, 0, "none", TTL),
        )
        .await;
    assert_eq!(expired.status, 409);
    assert_eq!(expired.json()["reason"], "lease_expired");

    let response = witness
        .post(
            "/v1/lease/acquire",
            &acquire(
                &holder("node-b"),
                "node-b",
                Some((first.term, first.revision)),
                2,
                0,
                "none",
                TTL,
            ),
        )
        .await;
    assert_eq!(response.status, 200);
    let second = response.record();
    assert_eq!(second.term, 2);
    assert_eq!(second.revision, 2);
    assert_eq!(second.holder, holder("node-b"));
}

// --- acquire CAS/version rules -------------------------------------------

#[tokio::test]
async fn acquire_rejects_term_version_and_fork_mismatches_without_state_change() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    let first_hash = hash(1);
    let renew_to_hash = witness
        .post(
            "/v1/lease/renew",
            &renew(&first.holder, 1, first.revision, 1, &first_hash, TTL),
        )
        .await;
    assert_eq!(renew_to_hash.status, 200);
    let baseline = renew_to_hash.record();
    witness.clock.advance(30_000);

    let cases = [
        (3, 1, first_hash.clone()), // term jump
        (2, 0, "none".to_string()), // version regression
        (2, 1, hash(2)),            // same version, different hash
        (2, 1_000_002, hash(3)),    // version lead too large
    ];
    for (term, version, bundle_hash) in cases {
        let response = witness
            .post(
                "/v1/lease/acquire",
                &acquire(
                    &holder("node-b"),
                    "node-b",
                    Some((baseline.term, baseline.revision)),
                    term,
                    version,
                    &bundle_hash,
                    TTL,
                ),
            )
            .await;
        assert_eq!(response.status, 409, "term {term} version {version}");
        assert_eq!(response.json()["error"], "cas_mismatch");
        assert!(response.json().get("current").is_some());
    }

    let current = witness.get("/v1/lease").await.record();
    assert_eq!(current, baseline, "failed CAS must not change the record");
}

#[tokio::test]
async fn acquire_accepts_equal_version_with_same_hash_and_higher_version() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    let first_hash = hash(1);
    let renewed = witness
        .post(
            "/v1/lease/renew",
            &renew(&first.holder, 1, first.revision, 1, &first_hash, TTL),
        )
        .await
        .record();
    witness.clock.advance(30_000);

    let same = witness
        .post(
            "/v1/lease/acquire",
            &acquire(
                &holder("node-b"),
                "node-b",
                Some((renewed.term, renewed.revision)),
                2,
                1,
                &first_hash,
                TTL,
            ),
        )
        .await;
    assert_eq!(same.status, 200);
    assert_eq!(same.record().version, 1);

    witness.clock.advance(30_000);
    let higher = witness
        .post(
            "/v1/lease/acquire",
            &acquire(
                &holder("node-c"),
                "node-c",
                Some((2, same.record().revision)),
                3,
                2,
                &hash(2),
                TTL,
            ),
        )
        .await;
    assert_eq!(higher.status, 200);
    assert_eq!(higher.record().version, 2);
}

#[tokio::test]
async fn acquire_rejects_a_live_lease_even_with_matching_expectations() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    witness.clock.advance(1_000);

    let response = witness
        .post(
            "/v1/lease/acquire",
            &acquire(
                &holder("node-b"),
                "node-b",
                Some((first.term, first.revision)),
                2,
                0,
                "none",
                TTL,
            ),
        )
        .await;
    assert_eq!(response.status, 409);
    assert_eq!(response.json()["reason"], "lease_held");
    assert_eq!(witness.get("/v1/lease").await.record(), first);
}

#[tokio::test]
async fn acquire_requires_null_expectations_for_an_empty_witness_and_term_one() {
    let witness = TestWitness::start().await;

    let with_expectation = witness
        .post(
            "/v1/lease/acquire",
            &acquire(&holder("node-a"), "node-a", Some((1, 1)), 1, 0, "none", TTL),
        )
        .await;
    assert_eq!(with_expectation.status, 409);

    let wrong_term = witness
        .post(
            "/v1/lease/acquire",
            &acquire(&holder("node-a"), "node-a", None, 2, 0, "none", TTL),
        )
        .await;
    assert_eq!(wrong_term.status, 409);

    let ok = first_grant(&witness).await;
    assert_eq!(ok.term, 1);
}

#[tokio::test]
async fn concurrent_acquires_on_an_expired_record_have_exactly_one_winner() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    witness.clock.advance(30_000);

    let body_a = acquire(
        &holder("node-a"),
        "node-a",
        Some((first.term, first.revision)),
        2,
        0,
        "none",
        TTL,
    );
    let body_b = acquire(
        &holder("node-b"),
        "node-b",
        Some((first.term, first.revision)),
        2,
        0,
        "none",
        TTL,
    );
    let (a, b) = tokio::join!(
        witness.post("/v1/lease/acquire", &body_a),
        witness.post("/v1/lease/acquire", &body_b)
    );
    let statuses = [a.status, b.status];
    assert_eq!(
        statuses.iter().filter(|status| **status == 200).count(),
        1,
        "exactly one acquire must win: {statuses:?}"
    );
    assert_eq!(
        statuses.iter().filter(|status| **status == 409).count(),
        1,
        "the loser must get 409: {statuses:?}"
    );

    let current = witness.get("/v1/lease").await.record();
    assert_eq!(current.term, 2);
    assert_eq!(current.revision, 2);
}

// --- TTL and hash normalization ------------------------------------------

#[tokio::test]
async fn ttl_bounds_are_400_and_do_not_change_state() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    witness.clock.advance(30_000);

    for ttl in [4, 301] {
        let response = witness
            .post(
                "/v1/lease/acquire",
                &acquire(
                    &holder("node-b"),
                    "node-b",
                    Some((first.term, first.revision)),
                    2,
                    0,
                    "none",
                    ttl,
                ),
            )
            .await;
        assert_eq!(response.status, 400, "ttl {ttl}");
        assert_eq!(response.json()["error"], "ttl_out_of_range");
    }

    let current = witness.get("/v1/lease").await.record();
    assert_eq!(current, first);

    witness.clock.advance(1_000);
    for ttl in [4, 301] {
        let response = witness
            .post(
                "/v1/lease/renew",
                &renew(&first.holder, first.term, first.revision, 0, "none", ttl),
            )
            .await;
        assert_eq!(response.status, 400, "renew ttl {ttl}");
    }
}

#[tokio::test]
async fn hashes_accept_and_strip_the_blake3_prefix_and_reject_malformed_values() {
    let witness = TestWitness::start().await;
    let bare = hash(0xab);
    let response = witness
        .post(
            "/v1/lease/acquire",
            &acquire(
                &holder("node-a"),
                "node-a",
                None,
                1,
                1,
                &format!("blake3:{bare}"),
                TTL,
            ),
        )
        .await;
    assert_eq!(response.status, 200);
    assert_eq!(response.record().bundle_hash, bare);
    assert_eq!(witness.get("/v1/lease").await.record().bundle_hash, bare);
    assert_eq!(normalize_hash(&format!("BLAKE3:{bare}")).unwrap(), bare);

    // A malformed hash is a 400, not a CAS conflict.
    for bad in [
        "xyz",
        "abc",
        &"a".repeat(63),
        &format!("{}g", "a".repeat(63)),
    ] {
        let response = witness
            .post(
                "/v1/lease/acquire",
                &acquire(&holder("node-a"), "node-a", None, 1, 1, bad, TTL),
            )
            .await;
        assert_eq!(response.status, 400, "hash {bad}");
    }
}

// --- auth, cluster and TLS ------------------------------------------------

#[tokio::test]
async fn missing_or_wrong_token_is_401_and_does_not_change_state() {
    let witness = TestWitness::start().await;
    let body = acquire(&holder("node-a"), "node-a", None, 1, 0, "none", TTL);
    let bytes = serde_json::to_vec(&body).unwrap();

    let missing = witness
        .request_with(
            "/v1/lease/acquire",
            None,
            Some(CLUSTER),
            Some(&bytes),
            "POST",
        )
        .await;
    assert_eq!(missing.status, 401);

    let wrong = witness
        .request_with(
            "/v1/lease/acquire",
            Some("wrong-token"),
            Some(CLUSTER),
            Some(&bytes),
            "POST",
        )
        .await;
    assert_eq!(wrong.status, 401);

    let no_lease = witness
        .request_with("/v1/lease", None, Some(CLUSTER), None, "GET")
        .await;
    assert_eq!(no_lease.status, 401, "GET /v1/lease must be authenticated");
    assert_eq!(witness.post("/v1/lease/acquire", &body).await.status, 200);
}

#[tokio::test]
async fn missing_or_wrong_cluster_is_403_and_does_not_change_state() {
    let witness = TestWitness::start().await;
    let body = acquire(&holder("node-a"), "node-a", None, 1, 0, "none", TTL);
    let bytes = serde_json::to_vec(&body).unwrap();

    for cluster in [None, Some("other-cluster")] {
        let response = witness
            .request_with(
                "/v1/lease/acquire",
                Some(TOKEN),
                cluster,
                Some(&bytes),
                "POST",
            )
            .await;
        assert_eq!(response.status, 403, "cluster {cluster:?}");
    }
    assert_eq!(witness.get("/v1/lease").await.status, 204);
}

#[tokio::test]
async fn tls_rejects_wrong_ca_wrong_san_and_wrong_pin() {
    let witness = TestWitness::start().await;
    let foreign_dir = unique_dir("witness_foreign");
    let foreign = crate::crypto::generate_ha_certs(&foreign_dir, true, false).unwrap();

    assert!(
        witness
            .connect(Some(&foreign.ca_cert_path), "127.0.0.1", None)
            .await
            .is_err(),
        "a different CA must not verify the witness certificate"
    );
    assert!(
        witness
            .connect(Some(&witness.ca), "wrong.example", None)
            .await
            .is_err(),
        "a server_name outside the certificate SAN must fail"
    );
    let bad_pin = format!("blake3:{}", "0".repeat(64));
    assert!(
        witness
            .connect(Some(&witness.ca), "127.0.0.1", Some(&bad_pin))
            .await
            .is_err(),
        "a wrong fingerprint pin must fail even with the right CA"
    );
    let _ = std::fs::remove_dir_all(&foreign_dir);
}

#[tokio::test]
async fn silent_tcp_client_does_not_delay_authenticated_requests() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;

    // Hold a TCP connection open without sending a ClientHello. The accept
    // loop must return immediately and run the handshake in this connection's
    // own task; the old serialized accept loop would block here for 5 s.
    let silent = TcpStream::connect(witness.addr())
        .await
        .expect("silent TCP client");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let info = tokio::time::timeout(Duration::from_secs(2), witness.get("/v1/info"))
        .await
        .expect("a silent handshake must not delay GET /v1/info");
    assert_eq!(info.status, 200);

    witness.clock.advance(1_000);
    let renewed = tokio::time::timeout(
        Duration::from_secs(2),
        witness.post(
            "/v1/lease/renew",
            &renew(&first.holder, 1, first.revision, 0, "none", TTL),
        ),
    )
    .await
    .expect("a silent handshake must not delay POST /v1/lease/renew");
    assert_eq!(renewed.status, 200);

    drop(silent);
}

#[tokio::test]
async fn token_file_permissions_are_enforced_at_startup() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = unique_dir("witness_token_mode");
        std::fs::create_dir_all(&dir).unwrap();
        let certs = crate::crypto::generate_ha_certs(&dir.join("certs"), true, false).unwrap();
        let token_file = dir.join("witness.token");
        std::fs::write(&token_file, TOKEN).unwrap();
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let config = WitnessConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            cluster_id: CLUSTER.to_string(),
            cert: certs.master_cert_path.unwrap(),
            key: certs.master_key_path.unwrap(),
            token_file,
            state_dir: dir.join("state"),
        };
        let error = start_witness_server(config, Arc::new(ManualClock::new(START_MS)))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "token_file_permissions");

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[tokio::test]
async fn healthz_returns_503_when_the_state_dir_is_not_writable_and_release_is_absent() {
    let witness = TestWitness::start().await;
    assert_eq!(
        witness
            .request_with("/healthz", None, None, None, "GET")
            .await
            .status,
        200
    );

    let release = witness
        .request_with(
            "/v1/lease/release",
            Some(TOKEN),
            Some(CLUSTER),
            Some(b"{}"),
            "POST",
        )
        .await;
    assert_eq!(release.status, 404, "2.0 has no release endpoint");
    let unknown = witness
        .request_with("/v1/unknown", Some(TOKEN), Some(CLUSTER), None, "GET")
        .await;
    assert_eq!(unknown.status, 404);

    std::fs::remove_dir_all(&witness.state_dir).unwrap();
    assert_eq!(
        witness
            .request_with("/healthz", None, None, None, "GET")
            .await
            .status,
        503,
        "a missing/unwritable state directory must report unhealthy"
    );
}

// --- persistence, restart, refusal and clock ------------------------------

#[tokio::test]
async fn restart_reloads_the_same_term_revision_and_expiry() {
    let mut witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    witness.restart().await;

    let reloaded = witness.get("/v1/lease").await.record();
    assert_eq!(reloaded, first);

    let info = witness.get("/v1/info").await.json();
    assert_eq!(info["now_unix_ms"], START_MS);
}

#[tokio::test]
async fn corrupt_record_or_missing_record_with_initialized_refuses_startup() {
    let dir = unique_dir("witness_refuse");
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let clock: Arc<dyn Clock> = Arc::new(ManualClock::new(START_MS));

    std::fs::write(state.join(LEASE_FILE), b"{not json").unwrap();
    std::fs::write(state.join(INITIALIZED_FILE), b"initialized\n").unwrap();
    let error = LeaseStore::open(&state, CLUSTER, clock.clone()).unwrap_err();
    assert_eq!(error.code(), "state_corrupt");

    std::fs::remove_file(state.join(LEASE_FILE)).unwrap();
    let error = LeaseStore::open(&state, CLUSTER, clock.clone()).unwrap_err();
    assert_eq!(error.code(), "state_missing");

    let record = LeaseRecord {
        schema: 1,
        cluster_id: "other-cluster".to_string(),
        holder: holder("node-a"),
        node_id: "node-a".to_string(),
        term: 4,
        revision: 2,
        version: 1,
        bundle_hash: hash(1),
        acquired_unix_ms: START_MS,
        expires_unix_ms: START_MS + 30_000,
    };
    std::fs::write(state.join(LEASE_FILE), serde_json::to_vec(&record).unwrap()).unwrap();
    std::fs::write(state.join(INITIALIZED_FILE), b"initialized\n").unwrap();
    let error = LeaseStore::open(&state, CLUSTER, clock).unwrap_err();
    assert_eq!(error.code(), "state_cluster_mismatch");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn clock_forward_expires_and_clock_backward_keeps_the_holder() {
    let witness = TestWitness::start().await;
    let first = first_grant(&witness).await;

    witness.clock.advance(29_999);
    let still_valid = witness
        .post(
            "/v1/lease/renew",
            &renew(&first.holder, 1, first.revision, 0, "none", TTL),
        )
        .await;
    assert_eq!(still_valid.status, 200);
    let renewed = still_valid.record();

    // Move the witness clock back: expiry follows the witness, so the record
    // remains valid and no second holder can be granted.
    witness.clock.set(START_MS);
    let backward = witness
        .post(
            "/v1/lease/renew",
            &renew(&renewed.holder, 1, renewed.revision, 0, "none", TTL),
        )
        .await;
    assert_eq!(backward.status, 200);
    assert_eq!(backward.record().term, 1);

    witness.clock.advance(60_000);
    let expired = witness
        .post(
            "/v1/lease/renew",
            &renew(
                &renewed.holder,
                1,
                backward.record().revision,
                0,
                "none",
                TTL,
            ),
        )
        .await;
    assert_eq!(expired.status, 409);
}

// --- offline admin --------------------------------------------------------

#[tokio::test]
async fn lease_admin_set_backs_up_raises_and_expires_the_record() {
    let mut witness = TestWitness::start().await;
    let first = first_grant(&witness).await;
    witness.stop().await;

    let outcome =
        lease_admin_set_with_clock(&witness.state_dir, 8, 128, &hash(9), witness.clock.clone())
            .unwrap();
    assert_eq!(outcome.record.term, 8);
    assert_eq!(outcome.record.revision, first.revision + 1);
    assert_eq!(outcome.record.version, 128);
    assert_eq!(outcome.record.bundle_hash, hash(9));
    assert!(outcome.record.expires_unix_ms <= outcome.record.acquired_unix_ms);
    let backup = outcome.backup_path.expect("old record must be backed up");
    let backup_record: LeaseRecord =
        serde_json::from_slice(&std::fs::read(&backup).unwrap()).unwrap();
    assert_eq!(backup_record, first);

    witness.restart().await;
    let acquire = witness
        .post(
            "/v1/lease/acquire",
            &acquire(
                &holder("node-b"),
                "node-b",
                Some((outcome.record.term, outcome.record.revision)),
                9,
                128,
                &hash(9),
                TTL,
            ),
        )
        .await;
    assert_eq!(acquire.status, 200);
    assert_eq!(acquire.record().term, 9);
}

#[tokio::test]
async fn lease_admin_set_refuses_while_the_witness_holds_the_lock_and_on_lower_values() {
    let mut witness = TestWitness::start().await;
    let first = first_grant(&witness).await;

    let locked =
        lease_admin_set_with_clock(&witness.state_dir, 8, 128, &hash(9), witness.clock.clone())
            .unwrap_err();
    assert_eq!(locked.code(), "state_locked");

    witness.stop().await;
    let term_error = lease_admin_set_with_clock(
        &witness.state_dir,
        first.term,
        128,
        &hash(9),
        witness.clock.clone(),
    )
    .unwrap_err();
    assert_eq!(term_error.code(), "term_not_raised");
    let version_error = lease_admin_set_with_clock(
        &witness.state_dir,
        8,
        first.version,
        "none",
        witness.clock.clone(),
    )
    .unwrap_err();
    assert_eq!(version_error.code(), "version_not_raised");
}

#[tokio::test]
async fn lease_admin_term_only_raises_the_term_on_an_equal_version_and_hash() {
    let mut witness = TestWitness::start().await;
    let published = hash(0xab);
    let first = witness
        .post(
            "/v1/lease/acquire",
            &acquire(&holder("node-a"), "node-a", None, 1, 7, &published, TTL),
        )
        .await
        .record();
    assert_eq!(first.term, 1);
    assert_eq!(first.version, 7);

    witness.stop().await;

    // The strict recovery path still refuses an equal version.
    let strict =
        lease_admin_set_with_clock(&witness.state_dir, 2, 7, &published, witness.clock.clone())
            .unwrap_err();
    assert_eq!(strict.code(), "version_not_raised");

    // Term-only mode accepts the same published version/hash and bumps only
    // the term; the record is immediately expired for the next acquire.
    let outcome = lease_admin_set_term_only_with_clock(
        &witness.state_dir,
        2,
        7,
        &published,
        witness.clock.clone(),
    )
    .unwrap();
    assert_eq!(outcome.record.term, 2);
    assert_eq!(outcome.record.version, 7);
    assert_eq!(outcome.record.bundle_hash, published);
    assert_eq!(outcome.record.revision, first.revision + 1);
    assert!(outcome.record.expires_unix_ms <= outcome.record.acquired_unix_ms);

    // A different hash at the equal version is not a term-only update.
    let mismatch = lease_admin_set_term_only_with_clock(
        &witness.state_dir,
        3,
        7,
        &hash(0xcd),
        witness.clock.clone(),
    )
    .unwrap_err();
    assert_eq!(mismatch.code(), "bundle_hash_mismatch");

    // Neither a lower version nor an equal/lower term is accepted.
    let lower_version = lease_admin_set_term_only_with_clock(
        &witness.state_dir,
        3,
        6,
        &hash(0xcd),
        witness.clock.clone(),
    )
    .unwrap_err();
    assert_eq!(lower_version.code(), "version_not_raised");
    let lower_term = lease_admin_set_term_only_with_clock(
        &witness.state_dir,
        2,
        7,
        &published,
        witness.clock.clone(),
    )
    .unwrap_err();
    assert_eq!(lower_term.code(), "term_not_raised");

    // The next acquire takes over at term + 1 with the unchanged published
    // baseline, so the rotated master can acquire and publish its pending
    // version.
    witness.restart().await;
    let acquired = witness
        .post(
            "/v1/lease/acquire",
            &acquire(
                &holder("node-b"),
                "node-b",
                Some((outcome.record.term, outcome.record.revision)),
                3,
                7,
                &published,
                TTL,
            ),
        )
        .await;
    assert_eq!(acquired.status, 200);
    assert_eq!(acquired.record().term, 3);
}

#[tokio::test]
async fn lease_admin_set_uses_the_cluster_published_baseline_not_a_higher_version() {
    let mut witness = TestWitness::start().await;
    let first = first_grant(&witness).await;

    // The witness baseline is behind the cluster: 127/A here, 128/B in the
    // master's published state.
    let witness_hash = hash(0xaa);
    let high = witness
        .post(
            "/v1/lease/renew",
            &renew(&first.holder, 1, first.revision, 127, &witness_hash, TTL),
        )
        .await
        .record();
    assert_eq!(high.version, 127);
    witness.stop().await;

    let cluster_hash = hash(0xbb);
    let outcome = lease_admin_set_with_clock(
        &witness.state_dir,
        9,
        128,
        &cluster_hash,
        witness.clock.clone(),
    )
    .unwrap();
    assert_eq!(outcome.record.version, 128);

    witness.restart().await;
    let acquired = witness
        .post(
            "/v1/lease/acquire",
            &acquire(
                &holder("node-b"),
                "node-b",
                Some((outcome.record.term, outcome.record.revision)),
                10,
                128,
                &cluster_hash,
                TTL,
            ),
        )
        .await;
    assert_eq!(
        acquired.status, 200,
        "the cluster's published baseline (128/B) must be acquirable at equality: {:?}",
        acquired.body
    );
    assert_eq!(acquired.record().version, 128);
}

#[test]
fn runbook_recovery_guidance_matches_the_acquire_baseline_rule() {
    let runbook = include_str!("../../../../docs/runbook-witness.md");
    assert!(
        runbook.contains("current published `(published_version, published_hash)`"),
        "the runbook must tell operators to use the cluster's published baseline"
    );
    assert!(
        runbook.contains("must **not** be above the cluster baseline"),
        "the runbook must warn that a witness version above the cluster wedges promotion"
    );
    assert!(
        runbook.contains("only raises"),
        "the runbook must say lease-admin set cannot lower a too-high version"
    );
    assert!(
        !runbook.contains("above the cluster high-water mark"),
        "stale guidance raises the witness above the cluster and wedges promotion"
    );
    assert!(
        !runbook.contains("1,000,000 above the current record"),
        "lease-admin set does not implement a lead cap; the runbook must not claim one"
    );
    assert!(
        !runbook.contains("use `lease-admin set` after an explicit backup"),
        "lease-admin set cannot read a corrupt record, so it cannot repair state_corrupt"
    );
}

// --- body limits and malformed requests ----------------------------------

#[tokio::test]
async fn oversized_body_is_413_and_malformed_json_is_400_while_server_stays_healthy() {
    let witness = TestWitness::start().await;

    let oversized = vec![b' '; 17 * 1024];
    let response = witness
        .request_with(
            "/v1/lease/acquire",
            Some(TOKEN),
            Some(CLUSTER),
            Some(&oversized),
            "POST",
        )
        .await;
    assert_eq!(response.status, 413);

    let malformed = witness
        .request_with(
            "/v1/lease/acquire",
            Some(TOKEN),
            Some(CLUSTER),
            Some(b"{not json"),
            "POST",
        )
        .await;
    assert_eq!(malformed.status, 400);

    let missing_field = witness
        .post("/v1/lease/acquire", &json!({"holder": holder("node-a")}))
        .await;
    assert_eq!(missing_field.status, 400);

    let health = witness
        .request_with("/healthz", None, None, None, "GET")
        .await;
    assert_eq!(health.status, 200);
    assert_eq!(witness.get("/v1/lease").await.status, 204);
}
