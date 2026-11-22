//! Engine behavior tests against the real in-process TLS witness with
//! deterministic clocks/timers.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use sito_ha_types::bundle::{AppliedWatermark, ConfigBundle};
use sito_ha_types::config::{PromotionConfig, WitnessClientConfig};
use sito_ha_types::status::PublicationState;

use super::clock::{ManualMonotonicClock, ManualTimers, MonotonicClock};
use super::engine::{
    ConfiguredRole, EffectiveRole, Eligibility, LeaseBackend, PreparedBundle, PromotionEngine,
    PromotionHost, PromotionOutcome, PromotionPhase,
};
use super::reconcile::PeerReport;
use super::state::{HaStateStore, LoadedState, PersistedMasterState};
use super::witness_client::WitnessClient;
use super::witness_client::WitnessClientError;
use crate::bundle::{build_and_sign_push, push_payload_hash};
use crate::crypto::Ed25519SigningKey;
use crate::witness::clock::ManualClock;
use crate::witness::record::{AcquireRequest, LeaseInfo, LeaseRecord, RenewRequest};
use crate::witness::server::{WitnessConfig, WitnessHandle, start_witness_server};

const CLUSTER: &str = "home-dns";
const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const START_MS: i64 = 1_760_000_000_000;

struct Fixture {
    dir: PathBuf,
    ca: PathBuf,
    token_file: PathBuf,
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
    async fn start(label: &str) -> Self {
        let dir = unique_dir(label);
        std::fs::create_dir_all(&dir).unwrap();
        let certs = crate::crypto::generate_ha_certs(&dir.join("certs"), true, false).unwrap();
        let token_file = dir.join("witness.token");
        write_secret(&token_file, TOKEN.as_bytes());
        let clock = Arc::new(ManualClock::new(START_MS));
        let witness_clock: Arc<dyn crate::witness::clock::Clock> = clock.clone();
        let handle = start_witness_server(
            WitnessConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                cluster_id: CLUSTER.to_string(),
                cert: certs.master_cert_path.clone().unwrap(),
                key: certs.master_key_path.clone().unwrap(),
                token_file: token_file.clone(),
                state_dir: dir.join("state"),
            },
            witness_clock,
        )
        .await
        .unwrap();
        let addr = handle.local_addr();
        Self {
            dir,
            ca: certs.ca_cert_path,
            token_file,
            addr,
            clock,
            handle: Some(handle),
        }
    }

    fn config(&self, node_id: &str) -> PromotionConfig {
        PromotionConfig {
            enabled: true,
            candidate: true,
            cluster_id: Some(CLUSTER.to_string()),
            node_id: Some(node_id.to_string()),
            lease_ttl_secs: 5,
            renew_interval_secs: 1,
            heartbeat_timeout_secs: Some(45),
            require_manual_confirmation: false,
            reconcile_window_secs: 1,
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

    fn client(&self, node_id: &str) -> WitnessClient {
        WitnessClient::new(&self.config(node_id)).unwrap()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn engine(
        &self,
        node_id: &str,
        role: ConfiguredRole,
        host: Arc<TestHost>,
        clock: Arc<ManualMonotonicClock>,
        events: Arc<Mutex<Vec<String>>>,
    ) -> PromotionEngine {
        let config = self.config(node_id);
        let backend = Arc::new(RecordingBackend {
            inner: Arc::new(self.client(node_id)),
            events: clone_events(&events),
        });
        PromotionEngine::with_runtime(
            config,
            role,
            self.dir.join(format!("data-{node_id}")),
            backend,
            host,
            clock.clone(),
            Arc::new(ManualTimers::new(clock)),
        )
        .unwrap()
    }
}

fn clone_events(events: &Arc<Mutex<Vec<String>>>) -> Arc<Mutex<Vec<String>>> {
    Arc::clone(events)
}

struct RecordingBackend {
    inner: Arc<WitnessClient>,
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingBackend {
    fn log(&self, event: impl Into<String>) {
        self.events.lock().unwrap().push(event.into());
    }
}

impl LeaseBackend for RecordingBackend {
    fn info(&self) -> super::clock::BoxFuture<'_, Result<LeaseInfo, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.info().await })
    }

    fn lease(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        let events = clone_events(&self.events);
        Box::pin(async move {
            let result = inner.lease().await;
            if let Ok(Some(ref record)) = result {
                events.lock().unwrap().push(format!(
                    "lease_resp:{}:{}",
                    record.version, record.bundle_hash
                ));
            }
            result
        })
    }

    fn acquire(
        &self,
        request: AcquireRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        self.log(format!("acquire_req:{}", request.version));
        let inner = Arc::clone(&self.inner);
        let events = clone_events(&self.events);
        Box::pin(async move {
            let result = inner.acquire(&request).await;
            if let Ok(ref record) = result {
                events.lock().unwrap().push(format!(
                    "lease_resp:{}:{}",
                    record.version, record.bundle_hash
                ));
            }
            result
        })
    }

    fn renew(
        &self,
        request: RenewRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        let events = clone_events(&self.events);
        Box::pin(async move {
            let result = inner.renew(&request).await;
            if let Ok(ref record) = result {
                events.lock().unwrap().push(format!(
                    "lease_resp:{}:{}",
                    record.version, record.bundle_hash
                ));
            }
            result
        })
    }
}

struct TestHost {
    key: Ed25519SigningKey,
    state_path: PathBuf,
    events: Arc<Mutex<Vec<String>>>,
    watermark: Mutex<Option<AppliedWatermark>>,
    eligibility: Mutex<Eligibility>,
    reports: Mutex<Vec<PeerReport>>,
    hello_only: AtomicBool,
    writable: AtomicBool,
    writable_reason: Mutex<Option<String>>,
    role: Mutex<EffectiveRole>,
    fail_prepare: AtomicBool,
    fail_publish: AtomicBool,
    pushed: Mutex<Option<PreparedBundle>>,
    adopted: Mutex<Option<PreparedBundle>>,
    publish_during_hello_only: AtomicBool,
}

impl TestHost {
    fn new(dir: &Path, events: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            key: Ed25519SigningKey::generate().unwrap(),
            state_path: dir.join("ha_state.toml"),
            events,
            watermark: Mutex::new(None),
            eligibility: Mutex::new(Eligibility::default()),
            reports: Mutex::new(Vec::new()),
            hello_only: AtomicBool::new(false),
            writable: AtomicBool::new(false),
            writable_reason: Mutex::new(None),
            role: Mutex::new(EffectiveRole::Slave),
            fail_prepare: AtomicBool::new(false),
            fail_publish: AtomicBool::new(false),
            pushed: Mutex::new(None),
            adopted: Mutex::new(None),
            publish_during_hello_only: AtomicBool::new(false),
        }
    }

    fn log(&self, event: impl Into<String>) {
        self.events.lock().unwrap().push(event.into());
    }

    fn set_reports(&self, reports: Vec<PeerReport>) {
        *self.reports.lock().unwrap() = reports;
    }
}

impl PromotionHost for TestHost {
    fn prepare_bundle(&self, term: u64, version: u64) -> Result<PreparedBundle, String> {
        if self.fail_prepare.load(Ordering::SeqCst) {
            return Err("injected prepare failure".to_string());
        }
        self.log(format!("prepare:{version}"));
        let bundle = ConfigBundle {
            version,
            term,
            config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
            ..ConfigBundle::default()
        };
        let push = build_and_sign_push(&bundle, &self.key).map_err(|e| e.to_string())?;
        let hash = push_payload_hash(&push).map_err(|e| e.to_string())?;
        Ok(PreparedBundle { bundle, hash })
    }

    fn applied_watermark(&self) -> Option<AppliedWatermark> {
        self.watermark.lock().unwrap().clone()
    }

    fn eligibility(&self) -> Eligibility {
        self.eligibility.lock().unwrap().clone()
    }

    fn master_alive(&self) -> bool {
        false
    }

    fn set_writable(&self, writable: bool, reason: Option<String>) {
        self.writable.store(writable, Ordering::SeqCst);
        *self.writable_reason.lock().unwrap() = reason.clone();
        self.log(format!(
            "writable:{writable}:{}",
            reason.unwrap_or_default()
        ));
    }

    fn switch_role(&self, role: EffectiveRole) -> super::clock::BoxFuture<'_, Result<(), String>> {
        self.log(format!("switch:{role:?}"));
        *self.role.lock().unwrap() = role;
        Box::pin(async { Ok(()) })
    }

    fn begin_hello_only(&self) -> super::clock::BoxFuture<'_, Result<(), String>> {
        self.hello_only.store(true, Ordering::SeqCst);
        self.log("begin_hello_only");
        Box::pin(async { Ok(()) })
    }

    fn end_hello_only(&self) -> super::clock::BoxFuture<'_, Result<(), String>> {
        self.hello_only.store(false, Ordering::SeqCst);
        self.log("end_hello_only");
        Box::pin(async { Ok(()) })
    }

    fn collect_reconcile_reports(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Vec<PeerReport>, String>> {
        let reports = self.reports.lock().unwrap().clone();
        self.log(format!("reports:{}", reports.len()));
        Box::pin(async move { Ok(reports) })
    }

    fn publish_first(
        &self,
        prepared: &PreparedBundle,
    ) -> super::clock::BoxFuture<'_, Result<String, String>> {
        if self.hello_only.load(Ordering::SeqCst) {
            self.publish_during_hello_only.store(true, Ordering::SeqCst);
        }
        if self.fail_publish.load(Ordering::SeqCst) {
            return Box::pin(async { Err("injected publish failure".to_string()) });
        }
        self.log(format!(
            "publish:{}:{}",
            prepared.bundle.version, prepared.hash
        ));
        let publication_state = std::fs::read_to_string(&self.state_path)
            .ok()
            .and_then(|data| serde_json::from_str::<serde_json::Value>(&data).ok())
            .and_then(|value| {
                value
                    .get("publication_state")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            });
        self.log(format!(
            "publish_state:{}",
            publication_state.unwrap_or_else(|| "missing".to_string())
        ));
        *self.pushed.lock().unwrap() = Some(prepared.clone());
        let hash = prepared.hash.clone();
        Box::pin(async move { Ok(hash) })
    }

    fn adopt_published(
        &self,
        prepared: &PreparedBundle,
    ) -> super::clock::BoxFuture<'_, Result<(), String>> {
        self.log(format!("adopt:{}", prepared.bundle.version));
        *self.adopted.lock().unwrap() = Some(prepared.clone());
        Box::pin(async { Ok(()) })
    }

    fn stop_publishing(&self) {
        self.log("stop_publishing");
    }

    fn close_replication_sessions(&self, reason: &str) {
        self.log(format!("close_sessions:{reason}"));
    }

    fn critical_local_failure(&self, reason: &str) {
        self.log(format!("critical:{reason}"));
    }
}

fn unique_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "sito_promotion_engine_{label}_{}_{}",
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

fn hash(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

fn watermarked(term: u64, version: u64, hash: &str) -> AppliedWatermark {
    AppliedWatermark {
        protocol_version: crate::protocol::PROTOCOL_VERSION,
        version,
        term,
        payload_hash: hash.to_string(),
        signing_key_fingerprint: None,
        timestamp: 1,
        forked: false,
        forked_at_version: 0,
        applied_config_digest: None,
    }
}

struct Harness {
    fixture: Fixture,
    clock: Arc<ManualMonotonicClock>,
    events: Arc<Mutex<Vec<String>>>,
    host: Arc<TestHost>,
}

impl Harness {
    async fn new(label: &str, node_id: &str) -> Self {
        let fixture = Fixture::start(label).await;
        let data_dir = fixture.dir.join(format!("data-{node_id}"));
        let events = Arc::new(Mutex::new(Vec::new()));
        let host = Arc::new(TestHost::new(&data_dir, Arc::clone(&events)));
        Self {
            fixture,
            clock: Arc::new(ManualMonotonicClock::new(1_000, START_MS)),
            events,
            host,
        }
    }

    fn engine(&self, node_id: &str, role: ConfiguredRole) -> PromotionEngine {
        self.fixture.engine(
            node_id,
            role,
            Arc::clone(&self.host),
            Arc::clone(&self.clock),
            Arc::clone(&self.events),
        )
    }

    fn data_dir(&self, node_id: &str) -> PathBuf {
        self.fixture.dir.join(format!("data-{node_id}"))
    }

    fn event_index(&self, prefix: &str) -> Option<usize> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .position(|event| event.starts_with(prefix))
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

fn seed_state(
    dir: &Path,
    term: u64,
    bundle_version: u64,
    publication_state: PublicationState,
    published: (u64, &str),
    pending_hash: Option<&str>,
    last_applied: (u64, &str),
) {
    let store = HaStateStore::new(dir.join("ha_state.toml"));
    let state = PersistedMasterState {
        protocol_version: crate::protocol::PROTOCOL_VERSION,
        bundle: ConfigBundle {
            version: bundle_version,
            term,
            config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
            ..ConfigBundle::default()
        },
        signing_key_pubkey: None,
        publication_state: Some(publication_state),
        published_version: Some(published.0),
        published_hash: Some(published.1.to_string()),
        pending_hash: pending_hash.map(str::to_string),
        promotion_origin: Some("automatic".to_string()),
        lease_holder: Some("node-a/boot".to_string()),
        cluster_id: Some(CLUSTER.to_string()),
        node_id: Some("node-a".to_string()),
        promoted_at_unix_ms: Some(1),
        last_applied_version: Some(last_applied.0),
        last_applied_hash: Some(last_applied.1.to_string()),
    };
    store.save(&state).unwrap();
}

async fn seed_witness_record(
    fixture: &Fixture,
    node: &str,
    target_term: u64,
    version: u64,
    hash: &str,
) {
    let client = fixture.client(node);
    let mut expected = None;
    let mut term = 1;
    if let Some(record) = client.lease().await.unwrap() {
        expected = Some((record.term, record.revision));
        term = record.term + 1;
        fixture.clock.advance(5 * 1000);
    }
    let holder = format!("{node}/seed-boot");
    while term <= target_term {
        let current = expected;
        client
            .acquire(&AcquireRequest {
                holder: holder.clone(),
                node_id: node.to_string(),
                expected_term: current.map(|(term, _)| term),
                expected_revision: current.map(|(_, revision)| revision),
                term,
                version,
                bundle_hash: hash.to_string(),
                ttl_secs: 5,
            })
            .await
            .unwrap();
        expected = client
            .lease()
            .await
            .unwrap()
            .map(|record| (record.term, record.revision));
        if term < target_term {
            fixture.clock.advance(5 * 1000);
        }
        term += 1;
    }
    // Make the seeded record immediately acquirable by the engine.
    fixture.clock.advance(5 * 1000);
}

#[tokio::test]
async fn master_startup_runs_acquire_quiesce_reconcile_publish() {
    let harness = Harness::new("master_ok", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(
        engine.boot().unwrap(),
        PromotionOutcome::ReadOnly {
            reason: "not_candidate".to_string(),
            retryable: false
        }
    );
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master);

    assert!(harness.host.writable.load(Ordering::SeqCst));
    assert_eq!(*harness.host.role.lock().unwrap(), EffectiveRole::Master);
    assert!(
        !harness
            .host
            .publish_during_hello_only
            .load(Ordering::SeqCst)
    );
    let events = harness.events();
    let begin = events.iter().position(|e| e == "begin_hello_only").unwrap();
    let end = events.iter().position(|e| e == "end_hello_only").unwrap();
    let publish = events
        .iter()
        .position(|e| e.starts_with("publish:1:"))
        .unwrap();
    assert!(begin < end && end < publish, "{events:?}");
    assert!(
        events.iter().any(|e| e == "publish_state:publishing"),
        "the state must be 'publishing' before the first push: {events:?}"
    );
    let publish_index = events
        .iter()
        .position(|e| e.starts_with("publish:1:"))
        .unwrap();
    assert!(
        !events[..publish_index]
            .iter()
            .any(|e| e.starts_with("lease_resp:1:")),
        "the witness must stay at the published baseline through quiesce/reconciliation: {events:?}"
    );

    let client = harness.fixture.client("node-a");
    let record = client.lease().await.unwrap().unwrap();
    let prepared = harness.host.pushed.lock().unwrap().clone().unwrap();
    assert_eq!(record.term, 1);
    assert_eq!(record.version, 1);
    assert_eq!(record.bundle_hash, prepared.hash);

    let loaded = HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
        .load()
        .unwrap();
    let LoadedState::Present { bookkeeping, .. } = loaded else {
        panic!("state");
    };
    let bookkeeping = bookkeeping.unwrap();
    assert_eq!(bookkeeping.publication_state, PublicationState::Published);
    assert_eq!(bookkeeping.published_version, 1);
}

#[tokio::test]
async fn master_unreachable_witness_starts_read_only_without_exiting() {
    let harness = Harness::new("master_down", "node-a").await;
    let mut fixture = harness.fixture;
    fixture.handle.take().unwrap().shutdown().await;
    let engine = fixture.engine(
        "node-a",
        ConfiguredRole::Master,
        Arc::clone(&harness.host),
        Arc::clone(&harness.clock),
        Arc::clone(&harness.events),
    );
    let outcome = engine.start_master().await;
    match outcome {
        PromotionOutcome::ReadOnly {
            reason,
            retryable: true,
        } => assert_eq!(reason, "witness_unavailable"),
        other => panic!("expected read-only unavailable, got {other:?}"),
    }
    assert!(!harness.host.writable.load(Ordering::SeqCst));
    assert!(!engine.snapshot().fenced);
}

#[tokio::test]
async fn two_candidates_only_one_acquires() {
    let fixture = Fixture::start("two_candidates").await;
    let clock = Arc::new(ManualMonotonicClock::new(1_000, START_MS));
    let events_a = Arc::new(Mutex::new(Vec::new()));
    let events_b = Arc::new(Mutex::new(Vec::new()));
    let host_a = Arc::new(TestHost::new(
        &fixture.dir.join("data-node-a"),
        events_a.clone(),
    ));
    let host_b = Arc::new(TestHost::new(
        &fixture.dir.join("data-node-b"),
        events_b.clone(),
    ));
    let engine_a = fixture.engine(
        "node-a",
        ConfiguredRole::Slave,
        host_a.clone(),
        clock.clone(),
        events_a,
    );
    let engine_b = fixture.engine(
        "node-b",
        ConfiguredRole::Slave,
        host_b.clone(),
        clock.clone(),
        events_b,
    );
    let (a, b) = tokio::join!(
        engine_a.candidate_attempt(false),
        engine_b.candidate_attempt(false)
    );
    let winners = [&a, &b]
        .iter()
        .filter(|outcome| matches!(outcome, PromotionOutcome::Master))
        .count();
    assert_eq!(winners, 1, "a={a:?} b={b:?}");
    let loser_writable = if matches!(a, PromotionOutcome::Master) {
        host_b.writable.load(Ordering::SeqCst)
    } else {
        host_a.writable.load(Ordering::SeqCst)
    };
    assert!(!loser_writable, "the losing candidate must stay read-only");

    let client = fixture.client("node-a");
    let record = client.lease().await.unwrap().unwrap();
    assert_eq!(record.term, 1, "only one term may be granted");
}

#[tokio::test]
async fn pending_state_after_crash_reuses_the_publish_version_and_baseline() {
    let harness = Harness::new("pending_reuse", "node-a").await;
    let baseline = hash(0xab);
    let pending = hash(0xcd);
    seed_witness_record(&harness.fixture, "node-a", 1, 0, "none").await;
    seed_witness_record(&harness.fixture, "node-a", 2, 0, "none").await;
    seed_witness_record(&harness.fixture, "node-a", 3, 7, &baseline).await;
    seed_state(
        &harness.data_dir("node-a"),
        3,
        8,
        PublicationState::Pending,
        (7, &baseline),
        Some(&pending),
        (7, &baseline),
    );
    harness.clock.set_boot(1_000);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master);
    let events = harness.events();
    assert!(events.iter().any(|e| e == "prepare:8"), "{events:?}");
    assert!(
        events.iter().any(|e| e == "acquire_req:7"),
        "the witness must receive the published baseline, never pending 8: {events:?}"
    );
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.term, 4);
    assert_eq!(record.version, 8);
    assert_eq!(
        record.bundle_hash,
        harness.host.pushed.lock().unwrap().clone().unwrap().hash
    );
}

#[tokio::test]
async fn publishing_state_matching_the_witness_is_recovered_as_published() {
    let harness = Harness::new("publishing_recover", "node-a").await;
    let baseline = hash(0xab);
    let pending = hash(0xcd);
    seed_witness_record(&harness.fixture, "node-a", 1, 0, "none").await;
    seed_witness_record(&harness.fixture, "node-a", 2, 0, "none").await;
    seed_witness_record(&harness.fixture, "node-a", 3, 7, &baseline).await;
    seed_state(
        &harness.data_dir("node-a"),
        3,
        8,
        PublicationState::Publishing,
        (7, &baseline),
        Some(&pending),
        (8, &pending),
    );
    // Simulate the post-publish renewal that succeeded before the "published"
    // state write: the witness now holds version 8/pending.
    seed_witness_record(&harness.fixture, "node-a", 4, 8, &pending).await;
    harness.clock.set_boot(1_000);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master);
    let events = harness.events();
    assert!(
        events.iter().any(|e| e == "prepare:9"),
        "inferred baseline 8 must publish version 9: {events:?}"
    );
    assert!(events.iter().any(|e| e == "acquire_req:8"), "{events:?}");
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.term, 5);
    assert_eq!(record.version, 9);
}

#[tokio::test]
async fn reconciliation_aborts_on_ahead_peer_and_publishes_nothing() {
    let harness = Harness::new("reconcile_ahead", "node-a").await;
    harness.host.set_reports(vec![PeerReport {
        instance: "slave-ahead".to_string(),
        have_term: 1,
        have_version: 5,
        have_bundle_hash: Some(hash(0xef)),
    }]);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "candidate_behind".to_string(),
            retryable: false
        }
    );
    assert!(!harness.host.writable.load(Ordering::SeqCst));
    assert!(harness.event_index("publish:").is_none());
    assert!(!engine.snapshot().fenced);
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.version, 0,
        "the witness never holds the pending version"
    );
}

#[tokio::test]
async fn reconciliation_aborts_on_same_version_fork_and_unknown_hash() {
    let harness = Harness::new("reconcile_fork", "node-a").await;
    let baseline = hash(0xab);
    seed_witness_record(&harness.fixture, "node-a", 1, 0, "none").await;
    seed_state(
        &harness.data_dir("node-a"),
        0,
        7,
        PublicationState::Published,
        (7, &baseline),
        None,
        (7, &baseline),
    );
    harness.host.set_reports(vec![PeerReport {
        instance: "forked".to_string(),
        have_term: 0,
        have_version: 7,
        have_bundle_hash: Some(hash(0xcd)),
    }]);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "cluster_forked".to_string(),
            retryable: false
        }
    );
    assert!(harness.event_index("publish:").is_none());

    let harness = Harness::new("reconcile_unknown", "node-a").await;
    let baseline = hash(0xab);
    seed_witness_record(&harness.fixture, "node-a", 1, 0, "none").await;
    seed_state(
        &harness.data_dir("node-a"),
        0,
        7,
        PublicationState::Published,
        (7, &baseline),
        None,
        (7, &baseline),
    );
    harness.host.set_reports(vec![PeerReport {
        instance: "old-peer".to_string(),
        have_term: 0,
        have_version: 7,
        have_bundle_hash: None,
    }]);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "candidate_hash_unknown".to_string(),
            retryable: false
        }
    );
    assert!(harness.event_index("publish:").is_none());
}

#[tokio::test]
async fn self_fence_persists_and_a_restart_refuses_to_acquire() {
    let harness = Harness::new("self_fence", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    let term = engine.snapshot().term;

    // Move past TTL - max(2, renew_interval) without renewing.
    harness.clock.advance_boot(5_000);
    assert!(engine.check_self_fence().unwrap());
    assert_eq!(engine.snapshot().phase, PromotionPhase::Fenced);
    let marker = engine.fence_store().load().unwrap().unwrap();
    assert_eq!(marker.reason, "lease_lost");
    assert_eq!(marker.fenced_term, term);

    // A restarted process reads the marker and never acquires, even though the
    // witness record is reachable and expired.
    let restarted = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(restarted.boot().unwrap(), PromotionOutcome::Fenced);
    assert_eq!(restarted.start_master().await, PromotionOutcome::Fenced);
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.term, term,
        "a fenced node must not acquire a new term"
    );
}

#[tokio::test]
async fn state_write_failure_fences_before_publishing() {
    let harness = Harness::new("state_fail", "node-a").await;
    harness.host.fail_prepare.store(true, Ordering::SeqCst);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Fenced);
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "state_write_failed"
    );
    assert!(!harness.host.writable.load(Ordering::SeqCst));
    assert!(harness.event_index("publish:").is_none());
}

#[tokio::test]
async fn manual_confirmation_is_one_shot_and_master_alive_discards_it() {
    let harness = Harness::new("confirm", "node-a").await;
    let mut config = harness.fixture.config("node-a");
    config.require_manual_confirmation = true;
    let events = Arc::new(Mutex::new(Vec::new()));
    let host = Arc::new(TestHost::new(&harness.data_dir("node-a"), events.clone()));
    let backend = Arc::new(RecordingBackend {
        inner: Arc::new(harness.fixture.client("node-a")),
        events: events.clone(),
    });
    let engine = PromotionEngine::with_runtime(
        config,
        ConfiguredRole::Slave,
        harness.data_dir("node-a"),
        backend,
        host.clone(),
        harness.clock.clone(),
        Arc::new(ManualTimers::new(harness.clock.clone())),
    )
    .unwrap();
    engine.boot().unwrap();
    assert_eq!(
        engine.candidate_attempt(false).await,
        PromotionOutcome::ManualConfirmationRequired
    );

    engine
        .confirmation_store()
        .confirm(harness.clock.wall_unix_ms())
        .unwrap();
    // A live master discards it without acquiring.
    assert_eq!(
        engine.candidate_attempt(true).await,
        PromotionOutcome::Waiting
    );
    assert!(engine.confirmation_store().peek().unwrap().is_none());

    engine
        .confirmation_store()
        .confirm(harness.clock.wall_unix_ms())
        .unwrap();
    assert_eq!(
        engine.candidate_attempt(false).await,
        PromotionOutcome::Master
    );
}

#[tokio::test]
async fn late_ahead_peer_is_latched_after_success() {
    let harness = Harness::new("late_peer", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    let late = PeerReport {
        instance: "late".to_string(),
        have_term: 9,
        have_version: 99,
        have_bundle_hash: Some(hash(0xaa)),
    };
    assert!(engine.note_late_peer(&late));
    assert_eq!(engine.latched_peers(), vec!["late".to_string()]);
}

#[tokio::test]
async fn master_refuses_term_ahead_state_behind_and_state_forked() {
    // State term above the witness.
    let harness = Harness::new("master_term_ahead", "node-a").await;
    seed_witness_record(&harness.fixture, "node-a", 3, 7, &hash(0xab)).await;
    seed_state(
        &harness.data_dir("node-a"),
        5,
        7,
        PublicationState::Published,
        (7, &hash(0xab)),
        None,
        (7, &hash(0xab)),
    );
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "master_term_ahead".to_string(),
            retryable: false
        }
    );
    assert!(harness.event_index("acquire_req:").is_none());

    // Published state below the witness.
    let harness = Harness::new("master_behind", "node-a").await;
    seed_witness_record(&harness.fixture, "node-a", 1, 0, "none").await;
    seed_witness_record(&harness.fixture, "node-a", 2, 7, &hash(0xab)).await;
    seed_state(
        &harness.data_dir("node-a"),
        2,
        6,
        PublicationState::Published,
        (6, &hash(0xcd)),
        None,
        (6, &hash(0xcd)),
    );
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "master_state_behind".to_string(),
            retryable: false
        }
    );
    assert!(harness.event_index("acquire_req:").is_none());

    // Same published version, different hash.
    let harness = Harness::new("master_forked", "node-a").await;
    seed_witness_record(&harness.fixture, "node-a", 1, 0, "none").await;
    seed_witness_record(&harness.fixture, "node-a", 2, 7, &hash(0xab)).await;
    seed_state(
        &harness.data_dir("node-a"),
        2,
        7,
        PublicationState::Published,
        (7, &hash(0xcd)),
        None,
        (7, &hash(0xcd)),
    );
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "master_state_forked".to_string(),
            retryable: false
        }
    );
}

#[tokio::test]
async fn candidate_with_matching_watermark_promotes_after_master_loss() {
    let harness = Harness::new("candidate_ok", "node-b").await;
    let baseline = hash(0xab);
    seed_witness_record(&harness.fixture, "node-a", 1, 7, &baseline).await;
    *harness.host.watermark.lock().unwrap() = Some(watermarked(1, 7, &baseline));
    let engine = harness.engine("node-b", ConfiguredRole::Slave);
    assert_eq!(engine.boot().unwrap(), PromotionOutcome::Waiting);
    let outcome = engine.candidate_attempt(false).await;
    assert_eq!(outcome, PromotionOutcome::Master);
    assert_eq!(*harness.host.role.lock().unwrap(), EffectiveRole::Master);
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.term, 2);
    assert_eq!(record.version, 8);
}

#[tokio::test]
async fn candidate_eligibility_gates_refuse_without_acquiring() {
    #[allow(clippy::type_complexity)]
    let cases: [(&str, fn(&mut Eligibility)); 4] = [
        ("degraded", |e| e.degraded = true),
        ("diverged", |e| e.diverged_or_forked = true),
        ("restart", |e| e.restart_required = true),
        ("foreign", |e| e.foreign_or_stale_state = true),
    ];
    for (label, mutate) in cases {
        let harness = Harness::new(label, "node-b").await;
        *harness.host.eligibility.lock().unwrap() = {
            let mut eligibility = Eligibility::default();
            mutate(&mut eligibility);
            eligibility
        };
        let engine = harness.engine("node-b", ConfiguredRole::Slave);
        engine.boot().unwrap();
        let outcome = engine.candidate_attempt(false).await;
        assert!(
            matches!(
                outcome,
                PromotionOutcome::ReadOnly {
                    ref reason,
                    retryable: false
                } if reason == "candidate_diverged"
            ),
            "{label}: {outcome:?}"
        );
        assert!(harness.event_index("acquire_req:").is_none());
        assert!(harness.event_index("begin_hello_only").is_none());
    }
}

#[tokio::test]
async fn candidate_behind_forked_and_term_ahead_refuse_at_the_engine() {
    // Behind the witness record.
    let harness = Harness::new("candidate_behind", "node-b").await;
    let baseline = hash(0xab);
    seed_witness_record(&harness.fixture, "node-a", 1, 7, &baseline).await;
    *harness.host.watermark.lock().unwrap() = Some(watermarked(1, 6, &hash(0xcd)));
    let engine = harness.engine("node-b", ConfiguredRole::Slave);
    engine.boot().unwrap();
    assert_eq!(
        engine.candidate_attempt(false).await,
        PromotionOutcome::ReadOnly {
            reason: "candidate_behind".to_string(),
            retryable: false
        }
    );
    assert!(harness.event_index("acquire_req:").is_none());

    // Same version, different hash.
    let harness = Harness::new("candidate_forked", "node-b").await;
    let baseline = hash(0xab);
    seed_witness_record(&harness.fixture, "node-a", 1, 7, &baseline).await;
    *harness.host.watermark.lock().unwrap() = Some(watermarked(1, 7, &hash(0xcd)));
    let engine = harness.engine("node-b", ConfiguredRole::Slave);
    engine.boot().unwrap();
    assert_eq!(
        engine.candidate_attempt(false).await,
        PromotionOutcome::ReadOnly {
            reason: "candidate_forked".to_string(),
            retryable: false
        }
    );
    assert!(harness.event_index("acquire_req:").is_none());

    // Local term above the witness record.
    let harness = Harness::new("candidate_term_ahead", "node-b").await;
    seed_witness_record(&harness.fixture, "node-a", 3, 7, &hash(0xab)).await;
    *harness.host.watermark.lock().unwrap() = Some(watermarked(5, 7, &hash(0xab)));
    let engine = harness.engine("node-b", ConfiguredRole::Slave);
    engine.boot().unwrap();
    assert_eq!(
        engine.candidate_attempt(false).await,
        PromotionOutcome::ReadOnly {
            reason: "candidate_term_ahead".to_string(),
            retryable: false
        }
    );
    assert!(harness.event_index("acquire_req:").is_none());
}

#[tokio::test]
async fn failed_first_publish_keeps_the_pending_state_and_reuses_the_version() {
    let harness = Harness::new("publish_fail", "node-a").await;
    harness.host.fail_publish.store(true, Ordering::SeqCst);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "promotion_interrupted".to_string(),
            retryable: true
        }
    );
    assert!(!harness.host.writable.load(Ordering::SeqCst));
    let loaded = HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
        .load()
        .unwrap();
    let LoadedState::Present { state, bookkeeping } = loaded else {
        panic!("state");
    };
    assert_eq!(state.bundle.version, 1, "the pending version is retained");
    assert_eq!(
        bookkeeping.unwrap().publication_state,
        PublicationState::Publishing
    );
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.version, 0,
        "the witness never holds an unpublished version"
    );

    // Restart after expiry: no peer proves the publish, so version 1 is safely
    // reused, never skipped to 2.
    harness.fixture.clock.advance(5 * 1000);
    harness.host.fail_publish.store(false, Ordering::SeqCst);
    harness.clock.advance_boot(5_000);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master);
    let events = harness.events();
    assert!(events.iter().any(|e| e == "prepare:1"), "{events:?}");
    assert!(
        events.iter().any(|e| e.starts_with("publish:1:")),
        "{events:?}"
    );
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.term, 2);
    assert_eq!(record.version, 1);
}

#[tokio::test]
async fn published_state_write_failure_does_not_renew_and_restart_recovers() {
    let harness = Harness::new("published_fail", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.fail_published_state_write();
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "promotion_interrupted".to_string(),
            retryable: false
        }
    );
    assert!(!harness.host.writable.load(Ordering::SeqCst));
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.version, 0,
        "no witness renewal may advertise the unpublished version"
    );

    // A reachable slave at publish_version with the pending hash proves the
    // push succeeded on restart; the engine marks it published and renews.
    let prepared = harness.host.pushed.lock().unwrap().clone().unwrap();
    harness.host.set_reports(vec![PeerReport {
        instance: "slave-proof".to_string(),
        have_term: 1,
        have_version: 1,
        have_bundle_hash: Some(prepared.hash.clone()),
    }]);
    harness.fixture.clock.advance(5 * 1000);
    harness.clock.advance_boot(5_000);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master);
    let events = harness.events();
    assert!(
        events.iter().any(|e| e == "adopt:1"),
        "the proven publish is adopted, not re-pushed: {events:?}"
    );
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.term, 2);
    assert_eq!(
        record.version, 2,
        "the proven baseline 1 still needs a new-term publish above it"
    );
}

#[tokio::test]
async fn boot_id_and_wall_step_fence_the_master() {
    let harness = Harness::new("clock_fence", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    harness.clock.set_boot_id("different-boot");
    assert!(engine.check_self_fence().unwrap());
    assert_eq!(engine.snapshot().phase, PromotionPhase::Fenced);
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "clock_step"
    );

    let harness = Harness::new("wall_fence", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    harness.clock.advance_wall(31_000);
    assert!(engine.check_self_fence().unwrap());
    assert_eq!(engine.snapshot().phase, PromotionPhase::Fenced);
}

#[tokio::test]
async fn both_fence_writes_failing_is_a_critical_local_failure() {
    let harness = Harness::new("both_fence", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    let data_dir = harness.data_dir("node-a");
    std::fs::remove_dir_all(&data_dir).unwrap();
    std::fs::write(&data_dir, b"not a directory").unwrap();
    harness.clock.advance_boot(5_000);
    assert!(engine.check_self_fence().is_err());
    assert!(
        harness
            .events()
            .iter()
            .any(|event| event.starts_with("critical:")),
        "both fence writes failing must log a critical failure: {:?}",
        harness.events()
    );
    assert_eq!(engine.snapshot().phase, PromotionPhase::Fenced);
    let _ = std::fs::remove_file(&data_dir);
}

#[tokio::test]
async fn restart_with_slave_role_is_a_candidate_and_never_writable_from_state() {
    let harness = Harness::new("role_restart", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    let host = Arc::new(TestHost::new(
        &harness.data_dir("node-a"),
        Arc::new(Mutex::new(Vec::new())),
    ));
    let restarted = harness.fixture.engine(
        "node-a",
        ConfiguredRole::Slave,
        host.clone(),
        Arc::clone(&harness.clock),
        Arc::new(Mutex::new(Vec::new())),
    );
    assert_eq!(restarted.boot().unwrap(), PromotionOutcome::Waiting);
    assert!(!host.writable.load(Ordering::SeqCst));
    assert_eq!(*host.role.lock().unwrap(), EffectiveRole::Slave);
    let outcome = restarted.candidate_attempt(false).await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "lease_held_by_other".to_string(),
            retryable: true
        }
    );
    assert!(!host.writable.load(Ordering::SeqCst));
}
