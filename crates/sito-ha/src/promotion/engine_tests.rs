//! Engine behavior tests against the real in-process TLS witness with
//! deterministic clocks/timers.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sito_ha_types::bundle::{AppliedWatermark, ConfigBundle};
use sito_ha_types::config::{PromotionConfig, WitnessClientConfig};
use sito_ha_types::status::PublicationState;

use super::clock::{ManualMonotonicClock, ManualTimers, MonotonicClock};
use super::engine::{
    ConfiguredRole, EffectiveRole, Eligibility, LeaseBackend, PreparedBundle, PromotionEngine,
    PromotionHost, PromotionOutcome, PromotionPhase, PublishDeadline,
};
use super::reconcile::PeerReport;
use super::state::{HaStateStore, LoadedState, PersistedMasterState, PublicationBaseline};
use super::witness_client::WitnessClient;
use super::witness_client::WitnessClientError;
use crate::bundle::{build_and_sign_push, push_payload_hash};
use crate::crypto::Ed25519SigningKey;
use crate::witness::clock::ManualClock;
use crate::witness::record::{AcquireRequest, LeaseInfo, LeaseRecord, RenewRequest};
use crate::witness::server::{WitnessConfig, WitnessHandle, start_witness_server};
use sito_stats::MetricsRegistry;

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
        self.engine_with_config(self.config(node_id), role, host, clock, events)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn engine_with_config(
        &self,
        config: PromotionConfig,
        role: ConfiguredRole,
        host: Arc<TestHost>,
        clock: Arc<ManualMonotonicClock>,
        events: Arc<Mutex<Vec<String>>>,
    ) -> PromotionEngine {
        let backend = Arc::new(RecordingBackend {
            inner: Arc::new(self.client(config.node_id.as_deref().unwrap_or("node"))),
            events: clone_events(&events),
        });
        let data_dir = self.dir.join(format!(
            "data-{}",
            config.node_id.as_deref().unwrap_or("node")
        ));
        PromotionEngine::with_runtime(
            config,
            role,
            data_dir,
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
        self.log(format!(
            "renew_req:{}:{}",
            request.version, request.bundle_hash
        ));
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

struct ConflictBackend {
    inner: Arc<WitnessClient>,
    conflict: Mutex<Option<LeaseRecord>>,
    fail_info: AtomicBool,
}

impl LeaseBackend for ConflictBackend {
    fn info(&self) -> super::clock::BoxFuture<'_, Result<LeaseInfo, WitnessClientError>> {
        if self.fail_info.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(WitnessClientError::Unavailable {
                    detail: "injected witness info failure".to_string(),
                })
            });
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.info().await })
    }

    fn lease(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.lease().await })
    }

    fn acquire(
        &self,
        request: AcquireRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.acquire(&request).await })
    }

    fn renew(
        &self,
        request: RenewRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        if let Some(current) = self.conflict.lock().unwrap().clone() {
            return Box::pin(async move {
                Err(WitnessClientError::Conflict {
                    reason: Some("holder_mismatch".to_string()),
                    detail: Some("injected conflict".to_string()),
                    current: Some(Box::new(current)),
                })
            });
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.renew(&request).await })
    }
}

struct ToggleBackend {
    inner: Arc<WitnessClient>,
    fail_renew: Arc<AtomicBool>,
}

impl LeaseBackend for ToggleBackend {
    fn info(&self) -> super::clock::BoxFuture<'_, Result<LeaseInfo, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.info().await })
    }

    fn lease(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.lease().await })
    }

    fn acquire(
        &self,
        request: AcquireRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.acquire(&request).await })
    }

    fn renew(
        &self,
        request: RenewRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        if self.fail_renew.load(Ordering::SeqCst) {
            return Box::pin(async {
                Err(WitnessClientError::Unavailable {
                    detail: "injected transport renewal failure".to_string(),
                })
            });
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.renew(&request).await })
    }
}

#[derive(Debug, Clone, Copy)]
enum InjectedWitnessError {
    Transport,
    Auth,
    Server,
}

impl InjectedWitnessError {
    fn build(self) -> WitnessClientError {
        match self {
            Self::Transport => WitnessClientError::Unavailable {
                detail: "injected transport failure".to_string(),
            },
            Self::Auth => WitnessClientError::Auth {
                detail: "injected 401".to_string(),
            },
            Self::Server => WitnessClientError::Server {
                status: 503,
                error: Some("unavailable".to_string()),
                reason: None,
                detail: Some("injected 5xx".to_string()),
            },
        }
    }
}

struct ErrorBackend {
    kind: InjectedWitnessError,
}
impl LeaseBackend for ErrorBackend {
    fn info(&self) -> super::clock::BoxFuture<'_, Result<LeaseInfo, WitnessClientError>> {
        let kind = self.kind;
        Box::pin(async move { Err(kind.build()) })
    }

    fn lease(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>> {
        let kind = self.kind;
        Box::pin(async move { Err(kind.build()) })
    }

    fn acquire(
        &self,
        _request: AcquireRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        let kind = self.kind;
        Box::pin(async move { Err(kind.build()) })
    }

    fn renew(
        &self,
        _request: RenewRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        let kind = self.kind;
        Box::pin(async move { Err(kind.build()) })
    }
}

/// A real witness client whose whole endpoint can be taken offline.
struct OutageBackend {
    inner: Arc<WitnessClient>,
    fail: Arc<AtomicBool>,
}

impl OutageBackend {
    fn error() -> WitnessClientError {
        WitnessClientError::Unavailable {
            detail: "injected witness outage".to_string(),
        }
    }
}

impl LeaseBackend for OutageBackend {
    fn info(&self) -> super::clock::BoxFuture<'_, Result<LeaseInfo, WitnessClientError>> {
        if self.fail.load(Ordering::SeqCst) {
            return Box::pin(async { Err(OutageBackend::error()) });
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.info().await })
    }

    fn lease(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>> {
        if self.fail.load(Ordering::SeqCst) {
            return Box::pin(async { Err(OutageBackend::error()) });
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.lease().await })
    }

    fn acquire(
        &self,
        request: AcquireRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        if self.fail.load(Ordering::SeqCst) {
            return Box::pin(async { Err(OutageBackend::error()) });
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.acquire(&request).await })
    }

    fn renew(
        &self,
        request: RenewRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        if self.fail.load(Ordering::SeqCst) {
            return Box::pin(async { Err(OutageBackend::error()) });
        }
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.renew(&request).await })
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
    publish_during_hello_only: AtomicBool,
    published_baseline: Mutex<Option<PublicationBaseline>>,
    latched: Mutex<Vec<String>>,
    late_reports: Mutex<Vec<PeerReport>>,
    fail_renew_on_reports: Mutex<Option<Arc<AtomicBool>>>,
    fail_renew_on_hello_end: Mutex<Option<Arc<AtomicBool>>>,
    admissions_denied: AtomicBool,
    clock: Mutex<Option<Arc<ManualMonotonicClock>>>,
    slow_publish_millis: Mutex<Option<u64>>,
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
            publish_during_hello_only: AtomicBool::new(false),
            published_baseline: Mutex::new(None),
            latched: Mutex::new(Vec::new()),
            late_reports: Mutex::new(Vec::new()),
            fail_renew_on_reports: Mutex::new(None),
            fail_renew_on_hello_end: Mutex::new(None),
            admissions_denied: AtomicBool::new(false),
            clock: Mutex::new(None),
            slow_publish_millis: Mutex::new(None),
        }
    }

    fn set_clock(&self, clock: Arc<ManualMonotonicClock>) {
        *self.clock.lock().unwrap() = Some(clock);
    }

    fn set_slow_publish_millis(&self, millis: u64) {
        *self.slow_publish_millis.lock().unwrap() = Some(millis);
    }

    fn fail_renew_on_reports(&self, flag: Arc<AtomicBool>) {
        *self.fail_renew_on_reports.lock().unwrap() = Some(flag);
    }

    fn fail_renew_on_hello_end(&self, flag: Arc<AtomicBool>) {
        *self.fail_renew_on_hello_end.lock().unwrap() = Some(flag);
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

    fn current_published_baseline(&self) -> Option<PublicationBaseline> {
        if let Some(baseline) = self.published_baseline.lock().unwrap().clone() {
            return Some(baseline);
        }
        // Mirror the production host: renewal uses the durable published
        // baseline from `ha_state.toml`, never an in-memory pre-commit value.
        let loaded = HaStateStore::new(self.state_path.clone()).load().ok()?;
        match loaded {
            LoadedState::Present {
                bookkeeping: Some(bookkeeping),
                ..
            } => Some(bookkeeping.baseline()),
            _ => None,
        }
    }

    fn signing_key_pubkey(&self) -> Option<String> {
        Some(self.key.public_key_hex())
    }

    fn take_late_peer_reports(&self) -> Vec<PeerReport> {
        std::mem::take(&mut *self.late_reports.lock().unwrap())
    }

    fn hash_bundle(&self, bundle: &ConfigBundle) -> Result<String, String> {
        let push = build_and_sign_push(bundle, &self.key).map_err(|error| error.to_string())?;
        push_payload_hash(&push).map_err(|error| error.to_string())
    }

    fn latch_peer(&self, report: &PeerReport, reason: &str) {
        self.log(format!("latch:{}:{reason}", report.instance));
        self.latched.lock().unwrap().push(report.instance.clone());
    }

    fn eligibility(&self) -> Eligibility {
        self.eligibility.lock().unwrap().clone()
    }

    fn master_alive(&self) -> bool {
        false
    }

    fn set_writable(&self, writable: bool, reason: Option<String>) {
        if !writable {
            self.admissions_denied.store(true, Ordering::SeqCst);
        }
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
        if let Some(flag) = self.fail_renew_on_hello_end.lock().unwrap().clone() {
            flag.store(true, Ordering::SeqCst);
        }
        self.log("end_hello_only");
        Box::pin(async { Ok(()) })
    }

    fn collect_reconcile_reports(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Vec<PeerReport>, String>> {
        let reports = self.reports.lock().unwrap().clone();
        if let Some(flag) = self.fail_renew_on_reports.lock().unwrap().clone() {
            flag.store(true, Ordering::SeqCst);
        }
        self.log(format!("reports:{}", reports.len()));
        Box::pin(async move { Ok(reports) })
    }

    fn publish_first<'a>(
        &'a self,
        prepared: &'a PreparedBundle,
        deadline: &'a PublishDeadline,
    ) -> super::clock::BoxFuture<'a, Result<String, String>> {
        if self.hello_only.load(Ordering::SeqCst) {
            self.publish_during_hello_only.store(true, Ordering::SeqCst);
        }
        if self.fail_publish.load(Ordering::SeqCst) {
            return Box::pin(async { Err("injected publish failure".to_string()) });
        }
        // Model a slow durable pre-publish write: the host advances the clock
        // and must refuse to push when the deadline handle is no longer safe.
        if let Some(delay) = *self.slow_publish_millis.lock().unwrap() {
            if let Some(clock) = self.clock.lock().unwrap().clone() {
                clock.advance_boot(delay);
            }
            if !deadline.is_safe() {
                self.log("publish_deadline_passed");
                return Box::pin(async {
                    Err("self-fence deadline passed before the push".to_string())
                });
            }
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
        let clock = Arc::new(ManualMonotonicClock::new(1_000, START_MS));
        host.set_clock(Arc::clone(&clock));
        Self {
            fixture,
            clock,
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
            reason: "witness_unavailable".to_string(),
            retryable: true
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
    let snapshot = engine.snapshot();
    assert!(
        !snapshot.lease_held,
        "a terminal abort must not keep advertising a held lease"
    );
    assert_eq!(snapshot.lease_revision, None);
    assert_eq!(snapshot.lease_expires_unix_ms, None);
    assert_eq!(snapshot.lease_expires_in_secs, None);
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
async fn promotion_records_metrics_from_a_successful_acquisition() {
    let harness = Harness::new("metrics", "node-a").await;
    let metrics = MetricsRegistry::new("2.0.0", "test");
    metrics.init_ha_promotion_metrics(true);
    let engine = harness
        .engine("node-a", ConfiguredRole::Master)
        .with_metrics(metrics.clone());
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);

    let rendered = metrics.render_prometheus();
    assert!(rendered.contains(r#"sito_ha_promotion_attempts_total{result="success"} 1"#));
    assert!(
        rendered.contains(
            r#"sito_ha_promotion_witness_requests_total{op="acquire",result="success"} 1"#
        )
    );
    assert!(
        rendered
            .contains(r#"sito_ha_promotion_witness_requests_total{op="lease",result="success"}"#)
    );
    assert!(rendered.contains("sito_ha_promotion_last_success_timestamp_seconds"));
    assert!(
        !rendered.contains("sito_ha_promotion_last_success_timestamp_seconds 0"),
        "a successful acquisition must publish a non-zero success timestamp"
    );
    // Bounded labels only: no node, holder, token or cluster labels.
    for forbidden in ["node_id=", "holder=", "token=", "cluster_id="] {
        assert!(
            !rendered.contains(forbidden),
            "{forbidden} must not be a label"
        );
    }
}

#[tokio::test]
async fn witness_failures_clear_reachability_and_use_the_witness_error_label() {
    for kind in [
        InjectedWitnessError::Transport,
        InjectedWitnessError::Auth,
        InjectedWitnessError::Server,
    ] {
        let harness = Harness::new("witness_error_metric", "node-a").await;
        let metrics = MetricsRegistry::new("2.0.0", "test");
        metrics.init_ha_promotion_metrics(true);
        let config = harness.fixture.config("node-a");
        let clock: Arc<dyn MonotonicClock> = harness.clock.clone();
        let engine = PromotionEngine::with_runtime(
            config,
            ConfiguredRole::Master,
            harness.data_dir("node-a"),
            Arc::new(ErrorBackend { kind }),
            {
                let host: Arc<dyn PromotionHost> = harness.host.clone();
                host
            },
            clock,
            Arc::new(ManualTimers::new(Arc::clone(&harness.clock))),
        )
        .unwrap()
        .with_metrics(metrics.clone());

        let _ = engine.start_master().await;
        let rendered = metrics.render_prometheus();
        assert!(
            rendered.contains(
                r#"sito_ha_promotion_witness_requests_total{op="lease",result="witness_error"} 1"#
            ),
            "{kind:?} must appear as witness_error, got:\n{rendered}"
        );
        assert!(
            !rendered.contains(r#"result="error""#),
            "the unbounded 'error' label must never be emitted"
        );
        assert!(
            !engine.snapshot().witness_reachable,
            "a failed probe must clear witness_reachable"
        );
    }
}

#[tokio::test]
async fn witness_outage_after_acquire_clears_reachability() {
    let harness = Harness::new("reachability", "node-a").await;
    let fail = Arc::new(AtomicBool::new(false));
    let config = harness.fixture.config("node-a");
    let clock: Arc<dyn MonotonicClock> = harness.clock.clone();
    let backend = Arc::new(OutageBackend {
        inner: Arc::new(harness.fixture.client("node-a")),
        fail: Arc::clone(&fail),
    });
    let engine = PromotionEngine::with_runtime(
        config,
        ConfiguredRole::Master,
        harness.data_dir("node-a"),
        backend,
        {
            let host: Arc<dyn PromotionHost> = harness.host.clone();
            host
        },
        clock,
        Arc::new(ManualTimers::new(Arc::clone(&harness.clock))),
    )
    .unwrap();
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    assert!(engine.snapshot().witness_reachable);

    fail.store(true, Ordering::SeqCst);
    assert!(engine.renew_once().await.is_err());
    assert!(
        !engine.snapshot().witness_reachable,
        "a failed renewal probe must clear witness_reachable"
    );
}

#[tokio::test]
async fn candidate_boot_has_no_master_evidence_until_a_frame_arrives() {
    let harness = Harness::new("candidate_boot", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Slave);
    engine.boot().unwrap();
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.phase, PromotionPhase::WaitingForMasterLoss);
    assert_eq!(
        snapshot.reason.as_deref(),
        Some("not_candidate"),
        "boot must not claim a live master before any frame is observed"
    );
    assert!(snapshot.candidate);

    // Once the supervisor sees a live master frame it publishes master_alive.
    engine.note_waiting_for_master("master_alive");
    assert_eq!(engine.snapshot().reason.as_deref(), Some("master_alive"));
}

#[tokio::test]
async fn boot_copies_the_active_bundle_hash() {
    let harness = Harness::new("boot_hash", "node-a").await;
    let published = hash(0xab);
    seed_state(
        &harness.data_dir("node-a"),
        4,
        128,
        PublicationState::Published,
        (128, &published),
        None,
        (128, &published),
    );
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let snapshot = engine.snapshot();
    assert_eq!(snapshot.version, 128);
    assert_eq!(snapshot.bundle_hash, published);
    assert_ne!(snapshot.bundle_hash, "none");
}

#[tokio::test]
async fn runtime_fence_reasons_use_stable_documented_codes() {
    use super::fence::FenceReason;

    let harness = Harness::new("fence_codes", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    for (reason, code) in [
        (FenceReason::ClockAnomaly, "clock_step"),
        (FenceReason::StateWriteFailed, "state_write_failed"),
        (FenceReason::RoleSwitchFailed, "role_switch_failed"),
    ] {
        engine.fence(reason, "test").unwrap();
        let snapshot = engine.snapshot();
        assert_eq!(snapshot.phase, PromotionPhase::Fenced);
        assert_eq!(snapshot.reason.as_deref(), Some(code));
    }
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

    // `sito ha clear-fence --confirm` removes both markers locally; the next
    // start is no longer refused and may acquire a fresh term.
    restarted.fence_store().clear().unwrap();
    assert!(restarted.fence_store().load().unwrap().is_none());
    // Expire the old holder's witness record: clearing the fence only removes
    // the durable no-reacquire marker, it does not grant a lease.
    harness.fixture.clock.advance(5_000);
    let cleared = harness.engine("node-a", ConfiguredRole::Master);
    assert_ne!(cleared.boot().unwrap(), PromotionOutcome::Fenced);
    assert_eq!(
        cleared.start_master().await,
        PromotionOutcome::Master,
        "after clearing the fence the node may acquire a new term"
    );
    assert!(cleared.snapshot().term > term);
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
    assert!(!engine.snapshot().fenced, "recovery must not self-fence");
    let events = harness.events();
    assert!(
        events.iter().any(|e| e == "prepare:2"),
        "the proven baseline 1 is published above as 2: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e == &format!("renew_req:1:{}", prepared.hash)),
        "the recovery renewal uses the proven published baseline, not a skipped version: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.starts_with("publish:2:")),
        "a new-term publish is still required above the proven baseline: {events:?}"
    );
    let loaded = HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
        .load()
        .unwrap();
    let LoadedState::Present { bookkeeping, state } = loaded else {
        panic!("state");
    };
    let bookkeeping = bookkeeping.unwrap();
    assert_eq!(bookkeeping.publication_state, PublicationState::Published);
    assert_eq!(bookkeeping.published_version, 2);
    assert_eq!(state.bundle.version, 2);
    assert!(
        state.signing_key_pubkey.is_some(),
        "the promoted state records the signing key"
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

#[tokio::test]
async fn reconcile_window_longer_than_the_ttl_keeps_renewing() {
    let harness = Harness::new("window_gt_ttl", "node-a").await;
    let mut config = harness.fixture.config("node-a");
    config.lease_ttl_secs = 5;
    config.reconcile_window_secs = 10;
    let engine = harness.fixture.engine_with_config(
        config,
        ConfiguredRole::Master,
        Arc::clone(&harness.host),
        Arc::clone(&harness.clock),
        Arc::clone(&harness.events),
    );
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master);
    let events = harness.events();
    let publish = events
        .iter()
        .position(|event| event.starts_with("publish:1:"))
        .unwrap();
    let renewals = events[..publish]
        .iter()
        .filter(|event| event.starts_with("lease_resp:0:"))
        .count();
    assert!(
        renewals >= 2,
        "the reconcile window must renew the lease while it waits: {events:?}"
    );
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.version, 1);
    assert_eq!(record.term, 1);
}

#[tokio::test]
async fn legacy_state_without_bookkeeping_infers_from_the_bundle_not_applied_version() {
    let harness = Harness::new("legacy_state", "node-a").await;
    let bundle = ConfigBundle {
        version: 7,
        term: 2,
        config_toml: "config_version = 2\n[server]\nrole = \"slave\"\n".to_string(),
        ..ConfigBundle::default()
    };
    let hash = harness.host.hash_bundle(&bundle).unwrap();
    seed_witness_record(&harness.fixture, "node-a", 3, 7, &hash).await;
    seed_state(
        &harness.data_dir("node-a"),
        2,
        7,
        PublicationState::Published,
        (7, &hash),
        None,
        (7, &hash),
    );
    // Rewrite the state in the older shape: no promotion bookkeeping at all.
    let mut legacy: PersistedMasterState =
        match HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
            .load()
            .unwrap()
        {
            LoadedState::Present { state, .. } => *state,
            LoadedState::Missing => panic!("seeded state missing"),
        };
    legacy.publication_state = None;
    legacy.published_version = None;
    legacy.published_hash = None;
    legacy.pending_hash = None;
    HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
        .save(&legacy)
        .unwrap();

    let loaded = HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
        .load()
        .unwrap();
    let LoadedState::Present { ref state, .. } = loaded else {
        panic!()
    };
    let recomputed = harness.host.hash_bundle(&state.bundle).unwrap();
    assert_eq!(recomputed, hash, "test fixture hash mismatch");
    let witness_hash = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap()
        .bundle_hash;
    assert_eq!(witness_hash, hash, "witness/state hash mismatch");
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master);
    let events = harness.events();
    assert!(events.iter().any(|e| e == "prepare:8"), "{events:?}");
    assert!(
        events.iter().any(|e| e == "acquire_req:7"),
        "the legacy bundle baseline must be used, never applied_version 0: {events:?}"
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
}

#[tokio::test]
async fn renewal_refreshes_the_baseline_after_a_normal_publish() {
    let harness = Harness::new("baseline_refresh", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    *harness.host.published_baseline.lock().unwrap() =
        Some(PublicationBaseline::new(2, &hash(0xef)).unwrap());
    engine.renew_once().await.unwrap();
    let events = harness.events();
    assert!(
        events
            .iter()
            .any(|event| event == &format!("lease_resp:2:{}", hash(0xef))),
        "renewal must advertise the latest normal-published baseline: {events:?}"
    );
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.version, 2);
}

#[tokio::test]
async fn pending_state_write_failure_fences_without_publishing() {
    let harness = Harness::new("pending_fail", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.fail_pending_state_write();
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Fenced);
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "state_write_failed"
    );
    assert!(harness.event_index("publish:").is_none());
}

#[tokio::test]
async fn late_ahead_peer_is_reported_to_the_runtime_latch() {
    let harness = Harness::new("late_latch_host", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    let late = PeerReport {
        instance: "late-host".to_string(),
        have_term: 9,
        have_version: 99,
        have_bundle_hash: Some(hash(0xaa)),
    };
    assert!(engine.note_late_peer(&late));
    assert_eq!(
        harness.host.latched.lock().unwrap().as_slice(),
        ["late-host".to_string()]
    );
    assert!(
        harness
            .events()
            .iter()
            .any(|event| event.starts_with("latch:late-host:")),
        "the runtime latch hook must receive the late ahead peer"
    );
}

#[tokio::test]
async fn renewal_conflict_without_the_witness_clock_fences() {
    let harness = Harness::new("renew_conflict_no_clock", "node-a").await;
    let conflict_backend = Arc::new(ConflictBackend {
        inner: Arc::new(harness.fixture.client("node-a")),
        conflict: Mutex::new(None),
        fail_info: AtomicBool::new(false),
    });
    let clock: Arc<dyn MonotonicClock> = harness.clock.clone();
    let host: Arc<dyn PromotionHost> = harness.host.clone();
    let engine = PromotionEngine::with_runtime(
        harness.fixture.config("node-a"),
        ConfiguredRole::Master,
        harness.data_dir("node-a"),
        conflict_backend.clone(),
        host,
        clock,
        Arc::new(ManualTimers::new(Arc::clone(&harness.clock))),
    )
    .unwrap();
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    // Every subsequent info call fails, and the renewal returns a conflict
    // with a current record that cannot be classified without the witness
    // clock.
    conflict_backend.fail_info.store(true, Ordering::SeqCst);
    *conflict_backend.conflict.lock().unwrap() = Some(LeaseRecord {
        schema: 1,
        cluster_id: CLUSTER.to_string(),
        holder: "node-a/other-boot".to_string(),
        node_id: "node-a".to_string(),
        term: 1,
        revision: 2,
        version: 1,
        bundle_hash: hash(0xab),
        acquired_unix_ms: 1,
        expires_unix_ms: i64::MAX,
    });
    assert!(engine.renew_once().await.is_err());
    assert!(engine.snapshot().fenced, "uncertain lease time must fence");
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "lease_lost"
    );
}

#[tokio::test]
async fn engine_level_renewal_409_fences_immediately() {
    let harness = Harness::new("renew_409", "node-a").await;
    let conflict_backend = Arc::new(ConflictBackend {
        inner: Arc::new(harness.fixture.client("node-a")),
        conflict: Mutex::new(None),
        fail_info: AtomicBool::new(false),
    });
    let config = harness.fixture.config("node-a");
    let clock: Arc<dyn MonotonicClock> = harness.clock.clone();
    let host: Arc<dyn PromotionHost> = harness.host.clone();
    let engine = PromotionEngine::with_runtime(
        config,
        ConfiguredRole::Master,
        harness.data_dir("node-a"),
        conflict_backend.clone(),
        host,
        clock,
        Arc::new(ManualTimers::new(Arc::clone(&harness.clock))),
    )
    .unwrap();
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    *conflict_backend.conflict.lock().unwrap() = Some(LeaseRecord {
        schema: 1,
        cluster_id: CLUSTER.to_string(),
        holder: "node-b/other-boot".to_string(),
        node_id: "node-b".to_string(),
        term: 1,
        revision: 2,
        version: 1,
        bundle_hash: hash(0xab),
        acquired_unix_ms: 1,
        expires_unix_ms: i64::MAX,
    });
    assert!(engine.renew_once().await.is_err());
    assert!(engine.snapshot().fenced);
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "lease_lost"
    );
}

fn run_toggle_engine(
    harness: &Harness,
    host: Arc<TestHost>,
    flag: Arc<AtomicBool>,
) -> PromotionEngine {
    let config = harness.fixture.config("node-a");
    let clock: Arc<dyn MonotonicClock> = harness.clock.clone();
    let host_trait: Arc<dyn PromotionHost> = host;
    let backend = Arc::new(ToggleBackend {
        inner: Arc::new(harness.fixture.client("node-a")),
        fail_renew: flag,
    });
    PromotionEngine::with_runtime(
        config,
        ConfiguredRole::Master,
        harness.data_dir("node-a"),
        backend,
        host_trait,
        clock,
        Arc::new(ManualTimers::new(Arc::clone(&harness.clock))),
    )
    .unwrap()
}

#[tokio::test]
async fn transport_renewal_failure_at_first_publish_boundary_denies_admission() {
    let harness = Harness::new("renew_boundary", "node-a").await;
    let flag = Arc::new(AtomicBool::new(false));
    harness.host.fail_renew_on_reports(Arc::clone(&flag));
    let engine = run_toggle_engine(&harness, Arc::clone(&harness.host), flag);
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "lease_lost".to_string(),
            retryable: true,
        }
    );
    assert!(
        harness.host.admissions_denied.load(Ordering::SeqCst),
        "a terminal read-only return must deny replication admission"
    );
    assert!(!harness.host.writable.load(Ordering::SeqCst));
}

#[tokio::test]
async fn transport_renewal_failure_before_first_push_denies_admission() {
    let harness = Harness::new("renew_before_push", "node-a").await;
    let flag = Arc::new(AtomicBool::new(false));
    harness.host.fail_renew_on_hello_end(Arc::clone(&flag));
    let engine = run_toggle_engine(&harness, Arc::clone(&harness.host), flag);
    let outcome = engine.start_master().await;
    assert_eq!(
        outcome,
        PromotionOutcome::ReadOnly {
            reason: "lease_lost".to_string(),
            retryable: true,
        }
    );
    assert!(harness.host.admissions_denied.load(Ordering::SeqCst));
    assert!(harness.event_index("publish:").is_none());
}

/// A backend whose renew call advances the monotonic clock past the deadline
/// and then returns a syntactically valid ACK. The engine must reject the ACK
/// and fence instead of extending the lease.
struct SlowAckBackend {
    inner: Arc<WitnessClient>,
    clock: Arc<ManualMonotonicClock>,
    advance_millis: u64,
}

impl LeaseBackend for SlowAckBackend {
    fn info(&self) -> super::clock::BoxFuture<'_, Result<LeaseInfo, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.info().await })
    }

    fn lease(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.lease().await })
    }

    fn acquire(
        &self,
        request: AcquireRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.acquire(&request).await })
    }

    fn renew(
        &self,
        request: RenewRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        let clock = Arc::clone(&self.clock);
        let advance = self.advance_millis;
        Box::pin(async move {
            clock.advance_boot(advance);
            Ok(LeaseRecord {
                schema: 1,
                cluster_id: CLUSTER.to_string(),
                holder: request.holder,
                node_id: "node-a".to_string(),
                term: request.term,
                revision: request.expected_revision + 1,
                version: request.version,
                bundle_hash: request.bundle_hash,
                acquired_unix_ms: 1,
                expires_unix_ms: i64::MAX,
            })
        })
    }
}

/// A backend whose renew call blocks longer than the remaining self-fence
/// budget. The engine must time out, close the gate and fence.
struct SlowSleepBackend {
    inner: Arc<WitnessClient>,
    sleep: Duration,
    slow: Arc<AtomicBool>,
}

impl LeaseBackend for SlowSleepBackend {
    fn info(&self) -> super::clock::BoxFuture<'_, Result<LeaseInfo, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.info().await })
    }

    fn lease(
        &self,
    ) -> super::clock::BoxFuture<'_, Result<Option<LeaseRecord>, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.lease().await })
    }

    fn acquire(
        &self,
        request: AcquireRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        let inner = Arc::clone(&self.inner);
        Box::pin(async move { inner.acquire(&request).await })
    }

    fn renew(
        &self,
        request: RenewRequest,
    ) -> super::clock::BoxFuture<'_, Result<LeaseRecord, WitnessClientError>> {
        if !self.slow.load(Ordering::SeqCst) {
            let inner = Arc::clone(&self.inner);
            return Box::pin(async move { inner.renew(&request).await });
        }
        let sleep = self.sleep;
        Box::pin(async move {
            tokio::time::sleep(sleep).await;
            Err(WitnessClientError::Unavailable {
                detail: "slow renewal".to_string(),
            })
        })
    }
}

#[tokio::test]
async fn retried_first_publish_quiesce_never_sends_the_pending_version() {
    let harness = Harness::new("retry_pending", "node-a").await;
    harness.host.fail_publish.store(true, Ordering::SeqCst);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert!(matches!(
        engine.start_master().await,
        PromotionOutcome::ReadOnly { .. }
    ));
    let loaded = HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
        .load()
        .unwrap();
    let LoadedState::Present { state, bookkeeping } = loaded else {
        panic!("state");
    };
    assert_eq!(state.bundle.version, 1);
    let pending_hash = bookkeeping.unwrap().pending_hash.unwrap();

    // Expire the witness grant and retry. The staged pending version 1 must
    // never be announced as the renewal baseline: only the published 0/none.
    harness.fixture.clock.advance(5_000);
    harness.clock.advance_boot(5_000);
    harness.host.fail_publish.store(false, Ordering::SeqCst);
    let retry_start = harness.events().len();
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    harness.clock.set_boot(1_000);
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master, "{:?}", harness.events());
    let events = harness.events();
    let publish = events[retry_start..]
        .iter()
        .position(|event| event.starts_with("publish:1:"))
        .map(|index| retry_start + index)
        .expect("retry publishes version 1");
    let renewals = events[retry_start..publish]
        .iter()
        .filter(|event| event.starts_with("renew_req:"))
        .collect::<Vec<_>>();
    assert!(
        !renewals.is_empty(),
        "quiesce/reconciliation must renew: {events:?}"
    );
    assert!(
        renewals
            .iter()
            .all(|event| event.starts_with("renew_req:0:")),
        "quiesce/reconciliation must renew with the published baseline only: {renewals:?}"
    );
    assert!(
        events[..publish]
            .iter()
            .all(|event| !event.starts_with("renew_req:1:")),
        "the pending version 1 ({pending_hash}) must never be sent to the witness"
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
async fn renewal_uses_the_durable_published_baseline_only() {
    let harness = Harness::new("second_persist", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    // The host reads only the durable published baseline. A normal publish
    // advances the coordinator's in-memory bookkeeping before its second
    // durable write; that uncommitted value must never reach the witness. The
    // coordinator-level failed-second-persist test covers the write failure;
    // here the renewal must use the durable 1, never an in-memory 2.
    *harness.host.published_baseline.lock().unwrap() = None;
    let loaded = HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
        .load()
        .unwrap();
    let LoadedState::Present { bookkeeping, .. } = loaded else {
        panic!("state");
    };
    let published = bookkeeping.unwrap();
    assert_eq!(published.published_version, 1);
    engine.renew_once().await.unwrap();
    let events = harness.events();
    assert!(
        events.iter().any(|event| event.starts_with("renew_req:1:")),
        "the durable published baseline is renewed: {events:?}"
    );
}

#[tokio::test]
async fn already_published_recovery_renews_with_the_proven_baseline_and_publishes_above_it() {
    let harness = Harness::new("already_published", "node-a").await;
    let baseline = hash(0xab);
    let pending = hash(0xcd);
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
    harness.host.set_reports(vec![PeerReport {
        instance: "proof-slave".to_string(),
        have_term: 3,
        have_version: 8,
        have_bundle_hash: Some(pending.clone()),
    }]);
    harness.clock.set_boot(1_000);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    engine.boot().unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Master, "{:?}", harness.events());
    assert!(
        !engine.snapshot().fenced,
        "the proven publish must not self-fence: {:?}",
        harness.events()
    );
    let events = harness.events();
    assert!(
        events
            .iter()
            .any(|event| event == &format!("renew_req:8:{pending}")),
        "the proven baseline 8/{pending} is renewed before publishing above it: {events:?}"
    );
    assert!(
        events.iter().any(|event| event.starts_with("publish:9:")),
        "the new term publishes strictly above the proven baseline: {events:?}"
    );
    assert!(
        events.iter().any(|event| event.starts_with("renew_req:9:")),
        "the post-publish renewal advances to 9: {events:?}"
    );
    let loaded = HaStateStore::new(harness.data_dir("node-a").join("ha_state.toml"))
        .load()
        .unwrap();
    let LoadedState::Present { state, bookkeeping } = loaded else {
        panic!("state");
    };
    assert_eq!(state.bundle.version, 9);
    let bookkeeping = bookkeeping.unwrap();
    assert_eq!(bookkeeping.publication_state, PublicationState::Published);
    assert_eq!(bookkeeping.published_version, 9);
    assert!(
        state.signing_key_pubkey.is_some(),
        "the promoted state records the signing key"
    );
    let record = harness
        .fixture
        .client("node-a")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.term, 4);
    assert_eq!(record.version, 9);
}

#[tokio::test]
async fn slow_ack_after_the_deadline_fences_without_publishing() {
    let harness = Harness::new("slow_ack", "node-a").await;
    let backend = Arc::new(SlowAckBackend {
        inner: Arc::new(harness.fixture.client("node-a")),
        clock: Arc::clone(&harness.clock),
        advance_millis: 10_000,
    });
    let clock: Arc<dyn MonotonicClock> = harness.clock.clone();
    let host: Arc<dyn PromotionHost> = harness.host.clone();
    let engine = PromotionEngine::with_runtime(
        harness.fixture.config("node-a"),
        ConfiguredRole::Master,
        harness.data_dir("node-a"),
        backend,
        host,
        clock,
        Arc::new(ManualTimers::new(Arc::clone(&harness.clock))),
    )
    .unwrap();
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Fenced);
    assert!(engine.snapshot().fenced);
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "lease_lost"
    );
    assert!(
        harness.event_index("publish:").is_none(),
        "no publish may happen after the deadline: {:?}",
        harness.events()
    );
    assert!(
        harness.host.admissions_denied.load(Ordering::SeqCst),
        "the gate must close on the slow ACK"
    );
}

#[tokio::test]
async fn slow_renewal_times_out_before_the_deadline_and_closes_the_gate() {
    let harness = Harness::new("slow_timeout", "node-a").await;
    let slow = Arc::new(AtomicBool::new(false));
    let backend = Arc::new(SlowSleepBackend {
        inner: Arc::new(harness.fixture.client("node-a")),
        sleep: Duration::from_millis(800),
        slow: Arc::clone(&slow),
    });
    let clock: Arc<dyn MonotonicClock> = harness.clock.clone();
    let host: Arc<dyn PromotionHost> = harness.host.clone();
    let engine = PromotionEngine::with_runtime(
        harness.fixture.config("node-a"),
        ConfiguredRole::Master,
        harness.data_dir("node-a"),
        backend,
        host,
        clock,
        Arc::new(ManualTimers::new(Arc::clone(&harness.clock))),
    )
    .unwrap();
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    let deadline = engine.self_fence_deadline_millis().expect("deadline");
    let now = harness.clock.boot_millis().unwrap();
    assert!(deadline > now);
    // Leave ~120 ms of self-fence budget; the renewal sleeps far longer.
    harness.clock.advance_boot(deadline - now - 120);
    slow.store(true, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let result = engine.renew_once().await;
    assert!(result.is_err(), "the slow renewal must fence");
    assert!(engine.snapshot().fenced);
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "lease_lost"
    );
    assert!(
        started.elapsed() < Duration::from_millis(700),
        "the bounded call must return before the witness timeout"
    );
    assert!(
        harness.host.admissions_denied.load(Ordering::SeqCst),
        "the API gate must close when the bounded renewal times out"
    );
}

#[tokio::test]
async fn boot_clock_unavailable_at_the_reconcile_window_fences() {
    let harness = Harness::new("reconcile_clock", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    // Quiesce completes normally, then the boot clock disappears exactly at
    // the reconcile window's start read. This isolates the reconcile fail-closed
    // path from the quiesce/renewal clock checks.
    let clock = Arc::clone(&harness.clock);
    engine.set_quiesce_complete_hook(Arc::new(move || {
        clock.set_boot_unavailable(true);
    }));
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Fenced);
    assert!(engine.snapshot().fenced);
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "clock_step"
    );
    assert!(
        harness.event_index("publish:").is_none(),
        "an unavailable boot clock must never skip the reconcile window and publish: {:?}",
        harness.events()
    );
}

#[tokio::test]
async fn expired_own_grant_reacquires_term_plus_one() {
    let harness = Harness::new("expired_own", "node-b").await;
    let baseline = hash(0xab);
    seed_witness_record(&harness.fixture, "node-a", 1, 7, &baseline).await;
    *harness.host.watermark.lock().unwrap() = Some(watermarked(1, 7, &baseline));
    let engine = harness.engine("node-b", ConfiguredRole::Slave);
    engine.boot().unwrap();
    // Seed an own-holder record through the witness (the engine's holder is a
    // fresh boot id) and let it expire.
    let client = harness.fixture.client("node-b");
    let record = client
        .acquire(&AcquireRequest {
            holder: engine.holder().to_string(),
            node_id: "node-b".to_string(),
            expected_term: Some(1),
            expected_revision: Some(client.lease().await.unwrap().unwrap().revision),
            term: 2,
            version: 7,
            bundle_hash: baseline.clone(),
            ttl_secs: 5,
        })
        .await
        .unwrap();
    assert_eq!(record.holder, engine.holder());
    harness.fixture.clock.advance(5_000);
    let outcome = engine.candidate_attempt(false).await;
    assert_eq!(outcome, PromotionOutcome::Master, "{:?}", harness.events());
    let record = harness
        .fixture
        .client("node-b")
        .lease()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.term, 3,
        "an expired own grant is re-acquired, not renewed"
    );
    assert_eq!(record.version, 8);
}

#[tokio::test]
async fn late_peer_reports_are_consumed_and_latched_by_the_engine() {
    let harness = Harness::new("late_consume", "node-a").await;
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    assert_eq!(engine.start_master().await, PromotionOutcome::Master);
    harness.host.late_reports.lock().unwrap().push(PeerReport {
        instance: "late-late".to_string(),
        have_term: 9,
        have_version: 99,
        have_bundle_hash: Some(hash(0xaa)),
    });
    assert_eq!(engine.process_late_peer_reports(), 1);
    assert_eq!(engine.latched_peers(), vec!["late-late".to_string()]);
    assert_eq!(
        harness.host.latched.lock().unwrap().as_slice(),
        ["late-late".to_string()]
    );
    assert_eq!(
        engine.process_late_peer_reports(),
        0,
        "the queue is drained"
    );
}

#[tokio::test]
async fn slow_first_publish_crossing_the_deadline_fences_and_publishes_nothing() {
    let harness = Harness::new("slow_first_publish", "node-a").await;
    // The host models a durable pre-publish write that consumes the whole
    // self-fence budget before the push.
    harness.host.set_slow_publish_millis(10_000);
    let engine = harness.engine("node-a", ConfiguredRole::Master);
    let outcome = engine.start_master().await;
    assert_eq!(outcome, PromotionOutcome::Fenced);
    assert!(engine.snapshot().fenced);
    assert_eq!(
        engine.fence_store().load().unwrap().unwrap().reason,
        "lease_lost"
    );
    assert!(
        harness.event_index("publish:").is_none(),
        "nothing may be pushed after the deadline: {:?}",
        harness.events()
    );
    assert!(
        harness
            .events()
            .iter()
            .any(|event| event == "publish_deadline_passed"),
        "the host must reject the push when the deadline handle is unsafe: {:?}",
        harness.events()
    );
    assert!(!harness.host.writable.load(Ordering::SeqCst));
}
