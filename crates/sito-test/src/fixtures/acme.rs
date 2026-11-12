//! A deterministic local ACME CA and challenge server for tests.
//!
//! The mock CA implements the RFC 8555 directory/account/order/authorization/
//! challenge/finalize/certificate flow over HTTPS. It intentionally does not
//! perform challenge validation, does not verify JWS signatures, and always
//! issues a certificate for the CSR it receives. That is enough to exercise
//! sito's renewal scheduling, challenge selection, persistence, and TLS
//! manager reloads; it is not a conformance test of the ACME client itself.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{
    CertificateDer, CertificateSigningRequestDer, PrivateKeyDer, PrivatePkcs8KeyDer,
};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use crate::fixtures::net::{PortClaim, bind_claimed_tcp};

/// Default domain the mock CA issues certificates for.
pub const DEFAULT_DOMAIN: &str = "acme.example.test";

const NONCE_HEADER: &str = "replay-nonce";

struct MockOrder {
    domain: String,
    challenge_ready: bool,
    certificate_pem: Option<String>,
}

struct MockAcmeState {
    base: String,
    issuer: Issuer<'static, KeyPair>,
    next_account: u64,
    next_order: u64,
    orders: HashMap<u64, MockOrder>,
    selected_challenges: Vec<String>,
}

/// A running mock ACME CA.
pub struct MockAcme {
    addr: SocketAddr,
    directory_url: String,
    root_path: PathBuf,
    state: Arc<Mutex<MockAcmeState>>,
    handle: tokio::task::JoinHandle<()>,
    _claim: PortClaim,
}

impl MockAcme {
    /// Starts a mock CA on an ephemeral loopback TLS port.
    pub async fn start() -> Self {
        install_crypto_provider();
        let ca_key = KeyPair::generate().expect("CA key");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "sito mock ACME CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA cert");

        let server_key = KeyPair::generate().expect("server key");
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])
                .expect("server params");
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        let server_cert = server_params
            .signed_by(&server_key, &Issuer::from_params(&ca_params, &ca_key))
            .expect("server cert");

        let root_path = std::env::temp_dir().join(format!(
            "sito_mock_acme_root_{}_{}.pem",
            std::process::id(),
            random_suffix()
        ));
        std::fs::write(&root_path, ca_cert.pem()).expect("write mock CA root");

        let (listener, claim) = bind_claimed_tcp().await.expect("bind mock ACME");
        let addr = listener.local_addr().expect("mock ACME addr");
        let base = format!("https://localhost:{}", addr.port());

        let tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .expect("mock ACME TLS config");

        let state = Arc::new(Mutex::new(MockAcmeState {
            base: base.clone(),
            issuer: Issuer::new(ca_params, ca_key),
            next_account: 0,
            next_order: 0,
            orders: HashMap::new(),
            selected_challenges: Vec::new(),
        }));

        let app = Router::new()
            .route("/directory", get(directory))
            .route("/new-nonce", head(new_nonce))
            .route("/new-account", post(new_account))
            .route("/new-order", post(new_order))
            .route("/authz/{id}", post(authorization))
            .route("/challenge/{id}/{kind}", post(challenge))
            .route("/order/{id}", post(order))
            .route("/finalize/{id}", post(finalize))
            .route("/cert/{id}", post(certificate))
            .with_state(Arc::clone(&state));

        let acceptor = TlsAcceptor::from(Arc::new(tls_config));
        let tls_listener = TlsListener {
            inner: listener,
            acceptor,
        };
        let handle = tokio::spawn(async move {
            let _ = axum::serve(tls_listener, app).await;
        });

        Self {
            addr,
            directory_url: format!("{base}/directory"),
            root_path,
            state,
            handle,
            _claim: claim,
        }
    }

    /// The bound TLS socket address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The RFC 8555 directory URL.
    #[must_use]
    pub fn directory_url(&self) -> &str {
        &self.directory_url
    }

    /// Path to the CA root certificate PEM (for client trust).
    #[must_use]
    pub fn root_certificate_path(&self) -> &Path {
        &self.root_path
    }

    /// Challenge types the client selected, in order.
    #[must_use]
    pub fn selected_challenges(&self) -> Vec<String> {
        self.state
            .lock()
            .expect("mock ACME state")
            .selected_challenges
            .clone()
    }

    /// Number of orders created so far.
    #[must_use]
    pub fn order_count(&self) -> usize {
        self.state.lock().expect("mock ACME state").orders.len()
    }
}

impl Drop for MockAcme {
    fn drop(&mut self) {
        self.handle.abort();
        match std::fs::remove_file(&self.root_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::debug!(
                    path = %self.root_path.display(),
                    %error,
                    "Could not remove the mock ACME root certificate"
                );
            }
        }
    }
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn random_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[allow(clippy::needless_pass_by_value)] // json! bodies are owned temporaries
fn nonce_response(status: StatusCode, body: Value, location: Option<String>) -> Response {
    let mut response = (
        status,
        [
            (header::CONTENT_TYPE, "application/json"),
            (HeaderName::from_static(NONCE_HEADER), "mock-nonce"),
        ],
        body.to_string(),
    )
        .into_response();
    if let Some(location) = location {
        response.headers_mut().insert(
            header::LOCATION,
            location.parse().expect("valid location header"),
        );
    }
    response
}

fn jws_payload(body: &Bytes) -> Value {
    let Ok(envelope) = serde_json::from_slice::<Value>(body) else {
        return Value::Null;
    };
    let payload = envelope
        .get("payload")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if payload.is_empty() {
        return Value::Null;
    }
    BASE64_URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or(Value::Null)
}

fn order_body(state: &MockAcmeState, id: u64, status: &str) -> Value {
    let valid = status == "valid";
    json!({
        "status": status,
        "authorizations": [format!("{}/authz/{id}", state.base)],
        "finalize": format!("{}/finalize/{id}", state.base),
        "certificate": valid.then(|| format!("{}/cert/{id}", state.base)),
        "error": null,
    })
}

fn order_status(state: &MockAcmeState, id: u64) -> &'static str {
    match state.orders.get(&id) {
        Some(order) if order.certificate_pem.is_some() => "valid",
        Some(order) if order.challenge_ready => "ready",
        Some(_) => "pending",
        None => "invalid",
    }
}

async fn directory(State(state): State<Arc<Mutex<MockAcmeState>>>) -> Response {
    let state = state.lock().expect("mock state");
    nonce_response(
        StatusCode::OK,
        json!({
            "newNonce": format!("{}/new-nonce", state.base),
            "newAccount": format!("{}/new-account", state.base),
            "newOrder": format!("{}/new-order", state.base),
            "revokeCert": format!("{}/revoke-cert", state.base),
            "keyChange": format!("{}/key-change", state.base),
        }),
        None,
    )
}

async fn new_nonce() -> Response {
    (
        StatusCode::OK,
        [(HeaderName::from_static(NONCE_HEADER), "mock-nonce")],
        "",
    )
        .into_response()
}

async fn new_account(State(state): State<Arc<Mutex<MockAcmeState>>>) -> Response {
    let mut state = state.lock().expect("mock state");
    state.next_account += 1;
    let id = state.next_account;
    nonce_response(
        StatusCode::CREATED,
        json!({"status": "valid"}),
        Some(format!("{}/account/{id}", state.base)),
    )
}

async fn new_order(State(state): State<Arc<Mutex<MockAcmeState>>>, body: Bytes) -> Response {
    let mut state = state.lock().expect("mock state");
    state.next_order += 1;
    let id = state.next_order;
    let payload = jws_payload(&body);
    let domain = payload
        .get("identifiers")
        .and_then(Value::as_array)
        .and_then(|identifiers| identifiers.first())
        .and_then(|identifier| identifier.get("value"))
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_DOMAIN)
        .to_string();
    state.orders.insert(
        id,
        MockOrder {
            domain,
            challenge_ready: false,
            certificate_pem: None,
        },
    );
    nonce_response(
        StatusCode::CREATED,
        order_body(&state, id, "pending"),
        Some(format!("{}/order/{id}", state.base)),
    )
}

async fn authorization(
    State(state): State<Arc<Mutex<MockAcmeState>>>,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    let state = state.lock().expect("mock state");
    let Some(order) = state.orders.get(&id) else {
        return nonce_response(StatusCode::NOT_FOUND, json!({"detail": "no order"}), None);
    };
    let status = if order.challenge_ready {
        "valid"
    } else {
        "pending"
    };
    nonce_response(
        StatusCode::OK,
        json!({
            "identifier": {"type": "dns", "value": order.domain},
            "status": status,
            "wildcard": false,
            "challenges": [
                {
                    "type": "tls-alpn-01",
                    "url": format!("{}/challenge/{id}/tls-alpn-01", state.base),
                    "token": format!("tls-token-{id}"),
                    "status": status,
                },
                {
                    "type": "http-01",
                    "url": format!("{}/challenge/{id}/http-01", state.base),
                    "token": format!("http-token-{id}"),
                    "status": status,
                }
            ],
        }),
        None,
    )
}

async fn challenge(
    State(state): State<Arc<Mutex<MockAcmeState>>>,
    AxumPath((id, kind)): AxumPath<(u64, String)>,
) -> Response {
    let mut state = state.lock().expect("mock state");
    state.selected_challenges.push(kind.clone());
    if let Some(order) = state.orders.get_mut(&id) {
        order.challenge_ready = true;
        nonce_response(
            StatusCode::OK,
            json!({
                "type": kind,
                "url": format!("{}/challenge/{id}/{kind}", state.base),
                "token": format!("token-{id}"),
                "status": "valid",
            }),
            None,
        )
    } else {
        nonce_response(StatusCode::NOT_FOUND, json!({"detail": "no order"}), None)
    }
}

async fn order(
    State(state): State<Arc<Mutex<MockAcmeState>>>,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    let state = state.lock().expect("mock state");
    let status = order_status(&state, id);
    nonce_response(StatusCode::OK, order_body(&state, id, status), None)
}

async fn finalize(
    State(state): State<Arc<Mutex<MockAcmeState>>>,
    AxumPath(id): AxumPath<u64>,
    body: Bytes,
) -> Response {
    let payload = jws_payload(&body);
    let Some(csr) = payload.get("csr").and_then(Value::as_str) else {
        return nonce_response(
            StatusCode::BAD_REQUEST,
            json!({"detail": "missing csr"}),
            None,
        );
    };

    let mut state = state.lock().expect("mock state");
    let issued = (|| -> Result<String, String> {
        let der = BASE64_URL_SAFE_NO_PAD
            .decode(csr)
            .map_err(|e| format!("csr base64: {e}"))?;
        let csr_der = CertificateSigningRequestDer::from(der);
        let mut params = CertificateSigningRequestParams::from_der(&csr_der)
            .map_err(|e| format!("csr parse: {e}"))?;
        // Real CAs issue ~90-day certificates; this also makes the short-lived
        // bootstrap placeholder distinguishable in the assertions.
        let now = time::OffsetDateTime::now_utc();
        params.params.not_before = now;
        params.params.not_after = now + time::Duration::days(90);
        let cert = params
            .signed_by(&state.issuer)
            .map_err(|e| format!("csr sign: {e}"))?;
        Ok(cert.pem())
    })();

    match issued {
        Ok(pem) => {
            if let Some(order) = state.orders.get_mut(&id) {
                order.certificate_pem = Some(pem);
            }
            nonce_response(StatusCode::OK, order_body(&state, id, "valid"), None)
        }
        Err(e) => nonce_response(StatusCode::BAD_REQUEST, json!({"detail": e}), None),
    }
}

async fn certificate(
    State(state): State<Arc<Mutex<MockAcmeState>>>,
    AxumPath(id): AxumPath<u64>,
) -> Response {
    let state = state.lock().expect("mock state");
    match state
        .orders
        .get(&id)
        .and_then(|order| order.certificate_pem.clone())
    {
        Some(pem) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/pem-certificate-chain"),
                (HeaderName::from_static(NONCE_HEADER), "mock-nonce"),
            ],
            pem,
        )
            .into_response(),
        None => nonce_response(StatusCode::NOT_FOUND, json!({"detail": "no cert"}), None),
    }
}

/// A TCP listener that performs the server side of TLS before handing the
/// decrypted stream to axum.
struct TlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            if let Ok((stream, addr)) = self.inner.accept().await
                && let Ok(tls) = self.acceptor.accept(stream).await
            {
                return (tls, addr);
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

// ---------------------------------------------------------------------------
// HTTP-01 challenge server
// ---------------------------------------------------------------------------

/// A tiny HTTP-01 challenge responder.
///
/// Tests register `token -> key_authorization`, point the ACME client's
/// challenge map at this server, and assert that the CA-visible endpoint
/// answers. It serves only `/.well-known/acme-challenge/{token}`.
#[derive(Debug)]
pub struct MockHttp01Server {
    addr: SocketAddr,
    tokens: Arc<dashmap::DashMap<String, String>>,
    hits: Arc<AtomicUsize>,
    handle: tokio::task::JoinHandle<()>,
    _claim: PortClaim,
}

impl MockHttp01Server {
    /// Starts the challenge server on an ephemeral loopback port.
    pub async fn start() -> std::io::Result<Self> {
        let (listener, claim) = bind_claimed_tcp().await?;
        let addr = listener.local_addr()?;
        let tokens: Arc<dashmap::DashMap<String, String>> = Arc::new(dashmap::DashMap::new());
        let hits = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/.well-known/acme-challenge/{token}", get(http01_challenge))
            .with_state(ChallengeState {
                tokens: Arc::clone(&tokens),
                hits: Arc::clone(&hits),
            });
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            addr,
            tokens,
            hits,
            handle,
            _claim: claim,
        })
    }

    /// The bound socket address.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Registers a token/key-authorization pair.
    pub fn add_token(&self, token: &str, key_authorization: &str) {
        self.tokens
            .insert(token.to_string(), key_authorization.to_string());
    }

    /// Full URL for a token.
    #[must_use]
    pub fn url(&self, token: &str) -> String {
        format!("http://{}/.well-known/acme-challenge/{token}", self.addr)
    }

    /// Number of challenge requests served.
    #[must_use]
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

#[derive(Clone)]
struct ChallengeState {
    tokens: Arc<dashmap::DashMap<String, String>>,
    hits: Arc<AtomicUsize>,
}

async fn http01_challenge(
    State(state): State<ChallengeState>,
    AxumPath(token): AxumPath<String>,
    Query(_query): Query<HashMap<String, String>>,
) -> Response {
    state.hits.fetch_add(1, Ordering::SeqCst);
    match state.tokens.get(&token) {
        Some(value) => (StatusCode::OK, value.clone()).into_response(),
        None => (StatusCode::NOT_FOUND, "unknown challenge").into_response(),
    }
}

impl Drop for MockHttp01Server {
    fn drop(&mut self) {
        self.handle.abort();
    }
}
