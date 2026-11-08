//! WP-0.2 acceptance: ACME bootstrap, issuance, renewal and all-transport
//! reload against a deterministic local ACME CA.
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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderName, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post};
use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa, Issuer,
    KeyPair, KeyUsagePurpose,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{
    CertificateDer, CertificateSigningRequestDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName,
    UnixTime,
};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::{Value, json};
use sito_transport::{
    AcmeChallengeOptions, AcmeServiceConfig, TlsAcceptorManager, TlsManagerSet,
    certificate_needs_renewal, days_until_expiration, generate_self_signed_cert,
    load_server_config, load_server_config_with_challenges,
    obtain_or_renew_certificate_for_transports, record_bootstrap_cert,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const DOMAIN: &str = "acme.example.test";

// ---------------------------------------------------------------------------
// Mock ACME CA
// ---------------------------------------------------------------------------

const NONCE_HEADER: &str = "replay-nonce";

struct MockOrder {
    domain: String,
    challenge_ready: bool,
    certificate_pem: Option<String>,
}

struct MockState {
    base: String,
    issuer: Issuer<'static, KeyPair>,
    next_account: u64,
    next_order: u64,
    orders: HashMap<u64, MockOrder>,
    selected_challenges: Vec<String>,
}

struct MockAcme {
    directory_url: String,
    root_path: PathBuf,
    state: Arc<Mutex<MockState>>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockAcme {
    fn drop(&mut self) {
        self.handle.abort();
    }
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

fn order_body(state: &MockState, id: u64, status: &str) -> Value {
    let valid = status == "valid";
    json!({
        "status": status,
        "authorizations": [format!("{}/authz/{id}", state.base)],
        "finalize": format!("{}/finalize/{id}", state.base),
        "certificate": valid.then(|| format!("{}/cert/{id}", state.base)),
        "error": null,
    })
}

fn order_status(state: &MockState, id: u64) -> &'static str {
    match state.orders.get(&id) {
        Some(order) if order.certificate_pem.is_some() => "valid",
        Some(order) if order.challenge_ready => "ready",
        Some(_) => "pending",
        None => "invalid",
    }
}

async fn directory(State(state): State<Arc<Mutex<MockState>>>) -> Response {
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

async fn new_account(State(state): State<Arc<Mutex<MockState>>>) -> Response {
    let mut state = state.lock().expect("mock state");
    state.next_account += 1;
    let id = state.next_account;
    nonce_response(
        StatusCode::CREATED,
        json!({"status": "valid"}),
        Some(format!("{}/account/{id}", state.base)),
    )
}

async fn new_order(State(state): State<Arc<Mutex<MockState>>>, body: Bytes) -> Response {
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
        .unwrap_or(DOMAIN)
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
    State(state): State<Arc<Mutex<MockState>>>,
    Path(id): Path<u64>,
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
    State(state): State<Arc<Mutex<MockState>>>,
    Path((id, kind)): Path<(u64, String)>,
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

async fn order(State(state): State<Arc<Mutex<MockState>>>, Path(id): Path<u64>) -> Response {
    let state = state.lock().expect("mock state");
    let status = order_status(&state, id);
    nonce_response(StatusCode::OK, order_body(&state, id, status), None)
}

async fn finalize(
    State(state): State<Arc<Mutex<MockState>>>,
    Path(id): Path<u64>,
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

async fn certificate(State(state): State<Arc<Mutex<MockState>>>, Path(id): Path<u64>) -> Response {
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

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

async fn start_mock_acme() -> MockAcme {
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
        rand_suffix()
    ));
    std::fs::write(&root_path, ca_cert.pem()).expect("write mock CA root");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock ACME");
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

    let state = Arc::new(Mutex::new(MockState {
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

    MockAcme {
        directory_url: format!("{base}/directory"),
        root_path,
        state,
        handle,
    }
}

fn rand_suffix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sito_m11_acme_{name}_{}_{}",
        std::process::id(),
        rand_suffix()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create test dir");
    dir
}

fn build_manager(
    cert: &std::path::Path,
    key: &std::path::Path,
    alpn: &[u8],
    challenge_keys: Option<Arc<dashmap::DashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
) -> TlsAcceptorManager {
    match challenge_keys {
        Some(keys) => TlsAcceptorManager::with_challenge_keys(
            load_server_config_with_challenges(
                cert,
                key,
                &[],
                vec![alpn.to_vec()],
                Arc::clone(&keys),
            )
            .expect("TLS config with challenges"),
            keys,
        ),
        None => TlsAcceptorManager::new(
            load_server_config(cert, key, &[], vec![alpn.to_vec()]).expect("TLS config"),
        ),
    }
}

fn first_cert_der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::pem_slice_iter(pem)
        .next()
        .expect("certificate in PEM")
        .expect("valid certificate")
        .as_ref()
        .to_vec()
}

#[derive(Debug)]
struct CapturingVerifier(Arc<Mutex<Option<Vec<u8>>>>);

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.0.lock().expect("capture lock") = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Performs a TLS handshake against a manager and returns the leaf certificate
/// it actually served.
async fn served_cert(mgr: &TlsAcceptorManager) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind handshake listener");
    let addr = listener.local_addr().expect("handshake addr");
    let acceptor = mgr.acceptor();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept handshake");
        let _ = acceptor.accept(stream).await;
    });

    let captured = Arc::new(Mutex::new(None));
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("safe protocol versions")
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(CapturingVerifier(Arc::clone(&captured))))
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = TcpStream::connect(addr).await.expect("connect handshake");
    let domain = ServerName::try_from("localhost").expect("server name");
    let _ = connector.connect(domain, tcp).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    captured
        .lock()
        .expect("capture lock")
        .clone()
        .expect("server presented a certificate")
}

fn write_bootstrap(storage: &std::path::Path) -> (String, String) {
    let (cert_pem, key_pem) =
        generate_self_signed_cert(&[DOMAIN.to_string()]).expect("bootstrap cert");
    std::fs::write(storage.join("cert.pem"), &cert_pem).expect("write bootstrap cert");
    sito_transport::write_secret_file(&storage.join("key.pem"), key_pem.as_bytes())
        .expect("write bootstrap key");
    record_bootstrap_cert(storage).expect("record bootstrap marker");
    (cert_pem, key_pem)
}

fn config_for(storage: &std::path::Path, mock: &MockAcme) -> AcmeServiceConfig {
    AcmeServiceConfig::new(
        "admin@example.test".to_string(),
        vec![DOMAIN.to_string()],
        storage.to_path_buf(),
    )
    .with_directory_url(mock.directory_url.clone())
    .with_root_certificate(mock.root_path.clone())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Acceptance: a fresh ACME-only install (only a bootstrap certificate on
/// disk) orders a real certificate, all four transports pick it up, renewal
/// issues a new certificate, and the account file survives corruption and a
/// directory change.
#[tokio::test(flavor = "multi_thread")]
async fn test_acme_bootstrap_issuance_all_transports_and_renewal() {
    let mock = start_mock_acme().await;
    let storage = test_dir("all_transports");
    write_bootstrap(&storage);

    let config = config_for(&storage, &mock);
    assert!(
        certificate_needs_renewal(&config),
        "bootstrap storage must request issuance"
    );
    assert!(config.is_bootstrap_cert());

    let challenge_keys = Arc::new(dashmap::DashMap::new());
    let dot = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"dot",
        None,
    );
    let doh = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"h2",
        Some(Arc::clone(&challenge_keys)),
    );
    let doq = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"doq",
        None,
    );
    let doh3 = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"h3",
        None,
    );
    let managers = TlsManagerSet {
        dot: Some(dot.clone()),
        doh: Some(doh.clone()),
        doq: Some(doq.clone()),
        doh3: Some(doh3.clone()),
    };
    let http01 = Arc::new(dashmap::DashMap::new());
    let options = AcmeChallengeOptions {
        tls_alpn_available: true,
        http01_available: true,
    };

    let issued =
        obtain_or_renew_certificate_for_transports(&config, &managers, Some(&http01), options)
            .await
            .expect("ACME issuance against the mock CA");
    assert!(issued, "a bootstrap certificate must trigger issuance");

    let issued_pem = std::fs::read(storage.join("cert.pem")).expect("issued cert");
    let issued_der = first_cert_der(&issued_pem);
    assert!(
        !config.is_bootstrap_cert(),
        "after issuance the stored certificate must no longer be a bootstrap placeholder"
    );
    assert!(
        days_until_expiration(&issued_pem).expect("issued validity") > 7,
        "the CA-issued certificate must not look like the short-lived bootstrap cert"
    );
    assert!(
        !storage.join("bootstrap").exists(),
        "the bootstrap marker must be removed after issuance"
    );
    assert!(
        storage.join("pair.sha256").exists(),
        "a completed rotation must record the certificate/key pair"
    );
    assert!(
        !certificate_needs_renewal(&config),
        "a freshly issued 90-day certificate must not trigger a renewal loop"
    );

    {
        let state = mock.state.lock().expect("mock state");
        assert_eq!(
            state.selected_challenges.last().map(String::as_str),
            Some("tls-alpn-01"),
            "a 443-capable deployment must use TLS-ALPN-01"
        );
    }

    for (name, manager) in [("dot", &dot), ("doh", &doh), ("doq", &doq), ("doh3", &doh3)] {
        assert_eq!(
            served_cert(manager).await,
            issued_der,
            "{name} must serve the ACME certificate, not the bootstrap pair"
        );
    }

    // Renewal: force the threshold above the issued lifetime and ensure a new
    // certificate is ordered, persisted, and reloaded everywhere.
    let renew_config = config.clone().with_renew_before_days(180);
    assert!(certificate_needs_renewal(&renew_config));
    assert!(
        obtain_or_renew_certificate_for_transports(
            &renew_config,
            &managers,
            Some(&http01),
            options,
        )
        .await
        .expect("ACME renewal against the mock CA")
    );
    let renewed_pem = std::fs::read(storage.join("cert.pem")).expect("renewed cert");
    let renewed_der = first_cert_der(&renewed_pem);
    assert_ne!(
        issued_der, renewed_der,
        "renewal must install a freshly issued certificate"
    );
    for manager in [&dot, &doh, &doq, &doh3] {
        assert_eq!(
            served_cert(manager).await,
            renewed_der,
            "all transports must reload the renewed certificate"
        );
    }

    // Account credentials are written atomically with owner-only permissions.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(storage.join("account.json"))
            .expect("account metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "account credentials must be owner-only");
    }
    assert!(
        !storage.join("account.tmp").exists(),
        "atomic account writes must not leave a temp file behind"
    );

    // Corrupt credentials: back up and re-register instead of blocking renewal.
    std::fs::write(storage.join("account.json"), b"{not json").expect("corrupt account");
    obtain_or_renew_certificate_for_transports(&renew_config, &managers, Some(&http01), options)
        .await
        .expect("issuance must recover from corrupt account credentials");
    assert!(
        storage.join("account.json.corrupt").exists(),
        "corrupt account credentials must be backed up"
    );
    let recovered: Value = serde_json::from_slice(
        &std::fs::read(storage.join("account.json")).expect("recovered account"),
    )
    .expect("recovered account must be valid JSON");
    assert_eq!(
        recovered.get("directory").and_then(Value::as_str),
        Some(mock.directory_url.as_str())
    );

    // Directory change: the configured directory wins over the stored one.
    let mut changed = recovered;
    changed["directory"] = Value::String("https://old-ca.invalid/directory".to_string());
    std::fs::write(
        storage.join("account.json"),
        serde_json::to_vec(&changed).expect("serialize changed account"),
    )
    .expect("write changed account");
    obtain_or_renew_certificate_for_transports(&renew_config, &managers, Some(&http01), options)
        .await
        .expect("issuance must recover from a directory change");
    assert!(
        storage.join("account.json.bak").exists(),
        "credentials from another directory must be backed up"
    );
    let re_registered: Value = serde_json::from_slice(
        &std::fs::read(storage.join("account.json")).expect("re-registered account"),
    )
    .expect("re-registered account must be valid JSON");
    assert_eq!(
        re_registered.get("directory").and_then(Value::as_str),
        Some(mock.directory_url.as_str())
    );

    let _ = std::fs::remove_dir_all(&storage);
}

/// Regression (P1-12): without a TCP 443 listener the client must select
/// HTTP-01 even when the CA also offers TLS-ALPN-01.
#[tokio::test(flavor = "multi_thread")]
async fn test_acme_without_443_listener_falls_back_to_http01() {
    let mock = start_mock_acme().await;
    let storage = test_dir("http01_fallback");
    write_bootstrap(&storage);

    let config = config_for(&storage, &mock);
    // A DoH TLS manager exists, but it is not bound to TCP 443, so TLS-ALPN-01
    // is not answerable; the previous behaviour selected it anyway.
    let challenge_keys = Arc::new(dashmap::DashMap::new());
    let doh = build_manager(
        &storage.join("cert.pem"),
        &storage.join("key.pem"),
        b"h2",
        Some(challenge_keys),
    );
    let managers = TlsManagerSet {
        doh: Some(doh),
        ..TlsManagerSet::default()
    };
    let http01 = Arc::new(dashmap::DashMap::new());
    let options = AcmeChallengeOptions {
        tls_alpn_available: false,
        http01_available: true,
    };

    let issued =
        obtain_or_renew_certificate_for_transports(&config, &managers, Some(&http01), options)
            .await
            .expect("HTTP-01 issuance against the mock CA");
    assert!(issued);

    let state = mock.state.lock().expect("mock state");
    assert_eq!(
        state.selected_challenges.last().map(String::as_str),
        Some("http-01"),
        "a deployment without a bound TCP 443 listener must fall back to HTTP-01"
    );

    let _ = std::fs::remove_dir_all(&storage);
}

/// Regression (P0-1): a fresh bootstrap certificate with no marker, no short
/// validity, but self-signed by an older version is still recognised as a
/// placeholder and renewed.
#[test]
fn test_legacy_self_signed_bootstrap_requires_renewal() {
    let storage = test_dir("legacy_bootstrap");
    let (cert_pem, key_pem) =
        generate_self_signed_cert(&[DOMAIN.to_string()]).expect("bootstrap cert");
    std::fs::write(storage.join("cert.pem"), cert_pem).expect("write cert");
    sito_transport::write_secret_file(&storage.join("key.pem"), key_pem.as_bytes())
        .expect("write key");
    // No bootstrap marker and no pair marker: exactly what 1.9.3 wrote.
    let config = AcmeServiceConfig::new(
        "admin@example.test".to_string(),
        vec![DOMAIN.to_string()],
        storage.clone(),
    );
    assert!(
        certificate_needs_renewal(&config),
        "a self-signed bootstrap certificate must never suppress ACME issuance"
    );
    let _ = std::fs::remove_dir_all(&storage);
}
