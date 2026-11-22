//! TLS HTTP front end for the witness lease server.

use std::future::Future as _;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header;
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use super::clock::Clock;
use super::record::{AcquireRequest, LEASE_PROTOCOL_VERSION, LeaseInfo, LeaseRecord, RenewRequest};
use super::store::{LeaseOpError, LeaseStore};
use super::{MAX_REQUEST_BODY, WitnessError, validate_cluster_id};

/// How long a single TLS handshake may take.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Read/write inactivity timeout for one HTTP connection.
const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// Token file mode required by the ADR.
const TOKEN_FILE_MODE: u32 = 0o600;

/// Configuration for `sito ha lease-server`.
#[derive(Debug, Clone)]
pub struct WitnessConfig {
    /// TCP listen address (default `0.0.0.0:8954`).
    pub listen: SocketAddr,
    /// Cluster identifier that every request must match.
    pub cluster_id: String,
    /// PEM server certificate (server-auth, SAN must match client `server_name`).
    pub cert: PathBuf,
    /// PEM private key for `cert`, mode 0600.
    pub key: PathBuf,
    /// File containing the shared bearer token, mode 0600.
    pub token_file: PathBuf,
    /// Durable state directory, created mode 0700.
    pub state_dir: PathBuf,
}

impl WitnessConfig {
    /// Validates identifiers, file readability and token-file permissions.
    pub fn validate(&self) -> Result<(), WitnessError> {
        validate_cluster_id(&self.cluster_id)?;
        for (label, path) in [("cert", &self.cert), ("key", &self.key)] {
            let metadata = std::fs::metadata(path).map_err(|error| {
                WitnessError::new(
                    "tls_error",
                    format!("cannot read {label} file '{}': {error}", path.display()),
                )
            })?;
            if !metadata.is_file() {
                return Err(WitnessError::new(
                    "tls_error",
                    format!("{label} path '{}' is not a file", path.display()),
                ));
            }
        }
        validate_token_file(&self.token_file)?;
        Ok(())
    }
}

/// Validates that `token_file` is a non-empty mode-0600 file.
pub fn validate_token_file(path: &Path) -> Result<(), WitnessError> {
    let _ = read_token_file(path)?;
    Ok(())
}

/// Reads and validates the shared bearer token file (mode 0600).
pub fn read_token_file(path: &Path) -> Result<String, WitnessError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let metadata = std::fs::metadata(path).map_err(|error| {
            WitnessError::new(
                "token_file_error",
                format!("cannot read token file '{}': {error}", path.display()),
            )
        })?;
        if !metadata.is_file() {
            return Err(WitnessError::new(
                "token_file_error",
                format!("token file '{}' is not a file", path.display()),
            ));
        }
        let mode = metadata.permissions().mode() & 0o777;
        if mode != TOKEN_FILE_MODE {
            return Err(WitnessError::new(
                "token_file_permissions",
                format!(
                    "token file '{}' must be mode 0600, found {mode:04o}",
                    path.display()
                ),
            ));
        }
    }
    let raw = std::fs::read(path).map_err(|error| {
        WitnessError::new(
            "token_file_error",
            format!("cannot read token file '{}': {error}", path.display()),
        )
    })?;
    if raw.len() > 4096 {
        return Err(WitnessError::new(
            "token_file_error",
            "token file is larger than 4096 bytes",
        ));
    }
    let text = String::from_utf8(raw)
        .map_err(|_| WitnessError::new("token_file_error", "token file is not valid UTF-8"))?;
    let token = text.trim_end_matches(['\r', '\n']);
    if token.is_empty() {
        return Err(WitnessError::new("token_file_error", "token file is empty"));
    }
    if token.contains('\r') || token.contains('\n') {
        return Err(WitnessError::new(
            "token_file_error",
            "token file contains an interior newline",
        ));
    }
    Ok(token.to_string())
}

#[derive(Clone)]
struct AppState {
    store: Arc<LeaseStore>,
    cluster_id: String,
    token_hash: [u8; 32],
}

/// A running witness server.
pub struct WitnessHandle {
    local_addr: SocketAddr,
    store: Arc<LeaseStore>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    join: Option<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for WitnessHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WitnessHandle")
            .field("local_addr", &self.local_addr)
            .field("state_dir", &self.store.state_dir())
            .finish_non_exhaustive()
    }
}

impl WitnessHandle {
    /// The bound listen address (useful with port 0 in tests).
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The state directory held by this process.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        self.store.state_dir()
    }

    /// The configured cluster identifier.
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        self.store.cluster_id()
    }

    /// Stops accepting connections and waits for the server task to finish.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for WitnessHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

/// Starts a witness server with the supplied clock.
///
/// Production callers pass [`super::clock::SystemClock`]; tests pass a
/// [`super::clock::ManualClock`] to exercise expiry without weakening the
/// server-side rules.
pub async fn start_witness_server(
    config: WitnessConfig,
    clock: Arc<dyn Clock>,
) -> Result<WitnessHandle, WitnessError> {
    config.validate()?;
    let token = read_token_file(&config.token_file)?;
    let token_hash = *blake3::hash(token.as_bytes()).as_bytes();
    let store = LeaseStore::open(&config.state_dir, &config.cluster_id, clock)?;
    let tls = build_tls_config(&config)?;
    let listener = TcpListener::bind(config.listen).await.map_err(|error| {
        WitnessError::new(
            "bind_error",
            format!("cannot bind witness listener on {}: {error}", config.listen),
        )
    })?;
    let local_addr = listener.local_addr().map_err(WitnessError::from)?;

    let state = Arc::new(AppState {
        store: Arc::clone(&store),
        cluster_id: config.cluster_id.clone(),
        token_hash,
    });
    let app = router(state);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let tls_listener = WitnessTlsListener {
        inner: listener,
        acceptor: TlsAcceptor::from(tls),
    };

    let join = tokio::spawn(async move {
        let mut shutdown_rx = shutdown_rx;
        let result = axum::serve(tls_listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.wait_for(|value| *value).await;
            })
            .await;
        if let Err(error) = result {
            tracing::error!(%error, "witness server stopped with an error");
        }
    });

    tracing::info!(
        listen = %local_addr,
        state_dir = %config.state_dir.display(),
        cluster_id = %config.cluster_id,
        "witness lease server started"
    );

    Ok(WitnessHandle {
        local_addr,
        store,
        shutdown_tx,
        join: Some(join),
    })
}

fn build_tls_config(config: &WitnessConfig) -> Result<Arc<rustls::ServerConfig>, WitnessError> {
    let certs = crate::transport::load_certs_pem(&config.cert)
        .map_err(|error| WitnessError::new("tls_error", error.to_string()))?;
    let key = crate::transport::load_key_pem(&config.key)
        .map_err(|error| WitnessError::new("tls_error", error.to_string()))?;
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|error| WitnessError::new("tls_error", error.to_string()))?
    // The witness authenticates clients with a bearer token, not a client
    // certificate. TLS still protects the token and the record in transit.
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|error| WitnessError::new("tls_error", error.to_string()))?;
    Ok(Arc::new(tls))
}

fn router(state: Arc<AppState>) -> Router {
    let v1 = Router::new()
        .route("/v1/info", get(get_info))
        .route("/v1/lease", get(get_lease))
        .route("/v1/lease/acquire", post(acquire))
        .route("/v1/lease/renew", post(renew))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            authenticate,
        ));
    Router::new()
        .route("/healthz", get(healthz))
        .merge(v1)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY))
        .with_state(state)
}

async fn healthz(State(state): State<Arc<AppState>>) -> StatusCode {
    if state.store.is_writable() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn get_info(State(state): State<Arc<AppState>>) -> Json<LeaseInfo> {
    Json(LeaseInfo {
        lease_protocol_version: LEASE_PROTOCOL_VERSION,
        cluster_id: state.cluster_id.clone(),
        now_unix_ms: state.store.now_unix_ms(),
    })
}

async fn get_lease(State(state): State<Arc<AppState>>) -> Response {
    match state.store.snapshot() {
        Some(record) => (StatusCode::OK, Json(record)).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn acquire(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let request: AcquireRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                None,
                Some(error.to_string()),
                None,
            );
        }
    };
    match state.store.acquire(&request) {
        Ok(record) => (StatusCode::OK, Json(record)).into_response(),
        Err(error) => operation_error(error),
    }
}

async fn renew(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    let request: RenewRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "invalid_json",
                None,
                Some(error.to_string()),
                None,
            );
        }
    };
    match state.store.renew(&request) {
        Ok(record) => (StatusCode::OK, Json(record)).into_response(),
        Err(error) => operation_error(error),
    }
}

fn operation_error(error: LeaseOpError) -> Response {
    match error {
        LeaseOpError::Invalid { reason, detail } => {
            error_response(StatusCode::BAD_REQUEST, reason, None, Some(detail), None)
        }
        LeaseOpError::Conflict {
            reason,
            detail,
            current,
        } => error_response(
            StatusCode::CONFLICT,
            "cas_mismatch",
            Some(reason),
            Some(detail),
            current.map(|record| *record),
        ),
        LeaseOpError::Storage(detail) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            None,
            Some(detail),
            None,
        ),
    }
}

fn error_response(
    status: StatusCode,
    error: &str,
    reason: Option<&str>,
    detail: Option<String>,
    current: Option<LeaseRecord>,
) -> Response {
    let mut body = serde_json::Map::new();
    body.insert(
        "error".to_string(),
        serde_json::Value::String(error.to_string()),
    );
    if let Some(reason) = reason {
        body.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }
    if let Some(detail) = detail {
        body.insert("detail".to_string(), serde_json::Value::String(detail));
    }
    if let Some(current) = current {
        body.insert(
            "current".to_string(),
            serde_json::to_value(current).unwrap_or(serde_json::Value::Null),
        );
    }
    (status, Json(serde_json::Value::Object(body))).into_response()
}

async fn authenticate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return unauthorized();
    };
    let presented = blake3::hash(token.as_bytes());
    if state.token_hash.ct_eq(presented.as_bytes()).unwrap_u8() != 1 {
        return unauthorized();
    }
    match headers
        .get("x-sito-cluster")
        .and_then(|value| value.to_str().ok())
    {
        Some(cluster) if cluster == state.cluster_id => {}
        _ => {
            return error_response(
                StatusCode::FORBIDDEN,
                "cluster_mismatch",
                None,
                Some("X-Sito-Cluster is missing or does not match this witness".to_string()),
                None,
            );
        }
    }
    next.run(request).await
}

fn unauthorized() -> Response {
    let mut response = error_response(
        StatusCode::UNAUTHORIZED,
        "unauthorized",
        None,
        Some("a valid bearer token is required".to_string()),
        None,
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        header::HeaderValue::from_static("Bearer"),
    );
    response
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() { None } else { Some(token) }
}

/// A TCP listener that performs TLS before handing the stream to axum.
struct WitnessTlsListener {
    inner: TcpListener,
    acceptor: TlsAcceptor,
}

impl axum::serve::Listener for WitnessTlsListener {
    type Io = TimeoutIo<TlsStream<TcpStream>>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.inner.accept().await {
                Ok((stream, addr)) => {
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, self.acceptor.accept(stream))
                        .await
                    {
                        Ok(Ok(tls)) => return (TimeoutIo::new(tls, IO_TIMEOUT), addr),
                        Ok(Err(error)) => {
                            tracing::debug!(%addr, %error, "witness TLS handshake failed");
                        }
                        Err(_) => {
                            tracing::debug!(%addr, "witness TLS handshake timed out");
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "witness TCP accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

/// Wraps a stream with a per-operation inactivity timeout.
struct TimeoutIo<S> {
    inner: S,
    timeout: Duration,
    read_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    write_deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> TimeoutIo<S> {
    fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            read_deadline: None,
            write_deadline: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for TimeoutIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_deadline.is_none() {
            this.read_deadline = Some(Box::pin(tokio::time::sleep(this.timeout)));
        }
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                this.read_deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let expired = this
                    .read_deadline
                    .as_mut()
                    .expect("read deadline was just initialized")
                    .as_mut()
                    .poll(cx)
                    .is_ready();
                if expired {
                    this.read_deadline = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "witness read timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TimeoutIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write_deadline.is_none() {
            this.write_deadline = Some(Box::pin(tokio::time::sleep(this.timeout)));
        }
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(result) => {
                this.write_deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                let expired = this
                    .write_deadline
                    .as_mut()
                    .expect("write deadline was just initialized")
                    .as_mut()
                    .poll(cx)
                    .is_ready();
                if expired {
                    this.write_deadline = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "witness write timeout",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
