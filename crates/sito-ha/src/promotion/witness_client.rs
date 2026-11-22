//! Client for the built-in witness lease server.
//!
//! This is the transport foundation for opt-in automatic promotion
//! (ADR-0010). It performs TLS with CA verification (plus an optional BLAKE3
//! pin of the DER server certificate), bearer authentication from a `0600`
//! token file, and the `info`/`lease`/`acquire`/`renew` calls. There is no
//! plaintext or unauthenticated fallback: every failure is returned as a typed
//! error so the promotion engine (C3b2b) can start read-only with a specific
//! reason.
//!
//! The client does not own promotion state, quiesce, reconciliation, fencing or
//! retry policy.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use serde::Deserialize;
use sito_ha_types::config::{PromotionConfig, WitnessUrl, parse_witness_url};
use sito_ha_types::hash::normalize_bundle_hash;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::transport::build_client_tls_config;
use crate::witness::{
    AcquireRequest, LEASE_PROTOCOL_VERSION, LeaseInfo, LeaseRecord, RenewRequest, read_token_file,
};

/// Maximum time for one witness request (connect, TLS handshake and response).
pub const WITNESS_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A typed witness client failure.
///
/// The variants map to the ADR's stable read-only reasons where one exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessClientError {
    /// Automatic promotion is disabled for this node.
    Disabled,
    /// The configured client material is structurally unusable.
    InvalidConfig {
        /// Configuration key or component that failed.
        field: &'static str,
        /// Human-readable detail.
        detail: String,
    },
    /// The bearer token is missing, unreadable or rejected (401).
    Auth {
        /// Human-readable detail.
        detail: String,
    },
    /// `X-Sito-Cluster` is missing/mismatched, or the witness names another cluster.
    ClusterMismatch {
        /// Human-readable detail.
        detail: String,
    },
    /// TLS verification failed (CA, SAN or pin).
    Tls {
        /// Human-readable detail.
        detail: String,
    },
    /// The witness could not be reached or did not answer within the timeout.
    Unavailable {
        /// Human-readable detail.
        detail: String,
    },
    /// The response was not a valid witness response.
    Protocol {
        /// Human-readable detail.
        detail: String,
    },
    /// The witness speaks a different lease protocol version.
    ProtocolMismatch {
        /// Version reported by the witness.
        found: u32,
        /// Version supported by this client.
        expected: u32,
    },
    /// The local `bundle_hash` is malformed (rejected before any request).
    InvalidHash {
        /// Human-readable detail.
        detail: String,
    },
    /// A CAS conflict (HTTP 409), including the current record when supplied.
    Conflict {
        /// Witness-side conflict reason, for example `lease_held`.
        reason: Option<String>,
        /// Human-readable detail.
        detail: Option<String>,
        /// The current record, when the witness returned one.
        current: Option<Box<LeaseRecord>>,
    },
    /// The witness answered with a non-success HTTP status.
    Server {
        /// HTTP status code.
        status: u16,
        /// Machine-readable error name, for example `invalid_json`.
        error: Option<String>,
        /// Witness-side reason, when supplied.
        reason: Option<String>,
        /// Human-readable detail.
        detail: Option<String>,
    },
}

impl WitnessClientError {
    /// Stable ADR-0010 status reason for this failure.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Disabled => "promotion_disabled",
            Self::InvalidConfig { .. } => "witness_config_invalid",
            Self::Auth { .. } => "witness_auth_failed",
            Self::ClusterMismatch { .. } => "witness_cluster_mismatch",
            Self::Tls { .. } => "witness_tls_failed",
            Self::Unavailable { .. } => "witness_unavailable",
            Self::Server { status, .. } if *status >= 500 => "witness_unavailable",
            Self::InvalidHash { .. } => "invalid_bundle_hash",
            Self::Conflict { .. } => "lease_conflict",
            Self::Protocol { .. } | Self::ProtocolMismatch { .. } | Self::Server { .. } => {
                "witness_protocol_mismatch"
            }
        }
    }

    /// Whether retrying the same request with backoff can succeed.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::Unavailable { .. } => true,
            Self::Server { status, .. } => *status >= 500,
            _ => false,
        }
    }

    /// The current record carried by a 409 conflict, if any.
    #[must_use]
    pub fn current_record(&self) -> Option<&LeaseRecord> {
        match self {
            Self::Conflict { current, .. } => current.as_deref(),
            _ => None,
        }
    }
}

impl std::fmt::Display for WitnessClientError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(formatter, "promotion is disabled"),
            Self::InvalidConfig { field, detail } => {
                write!(formatter, "invalid {field}: {detail}")
            }
            Self::Auth { detail } => write!(formatter, "witness authentication failed: {detail}"),
            Self::ClusterMismatch { detail } => {
                write!(formatter, "witness cluster mismatch: {detail}")
            }
            Self::Tls { detail } => write!(formatter, "witness TLS verification failed: {detail}"),
            Self::Unavailable { detail } => write!(formatter, "witness unavailable: {detail}"),
            Self::Protocol { detail } => write!(formatter, "invalid witness response: {detail}"),
            Self::ProtocolMismatch { found, expected } => write!(
                formatter,
                "witness lease protocol version {found} does not match the supported version {expected}"
            ),
            Self::InvalidHash { detail } => write!(formatter, "invalid bundle_hash: {detail}"),
            Self::Conflict {
                reason,
                detail,
                current,
            } => {
                write!(formatter, "witness lease conflict")?;
                if let Some(reason) = reason {
                    write!(formatter, " ({reason})")?;
                }
                if let Some(detail) = detail {
                    write!(formatter, ": {detail}")?;
                }
                if let Some(current) = current {
                    write!(
                        formatter,
                        "; current holder={} term={} revision={} version={} hash={}",
                        current.holder,
                        current.term,
                        current.revision,
                        current.version,
                        current.bundle_hash
                    )?;
                }
                Ok(())
            }
            Self::Server {
                status,
                error,
                reason,
                detail,
            } => {
                write!(formatter, "witness returned HTTP {status}")?;
                if let Some(error) = error {
                    write!(formatter, " ({error})")?;
                }
                if let Some(reason) = reason {
                    write!(formatter, "; reason: {reason}")?;
                }
                if let Some(detail) = detail {
                    write!(formatter, ": {detail}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for WitnessClientError {}

/// A connected-on-demand client for one witness lease server.
#[derive(Clone)]
pub struct WitnessClient {
    endpoint: WitnessUrl,
    cluster_id: String,
    server_name: ServerName<'static>,
    token: String,
    tls: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for WitnessClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WitnessClient")
            .field("endpoint", &self.endpoint)
            .field("cluster_id", &self.cluster_id)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl WitnessClient {
    /// Builds a client from a validated `[ha.promotion]` section.
    ///
    /// Reads (but does not send) the CA bundle and bearer token file. Network
    /// reachability is checked per request, so an unreachable witness is
    /// reported by [`Self::info`]/[`Self::lease`] rather than at construction.
    pub fn new(config: &PromotionConfig) -> Result<Self, WitnessClientError> {
        if !config.enabled {
            return Err(WitnessClientError::Disabled);
        }
        let cluster_id =
            config
                .cluster_id
                .clone()
                .ok_or_else(|| WitnessClientError::InvalidConfig {
                    field: "ha.promotion.cluster_id",
                    detail: "cluster_id is required when promotion is enabled".to_string(),
                })?;
        let url =
            config
                .witness
                .url
                .as_deref()
                .ok_or_else(|| WitnessClientError::InvalidConfig {
                    field: "ha.promotion.witness.url",
                    detail: "witness.url is required when promotion is enabled".to_string(),
                })?;
        let endpoint =
            parse_witness_url(url).map_err(|error| WitnessClientError::InvalidConfig {
                field: "ha.promotion.witness.url",
                detail: error.to_string(),
            })?;

        let ca = config
            .witness
            .ca
            .as_deref()
            .ok_or_else(|| WitnessClientError::InvalidConfig {
                field: "ha.promotion.witness.ca",
                detail: "witness.ca is required when promotion is enabled".to_string(),
            })?;
        if !ca.is_absolute() {
            return Err(WitnessClientError::InvalidConfig {
                field: "ha.promotion.witness.ca",
                detail: "witness.ca must be an absolute path".to_string(),
            });
        }
        let fingerprint = config.witness.normalized_fingerprint().map_err(|error| {
            WitnessClientError::InvalidConfig {
                field: "ha.promotion.witness.fingerprint",
                detail: error.to_string(),
            }
        })?;
        let token_file = config.witness.token_file.as_deref().ok_or_else(|| {
            WitnessClientError::InvalidConfig {
                field: "ha.promotion.witness.token_file",
                detail: "witness.token_file is required when promotion is enabled".to_string(),
            }
        })?;
        if !token_file.is_absolute() {
            return Err(WitnessClientError::InvalidConfig {
                field: "ha.promotion.witness.token_file",
                detail: "witness.token_file must be an absolute path".to_string(),
            });
        }
        let token = read_token_file(token_file).map_err(|error| WitnessClientError::Auth {
            detail: error.to_string(),
        })?;

        let tls = build_client_tls_config(
            None,
            None,
            fingerprint.as_deref(),
            // There is deliberately no insecure/no-verification mode for the
            // witness: the CA is mandatory and a pin is additive.
            false,
            Some(ca),
        )
        .map_err(|error| WitnessClientError::Tls {
            detail: error.to_string(),
        })?;

        let server_name = config
            .witness
            .server_name
            .clone()
            .unwrap_or_else(|| endpoint.host.clone());
        let server_name = ServerName::try_from(server_name.clone()).map_err(|error| {
            WitnessClientError::InvalidConfig {
                field: "ha.promotion.witness.server_name",
                detail: format!("'{server_name}' is not a valid TLS server name: {error}"),
            }
        })?;

        Ok(Self {
            endpoint,
            cluster_id,
            server_name,
            token,
            tls,
        })
    }

    /// The configured cluster identifier (also sent as `X-Sito-Cluster`).
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    /// The parsed witness endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &WitnessUrl {
        &self.endpoint
    }

    /// `GET /v1/info`: protocol compatibility and witness clock hint.
    ///
    /// Verifies the reported lease protocol version and `cluster_id`; a
    /// mismatch is an error, never silently accepted.
    pub async fn info(&self) -> Result<LeaseInfo, WitnessClientError> {
        let response = self.request("GET", "/v1/info", None).await?;
        let body = expect_status(response, &[200])?;
        let info: LeaseInfo =
            serde_json::from_slice(&body).map_err(|error| WitnessClientError::Protocol {
                detail: format!("failed to parse /v1/info: {error}"),
            })?;
        if info.lease_protocol_version != LEASE_PROTOCOL_VERSION {
            return Err(WitnessClientError::ProtocolMismatch {
                found: info.lease_protocol_version,
                expected: LEASE_PROTOCOL_VERSION,
            });
        }
        if info.cluster_id != self.cluster_id {
            return Err(WitnessClientError::ClusterMismatch {
                detail: format!(
                    "witness belongs to cluster '{}', configured cluster_id is '{}'",
                    info.cluster_id, self.cluster_id
                ),
            });
        }
        Ok(info)
    }

    /// `GET /v1/lease`: the current record, including an expired one.
    pub async fn lease(&self) -> Result<Option<LeaseRecord>, WitnessClientError> {
        let response = self.request("GET", "/v1/lease", None).await?;
        match response.status {
            204 => Ok(None),
            200 => {
                let record: LeaseRecord =
                    serde_json::from_slice(&response.body).map_err(|error| {
                        WitnessClientError::Protocol {
                            detail: format!("failed to parse /v1/lease: {error}"),
                        }
                    })?;
                self.check_record_cluster(&record)?;
                Ok(Some(record))
            }
            status => Err(failure_from_response(status, &response.body)),
        }
    }

    /// `POST /v1/lease/acquire` with a normalized `bundle_hash`.
    ///
    /// The hash is normalized before the request, so a malformed value fails
    /// locally and no partial/invalid request reaches the witness.
    pub async fn acquire(
        &self,
        request: &AcquireRequest,
    ) -> Result<LeaseRecord, WitnessClientError> {
        let mut request = request.clone();
        request.bundle_hash = normalize_bundle_hash(request.version, &request.bundle_hash)
            .map_err(|error| WitnessClientError::InvalidHash {
                detail: error.to_string(),
            })?;
        let body = serde_json::to_vec(&request).map_err(|error| WitnessClientError::Protocol {
            detail: format!("failed to serialize acquire request: {error}"),
        })?;
        let response = self
            .request("POST", "/v1/lease/acquire", Some(&body))
            .await?;
        let body = expect_status(response, &[200])?;
        let record: LeaseRecord =
            serde_json::from_slice(&body).map_err(|error| WitnessClientError::Protocol {
                detail: format!("failed to parse acquired lease record: {error}"),
            })?;
        self.check_record_cluster(&record)?;
        Ok(record)
    }

    /// `POST /v1/lease/renew` with a normalized `bundle_hash`.
    pub async fn renew(&self, request: &RenewRequest) -> Result<LeaseRecord, WitnessClientError> {
        let mut request = request.clone();
        request.bundle_hash = normalize_bundle_hash(request.version, &request.bundle_hash)
            .map_err(|error| WitnessClientError::InvalidHash {
                detail: error.to_string(),
            })?;
        let body = serde_json::to_vec(&request).map_err(|error| WitnessClientError::Protocol {
            detail: format!("failed to serialize renew request: {error}"),
        })?;
        let response = self.request("POST", "/v1/lease/renew", Some(&body)).await?;
        let body = expect_status(response, &[200])?;
        let record: LeaseRecord =
            serde_json::from_slice(&body).map_err(|error| WitnessClientError::Protocol {
                detail: format!("failed to parse renewed lease record: {error}"),
            })?;
        self.check_record_cluster(&record)?;
        Ok(record)
    }

    fn check_record_cluster(&self, record: &LeaseRecord) -> Result<(), WitnessClientError> {
        if record.cluster_id != self.cluster_id {
            return Err(WitnessClientError::ClusterMismatch {
                detail: format!(
                    "lease record belongs to cluster '{}', configured cluster_id is '{}'",
                    record.cluster_id, self.cluster_id
                ),
            });
        }
        Ok(())
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, WitnessClientError> {
        match tokio::time::timeout(
            WITNESS_REQUEST_TIMEOUT,
            self.execute_request(method, path, body),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(WitnessClientError::Unavailable {
                detail: format!("{method} {path} timed out after {WITNESS_REQUEST_TIMEOUT:?}"),
            }),
        }
    }

    async fn execute_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, WitnessClientError> {
        let tcp = TcpStream::connect((self.endpoint.host.as_str(), self.endpoint.port))
            .await
            .map_err(|error| WitnessClientError::Unavailable {
                detail: format!(
                    "cannot connect to {}:{}: {error}",
                    self.endpoint.host, self.endpoint.port
                ),
            })?;
        let connector = TlsConnector::from(Arc::clone(&self.tls));
        let mut stream: TlsStream<TcpStream> = connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|error| WitnessClientError::Tls {
                detail: format!("TLS handshake with {} failed: {error}", self.endpoint.host),
            })?;

        let body = body.unwrap_or_default();
        let host_header = if self.endpoint.host.contains(':') {
            format!("[{}]:{}", self.endpoint.host, self.endpoint.port)
        } else {
            format!("{}:{}", self.endpoint.host, self.endpoint.port)
        };
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept: application/json\r\nAuthorization: Bearer {}\r\nX-Sito-Cluster: {}\r\nContent-Length: {}\r\n",
            self.token,
            self.cluster_id,
            body.len()
        );
        if method != "GET" {
            request.push_str("Content-Type: application/json\r\n");
        }
        request.push_str("\r\n");

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| WitnessClientError::Unavailable {
                detail: format!("failed to send {method} {path}: {error}"),
            })?;
        stream
            .write_all(body)
            .await
            .map_err(|error| WitnessClientError::Unavailable {
                detail: format!("failed to send {method} {path} body: {error}"),
            })?;
        stream
            .flush()
            .await
            .map_err(|error| WitnessClientError::Unavailable {
                detail: format!("failed to flush {method} {path}: {error}"),
            })?;

        let mut bytes = Vec::new();
        stream
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| WitnessClientError::Unavailable {
                detail: format!("failed to read {method} {path} response: {error}"),
            })?;
        parse_http_response(&bytes)
    }
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn expect_status(response: HttpResponse, expected: &[u16]) -> Result<Vec<u8>, WitnessClientError> {
    if expected.contains(&response.status) {
        Ok(response.body)
    } else {
        Err(failure_from_response(response.status, &response.body))
    }
}

#[derive(Debug, Default, Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    detail: Option<String>,
    #[serde(default)]
    current: Option<LeaseRecord>,
}

fn failure_from_response(status: u16, body: &[u8]) -> WitnessClientError {
    let error_body: ErrorBody = serde_json::from_slice(body).unwrap_or_default();
    match status {
        401 => WitnessClientError::Auth {
            detail: error_body
                .detail
                .unwrap_or_else(|| "the witness rejected the bearer token".to_string()),
        },
        403 => WitnessClientError::ClusterMismatch {
            detail: error_body.detail.unwrap_or_else(|| {
                "X-Sito-Cluster is missing or does not match the witness".to_string()
            }),
        },
        409 => WitnessClientError::Conflict {
            reason: error_body.reason,
            detail: error_body.detail,
            current: error_body.current.map(Box::new),
        },
        _ => WitnessClientError::Server {
            status,
            error: error_body.error,
            reason: error_body.reason,
            detail: error_body.detail,
        },
    }
}

fn parse_http_response(bytes: &[u8]) -> Result<HttpResponse, WitnessClientError> {
    let Some(split) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(WitnessClientError::Protocol {
            detail: "response has no HTTP header terminator".to_string(),
        });
    };
    let head =
        std::str::from_utf8(&bytes[..split]).map_err(|error| WitnessClientError::Protocol {
            detail: format!("response headers are not valid UTF-8: {error}"),
        })?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| WitnessClientError::Protocol {
            detail: "response has no HTTP status code".to_string(),
        })?;

    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    let raw_body = &bytes[split + 4..];
    let body = if chunked {
        decode_chunked(raw_body)?
    } else if let Some(length) = content_length {
        if raw_body.len() < length {
            return Err(WitnessClientError::Protocol {
                detail: format!(
                    "response body is {} bytes but Content-Length is {length}",
                    raw_body.len()
                ),
            });
        }
        raw_body[..length].to_vec()
    } else {
        raw_body.to_vec()
    };

    Ok(HttpResponse { status, body })
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, WitnessClientError> {
    let mut output = Vec::new();
    loop {
        let Some(line_end) = input.windows(2).position(|window| window == b"\r\n") else {
            return Err(WitnessClientError::Protocol {
                detail: "chunked response has no chunk size line".to_string(),
            });
        };
        let size_text = std::str::from_utf8(&input[..line_end]).map_err(|error| {
            WitnessClientError::Protocol {
                detail: format!("chunk size is not valid UTF-8: {error}"),
            }
        })?;
        let size =
            usize::from_str_radix(size_text.split(';').next().unwrap_or_default().trim(), 16)
                .map_err(|error| WitnessClientError::Protocol {
                    detail: format!("invalid chunk size: {error}"),
                })?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        if input.len() < size + 2 {
            return Err(WitnessClientError::Protocol {
                detail: "chunked response ended inside a chunk".to_string(),
            });
        }
        output.extend_from_slice(&input[..size]);
        if &input[size..size + 2] != b"\r\n" {
            return Err(WitnessClientError::Protocol {
                detail: "chunk is not terminated by CRLF".to_string(),
            });
        }
        input = &input[size + 2..];
    }
}
