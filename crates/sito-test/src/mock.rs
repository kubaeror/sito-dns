//! Mock upstream DNS server for integration tests.

use dashmap::DashMap;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sito_proto::rdata::{A, AAAA};
use sito_proto::{decode_message, encode_message, normalize_domain};
use sito_test_support::Clock;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::oneshot;
use tracing::trace;

const MALFORMED_RESPONSE: &[u8] = &[0xFF, 0xFF];

/// Optional clock-controlled response delay shared with the server task.
type ResponseDelay = Arc<std::sync::Mutex<Option<(Arc<dyn Clock>, Duration)>>>;

#[derive(Debug, Default, Clone)]
pub struct MockRecordResponse {
    pub answers: Vec<Record>,
    pub additionals: Vec<Record>,
}

#[derive(Debug, Default)]
struct MockBehavior {
    nodata: AtomicBool,
    edns: AtomicBool,
    truncate: AtomicBool,
    malformed: AtomicBool,
}

/// Binds UDP and TCP listeners to the same ephemeral loopback port and claims
/// it in the shared process-wide port broker.
///
/// Claiming matters in parallel test binaries: without it, a mock upstream can
/// steal the number a harness reserved for its DNS listener (which also binds
/// UDP and TCP on one port).
async fn bind_udp_tcp_pair() -> Result<(UdpSocket, TcpListener, SocketAddr, u16), anyhow::Error> {
    let mut last_error = None;
    for _ in 0..20 {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        match TcpListener::bind(addr).await {
            Ok(tcp_listener) => {
                if sito_test_support::claim_ports(&[addr.port()]) {
                    return Ok((socket, tcp_listener, addr, addr.port()));
                }
                // Another test reserved this number between bind and claim.
                last_error = Some(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("port {} is already reserved", addr.port()),
                ));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.map_or_else(
        || anyhow::anyhow!("no ephemeral UDP/TCP port pair available after 20 attempts"),
        anyhow::Error::from,
    ))
}

/// Lightweight in-process mock upstream DNS server.
///
/// UDP and TCP queries are accepted on the same ephemeral port. The default
/// response for a known owner with an unconfigured qtype is NXDOMAIN; use
/// [`MockDnsServer::with_nodata`] to return NODATA (NOERROR with no answers)
/// instead.
pub struct MockDnsServer {
    addr: SocketAddr,
    alive: Arc<AtomicBool>,
    query_count: Arc<AtomicUsize>,
    records: Arc<DashMap<(String, RecordType), MockRecordResponse>>,
    behavior: Arc<MockBehavior>,
    delay: ResponseDelay,
    reserved_ports: Vec<u16>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockDnsServer {
    /// Spawns a new mock DNS server on an ephemeral UDP/TCP port.
    pub async fn spawn() -> Result<Self, anyhow::Error> {
        let (socket, tcp_listener, addr, port) = bind_udp_tcp_pair().await?;

        let alive = Arc::new(AtomicBool::new(true));
        let query_count = Arc::new(AtomicUsize::new(0));
        let records: Arc<DashMap<(String, RecordType), MockRecordResponse>> =
            Arc::new(DashMap::new());
        let behavior = Arc::new(MockBehavior::default());
        let delay: ResponseDelay = Arc::new(std::sync::Mutex::new(None));
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let alive_clone = Arc::clone(&alive);
        let query_count_clone = Arc::clone(&query_count);
        let records_clone = Arc::clone(&records);
        let behavior_clone = Arc::clone(&behavior);
        let delay_clone = Arc::clone(&delay);

        tokio::spawn(async move {
            let socket = Arc::new(socket);
            let mut buf = [0u8; 4096];
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    res = socket.recv_from(&mut buf) => {
                        let Ok((len, src)) = res else { break; };
                        if !alive_clone.load(Ordering::SeqCst) {
                            // Drop packets to simulate a dead upstream
                            continue;
                        }

                        query_count_clone.fetch_add(1, Ordering::SeqCst);
                        let Some(response) = build_response(
                            &buf[..len],
                            &records_clone,
                            &behavior_clone,
                            true,
                        ) else {
                            continue;
                        };
                        let delay = delay_clone
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .clone();
                        if let Some((clock, duration)) = delay {
                            // Delay in a per-query task: a never-advanced
                            // ManualClock must not block the receive loop.
                            let socket = Arc::clone(&socket);
                            tokio::spawn(async move {
                                clock.sleep(duration).await;
                                let _ = socket.send_to(&response, src).await;
                            });
                        } else {
                            let _ = socket.send_to(&response, src).await;
                        }
                    }
                    res = tcp_listener.accept() => {
                        let Ok((stream, _)) = res else { continue; };
                        let alive = Arc::clone(&alive_clone);
                        let query_count = Arc::clone(&query_count_clone);
                        let records = Arc::clone(&records_clone);
                        let behavior = Arc::clone(&behavior_clone);
                        tokio::spawn(handle_tcp_connection(
                            stream,
                            alive,
                            query_count,
                            records,
                            behavior,
                        ));
                    }
                }
            }
        });

        trace!("Mock DNS server listening on {}", addr);
        Ok(Self {
            addr,
            alive,
            query_count,
            records,
            behavior,
            delay,
            reserved_ports: vec![port],
            shutdown_tx: Some(shutdown_tx),
        })
    }

    /// Bound socket address of this mock server.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Adds an A record to the mock server's database.
    pub fn add_a_record(&self, domain: &str, ip: Ipv4Addr, ttl: u32) {
        let norm = normalize_domain(domain).unwrap_or_else(|_| domain.to_string());
        let name = Name::from_str(&format!("{}.", norm.trim_end_matches('.'))).unwrap();
        let record = Record::from_rdata(name, ttl, RData::A(A(ip)));

        self.records
            .entry((norm, RecordType::A))
            .or_default()
            .answers
            .push(record);
    }

    /// Adds an AAAA record to the mock server's database.
    pub fn add_aaaa_record(&self, domain: &str, ip: Ipv6Addr, ttl: u32) {
        let norm = normalize_domain(domain).unwrap_or_else(|_| domain.to_string());
        let name = Name::from_str(&format!("{}.", norm.trim_end_matches('.'))).unwrap();
        let record = Record::from_rdata(name, ttl, RData::AAAA(AAAA(ip)));

        self.records
            .entry((norm, RecordType::AAAA))
            .or_default()
            .answers
            .push(record);
    }

    /// Adds custom answers and additionals for a given domain and qtype.
    pub fn add_custom_response(
        &self,
        domain: &str,
        qtype: RecordType,
        answers: Vec<Record>,
        additionals: Vec<Record>,
    ) {
        let norm = normalize_domain(domain).unwrap_or_else(|_| domain.to_string());
        self.records.insert(
            (norm, qtype),
            MockRecordResponse {
                answers,
                additionals,
            },
        );
    }

    /// Answers a known owner with an unconfigured qtype as NODATA (NOERROR with
    /// an empty answer section) instead of NXDOMAIN.
    ///
    /// Unknown owner names still return NXDOMAIN.
    #[must_use]
    pub fn with_nodata(self) -> Self {
        self.behavior.nodata.store(true, Ordering::SeqCst);
        self
    }

    /// Echoes the query's EDNS(0) OPT record, including the DO bit and the
    /// advertised payload size, in every response.
    #[must_use]
    pub fn with_edns(self) -> Self {
        self.behavior.edns.store(true, Ordering::SeqCst);
        self
    }

    /// Sets TC=1 and drops the answer section on UDP responses, so clients can
    /// exercise TCP fallback. TCP responses remain complete.
    #[must_use]
    pub fn with_truncation(self) -> Self {
        self.behavior.truncate.store(true, Ordering::SeqCst);
        self
    }

    /// Replies with a payload that cannot be decoded as a DNS message.
    #[must_use]
    pub fn with_malformed(self) -> Self {
        self.behavior.malformed.store(true, Ordering::SeqCst);
        self
    }

    /// Toggles mock server availability (if false, drops all incoming UDP queries).
    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::SeqCst);
    }

    /// Delays every UDP response by `duration` of `clock` time.
    ///
    /// A [`sito_test_support::ManualClock`] turns a slow/dead upstream into a
    /// deterministic test: the response is only released when the test calls
    /// `advance`, with no wall-clock sleep.
    pub fn set_response_delay(&self, clock: Arc<dyn Clock>, duration: Duration) {
        *self
            .delay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((clock, duration));
    }

    /// Number of queries received by this mock server.
    pub fn query_count(&self) -> usize {
        self.query_count.load(Ordering::SeqCst)
    }

    /// Stops the mock server.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn build_response(
    wire: &[u8],
    records: &DashMap<(String, RecordType), MockRecordResponse>,
    behavior: &MockBehavior,
    over_udp: bool,
) -> Option<Vec<u8>> {
    if behavior.malformed.load(Ordering::SeqCst) {
        return Some(MALFORMED_RESPONSE.to_vec());
    }

    let query = decode_message(wire).ok()?;
    let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.metadata.checking_disabled = query.metadata.checking_disabled;
    resp.queries.clone_from(&query.queries);

    if behavior.edns.load(Ordering::SeqCst)
        && let Some(client_edns) = &query.edns
    {
        let mut response_edns = Edns::new();
        response_edns.set_max_payload(client_edns.max_payload());
        response_edns.set_dnssec_ok(client_edns.flags().dnssec_ok);
        resp.set_edns(response_edns);
    }

    if let Some(q) = query.queries.first() {
        let domain_str = q.name().to_utf8();
        let norm = normalize_domain(&domain_str).unwrap_or_else(|_| domain_str.clone());
        let qtype = q.query_type();

        if let Some(entry) = records.get(&(norm.clone(), qtype)) {
            resp.metadata.response_code = ResponseCode::NoError;
            for r in &entry.answers {
                resp.answers.push(r.clone());
            }
            for r in &entry.additionals {
                resp.additionals.push(r.clone());
            }
        } else {
            let known_owner = records.iter().any(|entry| entry.key().0 == norm);
            resp.metadata.response_code = if behavior.nodata.load(Ordering::SeqCst) && known_owner {
                ResponseCode::NoError
            } else {
                ResponseCode::NXDomain
            };
        }
    }

    if over_udp && behavior.truncate.load(Ordering::SeqCst) {
        resp = resp.truncate();
    }

    encode_message(&resp).ok()
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    alive: Arc<AtomicBool>,
    query_count: Arc<AtomicUsize>,
    records: Arc<DashMap<(String, RecordType), MockRecordResponse>>,
    behavior: Arc<MockBehavior>,
) {
    loop {
        let mut length = [0u8; 2];
        if stream.read_exact(&mut length).await.is_err() {
            break;
        }
        let len = usize::from(u16::from_be_bytes(length));
        if len == 0 {
            break;
        }

        let mut buffer = vec![0u8; len];
        if stream.read_exact(&mut buffer).await.is_err() {
            break;
        }
        if !alive.load(Ordering::SeqCst) {
            continue;
        }

        query_count.fetch_add(1, Ordering::SeqCst);
        let Some(response) = build_response(&buffer, &records, &behavior, false) else {
            break;
        };
        let Ok(response_len) = u16::try_from(response.len()) else {
            break;
        };

        if stream.write_all(&response_len.to_be_bytes()).await.is_err() {
            break;
        }
        if stream.write_all(&response).await.is_err() {
            break;
        }
    }
}

impl Drop for MockDnsServer {
    fn drop(&mut self) {
        self.stop();
        sito_test_support::release_ports(&self.reserved_ports);
    }
}

#[cfg(test)]
mod tests {
    use super::{MockDnsServer, ResponseCode};
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use sito_proto::{decode_message, encode_message};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    fn query(name: &str, qtype: RecordType) -> Message {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.queries.push(Query::query(
            Name::from_str(name).expect("valid query name"),
            qtype,
        ));
        message
    }

    async fn udp_exchange(server: &MockDnsServer, query: &Message) -> Vec<u8> {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind client");
        socket.connect(server.addr()).await.expect("connect mock");
        socket
            .send(&encode_message(query).expect("encode query"))
            .await
            .expect("send query");
        let mut buffer = [0u8; 4096];
        let len = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buffer))
            .await
            .expect("mock response timed out")
            .expect("receive response");
        buffer[..len].to_vec()
    }

    async fn tcp_exchange(server: &MockDnsServer, query: &Message) -> Vec<u8> {
        let mut stream = tokio::net::TcpStream::connect(server.addr())
            .await
            .expect("connect mock over TCP");
        let wire = encode_message(query).expect("encode query");
        stream
            .write_all(&u16::try_from(wire.len()).expect("query fits").to_be_bytes())
            .await
            .expect("write length");
        stream.write_all(&wire).await.expect("write query");

        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await.expect("read length");
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream
            .read_exact(&mut response)
            .await
            .expect("read response");
        response
    }

    #[tokio::test]
    async fn test_nodata_for_known_owner_and_nxdomain_for_unknown_owner() {
        let server = MockDnsServer::spawn().await.expect("spawn mock");
        server.add_a_record("known.test", Ipv4Addr::new(192, 0, 2, 10), 60);

        // Existing behavior: a known owner with an unconfigured qtype is
        // NXDOMAIN until NODATA mode is requested.
        let default =
            decode_message(&udp_exchange(&server, &query("known.test.", RecordType::AAAA)).await)
                .expect("decode default response");
        assert_eq!(default.metadata.response_code, ResponseCode::NXDomain);

        let server = server.with_nodata();
        let known =
            decode_message(&udp_exchange(&server, &query("known.test.", RecordType::AAAA)).await)
                .expect("decode NODATA response");
        assert_eq!(known.metadata.response_code, ResponseCode::NoError);
        assert!(known.answers.is_empty(), "NODATA must carry no answers");

        let unknown =
            decode_message(&udp_exchange(&server, &query("unknown.test.", RecordType::AAAA)).await)
                .expect("decode NXDOMAIN response");
        assert_eq!(unknown.metadata.response_code, ResponseCode::NXDomain);
    }

    #[tokio::test]
    async fn test_edns_mode_echoes_do_bit_and_payload_size() {
        let server = MockDnsServer::spawn()
            .await
            .expect("spawn mock")
            .with_edns();
        server.add_a_record("edns.test", Ipv4Addr::new(192, 0, 2, 20), 60);

        let mut request = query("edns.test.", RecordType::A);
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        edns.set_dnssec_ok(true);
        request.set_edns(edns);

        let response =
            decode_message(&udp_exchange(&server, &request).await).expect("decode EDNS response");
        let response_edns = response.edns.expect("EDNS must be echoed");
        assert_eq!(response_edns.max_payload(), 1232);
        assert!(response_edns.flags().dnssec_ok, "the DO bit must be echoed");
        assert_eq!(response.answers.len(), 1);
    }

    #[tokio::test]
    async fn test_tcp_queries_are_answered() {
        let server = MockDnsServer::spawn().await.expect("spawn mock");
        server.add_a_record("tcp.test", Ipv4Addr::new(192, 0, 2, 30), 60);

        let response =
            decode_message(&tcp_exchange(&server, &query("tcp.test.", RecordType::A)).await)
                .expect("decode TCP response");
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert_eq!(response.answers.len(), 1);
        assert_eq!(server.query_count(), 1);
    }

    #[tokio::test]
    async fn test_truncation_sets_tc_over_udp_but_not_tcp() {
        let server = MockDnsServer::spawn()
            .await
            .expect("spawn mock")
            .with_truncation();
        server.add_a_record("trunc.test", Ipv4Addr::new(192, 0, 2, 40), 60);

        let udp =
            decode_message(&udp_exchange(&server, &query("trunc.test.", RecordType::A)).await)
                .expect("decode truncated response");
        assert!(udp.metadata.truncation, "UDP response must set TC=1");
        assert!(udp.answers.is_empty(), "truncated response drops answers");

        let tcp =
            decode_message(&tcp_exchange(&server, &query("trunc.test.", RecordType::A)).await)
                .expect("decode TCP response");
        assert!(!tcp.metadata.truncation);
        assert_eq!(tcp.answers.len(), 1, "TCP must still return the answer");
    }

    #[tokio::test]
    async fn test_malformed_mode_returns_undecodable_payload() {
        let server = MockDnsServer::spawn()
            .await
            .expect("spawn mock")
            .with_malformed();

        let udp = udp_exchange(&server, &query("malformed.test.", RecordType::A)).await;
        assert!(
            decode_message(&udp).is_err(),
            "malformed UDP payload must not decode"
        );

        let tcp = tcp_exchange(&server, &query("malformed.test.", RecordType::A)).await;
        assert!(
            decode_message(&tcp).is_err(),
            "malformed TCP payload must not decode"
        );
    }
}
