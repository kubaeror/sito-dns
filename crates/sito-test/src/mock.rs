//! Mock upstream DNS server for integration tests.

use dashmap::DashMap;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sito_proto::rdata::{A, AAAA};
use sito_proto::{decode_message, encode_message, normalize_domain};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;
use tracing::trace;

#[derive(Debug, Default, Clone)]
pub struct MockRecordResponse {
    pub answers: Vec<Record>,
    pub additionals: Vec<Record>,
}

/// Lightweight in-process mock upstream DNS server.
pub struct MockDnsServer {
    addr: SocketAddr,
    alive: Arc<AtomicBool>,
    query_count: Arc<AtomicUsize>,
    records: Arc<DashMap<(String, RecordType), MockRecordResponse>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl MockDnsServer {
    /// Spawns a new mock DNS server on an ephemeral UDP port.
    pub async fn spawn() -> Result<Self, anyhow::Error> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;

        let alive = Arc::new(AtomicBool::new(true));
        let query_count = Arc::new(AtomicUsize::new(0));
        let records: Arc<DashMap<(String, RecordType), MockRecordResponse>> =
            Arc::new(DashMap::new());
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let alive_clone = Arc::clone(&alive);
        let query_count_clone = Arc::clone(&query_count);
        let records_clone = Arc::clone(&records);

        tokio::spawn(async move {
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
                        let Ok(query) = decode_message(&buf[..len]) else { continue; };

                        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                        resp.metadata.recursion_desired = query.metadata.recursion_desired;
                        resp.metadata.recursion_available = true;
                        resp.queries = query.queries.clone();

                        if let Some(q) = query.queries.first() {
                            let domain_str = q.name().to_utf8();
                            let norm = normalize_domain(&domain_str).unwrap_or_else(|_| domain_str.clone());
                            let qtype = q.query_type();

                            if let Some(entry) = records_clone.get(&(norm, qtype)) {
                                resp.metadata.response_code = ResponseCode::NoError;
                                for r in &entry.answers {
                                    resp.answers.push(r.clone());
                                }
                                for r in &entry.additionals {
                                    resp.additionals.push(r.clone());
                                }
                            } else {
                                resp.metadata.response_code = ResponseCode::NXDomain;
                            }
                        }

                        if let Ok(encoded) = encode_message(&resp) {
                            let _ = socket.send_to(&encoded, src).await;
                        }
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

    /// Toggles mock server availability (if false, drops all incoming UDP queries).
    pub fn set_alive(&self, alive: bool) {
        self.alive.store(alive, Ordering::SeqCst);
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

impl Drop for MockDnsServer {
    fn drop(&mut self) {
        self.stop();
    }
}
