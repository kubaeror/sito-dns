//! QueryHandler implementation: request validation and stage orchestration.

#[allow(clippy::wildcard_imports)]
use super::*;

impl QueryHandler for DnsPipeline {
    async fn handle(&self, query: Message, client: ClientContext) -> Option<Message> {
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let _guard = InFlightGuard(Arc::clone(&self.in_flight));

        // P2-18: a DNS response (QR=1) is never a query to resolve. Drop it
        // instead of running it through policy/cache/upstream paths.
        if query.metadata.message_type != MessageType::Query {
            debug!("Dropping non-query DNS message (QR=1)");
            return None;
        }
        // Multi-question messages are not resolvable by this pipeline (and
        // are used by DoS probes to amplify work). Reject with FORMERR at the
        // start; the question section is deliberately not echoed.
        if query.queries.len() != 1 {
            debug!(
                questions = query.queries.len(),
                "Rejecting multi-question DNS query with FORMERR"
            );
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.response_code = ResponseCode::FormErr;
            response.metadata.recursion_desired = query.metadata.recursion_desired;
            response.metadata.recursion_available = true;
            response.metadata.checking_disabled = query.metadata.checking_disabled;
            if let Some(client_edns) = &query.edns {
                let mut edns = Edns::new();
                edns.set_max_payload(client_edns.max_payload());
                edns.set_dnssec_ok(client_edns.flags().dnssec_ok);
                response.set_edns(edns);
            }
            return Some(response);
        }

        // One snapshot per query: config, clients and rewrites cannot be torn
        // apart by a concurrent hot reload.
        let runtime_snapshot = self.runtime.snapshot();

        let mut client = client;
        // Evaluate schedules against the configured `clients.timezone`
        // (default: the system-local zone) instead of UTC.
        let now = runtime_snapshot.clients.now();
        let policy = runtime_snapshot.clients.resolve(&mut client, now);

        if let Some(ref m) = self.metrics {
            m.inc_clients_identified(if client.client_name.is_some() {
                "identified"
            } else {
                "ip"
            });
        }

        let query_id = query.metadata.id;
        let request_id = rand::random::<u64>();
        let span = tracing::debug_span!(
            "query",
            request_id = request_id,
            client_ip = %client.ip,
            client_name = ?client.client_name,
            group = %policy.group_name,
            query_id = query_id
        );
        let start = std::time::Instant::now();

        // The client must signal DNSSEC awareness (DO bit or AD bit) before we
        // may assert AD on the response (RFC 6840 section 5.7). The shared
        // response shaper enforces this from the query itself.
        let first_query = query.queries.first().expect("validated single question");
        let qname = first_query.name().clone();
        let qtype = first_query.query_type();
        // ASCII/punycode form: parental/service lists, safe-search and
        // per-domain routing are all stored as punycode.
        let domain_str = qname.to_ascii().to_lowercase();

        let mut context = PipelineContext::new(
            self,
            query,
            client,
            policy,
            runtime_snapshot,
            query_id,
            qname,
            qtype,
            domain_str,
            start,
        );
        let outcome = context.execute().instrument(span).await;
        context.finish(outcome)
    }
}
