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
        // One snapshot per query: config, clients and rewrites cannot be torn
        // apart by a concurrent hot reload.
        let runtime_snapshot = self.runtime.snapshot();
        let acl_start = std::time::Instant::now();

        // ADR-0011: source admission runs before identity resolution and every
        // expensive stage. The decision reads only the observed peer address
        // (`client.ip`) and the shared compiled ACL from this snapshot; it
        // never consults DoH path/SNI, headers, MAC/ARP, RouterOS leases,
        // secrets or groups. It must stay before the multi-question FORMERR
        // path so denied sources cannot exercise wire-level error handling.
        let acl = runtime_snapshot.clients.acl();
        let decision = acl.decide(client.ip);
        if let Some(ref metrics) = self.metrics {
            metrics.inc_acl_decision(
                decision.action.as_str(),
                decision.reason.as_str(),
                decision.family.as_str(),
            );
        }
        if decision.is_denied() {
            // The label is only needed for denied traffic (sampled log and
            // matched-prefix metric). Allowed queries stay allocation-free.
            let matched_prefix = decision.matched.map(sito_clients::AclPrefix::label);
            if let Some(ref metrics) = self.metrics
                && let Some(ref prefix) = matched_prefix
            {
                metrics.inc_acl_matched_prefix(
                    decision.action.as_str(),
                    prefix,
                    decision.family.as_str(),
                );
            }
            let deny_response = acl.deny_response();
            if deny_response == sito_clients::AclDenyResponse::Drop
                && let Some(ref metrics) = self.metrics
            {
                metrics.inc_acl_dropped(decision.family.as_str());
            }
            // Network metadata only: source IP, protocol, action, matched
            // prefix. No qname, path, SNI, header, entry/group name or secret.
            match self.acl_log.record(client.ip) {
                acl::AclLogLevel::Info => info!(
                    source_ip = %client.ip,
                    proto = %client.proto,
                    action = "deny",
                    reason = decision.reason.as_str(),
                    matched_prefix = matched_prefix.as_deref().unwrap_or("default"),
                    "DNS client ACL denied a query"
                ),
                acl::AclLogLevel::Debug => debug!(
                    source_ip = %client.ip,
                    proto = %client.proto,
                    action = "deny",
                    reason = decision.reason.as_str(),
                    matched_prefix = matched_prefix.as_deref().unwrap_or("default"),
                    "DNS client ACL denied a query"
                ),
            }

            if deny_response == sito_clients::AclDenyResponse::Drop {
                // No query-log entry, no pipeline work, no response. DoH and
                // DoH3 map `None` to HTTP 204 in the transport.
                return None;
            }

            // Synthesized REFUSED still increments the existing query-rate
            // series; ACL counters always increment because identity (and
            // therefore `ignore_stats`) is not resolved for denied traffic.
            if let Some(ref metrics) = self.metrics {
                let qtype = query
                    .queries
                    .first()
                    .map_or(0, |question| u16::from(question.query_type()));
                metrics.inc_queries(&client.proto, qtype, "refused");
                metrics.observe_query_duration("refused", acl_start.elapsed().as_secs_f64());
            }
            let mut response = Message::new(
                query.metadata.id,
                MessageType::Response,
                query.metadata.op_code,
            );
            response.metadata.response_code = ResponseCode::Refused;
            ResponseShaper::shape_with_payload(
                &mut response,
                &query,
                runtime_snapshot.dnssec_policy.mode(),
                runtime_snapshot.config.dns.edns_udp_size,
            );
            return Some(response);
        }

        // Multi-question messages are not resolvable by this pipeline (and
        // are used by DoS probes to amplify work). Reject with FORMERR at the
        // start. Shape through the shared path so the response advertises the
        // configured UDP payload instead of echoing the client's OPT/options;
        // the question section stays empty because FORMERR is question-less.
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
            ResponseShaper::shape_with_payload(
                &mut response,
                &query,
                runtime_snapshot.dnssec_policy.mode(),
                runtime_snapshot.config.dns.edns_udp_size,
            );
            response.queries.clear();
            return Some(response);
        }

        let mut client = client;
        // Evaluate schedules against the configured `clients.timezone`
        // (default: the system-local zone) instead of UTC.
        let now = runtime_snapshot.clients.now();
        let policy = runtime_snapshot.clients.resolve(&mut client, now);

        if !policy.ignore_stats
            && let Some(ref m) = self.metrics
        {
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
