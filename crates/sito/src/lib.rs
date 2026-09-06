//! `sito`
//!
//! Fast, memory-efficient, filtering DNS resolver server and CLI.

pub mod cli;
pub mod pipeline;
pub mod server;

pub use cli::{Cli, Commands, run_check_config, run_healthcheck};
pub use pipeline::DnsPipeline;
pub use server::{run_server, run_server_full, run_server_with_shutdown};

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use sito_cache::DnsCache;
    use sito_clients::{ClientRegistry, ClientsConfig, ParentalRegistry, ServiceRegistry};
    use sito_core::client::ClientContext;
    use sito_core::config::Config;
    use sito_filter::HostsFilterEngine;
    use sito_proto::rdata::A;
    use sito_rewrites::{RewriteTable, RewritesConfig};
    use sito_transport::QueryHandler;
    use sito_upstream::{BootstrapResolver, UpstreamManager};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn test_check_config_validation() {
        let temp_dir = std::env::temp_dir().join(format!("sito_check_cfg_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let valid_path = temp_dir.join("valid.toml");
        std::fs::write(
            &valid_path,
            "config_version = 1\n[server]\nrole = \"master\"\n",
        )
        .unwrap();
        assert!(run_check_config(&valid_path).is_ok());

        let invalid_path = temp_dir.join("invalid.toml");
        std::fs::write(
            &invalid_path,
            "config_version = 1\n[server]\nrole = \"unsupported_role\"\n",
        )
        .unwrap();
        assert!(run_check_config(&invalid_path).is_err());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_pipeline_blocking_caching_and_upstream() {
        let temp_dir = std::env::temp_dir().join(format!("sito_pipe_test_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // 1. Start mock upstream UDP server
        let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((len, src)) = mock_socket.recv_from(&mut buf).await {
                if let Ok(query) = sito_proto::decode_message(&buf[..len]) {
                    let mut resp =
                        Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                    resp.metadata.response_code = ResponseCode::NoError;
                    resp.queries = query.queries.clone();
                    if let Some(q) = query.queries.first() {
                        let record = Record::from_rdata(
                            q.name().clone(),
                            300,
                            RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
                        );
                        resp.answers.push(record);
                    }
                    let encoded = sito_proto::encode_message(&resp).unwrap();
                    let _ = mock_socket.send_to(&encoded, src).await;
                }
            }
        });

        // 2. Setup config
        let mut config = Config::default();
        config.server.data_dir = temp_dir.clone();
        config.upstream.servers = vec![mock_addr.to_string()];
        config.filtering.custom_rules = vec!["0.0.0.0 ads.example.com".to_string()];

        let bootstrap = BootstrapResolver::new(vec![], Duration::from_millis(500));
        let upstream = Arc::new(
            UpstreamManager::from_config(&config.upstream, &bootstrap)
                .await
                .unwrap(),
        );
        let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
        let filter = Arc::new(
            HostsFilterEngine::init(config.filtering.clone(), config.server.data_dir.clone()).await,
        );
        let in_flight = Arc::new(AtomicUsize::new(0));
        let dnssec = Arc::new(sito_dnssec::DnssecValidator::from_config(
            &config.dns.dnssec,
        ));

        let clients = Arc::new(ClientRegistry::new(ClientsConfig::default()));
        let parental = Arc::new(ParentalRegistry::bundled());
        let services = Arc::new(ServiceRegistry::bundled());
        let rewrites = Arc::new(RewriteTable::new(RewritesConfig::default()));

        let pipeline = DnsPipeline::new(
            Arc::new(config.clone()),
            filter,
            cache.clone(),
            upstream,
            dnssec,
            clients,
            parental,
            services,
            rewrites,
            in_flight,
        );

        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        // 3. Test blocked domain query (A record)
        let mut query_blocked = Message::new(101, MessageType::Query, OpCode::Query);
        query_blocked.queries.push(Query::query(
            Name::from_str("ads.example.com.").unwrap(),
            RecordType::A,
        ));

        let resp_blocked = pipeline
            .handle(query_blocked, client.clone())
            .await
            .unwrap();
        assert_eq!(resp_blocked.metadata.id, 101);
        assert_eq!(resp_blocked.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp_blocked.answers.len(), 1);
        assert_eq!(
            resp_blocked.answers[0].data,
            RData::A(A(Ipv4Addr::UNSPECIFIED))
        );

        // 4. Test allowed domain query (miss, upstream resolved, cached)
        let mut query_allowed = Message::new(202, MessageType::Query, OpCode::Query);
        let allowed_name = Name::from_str("example.com.").unwrap();
        query_allowed
            .queries
            .push(Query::query(allowed_name.clone(), RecordType::A));

        let resp_allowed = pipeline
            .handle(query_allowed.clone(), client.clone())
            .await
            .unwrap();
        assert_eq!(resp_allowed.metadata.id, 202);
        assert_eq!(resp_allowed.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp_allowed.answers.len(), 1);
        assert_eq!(
            resp_allowed.answers[0].data,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34)))
        );

        // 5. Test second query -> cache hit
        let mut query_cached = Message::new(303, MessageType::Query, OpCode::Query);
        query_cached
            .queries
            .push(Query::query(allowed_name, RecordType::A));

        let resp_cached = pipeline.handle(query_cached, client).await.unwrap();
        assert_eq!(resp_cached.metadata.id, 303);
        assert_eq!(resp_cached.answers.len(), 1);
        assert_eq!(
            resp_cached.answers[0].data,
            RData::A(A(Ipv4Addr::new(93, 184, 216, 34)))
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_pipeline_cname_uncloaking() {
        use hickory_proto::rr::rdata::CNAME;

        let temp_dir = std::env::temp_dir().join(format!("sito_cname_test_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // 1. Start mock upstream that returns a CNAME chain
        let mock_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_socket.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((len, src)) = mock_socket.recv_from(&mut buf).await {
                if let Ok(query) = sito_proto::decode_message(&buf[..len]) {
                    let mut resp =
                        Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                    resp.metadata.response_code = ResponseCode::NoError;
                    resp.queries = query.queries.clone();
                    if let Some(q) = query.queries.first() {
                        let cname_target = Name::from_str("cloaked.adnetwork.com.").unwrap();
                        let cname_record = Record::from_rdata(
                            q.name().clone(),
                            300,
                            RData::CNAME(CNAME(cname_target.clone())),
                        );
                        let a_record = Record::from_rdata(
                            cname_target,
                            300,
                            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
                        );
                        resp.answers.push(cname_record);
                        resp.answers.push(a_record);
                    }
                    let encoded = sito_proto::encode_message(&resp).unwrap();
                    let _ = mock_socket.send_to(&encoded, src).await;
                }
            }
        });

        // 2. Setup config with blocked domain matching CNAME target
        let mut config = Config::default();
        config.server.data_dir = temp_dir.clone();
        config.upstream.servers = vec![mock_addr.to_string()];
        config.filtering.cname_cloaking = true;
        config.filtering.custom_rules = vec!["||adnetwork.com^".to_string()];

        let bootstrap = BootstrapResolver::new(vec![], Duration::from_millis(500));
        let upstream = Arc::new(
            UpstreamManager::from_config(&config.upstream, &bootstrap)
                .await
                .unwrap(),
        );
        let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
        let filter = Arc::new(
            HostsFilterEngine::init(config.filtering.clone(), config.server.data_dir.clone()).await,
        );
        let in_flight = Arc::new(AtomicUsize::new(0));
        let dnssec = Arc::new(sito_dnssec::DnssecValidator::from_config(
            &config.dns.dnssec,
        ));

        let clients = Arc::new(ClientRegistry::new(ClientsConfig::default()));
        let parental = Arc::new(ParentalRegistry::bundled());
        let services = Arc::new(ServiceRegistry::bundled());
        let rewrites = Arc::new(RewriteTable::new(RewritesConfig::default()));

        let pipeline = DnsPipeline::new(
            Arc::new(config.clone()),
            filter,
            cache,
            upstream,
            dnssec,
            clients,
            parental,
            services,
            rewrites,
            in_flight,
        );

        let client = ClientContext::new("127.0.0.1".parse().unwrap());

        // 3. Query track.company.com (not directly blocked, but points via CNAME to adnetwork.com)
        let mut query = Message::new(555, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("track.company.com.").unwrap(),
            RecordType::A,
        ));

        let resp = pipeline.handle(query, client).await.unwrap();
        assert_eq!(resp.metadata.id, 555);
        assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        // Answer was replaced with blocked 0.0.0.0 response via CNAME uncloaking!
        assert_eq!(resp.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_server_run_and_graceful_shutdown() {
        // Find ephemeral free port
        let probe = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let probe_web = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let web_port = probe_web.local_addr().unwrap().port();
        drop(probe_web);

        let temp_dir = std::env::temp_dir().join(format!(
            "sito_srv_test_{}_{}_{}",
            std::process::id(),
            port,
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mut config = Config::default();
        config.server.data_dir = temp_dir.clone();
        config.dns.bind = vec!["127.0.0.1".parse().unwrap()];
        config.dns.port = port;
        let mut web_cfg = config.get_web_config();
        web_cfg.bind = "127.0.0.1".parse().unwrap();
        web_cfg.port = web_port;
        config.set_web_config(web_cfg);
        config.upstream.servers = vec!["127.0.0.1:1".to_string()]; // mock unreachable upstream

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let server_task =
            tokio::spawn(async move { run_server_with_shutdown(config, Some(shutdown_rx)).await });

        // Verify listener responds via UDP with retry loop (allowing server time to finish startup on busy CI runners)
        let client_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = SocketAddr::new("127.0.0.1".parse().unwrap(), port);
        client_sock.connect(server_addr).await.unwrap();

        let mut query = Message::new(999, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("blocked.test.").unwrap(),
            RecordType::A,
        ));
        let wire = sito_proto::encode_message(&query).unwrap();

        let mut received = false;
        let mut resp_buf = [0u8; 512];
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if client_sock.send(&wire).await.is_ok()
                && let Ok(Ok(len)) = tokio::time::timeout(
                    Duration::from_millis(100),
                    client_sock.recv(&mut resp_buf),
                )
                .await
                && len > 0
            {
                received = true;
                break;
            }
        }
        assert!(
            received,
            "Server failed to respond to UDP query during startup"
        );

        // Trigger shutdown
        let _ = shutdown_tx.send(());

        // Await server task completion with timeout
        let result = tokio::time::timeout(Duration::from_secs(6), server_task).await;
        assert!(result.is_ok(), "Server failed to shut down within timeout");
        assert!(result.unwrap().unwrap().is_ok());

        // Verify that querylog writer flushed all buffered logs to disk before exiting
        let stats_path = temp_dir.join("stats.db");
        if stats_path.exists() {
            let stats_db = sito_stats::StatsDb::open(&stats_path).await.unwrap();
            let logs = stats_db
                .query_logs(&sito_stats::QueryLogFilter::default())
                .await
                .unwrap();
            assert!(
                !logs.entries.is_empty(),
                "Query log batch should be flushed on graceful shutdown"
            );
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_pipeline_picks_up_rewrite_change_without_restart() {
        use arc_swap::ArcSwap;

        let temp_dir =
            std::env::temp_dir().join(format!("sito_rewrite_swap_{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let mut config = Config::default();
        config.server.data_dir = temp_dir.clone();
        config.upstream.servers = vec!["127.0.0.1:1".to_string()];

        let bootstrap = BootstrapResolver::new(vec![], Duration::from_millis(500));
        let upstream = Arc::new(
            UpstreamManager::from_config(&config.upstream, &bootstrap)
                .await
                .unwrap(),
        );
        let cache = Arc::new(DnsCache::new(config.dns.cache.clone()));
        let filter_engine = Arc::new(
            HostsFilterEngine::init(config.filtering.clone(), config.server.data_dir.clone()).await,
        );
        let dnssec = Arc::new(sito_dnssec::DnssecValidator::from_config(
            &config.dns.dnssec,
        ));
        let client_registry = Arc::new(ArcSwap::new(Arc::new(ClientRegistry::new(
            ClientsConfig::default(),
        ))));
        let parental_registry = Arc::new(ParentalRegistry::bundled());
        let service_registry = Arc::new(ServiceRegistry::bundled());
        let rewrites = Arc::new(ArcSwap::new(Arc::new(RewriteTable::new(
            RewritesConfig::default(),
        ))));
        let in_flight = Arc::new(AtomicUsize::new(0));

        let config_arc = Arc::new(ArcSwap::new(Arc::new(config.clone())));

        let pipeline = DnsPipeline::new(
            config_arc,
            filter_engine,
            cache,
            upstream,
            dnssec,
            client_registry,
            parental_registry,
            service_registry,
            rewrites.clone(),
            in_flight,
        );

        let client = ClientContext::new("127.0.0.1".parse().unwrap());
        let mut query = Message::new(101, MessageType::Query, OpCode::Query);
        query.queries.push(Query::query(
            Name::from_str("router.lan.").unwrap(),
            RecordType::A,
        ));

        // Before update: rewrites table is empty; upstream 127.0.0.1:1 fails or SERVFAIL
        let resp = pipeline
            .handle(query.clone(), client.clone())
            .await
            .unwrap();
        assert_ne!(resp.metadata.response_code, ResponseCode::NoError);

        // Update rewrites table dynamically via ArcSwap
        let new_rewrites = RewritesConfig {
            auto_ptr: true,
            entries: vec![sito_rewrites::RewriteEntryConfig {
                domain: "router.lan".to_string(),
                r#type: "A".to_string(),
                answer: "192.168.1.1".to_string(),
                exception_clients: vec![],
            }],
        };
        rewrites.store(Arc::new(RewriteTable::new(new_rewrites)));

        // After update: query resolves immediately without pipeline restart!
        let resp2 = pipeline.handle(query, client).await.unwrap();
        assert_eq!(resp2.metadata.response_code, ResponseCode::NoError);
        assert_eq!(resp2.answers.len(), 1);
        assert_eq!(
            resp2.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 168, 1, 1)))
        );

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
