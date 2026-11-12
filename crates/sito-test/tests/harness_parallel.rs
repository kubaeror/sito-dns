//! Parallel harness regression: multiple in-process servers reserve distinct
//! ports and stay queryable (WP-1.8).

use hickory_proto::rr::RecordType;
use sito_core::config::Config;
use sito_test::{MockDnsServer, TestServerInstance};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_harness_instances_get_distinct_ports_and_serve_queries() {
    const SERVERS: usize = 4;
    // Four workers plus this task: every server must be fully started (and
    // still alive) before the distinctness assertion runs, so a released port
    // that the OS later reuses cannot cause a false failure.
    let barrier = Arc::new(tokio::sync::Barrier::new(SERVERS + 1));
    let mut tasks = Vec::new();
    for index in 0..SERVERS as u8 {
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            let upstream = MockDnsServer::spawn().await.expect("mock upstream");
            upstream.add_a_record(
                &format!("parallel-{index}.test"),
                Ipv4Addr::new(192, 0, 2, index),
                60,
            );

            let mut config = Config::default();
            config.dns.dnssec.validate = false;
            config.upstream.servers = vec![upstream.addr().to_string()];

            let server = TestServerInstance::spawn(config)
                .await
                .expect("spawn parallel server");
            let response = server
                .client()
                .query_udp(&format!("parallel-{index}.test"), RecordType::A)
                .await
                .expect("query parallel server");
            assert_eq!(response.answers.len(), 1);

            barrier.wait().await;
            (server.port(), server)
        }));
    }

    tokio::time::timeout(Duration::from_secs(60), barrier.wait())
        .await
        .expect("all parallel harness tasks must reach the barrier");

    let mut servers = Vec::new();
    for task in tasks {
        servers.push(task.await.expect("parallel harness task"));
    }
    servers.sort_by_key(|(port, _)| *port);
    let ports: Vec<u16> = servers.iter().map(|(port, _)| *port).collect();
    for window in ports.windows(2) {
        assert_ne!(
            window[0], window[1],
            "concurrent harness instances must reserve distinct ports, got {ports:?}"
        );
    }

    for (_, server) in servers {
        server.shutdown().await.expect("shutdown parallel server");
    }
}
