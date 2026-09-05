//! Acceptance tests for Phase M9 — Hardening, Performance, and the 1.0 Release.

use std::fs;
use std::path::Path;
use std::process::Command;
use subtle::ConstantTimeEq;

use sito_clients::registry::{extract_id_from_sni, extract_id_from_url_path};
use sito_core::config::{Config, FilterListConfig, FilteringConfig};
use sito_filter::parser::parse_line;
use sito_filter::structures::RuleSetBuilder;
use sito_filter::subscription::SubscriptionFetcher;
use sito_proto::{decode_message, encode_message};

#[test]
fn test_m9_security_ssrf_url_scheme_allowlist() {
    // 1. Check FilteringConfig validation rejects unpermitted schemes
    let mut config = FilteringConfig::default();
    config.lists.push(FilterListConfig {
        name: "Evil SSRF Gopher".to_string(),
        url: "gopher://127.0.0.1:70/1_malicious".to_string(),
        enabled: true,
        refresh_hours: Some(24),
    });
    assert!(
        config.validate().is_err(),
        "FilteringConfig must reject gopher:// scheme"
    );

    config.lists[0].url = "ftp://internal.repo/list.txt".to_string();
    assert!(
        config.validate().is_err(),
        "FilteringConfig must reject ftp:// scheme"
    );

    config.lists[0].url = "ldap://127.0.0.1/o=auth".to_string();
    assert!(
        config.validate().is_err(),
        "FilteringConfig must reject ldap:// scheme"
    );

    // Permitted schemes: https, http, file
    config.lists[0].url = "https://big.oisd.nl".to_string();
    assert!(config.validate().is_ok(), "https:// must be permitted");

    config.lists[0].url = "http://internal-pi.lan/custom.txt".to_string();
    assert!(config.validate().is_ok(), "http:// must be permitted");

    config.lists[0].url = "file:///var/lib/sito/local_rules.txt".to_string();
    assert!(config.validate().is_ok(), "file:// must be permitted");

    // 2. Check SubscriptionFetcher rejects non-http/https/file schemes directly
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let fetcher = SubscriptionFetcher::new(
        std::time::Duration::from_secs(5),
        1024 * 1024,
        0,
        std::time::Duration::from_millis(10),
    );

    let temp_dir = std::env::temp_dir().join(format!("sito_ssrf_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);

    rt.block_on(async {
        let err = fetcher
            .fetch_or_cached("gopher_list", "gopher://127.0.0.1:70/test", &temp_dir)
            .await
            .expect_err("Should reject gopher scheme");
        assert!(
            err.to_string().contains("unsupported scheme")
                || err.to_string().contains("Invalid URL")
        );

        let err2 = fetcher
            .fetch_or_cached("ftp_list", "ftp://fileserver/hosts", &temp_dir)
            .await
            .expect_err("Should reject ftp scheme");
        assert!(
            err2.to_string().contains("unsupported scheme")
                || err2.to_string().contains("Invalid URL")
        );
    });

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_m9_security_redos_adversarial_patterns() {
    // Test adversarial regex patterns that cause catastrophic backtracking in backtracking engines
    let adversarial_patterns = [
        r"^((a+)+)$",
        r"^((a|a)+)+$",
        r"^(a+)+b$",
        r"^(a|aa)+$",
        r"^[a-zA-Z0-9]+([._-][a-zA-Z0-9]+)*$",
    ];

    let mut builder = RuleSetBuilder::new();
    for (i, pat) in adversarial_patterns.iter().enumerate() {
        builder.add_regex(pat.to_string(), i as u32);
    }

    let mut interner = sito_filter::structures::LabelInterner::new();
    let compiled = builder.build(&mut interner);
    assert!(
        compiled.regex.is_some(),
        "Regex DFA must compile without backtracking errors"
    );

    // Evaluate matching in linear time against adversarial input strings (e.g. 50 'a' characters)
    let evil_input = "a".repeat(50) + "!";
    let mut candidates = Vec::new();
    let start = std::time::Instant::now();
    compiled.collect_candidates(&evil_input, &interner, &mut candidates);
    let elapsed = start.elapsed();

    assert!(
        elapsed < std::time::Duration::from_millis(50),
        "DFA matching took {elapsed:?}, must execute in strictly linear time < 50ms without catastrophic backtracking"
    );
}

#[test]
fn test_m9_security_constant_time_comparison() {
    let token_a = b"sito_4f8a12b3c4d5e6f7a8b9c0d1e2f3a4b5";
    let token_b = b"sito_4f8a12b3c4d5e6f7a8b9c0d1e2f3a4b5";
    let token_c = b"sito_4f8a12b3c4d5e6f7a8b9c0d1e2f3a4b6"; // 1 bit flip at end
    let token_d = b"sito_short";

    assert!(bool::from(token_a.ct_eq(token_b)));
    assert!(!bool::from(token_a.ct_eq(token_c)));
    assert!(!bool::from(token_a.as_slice().ct_eq(token_d.as_slice())));
}

#[test]
fn test_m9_fuzz_parser_sanity_runners() {
    let mut rng_seed: u64 = 0x1234_5678_9ABC_DEF0;
    let mut next_rand = || {
        rng_seed = rng_seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        rng_seed
    };

    // 1. ABP parser fuzz sanity (2,000 iterations)
    let chars = "abcdefghijklmnopqrstuvwxyz0123456789.-_/*|~@$^,=[]{}()!#";
    for _ in 0..2000 {
        let len = (next_rand() % 128) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let idx = (next_rand() as usize) % chars.len();
            s.push(chars.as_bytes()[idx] as char);
        }
        // Parser must never panic
        let _ = parse_line(&s, "fuzz", 1);
    }

    // 2. TOML parser fuzz sanity (1,000 iterations)
    let toml_chars = "abcdefghijklmnopqrstuvwxyz0123456789= \n\t\"'[]{}.,-_:#";
    for _ in 0..1000 {
        let len = (next_rand() % 256) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let idx = (next_rand() as usize) % toml_chars.len();
            s.push(toml_chars.as_bytes()[idx] as char);
        }
        // Config parser must never panic
        let _ = Config::from_toml_str(&s);
    }

    // 3. ClientID extractor fuzz sanity (2,000 iterations)
    for _ in 0..2000 {
        let len = (next_rand() % 120) as usize;
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let b = (next_rand() % 256) as u8;
            if let Ok(ch) = std::str::from_utf8(&[b]) {
                s.push_str(ch);
            }
        }
        let _ = extract_id_from_sni(&s);
        let _ = extract_id_from_url_path(&s);
    }

    // 4. DNS wire decode fuzz sanity (2,000 iterations)
    for _ in 0..2000 {
        let len = (next_rand() % 256) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = (next_rand() % 256) as u8;
        }
        if let Ok(msg) = decode_message(&buf) {
            let _ = encode_message(&msg);
        }
    }
}

#[test]
fn test_m9_migration_script_sanity() {
    let script_path = Path::new("../../contrib/adguard_to_sito.py");
    let full_path = if script_path.exists() {
        script_path.to_path_buf()
    } else {
        Path::new("contrib/adguard_to_sito.py").to_path_buf()
    };

    assert!(
        full_path.exists(),
        "Migration script must exist at {full_path:?}"
    );

    // Create a mock AdGuardHome.yaml
    let temp_dir = std::env::temp_dir().join(format!("sito_agh_test_{}", std::process::id()));
    let _ = fs::create_dir_all(&temp_dir);
    let agh_yaml_path = temp_dir.join("AdGuardHome.yaml");
    let out_toml_path = temp_dir.join("config.toml");

    let sample_agh_yaml = r#"
dns:
  bind_hosts:
    - 127.0.0.1
  port: 5354
  upstream_dns:
    - tls://1.1.1.1
    - https://dns.quad9.net/dns-query
  bootstrap_dns:
    - 9.9.9.9
    - 1.1.1.1
  blocking_mode: null_ip
  cache_size: 67108864
  cache_ttl_min: 60
  cache_ttl_max: 86400
  rewrites:
    - domain: "*.lan"
      answer: "192.168.1.1"
filtering:
  enabled: true
filters:
  - name: "AdGuard Base"
    url: "https://filters.adtidy.org/extension/chromium/filters/2.txt"
    enabled: true
user_rules:
  - "||tracker.example.com^"
  - "@@||safe.example.com^"
http:
  port: 8081
querylog:
  enabled: true
  interval: 90
  anonymize_client_ip: false
"#;

    fs::write(&agh_yaml_path, sample_agh_yaml).expect("write mock yaml");

    // Execute converter script
    let output = Command::new("python3")
        .arg(&full_path)
        .arg("-i")
        .arg(&agh_yaml_path)
        .arg("-o")
        .arg(&out_toml_path)
        .output()
        .expect("Failed to execute python3 adguard_to_sito.py");

    assert!(
        output.status.success(),
        "Converter script failed: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        out_toml_path.exists(),
        "Output config.toml must be generated"
    );

    // Validate generated TOML with sito Config parser
    let generated_toml = fs::read_to_string(&out_toml_path).expect("read generated toml");
    let parsed_config =
        Config::from_toml_str(&generated_toml).expect("Generated TOML must be valid sito config");

    assert_eq!(parsed_config.dns.port, 5354);
    assert_eq!(parsed_config.upstream.servers.len(), 2);
    assert_eq!(parsed_config.filtering.custom_rules.len(), 2);
    assert_eq!(parsed_config.filtering.lists.len(), 1);

    let _ = fs::remove_dir_all(temp_dir);
}

#[test]
fn test_m9_release_configuration_and_systemd() {
    let manifest_path = Path::new("../../Cargo.toml");
    let cargo_toml_path = if manifest_path.exists() {
        manifest_path.to_path_buf()
    } else {
        Path::new("Cargo.toml").to_path_buf()
    };

    let cargo_content = fs::read_to_string(&cargo_toml_path).expect("read Cargo.toml");

    // Verify workspace version is at least 1.0.0
    assert!(
        cargo_content.contains("version = \"1.1.0\"")
            || cargo_content.contains("version = \"1.0.1\"")
            || cargo_content.contains("version = \"1.0.0\""),
        "Workspace package version must be at least 1.0.0"
    );

    // Verify release profile optimization
    assert!(
        cargo_content.contains("lto = \"fat\""),
        "Release profile must use lto = 'fat'"
    );
    assert!(
        cargo_content.contains("codegen-units = 1"),
        "Release profile must use codegen-units = 1"
    );
    assert!(
        cargo_content.contains("panic = \"abort\""),
        "Release profile must use panic = 'abort'"
    );
    assert!(
        cargo_content.contains("strip = true"),
        "Release profile must use strip = true"
    );

    // Verify systemd service unit
    let service_path = Path::new("../../contrib/systemd/sito.service");
    let svc_full = if service_path.exists() {
        service_path.to_path_buf()
    } else {
        Path::new("contrib/systemd/sito.service").to_path_buf()
    };

    assert!(svc_full.exists(), "sito.service must exist");
    let svc_content = fs::read_to_string(&svc_full).expect("read sito.service");
    assert!(svc_content.contains("ProtectSystem=strict"));
    assert!(svc_content.contains("NoNewPrivileges=true"));
    assert!(svc_content.contains("CAP_NET_BIND_SERVICE"));
    assert!(svc_content.contains("LimitNOFILE=1048576"));

    // Verify install.sh script exists
    let install_path = Path::new("../../contrib/install.sh");
    let inst_full = if install_path.exists() {
        install_path.to_path_buf()
    } else {
        Path::new("contrib/install.sh").to_path_buf()
    };
    assert!(inst_full.exists(), "install.sh must exist");
}
