#!/usr/bin/env python3
"""Self-test for contrib/adguard_to_sito.py.

Converts a realistic AdGuardHome.yaml fixture, parses the generated TOML and
asserts the mapping of every key that regressed in the audit (WP-8.4). Run:

    python3 contrib/tests/test_adguard_to_sito.py

Requires PyYAML (the converter uses it for real inputs) and Python 3.11+
(tomllib). No test framework needed.
"""

import importlib.util
import pathlib
import sys
import tomllib

try:
    import yaml
except ImportError:
    print("Error: PyYAML is required to run this self-test.", file=sys.stderr)
    sys.exit(1)

HERE = pathlib.Path(__file__).resolve().parent
CONVERTER_PATH = HERE.parent / "adguard_to_sito.py"
FIXTURE_PATH = HERE / "adguardhome_fixture.yaml"

spec = importlib.util.spec_from_file_location("adguard_to_sito", CONVERTER_PATH)
converter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(converter)


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def check(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def main() -> None:
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        agh_cfg = yaml.safe_load(f)

    toml_text = converter.convert_adguard_to_sito(agh_cfg)
    data = tomllib.loads(toml_text)

    # --- statistics.interval: int days and duration strings -----------------
    check(data["stats"]["retention_days"] == 14, "statistics.interval=14 was not mapped to retention_days")
    check(converter.parse_interval_days(2160, 90) == 2160, "int interval not accepted")
    check(converter.parse_interval_days("2160h0m0s", 90) == 90, "Go duration string not accepted")
    check(converter.parse_interval_days("24h", 90) == 1, "24h duration not accepted")
    check(converter.parse_interval_days("7d", 90) == 7, "day duration not accepted")
    check(converter.parse_interval_days("bogus", 90) == 90, "invalid interval did not fall back")

    # --- TLS ports: port_https is the DoH port ------------------------------
    check(data["dns"]["doh_port"] == 8443, "tls.port_https was not mapped to dns.doh_port")
    check(data["dns"]["dot_port"] == 8853, "tls.port_dns_over_tls was not mapped")
    check(data["dns"]["doq_port"] == 8853, "tls.port_dns_over_quic was not mapped")

    # --- filtering.blocked_response_ttl ------------------------------------
    check(data["filtering"]["blocking_ttl"] == 30, "filtering.blocked_response_ttl was not mapped")
    check(
        data["filtering"]["blocking_mode"] == "custom_ip:192.0.2.1",
        "dns.blocking_mode custom_ip was not mapped",
    )

    # --- dns.anonymize_client_ip -------------------------------------------
    check(
        data["privacy"]["anonymize_querylog"] is True,
        "dns.anonymize_client_ip was not mapped to privacy.anonymize_querylog",
    )

    # --- upstream schemes: DoH/DoQ preserved, sdns:// skipped ---------------
    servers = data["upstream"]["servers"]
    check(
        "https://dns.quad9.net/dns-query" in servers,
        "https:// upstream was downgraded or dropped",
    )
    check("quic://dns.adguard-dns.com" in servers, "quic:// upstream was downgraded or dropped")
    check("tls://1.1.1.1" in servers, "tls:// upstream was altered")
    check("9.9.9.9" in servers, "plain upstream was altered")
    check(
        not any("tls://dns.quad9.net" in s or "tls://dns.adguard-dns.com" in s for s in servers),
        "https://quic upstreams were downgraded to tls://",
    )
    check(not any("sdns://" in s for s in servers), "unsupported sdns:// upstream was emitted")

    # --- bootstrap: IPs only, hostnames skipped -----------------------------
    bootstrap = data["upstream"]["bootstrap"]
    check(bootstrap == ["9.9.9.9", "1.1.1.1"], f"bootstrap is not IP-only: {bootstrap!r}")
    check(
        all(converter.parse_bootstrap_ip(b) is not None for b in bootstrap),
        "bootstrap contains a non-IP entry",
    )
    check(converter.parse_bootstrap_ip("[2606:4700:4700::1111]:53") == "2606:4700:4700::1111", "IPv6 bootstrap")
    check(converter.parse_bootstrap_ip("dns.quad9.net") is None, "hostname bootstrap accepted")

    # --- clients, web, tls, rewrites ---------------------------------------
    check(data["web"]["port"] == 3000, "http.port was not mapped to web.port")
    check(data["tls"]["cert"] == "/etc/sito/cert.pem", "tls certificate path missing")
    check(len(data["clients"]["entries"]) == 2, "persistent clients were not emitted")
    guest = next(c for c in data["clients"]["entries"] if c["name"] == "Guest")
    check(guest["group"] == "no-filtering", "filtering-disabled client was not grouped")
    check(guest["ignore_query_log"] is True and guest["ignore_stats"] is True, "client toggles lost")
    laptop = next(c for c in data["clients"]["entries"] if c["name"] == "Laptop")
    check(
        laptop["upstreams"] == ["https://dns.google/dns-query"],
        "per-client https:// upstream was downgraded",
    )
    check(data["rewrites"]["entries"][0]["type"] == "A", "rewrite type inference changed")

    print("OK: contrib/adguard_to_sito.py self-test passed")


if __name__ == "__main__":
    main()
