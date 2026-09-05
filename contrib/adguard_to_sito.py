#!/usr/bin/env python3
"""
AdGuard Home to sito Configuration Converter
Converts AdGuardHome.yaml configurations into sito config.toml format.

Usage:
    python3 adguard_to_sito.py -i /path/to/AdGuardHome.yaml -o /etc/sito/config.toml
"""

import sys
import argparse
import re
from typing import Any, Dict, List

try:
    import yaml
except ImportError:
    yaml = None


def parse_yaml_fallback(text: str) -> Dict[str, Any]:
    """Basic line-based parser fallback if PyYAML is not installed."""
    data: Dict[str, Any] = {}
    current_section = ""
    for line in text.splitlines():
        line = line.rstrip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(" ") and ":" in line:
            current_section = line.split(":")[0].strip()
            data[current_section] = {}
    return data


def convert_blocking_mode(agh_mode: str) -> str:
    mapping = {
        "default": "zero_ip",
        "null_ip": "zero_ip",
        "nxdomain": "nxdomain",
        "refused": "refused",
        "custom_ip": "custom_ip",
    }
    return mapping.get(str(agh_mode).lower(), "zero_ip")


def convert_adguard_to_sito(agh_cfg: Dict[str, Any]) -> str:
    dns = agh_cfg.get("dns", {})
    tls = agh_cfg.get("tls", {})
    filtering = agh_cfg.get("filtering", {})
    clients = agh_cfg.get("clients", {})
    querylog = agh_cfg.get("querylog", {})
    stats = agh_cfg.get("stats", {})

    lines: List[str] = [
        "# Generated automatically from AdGuardHome.yaml by adguard_to_sito.py",
        "config_version = 1",
        "",
        "[server]",
        'role = "master"',
        'instance_name = "sito-migrated"',
        'data_dir = "/var/lib/sito"',
        'log_level = "info"',
        'log_format = "pretty"',
        "",
        "[dns]",
    ]

    # DNS bind
    bind_hosts = dns.get("bind_hosts", ["0.0.0.0"])
    bind_quoted = ", ".join(f'"{h}"' for h in bind_hosts)
    lines.append(f"bind = [{bind_quoted}]")
    lines.append(f"port = {dns.get('port', 53)}")

    # Encrypted transport ports
    if tls.get("enabled", False):
        lines.append(f"dot_port = {tls.get('port_dns_over_tls', 853)}")
        lines.append(f"doh_port = {tls.get('port_dns_over_https', 443)}")
        lines.append(f"doq_port = {tls.get('port_dns_over_quic', 853)}")
    else:
        lines.append("dot_port = 0")
        lines.append("doh_port = 0")
        lines.append("doq_port = 0")

    lines.append(f"rate_limit_per_ip = {dns.get('ratelimit', 20)}")
    lines.append(f"edns_udp_size = {dns.get('edns_client_subnet', {}).get('edns_udp_size', 1232) if isinstance(dns.get('edns_client_subnet'), dict) else 1232}")
    lines.append("")

    # DNS Cache
    lines.extend([
        "[dns.cache]",
        f"enabled = {str(dns.get('cache_enabled', True)).lower()}",
        f"size_mb = {max(16, int(dns.get('cache_size', 67108864) / (1024 * 1024)))}",
        f"min_ttl = {dns.get('cache_ttl_min', 60)}",
        f"max_ttl = {dns.get('cache_ttl_max', 86400)}",
        "prefetch = true",
        "serve_stale_hours = 12",
        "",
    ])

    # Upstreams
    upstreams = dns.get("upstream_dns", [])
    if not upstreams:
        upstreams = ["tls://dns.quad9.net", "https://cloudflare-dns.com/dns-query"]
    bootstrap = dns.get("bootstrap_dns", ["9.9.9.9", "1.1.1.1"])

    lines.append("[upstream]")
    lines.append("servers = [")
    for u in upstreams:
        lines.append(f'    "{u}",')
    lines.append("]")
    lines.append("bootstrap = [")
    for b in bootstrap:
        # Normalize plain IPs
        clean_b = b.split("://")[-1].split(":")[0]
        lines.append(f'    "{clean_b}",')
    lines.append("]")
    lines.append('strategy = "parallel"')
    lines.append("timeout_ms = 5000")
    lines.append("")

    # Filtering
    lines.extend([
        "[filtering]",
        f"enabled = {str(filtering.get('enabled', True)).lower()}",
        f'blocking_mode = "{convert_blocking_mode(dns.get("blocking_mode", "default"))}"',
        f"blocking_ttl = {dns.get('blocking_ipv4_ttl', 10)}",
        "cname_cloaking = true",
    ])

    # Custom rules
    user_rules = agh_cfg.get("user_rules", [])
    if user_rules:
        lines.append("custom_rules = [")
        for r in user_rules:
            escaped = r.replace('"', '\\"')
            lines.append(f'    "{escaped}",')
        lines.append("]")
    else:
        lines.append("custom_rules = []")
    lines.append("")

    # Subscription Filter Lists
    filters = agh_cfg.get("filters", [])
    for f in filters:
        name = f.get("name", "AdGuard List").replace('"', '\\"')
        url = f.get("url", "").replace('"', '\\"')
        if not url:
            continue
        enabled = str(f.get("enabled", True)).lower()
        lines.extend([
            "[[filtering.lists]]",
            f'name = "{name}"',
            f'url = "{url}"',
            f"enabled = {enabled}",
            "refresh_hours = 24",
            "",
        ])

    # Local rewrites
    rewrites = dns.get("rewrites", [])
    lines.append("[rewrites]")
    lines.append("auto_ptr = true")
    lines.append("")
    for rw in rewrites:
        domain = rw.get("domain", "")
        answer = rw.get("answer", "")
        if not domain or not answer:
            continue
        # Guess record type
        rtype = "A"
        if ":" in answer:
            rtype = "AAAA"
        elif not answer.replace(".", "").isdigit():
            rtype = "CNAME"
        lines.extend([
            "[[rewrites.entries]]",
            f'domain = "{domain}"',
            f'type = "{rtype}"',
            f'answer = "{answer}"',
            "exception_clients = []",
            "",
        ])

    # Clients
    persistent_clients = clients.get("persistent", [])
    if persistent_clients:
        lines.append("[clients]")
        for c in persistent_clients:
            c_name = c.get("name", "Client")
            c_ids = c.get("ids", [])
            ids_str = ", ".join(f'"{i}"' for i in c_ids)
            lines.extend([
                "[[clients.entries]]",
                f'name = "{c_name}"',
                f"ids = [{ids_str}]",
                f'group = "default"',
                f"safe_search = {str(c.get('safe_search', False)).lower()}",
                "",
            ])

    # Web & Auth
    http_port = agh_cfg.get("http", {}).get("port", 8080)
    lines.extend([
        "[web]",
        f"port = {http_port}",
        'bind = ["0.0.0.0"]',
        f"https = {str(tls.get('enabled', False)).lower()}",
    ])
    if tls.get("certificate_path"):
        lines.append(f'cert = "{tls.get("certificate_path")}"')
    if tls.get("private_key_path"):
        lines.append(f'key = "{tls.get("private_key_path")}"')
    lines.append("")

    # Stats
    lines.extend([
        "[stats]",
        f"query_log_enabled = {str(querylog.get('enabled', True)).lower()}",
        f"query_log_retention_days = {max(7, int(querylog.get('interval', 90)))}",
        f"anonymize_client_ip = {str(querylog.get('anonymize_client_ip', False)).lower()}",
        "prometheus_enabled = true",
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Convert AdGuardHome.yaml to sito config.toml")
    parser.add_argument("-i", "--input", required=True, help="Path to AdGuardHome.yaml")
    parser.add_argument("-o", "--output", help="Output path for config.toml (default: stdout)")

    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        content = f.read()

    if yaml is not None:
        agh_cfg = yaml.safe_load(content) or {}
    else:
        # Basic YAML fallback
        print("Warning: PyYAML not installed, performing regex/line extraction", file=sys.stderr)
        agh_cfg = parse_yaml_fallback(content)

    sito_toml = convert_adguard_to_sito(agh_cfg)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(sito_toml)
        print(f"Successfully converted '{args.input}' -> '{args.output}'")
    else:
        print(sito_toml)


if __name__ == "__main__":
    main()
