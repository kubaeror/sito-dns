#!/usr/bin/env python3
"""
AdGuard Home to sito Configuration Converter
Converts AdGuardHome.yaml configurations into sito config.toml format.

Usage:
    python3 adguard_to_sito.py -i /path/to/AdGuardHome.yaml -o /etc/sito/config.toml
"""

import sys
import argparse
import ipaddress
import math
import re
from typing import Any, Dict, List, Optional

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


def as_int(value: Any, default: int) -> int:
    """Best-effort integer conversion that never raises."""
    if value is None or isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def parse_interval_days(value: Any, default: int = 90) -> int:
    """Maps AdGuard's `statistics.interval` to sito's `stats.retention_days`.

    AdGuard stores whole days in current releases; duration strings ("24h",
    "168h0m0s", "7d") are accepted too for configs written by other tools.
    Unparseable values fall back to `default` with a warning.
    """
    if value is None or isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return max(1, int(value))
    text = str(value).strip().lower()
    if not text:
        return default
    if re.fullmatch(r"(?:\d+(?:\.\d+)?[smhdw])+", text):
        seconds = 0.0
        for amount, unit in re.findall(r"(\d+(?:\.\d+)?)([smhdw])", text):
            seconds += float(amount) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit]
        return max(1, math.ceil(seconds / 86400))
    try:
        return max(1, int(text))
    except ValueError:
        print(
            f"Warning: unrecognized statistics.interval value {value!r}; using {default} days",
            file=sys.stderr,
        )
        return default


def normalize_upstream(value: str) -> Optional[str]:
    """Maps an AdGuard upstream URL to a sito-supported upstream.

    DoH (`https://`) and DoQ (`quic://`) are preserved exactly - converting
    them to `tls://` would change the transport. Returns None when the scheme
    has no sito equivalent, so the caller can skip the entry with a warning.
    """
    v = str(value).strip()
    lower = v.lower()
    if not v:
        return None
    if lower.startswith("https://"):
        return v
    if lower.startswith("http://"):
        print(f"Warning: upstream {v!r} uses plaintext http://; converting to https://", file=sys.stderr)
        return f"https://{v.split('://', 1)[1]}"
    if lower.startswith("h3://"):
        # sito has no HTTP/3-only upstream transport; https:// keeps DoH.
        return f"https://{v.split('://', 1)[1]}"
    if lower.startswith(("quic://", "tls://", "udp://")):
        return v
    if lower.startswith("tcp://"):
        # sito's plain upstream speaks UDP with TCP fallback.
        print(
            f"Notice: upstream {v!r} uses tcp://; treating it as a plain upstream",
            file=sys.stderr,
        )
        return v.split("://", 1)[1]
    if "://" in v:
        scheme = v.split("://", 1)[0]
        print(f"Warning: unsupported upstream scheme '{scheme}://' in {v!r}; skipping", file=sys.stderr)
        return None
    return v


def parse_bootstrap_ip(value: Any) -> Optional[str]:
    """Extracts an IP literal from an AdGuard bootstrap entry.

    Accepts `9.9.9.9`, `9.9.9.9:53`, `[2606:4700::1111]:53`,
    `https://1.1.1.1/dns-query` and bare IPv6 literals. Returns None for
    hostnames or anything else that is not an IP address: sito's
    `upstream.bootstrap` only accepts IPs.
    """
    v = str(value).strip()
    if not v:
        return None
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0]
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if v.startswith("["):
        end = v.find("]")
        if end == -1:
            return None
        host = v[1:end]
    else:
        host, sep, port = v.rpartition(":")
        if not sep or not port.isdigit():
            return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return None


def toml_quote(value: Any) -> str:
    """Renders a Python value as a TOML basic string with full escaping."""
    out = ['"']
    for ch in str(value):
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04X}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def convert_blocking_mode(dns: Dict[str, Any]) -> str:
    """Maps AdGuard's blocking mode (and custom IP) to sito's blocking_mode.

    sito accepts `custom_ip:<ip>`; the bare `custom_ip` value is invalid.
    """
    mode = str(dns.get("blocking_mode", "default")).lower()
    if mode == "custom_ip":
        # sito carries a single custom address: prefer IPv4, fall back to IPv6.
        ip = dns.get("blocking_ipv4") or dns.get("blocking_ipv6")
        return f"custom_ip:{ip}" if ip else "zero_ip"
    mapping = {
        "default": "zero_ip",
        "null_ip": "zero_ip",
        "nxdomain": "nxdomain",
        "refused": "refused",
    }
    return mapping.get(mode, "zero_ip")


def convert_adguard_to_sito(agh_cfg: Dict[str, Any]) -> str:
    dns = agh_cfg.get("dns", {})
    tls = agh_cfg.get("tls", {})
    filtering = agh_cfg.get("filtering", {})
    clients = agh_cfg.get("clients", {})
    # AdGuard stores retention under `statistics.interval` (int days).
    stats = agh_cfg.get("statistics") or agh_cfg.get("stats") or {}

    lines: List[str] = [
        "# Generated automatically from AdGuardHome.yaml by adguard_to_sito.py",
        "config_version = 2",
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

    # DNS bind (AdGuard uses an empty list to mean all interfaces)
    bind_hosts = dns.get("bind_hosts") or ["0.0.0.0"]
    bind_quoted = ", ".join(toml_quote(h) for h in bind_hosts)
    lines.append(f"bind = [{bind_quoted}]")
    lines.append(f"port = {dns.get('port', 53)}")

    # Encrypted transport ports. AdGuard's key is `port_https`; the newer
    # `port_dns_over_https` spelling is accepted as a fallback.
    if tls.get("enabled", False):
        lines.append(f"dot_port = {as_int(tls.get('port_dns_over_tls'), 853)}")
        lines.append(f"doh_port = {as_int(tls.get('port_https', tls.get('port_dns_over_https')), 443)}")
        lines.append(f"doq_port = {as_int(tls.get('port_dns_over_quic'), 853)}")
    else:
        lines.append("dot_port = 0")
        lines.append("doh_port = 0")
        lines.append("doq_port = 0")

    lines.append(f"rate_limit_per_ip = {dns.get('ratelimit', 20)}")
    # AdGuard has no EDNS buffer-size key; keep sito's spec-safe default.
    lines.append(f"edns_udp_size = {dns.get('edns_udp_size', 1232)}")
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

    # Upstreams. Only sito-supported schemes are emitted; unsupported entries
    # (for example sdns:// DNSCrypt stamps) are skipped with a warning.
    upstreams = dns.get("upstream_dns", [])
    if not isinstance(upstreams, list) or not upstreams:
        upstreams = ["tls://dns.quad9.net", "1.1.1.1:53"]
    converted_upstreams: List[str] = []
    for u in upstreams:
        converted = normalize_upstream(u)
        if converted is not None and converted not in converted_upstreams:
            converted_upstreams.append(converted)
    if not converted_upstreams:
        print("Warning: no supported upstreams found; using sito defaults", file=sys.stderr)
        converted_upstreams = ["tls://dns.quad9.net", "1.1.1.1:53"]

    # Bootstrap hosts must be IP literals; anything else is skipped because
    # sito would reject the whole config.
    bootstrap_entries = dns.get("bootstrap_dns") or ["9.9.9.9", "1.1.1.1"]
    if not isinstance(bootstrap_entries, list):
        bootstrap_entries = [bootstrap_entries]
    bootstrap_ips: List[str] = []
    for entry in bootstrap_entries:
        ip = parse_bootstrap_ip(entry)
        if ip is None:
            print(
                f"Warning: bootstrap entry {entry!r} is not an IP address; skipping it",
                file=sys.stderr,
            )
        elif ip not in bootstrap_ips:
            bootstrap_ips.append(ip)

    lines.append("[upstream]")
    lines.append("servers = [")
    for u in converted_upstreams:
        lines.append(f"    {toml_quote(u)},")
    lines.append("]")
    if bootstrap_ips:
        lines.append("bootstrap = [")
        for b in bootstrap_ips:
            lines.append(f"    {toml_quote(b)},")
        lines.append("]")
    else:
        lines.append("# No valid bootstrap IPs were found in the AdGuard config; leaving")
        lines.append("# bootstrap unset so sito uses its built-in defaults.")
    lines.append('strategy = "parallel"')
    lines.append("timeout_ms = 5000")
    lines.append("")

    # Filtering
    lines.extend([
        "[filtering]",
        f"enabled = {str(filtering.get('enabled', True)).lower()}",
        f"blocking_mode = {toml_quote(convert_blocking_mode(dns))}",
        # AdGuard stores the blocked-response TTL under filtering.
        f"blocking_ttl = {as_int(filtering.get('blocked_response_ttl'), 10)}",
        "cname_cloaking = true",
    ])

    # Custom rules
    user_rules = agh_cfg.get("user_rules", [])
    if user_rules:
        lines.append("custom_rules = [")
        for r in user_rules:
            lines.append(f"    {toml_quote(r)},")
        lines.append("]")
    else:
        lines.append("custom_rules = []")
    lines.append("")

    # Subscription Filter Lists
    filters = agh_cfg.get("filters", [])
    for f in filters:
        url = f.get("url", "")
        if not url:
            continue
        name = f.get("name", "AdGuard List")
        enabled = str(f.get("enabled", True)).lower()
        lines.extend([
            "[[filtering.lists]]",
            f"name = {toml_quote(name)}",
            f"url = {toml_quote(url)}",
            f"enabled = {enabled}",
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
            f"domain = {toml_quote(domain)}",
            f"type = {toml_quote(rtype)}",
            f"answer = {toml_quote(answer)}",
            "exception_clients = []",
            "",
        ])

    # Clients. AdGuard keeps per-client policy on the client; sito keeps
    # filtering policy on groups, so clients with filtering disabled are
    # routed to a generated `no-filtering` group and per-client upstreams are
    # carried over. Other AdGuard per-client toggles (parental, safe browsing)
    # have no per-client equivalent and are intentionally not emitted.
    persistent_clients = clients.get("persistent", [])
    if persistent_clients:
        if any(c.get("filtering_enabled", True) is False for c in persistent_clients):
            lines.extend([
                '[clients.groups."no-filtering"]',
                "filtering = false",
                "",
            ])
        lines.append("[clients]")
        for c in persistent_clients:
            c_name = c.get("name", "Client")
            c_ids = c.get("ids", [])
            ids_str = ", ".join(toml_quote(i) for i in c_ids)
            group = "default" if c.get("filtering_enabled", True) is not False else "no-filtering"
            lines.extend([
                "[[clients.entries]]",
                f"name = {toml_quote(c_name)}",
                f"ids = [{ids_str}]",
                f"group = {toml_quote(group)}",
            ])
            client_upstreams = c.get("upstreams") or []
            converted_client_upstreams = []
            for u in client_upstreams:
                converted = normalize_upstream(u)
                if converted is not None and converted not in converted_client_upstreams:
                    converted_client_upstreams.append(converted)
            if converted_client_upstreams:
                upstreams_str = ", ".join(
                    toml_quote(u) for u in converted_client_upstreams
                )
                lines.append(f"upstreams = [{upstreams_str}]")
                lines.append("use_global_upstreams = false")
            if c.get("ignore_querylog"):
                lines.append("ignore_query_log = true")
            if c.get("ignore_statistics"):
                lines.append("ignore_stats = true")
            lines.append("")

    # TLS (certificates for DoT/DoH)
    cert_path = tls.get("certificate_path")
    key_path = tls.get("private_key_path")
    if cert_path and key_path:
        lines.extend([
            "[tls]",
            f"cert = {toml_quote(cert_path)}",
            f"key = {toml_quote(key_path)}",
            "",
        ])

    # Web & Auth
    http_port = agh_cfg.get("http", {}).get("port", 8080)
    lines.extend([
        "[web]",
        "enabled = true",
        f"port = {http_port}",
        'bind = "0.0.0.0"',
        "metrics_auth = true",
        "",
        "[auth]",
        "session_ttl_hours = 24",
        "login_rate_limit = 5",
        "",
    ])

    # Stats & privacy (sito models query logging retention and anonymization
    # separately from AdGuard)
    lines.extend([
        "[stats]",
        # AdGuard stores its retention interval (days) under
        # `statistics.interval`; duration strings are accepted as well.
        f"retention_days = {parse_interval_days(stats.get('interval'), 90)}",
        "",
        "[privacy]",
        # AdGuard keeps client-IP anonymization in the dns section.
        f"anonymize_querylog = {str(dns.get('anonymize_client_ip', False)).lower()}",
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
