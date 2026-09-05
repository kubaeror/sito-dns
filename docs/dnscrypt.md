# DNSCrypt Protocol Support and Proxy Integration

This document outlines `sito`'s approach to the **DNSCrypt v2** protocol, formalizing the architectural rationale from [ADR-0006](adr/0006-dnscrypt-stretch-goal.md) and providing practical production integration guides.

---

## 1. Executive Summary & Architectural Decision (ADR-0006)

DNSCrypt was an early encrypted DNS protocol developed prior to standardized IETF encrypted DNS protocols. It uses public-key cryptography to authenticate and encrypt DNS traffic between client and resolver over UDP and TCP.

In evaluating native protocol support for `sito`:
- **IETF Industry Standards**: Modern client operating systems (Android, iOS, macOS, Windows 11, systemd-resolved) natively implement standard IETF encrypted transports: **DoT** (RFC 7858), **DoH** (RFC 8484), **DoQ** (RFC 9250), and **DoH3** (RFC 9250 / RFC 9114). `sito` natively supports all four IETF protocols out-of-the-box.
- **Rust Ecosystem State**: As documented in [ADR-0006](adr/0006-dnscrypt-stretch-goal.md), there is currently no active, production-grade, independently audited DNSCrypt v2 server crate in the Rust ecosystem. Developing a custom cryptographic state engine from scratch would introduce unwarranted cryptographic risk and divert resources from modern protocols.
- **Decision**: Native DNSCrypt remains an optional stretch goal. For environments requiring DNSCrypt downstream termination or upstream resolution, `sito` recommends deploying verified proxy bridges (`dnscrypt-wrapper` or `dnscrypt-proxy`) terminating traffic to `sito`'s local loopback listeners.

---

## 2. DNSCrypt Protocol Architecture

DNSCrypt operates at the application layer over UDP and TCP (typically on port 443 or 8443):

### 2.1 Cryptographic Primitives
- **Key Exchange & Encryption**: X25519 (Curve25519) Diffie-Hellman key exchange with XSalsa20 stream cipher and Poly1305 MAC (`crypto_box_curve25519xsalsa20poly1305`).
- **Resolver Authentication**: Ed25519 digital signature keys sign temporary resolver certificate records (`TXT` queries for the resolver's provider name).
- **Session Keys**: Ephemeral client keys generate unique shared secrets per transaction or session, preventing passive replay and cross-session correlation.

### 2.2 Packet Framing & Padding
- **Query Structure**: A 8-byte resolver magic header, followed by the client public key (32 bytes), client nonce (12 bytes), and the encrypted/authenticated payload containing the DNS query.
- **Padding**: Queries are padded to a minimum size (typically 256 bytes) or multiples of 64 bytes to mitigate traffic analysis and size-based side-channel leaks.

---

## 3. Production Deployment: Downstream Termination via `dnscrypt-wrapper`

To accept DNSCrypt connections from legacy clients, deploy `dnscrypt-wrapper` as a sidecar or reverse proxy in front of `sito`.

```
+------------------+         DNSCrypt (UDP/TCP 8443)         +--------------------+
| DNSCrypt Clients | --------------------------------------> |  dnscrypt-wrapper  |
+------------------+                                         +---------+----------+
                                                                       | Plain DNS
                                                                       | (127.0.0.1:53)
                                                                       v
                                                             +--------------------+
                                                             |    sito daemon     |
                                                             +--------------------+
```

### 3.1 Setup `dnscrypt-wrapper`

1. **Install `dnscrypt-wrapper`**:
   ```bash
   sudo apt-get install dnscrypt-wrapper
   # or build from source / run via docker:
   # docker run -d --net=host jedisct1/dnscrypt-server
   ```

2. **Generate Provider Keys and Certificates**:
   ```bash
   mkdir -p /etc/dnscrypt-wrapper/keys
   cd /etc/dnscrypt-wrapper/keys
   dnscrypt-wrapper --gen-provider-keypair --provider-name=2.dnscrypt-cert.example.com
   dnscrypt-wrapper --gen-crypt-keypair
   dnscrypt-wrapper --gen-cert-file --crypt-secretkey-file=crypt_secret.key \
       --provider-cert-file=provider.cert --provider-secretkey-file=provider_secret.key \
       --min-lifetime=86400
   ```

3. **Run `dnscrypt-wrapper` Forwarding to `sito`**:
   ```bash
   dnscrypt-wrapper --listen-address=0.0.0.0:8443 \
       --resolver-address=127.0.0.1:53 \
       --provider-name=2.dnscrypt-cert.example.com \
       --crypt-secretkey-file=/etc/dnscrypt-wrapper/keys/crypt_secret.key \
       --provider-cert-file=/etc/dnscrypt-wrapper/keys/provider.cert
   ```

4. **Configure `sito`**:
   Ensure `sito` binds to `127.0.0.1:53`:
   ```toml
   [dns]
   bind = ["127.0.0.1", "::1"]
   port = 53
   ```

---

## 4. Production Deployment: Upstream Resolution via `dnscrypt-proxy`

To route `sito` queries upstream through remote DNSCrypt resolvers:

```
+--------------------+           Plain DNS            +--------------------+        DNSCrypt        +--------------------+
| sito DNS Resolver  | -----------------------------> |   dnscrypt-proxy   | ---------------------> | Public DNSCrypt    |
|                    |         (127.0.0.1:5353)       | (local forwarder)  |     (UDP/TCP 443)      | Upstream Resolvers |
+--------------------+                                +--------------------+                        +--------------------+
```

### 4.1 Setup `dnscrypt-proxy`

1. Configure `dnscrypt-proxy.toml`:
   ```toml
   listen_addresses = ['127.0.0.1:5353']
   server_names = ['quad9-dnscrypt-ip4-filter-pri', 'cisco']
   doh_servers = false
   dnscrypt_servers = true
   require_dnssec = true
   ```

2. Configure `sito` upstream in `config.toml`:
   ```toml
   [upstream]
   strategy = "parallel"
   servers = [
     "127.0.0.1:5353",
   ]
   timeout_ms = 2000
   ```

---

## 5. Future Native Implementation Roadmap

If a production-grade, memory-safe, audited DNSCrypt implementation in Rust matures, native integration into `sito-transport` will follow this structure:

1. **Listener Module (`sito-transport/src/dnscrypt.rs`)**:
   - Parse DNSCrypt magic headers and provider certificate `TXT` records.
   - Decrypt payload using `x25519-dalek` and `chacha20poly1305` or `crypto_box`.
   - Pass decoded `sito_proto::Message` directly into the existing `DnsPipeline`.
2. **Configuration**:
   - `[dns.dnscrypt]` section with `port`, `provider_name`, `provider_key`, and `cert_file`.
3. **Metrics**:
   - Prometheus label `proto="dnscrypt"`.
