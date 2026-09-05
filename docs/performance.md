# Performance Tuning and System Optimization Guide

This guide details the kernel sysctl parameters, operating system limits, build profiles, and hardware optimizations required to operate **sito** at line-rate scale (≥ 500,000 QPS) and ensure zero packet loss under heavy query bursts.

---

## 1. Linux Kernel `sysctl` Tuning (Section 16.3)

Standard Linux distribution defaults are optimized for general-purpose workloads, restricting network socket buffers to a few hundred kilobytes. Under bursts of DNS traffic, small kernel socket buffers overflow almost instantly, leading to silent UDP packet drops.

Add the following configuration to `/etc/sysctl.d/99-sito.conf`:

```ini
# Maximum socket receive buffer size (128 MB)
net.core.rmem_max = 134217728

# Maximum socket send buffer size (128 MB)
net.core.wmem_max = 134217728

# Default socket receive and send buffer sizes (2 MB)
net.core.rmem_default = 2097152
net.core.wmem_default = 2097152

# Maximum number of incoming packets queued on the network interface before handing to sockets
net.core.netdev_max_backlog = 250000

# Maximum TCP listen backlog queue for incoming connections (DoT, DoH H2, Web API)
net.core.somaxconn = 4096

# Minimum buffer reservation for UDP sockets under memory pressure
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# System-wide file descriptor limit (enables >1M concurrent TCP/DoT/DoH descriptors)
fs.file-max = 2097152
```

Apply immediately with:
```bash
sudo sysctl --system
```

### Parameter Rationale:
* **`net.core.rmem_max` & `wmem_max` (128 MB):** Allows `sito`'s multi-worker UDP listeners to set large socket buffer sizes (`SO_RCVBUF` / `SO_SNDBUF`), absorbing transient microbursts without drops.
* **`net.core.netdev_max_backlog` (250,000):** High-traffic DNS queries can arrival at several hundred thousand packets per second. Increasing this queue prevents the kernel network device layer from dropping ingress packets before they reach the protocol stack.
* **`net.core.somaxconn` (4096):** Prevents SYN flood drops on DoT (port 853) and DoH (port 443) during simultaneous TLS connection spikes.
* **`fs.file-max` (2,097,152):** Each active TCP/TLS connection uses a file descriptor. High-concurrency servers require abundant descriptor ceilings.

---

## 2. Process and File Descriptor Limits (`limits.conf`)

Ensure the `sito` service account is permitted to open necessary file descriptors and bind privileged ports without root privileges:

In `/etc/security/limits.d/99-sito.conf`:
```
sito    soft    nofile    1048576
sito    hard    nofile    1048576
```

In the systemd service unit (`/etc/systemd/system/sito.service`):
```ini
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

---

## 3. Network Interface Card (NIC) & RSS Tuning

### 3.1 Receive Side Scaling (RSS) & `SO_REUSEPORT`
`sito` binds multiple worker sockets using Linux `SO_REUSEPORT`. The Linux kernel distributes incoming UDP packets across these workers using a 4-tuple hash `(src_ip, src_port, dst_ip, dst_port)`.

To maximize multi-core throughput:
1. Ensure your NIC has multiple hardware RX queues equal to or greater than the number of worker threads:
   ```bash
   sudo ethtool -L eth0 combined 8
   ```
2. Enlarge the NIC ring buffers to prevent hardware-level packet drops:
   ```bash
   sudo ethtool -G eth0 rx 4096 tx 4096
   ```
3. Enable UDP 4-tuple RSS hashing in the NIC driver:
   ```bash
   sudo ethtool -K eth0 rxhash on
   sudo ethtool -N eth0 rx-flow-hash udp4 sdfn
   ```

---

## 4. Build Profile & Allocator Optimization

### 4.1 Production Release Profile
`sito` ships with a heavily optimized Cargo profile configured in `Cargo.toml`:

```toml
[profile.release]
lto = "fat"              # Cross-crate link-time optimization
codegen-units = 1        # Single-unit compilation for maximum cross-function inlining
panic = "abort"          # Eliminates unwinding landing pads and EH frames
strip = true             # Strips symbol tables and debuginfo
```

### 4.2 Global Allocator: `mimalloc`
For production environments, building `sito` with the optional `mimalloc` feature eliminates memory fragmentation caused by frequent cache evictions and dynamic list compilation:

```bash
cargo build --release --locked --features "embed-ui,mimalloc"
```

### 4.3 Profile-Guided Optimization (PGO)
For environments demanding every last drop of performance, compile with PGO:

1. Install `cargo-pgo`:
   ```bash
   cargo install cargo-pgo
   ```
2. Build instrumented binary:
   ```bash
   cargo pgo build --release --features "mimalloc"
   ```
3. Run representative benchmark load for 5 minutes:
   ```bash
   ./target/x86_64-unknown-linux-gnu/release/sito &
   dnsperf -s 127.0.0.1 -p 53 -d /path/to/tranco.txt -c 50 -l 300
   kill -INT %1
   ```
4. Build optimized binary with captured profile:
   ```bash
   cargo pgo optimize --release --features "mimalloc"
   ```
PGO provides an additional **8% to 15% throughput gain** by optimizing branch prediction and instruction cache locality for DNS query dispatch paths.
