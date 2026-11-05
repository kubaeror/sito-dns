# Build stage (tag kept for readability, digest pinned for supply-chain integrity)
#
# The builder always runs natively on the build host (BUILDPLATFORM) and
# cross-compiles with the Debian GNU cross toolchains. This keeps the release
# build (fat LTO) out of QEMU for linux/arm64 and linux/arm/v7, where full
# binary emulation made it many times slower. Only the C dependencies need the
# cross compilers; the Rust side is driven by the target triple.
FROM --platform=$BUILDPLATFORM rust:1.99-bookworm@sha256:9181b56c2a21ab1d5e73cffe04fc762426d30aa7fac3c91141dd033f49a7fc8b AS builder

# BuildKit provides these built-in arguments for the requested target platform.
ARG TARGETARCH
ARG TARGETVARIANT

# Map the Docker platform to a Rust target triple and install the matching
# cross toolchain (amd64 builds natively). Persist the triple so the build step
# does not repeat the mapping.
RUN set -eux; \
    case "${TARGETARCH}${TARGETVARIANT}" in \
        amd64) \
            RUST_TARGET="x86_64-unknown-linux-gnu" ;; \
        arm64) \
            RUST_TARGET="aarch64-unknown-linux-gnu"; \
            apt-get update; \
            apt-get install -y --no-install-recommends \
                gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross; \
            rm -rf /var/lib/apt/lists/* ;; \
        armv7) \
            RUST_TARGET="armv7-unknown-linux-gnueabihf"; \
            apt-get update; \
            apt-get install -y --no-install-recommends \
                gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf libc6-dev-armhf-cross; \
            rm -rf /var/lib/apt/lists/* ;; \
        *) \
            echo "unsupported Docker platform: ${TARGETARCH}${TARGETVARIANT}" >&2; \
            exit 1 ;; \
    esac; \
    rustup target add "${RUST_TARGET}"; \
    printf '%s' "${RUST_TARGET}" > /rust-target

# Point cargo, cc-rs and cmake-rs at the cross toolchain for the non-native
# targets. Underscored variable names are the portable form accepted by both
# build helpers (CC_/CXX_/AR_ use the target triple with '-' replaced by '_').
ENV CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
    CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar \
    CC_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-gcc \
    CXX_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-g++ \
    AR_armv7_unknown_linux_gnueabihf=arm-linux-gnueabihf-ar \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER=arm-linux-gnueabihf-gcc

WORKDIR /src
COPY . .
# mimalloc is enabled for every architecture (amd64, arm64, armv7), matching
# the release archives built by .github/workflows/release.yml.
RUN RUST_TARGET="$(cat /rust-target)" && \
    cargo build --release --locked -p sito \
        --features "embed-ui,mimalloc" \
        --target "${RUST_TARGET}" && \
    cp "target/${RUST_TARGET}/release/sito" /sito
# Create the data directory with nonroot ownership. Docker initialises fresh
# named volumes from the image path, so the volume is writable by uid/gid
# 65532 without a privileged init step.
RUN mkdir -p /sito-data && chown 65532:65532 /sito-data && touch /sito-data/.keep
# The setup wizard persists config.toml under /etc/sito. Create that path with
# nonroot ownership so fresh named volumes (and the image path itself) are
# writable without a privileged init step. Bind mounts still need a one-time
# `chown 65532:65532` on the host.
RUN mkdir -p /sito-config && chown 65532:65532 /sito-config && touch /sito-config/.keep

# Runtime stage (tag kept for readability, digest pinned for supply-chain integrity)
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=builder /sito /usr/bin/sito
# Note: running as nonroot on privileged ports (<1024, such as 53, 443, 853) requires NET_BIND_SERVICE capability:
# In docker run: --cap-add=NET_BIND_SERVICE
# In docker-compose:
#   cap_add:
#     - NET_BIND_SERVICE
# Data directory ownership: fresh named volumes inherit the nonroot ownership
# below. Bind-mounted host directories must be handed to uid/gid 65532 once:
#   sudo chown -R 65532:65532 /path/on/host
# This includes HA certificate directories. Private keys stay mode 0600 but
# must be owned by 65532, otherwise the mTLS replication listener cannot read
# them (DNS health would still pass). Generate with `ha gen-certs --uid 65532
# --gid 65532` or chown the copied keys after generating them.
COPY --from=builder --chown=65532:65532 /sito-data/ /var/lib/sito/
COPY --from=builder --chown=65532:65532 /sito-config/ /etc/sito/
USER nonroot
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp 443/udp 8080/tcp 8953/tcp
VOLUME ["/var/lib/sito"]
# --setup-fallback keeps the container healthy while first-boot setup is
# pending; after setup completes the DNS probe must succeed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
ENTRYPOINT ["/usr/bin/sito", "--config", "/etc/sito/config.toml"]
