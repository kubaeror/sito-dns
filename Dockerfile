# Build stage (tag kept for readability, digest pinned for supply-chain integrity)
FROM rust:1-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p sito --features "embed-ui,mimalloc"
# Create the data directory with nonroot ownership. Docker initialises fresh
# named volumes from the image path, so the volume is writable by uid/gid
# 65532 without a privileged init step.
RUN mkdir -p /sito-data && chown 65532:65532 /sito-data && touch /sito-data/.keep

# Runtime stage (tag kept for readability, digest pinned for supply-chain integrity)
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=builder /src/target/release/sito /usr/bin/sito
# Note: running as nonroot on privileged ports (<1024, such as 53, 443, 853) requires NET_BIND_SERVICE capability:
# In docker run: --cap-add=NET_BIND_SERVICE
# In docker-compose:
#   cap_add:
#     - NET_BIND_SERVICE
# Data directory ownership: fresh named volumes inherit the nonroot ownership
# below. Bind-mounted host directories must be handed to uid/gid 65532 once:
#   sudo chown -R 65532:65532 /path/on/host
COPY --from=builder --chown=65532:65532 /sito-data/ /var/lib/sito/
USER nonroot
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp 443/udp 8080/tcp 8953/tcp
VOLUME ["/var/lib/sito"]
# --setup-fallback keeps the container healthy while first-boot setup is
# pending; after setup completes the DNS probe must succeed.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/bin/sito", "--config", "/etc/sito/config.toml", "healthcheck", "--setup-fallback"]
ENTRYPOINT ["/usr/bin/sito", "--config", "/etc/sito/config.toml"]
