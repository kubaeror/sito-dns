# Build stage
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p sito --features "embed-ui"

# Runtime stage
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/sito /usr/bin/sito
# Note: running as nonroot on privileged ports (<1024, such as 53, 443, 853) requires NET_BIND_SERVICE capability:
# In docker run: --cap-add=NET_BIND_SERVICE
# In docker-compose:
#   cap_add:
#     - NET_BIND_SERVICE
USER nonroot
EXPOSE 53/udp 53/tcp 853/tcp 853/udp 443/tcp 8080/tcp
VOLUME ["/var/lib/sito"]
ENTRYPOINT ["/usr/bin/sito", "--config", "/etc/sito/config.toml"]
