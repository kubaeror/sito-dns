# Build stage
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p sito --features "embed-ui"

# Runtime stage
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/sito /usr/bin/sito
USER nonroot
EXPOSE 53/udp 53/tcp
VOLUME ["/var/lib/sito"]
ENTRYPOINT ["/usr/bin/sito", "--config", "/etc/sito/config.toml"]
