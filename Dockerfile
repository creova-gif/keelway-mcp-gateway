# syntax=docker/dockerfile:1

FROM rust:1-bookworm AS builder

WORKDIR /app

# Cache workspace dependencies before copying full source.
COPY Cargo.toml Cargo.lock ./
COPY crates/keelway-cli/Cargo.toml crates/keelway-cli/Cargo.toml
COPY crates/keelway-engine/Cargo.toml crates/keelway-engine/Cargo.toml

RUN mkdir -p crates/keelway-cli/src crates/keelway-engine/src crates/keelway-engine/benches \
    && echo 'fn main() {}' > crates/keelway-cli/src/main.rs \
    && echo 'pub fn _stub() {}' > crates/keelway-engine/src/lib.rs \
    && echo 'fn main() {}' > crates/keelway-engine/benches/gateway_overhead.rs \
    && cargo build --release --locked --bin keelway \
    && rm -rf crates/keelway-cli/src crates/keelway-engine/src crates/keelway-engine/benches

# Build the actual keelway binary.
COPY crates ./crates
RUN touch crates/keelway-engine/src/lib.rs crates/keelway-cli/src/main.rs \
    && cargo build --release --locked --bin keelway

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 keelway \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin keelway \
    && mkdir -p /etc/keelway /var/lib/keelway \
    && chown 10001:10001 /etc/keelway /var/lib/keelway

COPY --from=builder /app/target/release/keelway /usr/local/bin/keelway

USER 10001:10001

ENV KEELWAY_BIND_ADDR=0.0.0.0:8080
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/keelway"]
CMD ["gateway", "up", "--config", "/etc/keelway/keelway.yaml"]
