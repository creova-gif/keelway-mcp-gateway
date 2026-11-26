# ADR-011: Container Packaging, HTTP Modularization, Trace Correlation, and Circuit Gauge
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Deploying Keelway MCP Gateway in containerized environments (Kubernetes, Docker Compose, Cloud Run) requires a reproducible, minimal, non-root container image and a clean `.dockerignore` build context. At the same time, `crates/keelway-engine/src/mcp.rs` has grown to mix MCP JSON-RPC dispatch with Axum HTTP routing and middleware, operators need a direct response header (`x-trace-id`) to correlate HTTP responses with audit tape provenance, and Prometheus monitoring needs a numeric gauge (`keelway_circuits_open`) for open upstream circuit breakers alongside `/readyz`.

## Decision
1. **Non-Root Multi-Stage Container Build (`Dockerfile`, `.dockerignore`):**
   - Use a two-stage `Dockerfile`:
     - **Builder stage (`rust:1.85-bookworm`):** Pre-caches workspace dependencies and compiles the release binary via `cargo build --release --locked --bin keelway`.
     - **Runtime stage (`debian:bookworm-slim`):** Installs `ca-certificates` for outbound TLS verification, creates a dedicated non-root `keelway` system user/group (`USER keelway`), copies `/usr/local/bin/keelway`, exposes port `8080`, and sets `ENTRYPOINT ["/usr/local/bin/keelway"]` with default `CMD ["gateway", "up", "--config", "/etc/keelway/keelway.yaml"]`.
   - Add `.dockerignore` excluding `target/`, `.git/`, `.github/`, `.agents/`, `.gstack/`, `*.jsonl`, `.env*`, `docs/`, `benchmarks/`, and `examples/` so local build artifacts, secrets, and agent logs never enter the Docker build context.
2. **HTTP Handler Modularization (`http.rs`):**
   - Separate Axum HTTP router construction, endpoint handlers, header extraction/injection, and graceful shutdown wiring from `mcp.rs` into `crates/keelway-engine/src/http.rs`, keeping `mcp.rs` focused on JSON-RPC protocol routing, policy enforcement, and execution budgets.
3. **`x-trace-id` Response Correlation:**
   - Emit the `x-trace-id` header on gateway HTTP responses so callers and ingress proxies can correlate each HTTP response directly with its W3C `traceparent` / provenance identifier and hash-chained tape entry.
4. **`keelway_circuits_open` Observability Gauge:**
   - Expose the `keelway_circuits_open` Prometheus gauge in `/metrics` reporting the current number of upstream servers in the `Open` circuit state, enabling threshold-based alerting and dashboard panels without polling `/readyz`.

## Alternatives Considered
- **Single-Stage `rust:1.85-bookworm` Runtime Image:** Rejected because shipping the full Rust toolchain (~1.5 GB+) inflates image pull times and expands the container attack surface.
- **`scratch` or `distroless` Without Shell/CA Tooling:** Rejected in favor of `debian:bookworm-slim` with `ca-certificates` to match glibc dynamic linking for Rust `bookworm` builds cleanly while keeping image size small.
- **Keeping HTTP Handlers Inline in `mcp.rs`:** Rejected because coupling Axum HTTP transport details with JSON-RPC dispatch and policy logic increases file size and hinders independent maintenance.

## Consequences & Failure Modes
- **Config Mount Requirement:** The default `CMD` expects `/etc/keelway/keelway.yaml` to be mounted (or overridden via container arguments); starting the container without a config file will fail fast at startup.
- **Non-Root File Permissions:** Because the container runs as `USER keelway`, mounted configuration files, signing keys, and tape output directories must be readable (and writable where applicable) by the `keelway` user or group.
- **Gauge Aggregation Scope:** `keelway_circuits_open` reflects the count of open circuits per gateway instance; multi-replica deployments should aggregate or alert per pod/instance.
