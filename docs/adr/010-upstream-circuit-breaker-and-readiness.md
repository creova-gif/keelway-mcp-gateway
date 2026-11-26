# ADR-010: Upstream Circuit Breaker, Readiness Probe, and Transport Modularization
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
As Keelway MCP Gateway mediates tool, resource, and prompt calls across multiple upstream MCP servers, a degraded or unresponsive upstream server can exhaust gateway worker tasks, accumulate queued HTTP requests, and cause cascading latency across healthy upstreams. Operators and orchestrators (such as Kubernetes) also need a dedicated readiness signal that reflects upstream circuit health, clean HTTP connection draining on `SIGTERM`/`SIGINT`, and a clean separation between MCP protocol routing (`mcp.rs`) and upstream transport management (`upstream.rs`).

## Decision
1. **Per-Server Bounded Circuit Breaker (`keelway_engine::circuit`):**
   - Introduce `CircuitState` (`Closed`, `Open`, `HalfOpen`) and `CircuitBreaker` in `crates/keelway-engine/src/circuit.rs` with configurable `failure_threshold` (default `5`) and `cooldown` (default `15s`).
   - Track state per upstream server alias in a mutex-guarded `BTreeMap`:
     - **`Closed`:** Requests pass through; consecutive failures increment the counter until `failure_threshold` is reached, tripping the circuit to `Open`.
     - **`Open`:** Requests fail fast with `-32003` (`KeelwayError::UpstreamUnavailable`) without touching the upstream transport. Once `cooldown` elapses, the next `before_call` transitions the server to `HalfOpen` with `probe_in_flight = true`.
     - **`HalfOpen`:** Only a single probe request is permitted (`probe_in_flight = true`); concurrent callers fail fast with `KeelwayError::UpstreamUnavailable`. A successful probe resets the circuit to `Closed`, while a failed probe immediately re-opens it (`Open`).
2. **Readiness Probe (`/readyz`) and Graceful HTTP Shutdown Drain:**
   - Expose `/readyz` on the HTTP server reporting per-server `CircuitState` snapshots so load balancers and orchestrators can observe degraded upstreams.
   - Handle `SIGTERM` and `SIGINT` in the HTTP server to stop accepting new connections and drain in-flight requests gracefully before exiting.
3. **Upstream Transport Modularization (`upstream.rs`):**
   - Extract `UpstreamDriver` transport logic (stdio child process management and HTTP/SSE client handling) out of `mcp.rs` into `upstream.rs` to keep MCP JSON-RPC dispatch decoupled from transport lifecycle details.

## Alternatives Considered
- **Global Gateway Circuit Breaker:** Rejected because a single failing upstream server would trip the breaker for all unrelated, healthy upstreams.
- **Per-Request Retries Without Circuit Breaking:** Rejected because retrying against a stalled or overloaded upstream amplifies tail latency and holds open gateway resources.
- **Keeping `UpstreamDriver` Inline in `mcp.rs`:** Rejected because `mcp.rs` mixes JSON-RPC routing, policy/budget enforcement, and transport I/O, making independent testing and maintenance harder.

## Consequences & Failure Modes
- **Fail-Fast During Cooldown:** While a server circuit is `Open`, callers immediately receive `-32003 UpstreamUnavailable` for up to `cooldown` even if the upstream recovers earlier.
- **Single-Probe Half-Open Contention:** Concurrent calls arriving at the exact moment `cooldown` expires will see one probe admitted and others rejected with `UpstreamUnavailable` until the probe completes.
- **In-Process State:** Circuit state is held in memory per gateway instance and resets on process restart.
