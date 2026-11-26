# ADR-012: Security Headers Middleware, Budget Eviction, Health/Inflight Telemetry, and Deployment Manifests
- **Status:** Proposed
- **Owner:** Justin Mafie

## Context
As Keelway MCP Gateway moves toward containerized production deployments, four operational gaps remain:
1. **HTTP Security Headers Scope:** Currently only `ui_console_handler` (`/ui`) sets `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. API, observability, and P-10 routes (`/mcp`, `/healthz`, `/readyz`, `/metrics`, `/events`, `/p10/pending`, `/p10/resolve`) do not inherit these defensive headers uniformly.
2. **Unbounded `BudgetTracker` Map Growth:** `BudgetTracker` stores per-`(org_id, agent_id, server)` `BucketState` entries in a `HashMap`. Over long-lived gateway processes with ephemeral agent IDs, inactive buckets accumulate indefinitely even after their 60-second rate-limit window expires and `in_flight` returns to `0`.
3. **Liveness Uptime & Upstream In-Flight Visibility:** `/healthz` currently returns only `{"status": "ok"}`, and Prometheus `/metrics` lacks a gauge for active in-flight upstream calls (`keelway_active_upstream_inflight`) to pair with `keelway_circuits_open` during capacity and drain investigations.
4. **Reference Deployment Artifacts:** Operators need reproducible reference manifests (`deploy/compose.yaml`, `deploy/prometheus.yml`) and deployment documentation (`docs/DEPLOYMENT.md`) aligned with the non-root `Dockerfile`.

## Decision
1. **Router-Wide Security Headers Middleware (`http.rs`):**
   - Apply an Axum/Tower middleware layer across the entire `build_http_router` router to inject `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` on all HTTP responses (while keeping `/ui`'s stricter `Content-Security-Policy` and `X-Frame-Options: DENY` headers).
2. **`BudgetTracker` Idle Bucket Eviction (`budget.rs`):**
   - Periodically or opportunistically evict idle entries from `BudgetTracker::state` where `in_flight == 0` and all recorded timestamps have aged past the 60-second `RATE_LIMIT_WINDOW`, bounding memory proportional to active callers rather than historical callers.
3. **`/healthz` Uptime and `keelway_active_upstream_inflight` Metric (`http.rs`, `metrics.rs`):**
   - Extend `/healthz` to include process uptime (`uptime_secs`) alongside `"status": "ok"` for quick restart detection.
   - Expose `keelway_active_upstream_inflight` as a Prometheus gauge in `/metrics` tracking the number of currently active upstream tool/resource/prompt calls.
4. **Reference Compose, Prometheus, and Deployment Docs (`deploy/`, `docs/DEPLOYMENT.md`):**
   - Provide `deploy/compose.yaml` (hardened `keelway` service with `read_only: true`, `/tmp` tmpfs, `KEELWAY_BIND_ADDR=0.0.0.0:8080`, `/healthz` healthcheck, and a `prometheus` service) and `deploy/prometheus.yml` (15s scrape of `keelway:8080/metrics`), documented in `docs/DEPLOYMENT.md`.

## Alternatives Considered
- **Per-Handler Security Headers:** Rejected because duplicating `X-Content-Type-Options` and `Cache-Control` across every handler is error-prone when new routes are added.
- **External Reverse Proxy for All Security Headers:** Rejected as the sole mechanism because gateways are frequently deployed directly behind L4 load balancers or accessed over cluster-internal networks.
- **Fixed-Capacity LRU Cache for `BudgetTracker`:** Rejected because evicting an active bucket under high cardinality could reset rate-limit windows prematurely; evicting only idle buckets (`in_flight == 0` and expired timestamps) preserves strict budget enforcement.

## Consequences & Failure Modes
- **`Cache-Control: no-store` on All Routes:** Prevents intermediary or browser caching of `/metrics`, `/p10/pending`, and `/mcp` responses; if static assets with long-lived caching are ever served from the gateway, they must explicitly opt out.
- **Eviction Lock Contention:** Evicting idle buckets under the `BudgetTracker` mutex should be bounded (e.g., amortized or interval-gated) so large maps do not stall hot-path `acquire()` calls.
- **Read-Only Container Filesystem:** Running with `read_only: true` in `deploy/compose.yaml` requires any persistent audit tape path (`keelway-tape.jsonl`) to be explicitly mounted on a writable volume if tape persistence is enabled.
