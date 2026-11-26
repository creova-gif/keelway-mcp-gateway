# ADR-013: Token Digest Auth, StreamableHttp SSE Interop, Prometheus Alerts, and Kubernetes Manifests
- **Status:** Proposed
- **Owner:** Justin Mafie

## Context
As Keelway MCP Gateway is prepared for multi-tenant production clusters and heterogeneous upstream MCP servers, four areas require formal architectural alignment:
1. **In-Memory Static Token Hygiene (`mcp.rs`):** Retaining raw static bearer tokens as `HashMap<String, Principal>` keys keeps plaintext credentials resident in heap memory for the lifetime of the gateway process.
2. **MCP `StreamableHttp` SSE & Protocol Header Interoperability (`upstream.rs`):** Conformant MCP `StreamableHttp` servers may require `Accept: application/json, text/event-stream`, `MCP-Protocol-Version`, and `Mcp-Session-Id` headers, and may respond with `text/event-stream` (`data:` SSE frames) rather than a bare `application/json` body.
3. **Actionable Prometheus Alerting (`deploy/alerts.yml`):** Scraping `/metrics` alone does not define operational thresholds for open upstream circuits, elevated upstream error rates, P-10 human-approval queue backlogs, or Cedar policy denial spikes.
4. **Hardened Kubernetes Reference Manifests (`deploy/k8s/`):** Operators deploying to Kubernetes need baseline `Deployment` and `Service` manifests that enforce non-root execution, read-only root filesystems, dropped Linux capabilities, graceful shutdown, and Prometheus scrape annotations.

## Decision
1. **SHA-256 Static Token Digest Storage (`crates/keelway-engine/src/mcp.rs`):**
   - Store resolved static bearer tokens in `GatewayRuntime::token_digests` as `HashMap<[u8; 32], Principal>` keyed by `Sha256::digest(token.as_bytes())`.
   - `authenticate_bearer` hashes the incoming `Bearer` token with SHA-256 and performs a fixed-size `[u8; 32]` lookup, avoiding plaintext token retention in the lookup table.
2. **MCP `StreamableHttp` SSE Response Unwrapping & Protocol Headers (`upstream.rs`):**
   - Send `Accept: application/json, text/event-stream` along with MCP protocol/session headers (`MCP-Protocol-Version` and, when established, `Mcp-Session-Id`) on `StreamableHttp` upstream requests.
   - When an upstream responds with `Content-Type: text/event-stream`, stream the response through the sliding-window Aho-Corasick `SecretScrubber` first, then unwrap SSE `data:` event lines into the JSON-RPC response payload before error/result extraction.
3. **Prometheus Alerting Rules (`deploy/alerts.yml`):**
   - Provide a `keelway_gateway` Prometheus rule group defining:
     - `KeelwayUpstreamCircuitOpen`: `keelway_circuits_open > 0` for `1m`
     - `KeelwayUpstreamErrorsHigh`: `rate(keelway_upstream_errors_total[5m]) > 0.1` for `2m`
     - `KeelwayP10QueueBacklog`: `keelway_p10_pending > 10` for `5m`
     - `KeelwayPolicyDenySpike`: `rate(keelway_calls_total{outcome="denied_policy"}[5m]) > 1` for `2m`
4. **Hardened Kubernetes Manifests (`deploy/k8s/deployment.yaml`, `deploy/k8s/service.yaml`):**
   - `Deployment` (`keelway-gateway`): enforces `runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: ["ALL"]`, `KEELWAY_BIND_ADDR: "0.0.0.0:8080"`, `/healthz` liveness and `/readyz` readiness probes, `terminationGracePeriodSeconds: 30`, a read-only ConfigMap mount at `/etc/keelway`, a PVC mount at `/var/lib/keelway`, and a memory-backed `emptyDir` at `/tmp`.
   - `Service` (`keelway-gateway`): exposes `ClusterIP` port `8080` with `prometheus.io/scrape: "true"`, `prometheus.io/path: "/metrics"`, and `prometheus.io/port: "8080"` annotations.

## Alternatives Considered
- **Argon2/bcrypt Hashing for Static Bearer Tokens:** Rejected for per-request hot-path authentication because intentional key-stretching adds millisecond-scale latency to every MCP call, whereas high-entropy API tokens are not vulnerable to offline dictionary attacks and SHA-256 provides fast, fixed-size `[u8; 32]` lookup.
- **Buffering Full SSE Streams Before Secret Scrubbing:** Rejected because buffering unbounded or chunked SSE payloads before scrubbing increases peak memory and risks retaining unscrubbed secrets on partial reads; scrubbing chunks via the streaming Aho-Corasick scrubber before SSE frame unwrapping preserves egress safety.
- **Unprivileged Defaults Without Explicit `securityContext` in Kubernetes Manifests:** Rejected because many clusters enforce Pod Security Standards (`restricted`), requiring explicit `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, and `capabilities.drop: ["ALL"]`.

## Consequences & Failure Modes
- **Token Digest Lookup:** Because SHA-256 is deterministic without per-token salt, static tokens configured via `token_ref` must remain high-entropy secrets; `GatewayRuntime::build` still registers resolved `secret://` tokens with `SecretScrubber` to prevent accidental egress.
- **SSE Unwrapping Edge Cases:** Multi-line `data:` frames or keep-alive comment lines (`: ...`) in `text/event-stream` responses must be ignored or concatenated per the SSE specification so malformed or heartbeat-only streams surface clear upstream errors rather than silent empty payloads.
- **Kubernetes PVC & ConfigMap Prerequisites:** `deploy/k8s/deployment.yaml` expects `keelway-config` (ConfigMap) and `keelway-data` (PVC) to exist in the target namespace; if `keelway-data` is `ReadWriteOnce`, `replicas` should remain `1` or be backed by a `ReadWriteMany` volume / externalized tape sink.
