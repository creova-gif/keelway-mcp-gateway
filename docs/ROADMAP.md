# Keelway MCP Gateway — Product & Engineering Roadmap

Keelway MCP Gateway is a high-assurance security and governance proxy for Model Context Protocol (MCP) tool execution. It sits between autonomous AI agents and downstream MCP servers (`stdio` and Streamable HTTP), enforcing deterministic argument validation, Amazon Cedar authorization, execution budgets, human-in-the-loop approval gates, secret scrubbing, and tamper-evident audit logging.

---

## Milestone 1 — Core Federated Gateway & Offline Policy Testbench (Shipped, v0.1.0)

- **Multi-Server Federation:** Unified MCP gateway over local `stdio` child processes and remote Streamable HTTP (`/mcp`) upstreams with namespaced tool routing.
- **2-Stage Policy Evaluation:** Typed structural argument validators (filesystem paths, SQL AST via `sqlparser`, SSRF/host/IP, shell/argv) paired with schema-validated Amazon Cedar (`cedar-policy`) authorization.
- **Zero-Allocation Egress Scrubbing:** Aho-Corasick (`SecretScrubber` / `StreamingScrubber`) redaction of registered `secret://` credentials across tool responses and SSE streams.
- **Tamper-Evident Audit Tape:** Dedicated OS-thread SHA-256 hash-chained `keelway-tape.jsonl` writer ensuring fail-closed persistence before upstream dispatch or response release.
- **Offline Policy Testbench & Zero-Downtime Reload:** `keelway init`, `keelway policy test`, `keelway attack simulate`, `keelway trace inspect`, and `keelway replay --dry-run`, backed by lock-free `ArcSwap` configuration and policy hot-reload.

---

## Milestone 2 — Execution Governance, Human Gates & Observability (Shipped, v0.2.0)

- **Execution Budgets:** Per-principal / per-server sliding-window rate limits and RAII-guarded (`BudgetLease`) concurrency caps failing closed with JSON-RPC `-32004 BudgetExceeded`.
- **Clean-Environment `stdio` Isolation:** `Command::env_clear()` child spawning with a minimal safe baseline allowlist plus explicitly declared `server.transport.env` entries.
- **P-10 Human-in-the-Loop Approval Gates:** `P10GateManager` `oneshot` suspension for sensitive tools (`AWAITING` -> `SEALED` / `BLOCKED`, `-32005 ApprovalDenied`) with `GET /p10/pending`, `POST /p10/resolve`, RBAC role enforcement, cross-tenant isolation, self-approval prevention, and RAII gate cleanup on drop/timeout.
- **Real-Time Observability:** Prometheus text exposition at `GET /metrics`, tenant-scoped live decision stream via `GET /events` (SSE), and `GET /healthz` readiness checks.

---

## Milestone 3 — Cryptographic Provenance, Operator Console & Production Guardrails (In Progress)

- **M3A — Payload Limits & Unregistered Egress Scrubbing:**
  - Configurable `max_request_bytes` and `max_response_bytes` enforcement failing closed with JSON-RPC `-32006 PayloadTooLarge` to prevent memory exhaustion and oversized-payload bypasses.
  - Built-in pattern detectors in `SecretScrubber` for unregistered high-risk credentials (AWS access keys, GitHub PATs, PEM private keys) across all egress paths.
- **M3B — Cryptographic Provenance & Preflight Diagnostics:**
  - Ed25519 signed audit tape provenance (`ReceiptProvenance`) for verifiable offline receipt attestation.
  - W3C `traceparent` propagation and correlation across gateway spans, upstream calls, and audit receipts.
  - `keelway doctor` pre-flight production diagnostics validating config schemas, Cedar policies, secret provider bindings, and security posture.
- **M3C — Embedded Operator Console:**
  - Self-contained web console served at `GET /ui` featuring a live SSE decision stream, interactive P-10 approval queue, and Prometheus metric summary cards.

---

## Milestone 4 — Distributed Control Plane & Enterprise Policy Ecosystem (Planned)

- **OIDC/JWT & mTLS Principal Federation:** Cryptographic principal authentication with external IdP JWKS verification and mutual TLS client identity binding.
- **Distributed Governance State:** Redis/Postgres-backed execution budget counters and P-10 approval gate state enabling horizontal multi-replica gateway deployments.
- **Signed Policy Bundle Distribution:** Remote policy registry synchronization with cryptographic signature verification for centralized Cedar and validator bundle rollouts.
- **Full MCP Primitive Governance:** Extend policy evaluation, scrubbing, and audit receipts beyond `tools/call` to `resources/read` and `prompts/get`.
