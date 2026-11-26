# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **OIDC/JWT Bearer Principal Federation**: Cryptographic principal authentication using external IdP JWKS verification for incoming bearer tokens *(Milestone 4B, in progress)*.
- **Declared MCP `resources/list` & `prompts/list` Discovery**: Principal-scoped discovery for declared MCP resources and prompts *(Milestone 4B, in progress)*.
- **Configurable Circuit Breaker Thresholds**: Added `circuit_breaker_failure_threshold` and `circuit_breaker_cooldown_secs` configuration fields for per-upstream circuit breakers.
- **Operational Metrics & Health Telemetry**: Added `uptime_seconds` to `GET /healthz`, exposed `keelway_active_upstream_inflight` and `keelway_circuits_open` Prometheus gauges on `GET /metrics`, and added `Open Circuits`, `Active In-Flight`, and `Gateway Uptime` cards to the Operator Console (`GET /ui`).
- **Router-Wide Security Headers**: Applied defensive HTTP security headers across all gateway router responses.
- **Container & Compose Deployment**: Added production `Dockerfile`, `deploy/compose.yaml`, and `.env.example` for containerized gateway deployments.
- **Repository Governance & Dependency Automation**: Added `.github/CODEOWNERS` and `.github/dependabot.yml`.
- **Trace Inspection Filters**: Added `--tail`, `--trace-id`, `--decision`, and `--outcome` filtering options to `keelway trace inspect`.
- **Structured JSON Logging (`KEELWAY_LOG_FORMAT=json`)**: Added `KEELWAY_LOG_FORMAT=json` support for machine-parseable JSON tracing logs alongside the default human-readable format.
- **HTTP API Reference (`docs/API.md`)**: Added reference documentation covering gateway HTTP/JSON-RPC endpoints, authentication, and operational routes.
- **Concurrent Multi-Principal Stress & Isolation Test**: Added `concurrent_mixed_principals_preserve_tape_chain_and_budget_isolation` in `gateway_e2e` verifying strict per-principal budget isolation and hash-chained tape integrity under concurrent mixed-principal load.

### Changed
- **BudgetTracker Idle Bucket Eviction**: Added automatic eviction of idle sliding-window rate-limit buckets in `BudgetTracker` to bound long-running memory usage.
- **Operator Console (`GET /ui`)**: Added WCAG 2.1 AA accessibility enhancements and live stream filtering, search, and pause controls to the embedded operator console.
- **Preflight Validation (`keelway doctor`)**: Added positive-bound validation rejecting zero values for `max_request_bytes`, `max_response_bytes`, and `circuit_breaker_failure_threshold`, plus tape directory writability checks and `KEELWAY_TAPE_PATH` override support.
- **Release Benchmarks (`v0.3.0`)**: Refreshed measured local release benchmarks for `keelway-engine v0.3.0` in `README.md`.

## [0.3.0] - 2026-11-26

### Added
- **Embedded Operator Console (`GET /ui`)**: Zero-dependency HTML/JS operator console served directly from the gateway binary with a live SSE decision stream, interactive P-10 approval queue, and Prometheus metric summary cards ([ADR-007](docs/adr/007-embedded-operator-console.md)).
- **Ed25519 Signed Tape Provenance & W3C `traceparent`**: Optional Ed25519 receipt signing (`signing_key_ref`) with verifiable offline attestation (`keelway trace inspect --public-key <HEX>`), `keelway keygen` for generating signing keypairs, and W3C `traceparent` propagation/correlation across gateway spans, upstream calls, and audit receipts ([ADR-006](docs/adr/006-ed25519-tape-provenance-and-doctor.md)).
- **Preflight Diagnostics (`keelway doctor`)**: Offline pre-flight validation of configuration schemas, Cedar policies, secret provider bindings, and security posture ([ADR-006](docs/adr/006-ed25519-tape-provenance-and-doctor.md)).
- **Payload Size Guardrails & Egress Pattern Scrubbing**: Configurable `max_request_bytes` and `max_response_bytes` limits failing closed with JSON-RPC `-32006 PayloadTooLarge`, plus built-in Aho-Corasick/pattern scrubbing (`egress_pattern_scrubbing`) for unregistered AWS, GitHub, and PEM credentials across all egress paths ([ADR-005](docs/adr/005-egress-guardrails-and-payload-limits.md)).
- **MCP `ping`, Resource, and Prompt Governance**: Policy evaluation, scrubbing, and audit coverage extended to MCP `ping`, `resources/*`, and `prompts/*` primitives.

## [0.2.0] - 2026-11-25

### Added
- **Per-Principal Execution Budgets**: Sliding-window rate limits and RAII-guarded (`BudgetLease`) concurrency caps per principal and server, failing closed with JSON-RPC `-32004 BudgetExceeded` ([ADR-003](docs/adr/003-execution-budgets-and-stdio-env-isolation.md)).
- **Clean-Environment `stdio` Isolation**: Spawns local `stdio` MCP child processes with `Command::env_clear()`, forwarding only a minimal safe baseline plus explicitly declared `server.transport.env` entries ([ADR-003](docs/adr/003-execution-budgets-and-stdio-env-isolation.md)).
- **P-10 Human-in-the-Loop Approval Gates**: `approval_required` rules hold matching authorized calls in `AWAITING` state on an in-memory `oneshot` gate until resolved via `GET /p10/pending` and authenticated `POST /p10/resolve` (with RBAC enforcement, cross-tenant isolation, self-approval prevention, and `-32005 ApprovalDenied` on deny/timeout) ([ADR-004](docs/adr/004-p10-human-gates-and-observability.md)).
- **Real-Time Observability**: Prometheus text exposition at `GET /metrics`, tenant-scoped live decision stream at `GET /events` (SSE), and `GET /healthz` readiness checks ([ADR-004](docs/adr/004-p10-human-gates-and-observability.md)).

## [0.1.1] - 2026-11-24

### Fixed
- **Installer & Release Archive Polish**: Improved `install.sh` and release archive packaging for `aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` prebuilt binaries, plus synchronous `SIGHUP` registration and initial policy `mtime` capture at startup.

## [0.1.0] - 2026-11-24

### Added
- **Core Federated MCP Gateway**: Unified gateway over local `stdio` child processes and remote Streamable HTTP (`/mcp`) upstreams with canonical `<server_alias>__<sanitized_tool_name>` routing and per-principal `tools/list` filtering.
- **2-Stage Cedar + Typed Validators**: Deterministic argument validators (`path_within`, `glob`, `regex`, `sql_readonly` via `sqlparser` AST, `repo_allowlist`, SSRF/host/IP) paired with schema-validated Amazon Cedar policies and lock-free `ArcSwap` hot reload.
- **Aho-Corasick Secret Scrubber**: Gateway-side `secret://` credential resolution and zero-allocation redaction across tool responses, SSE streams, `stderr`, logs, and receipts.
- **OS-Thread SHA-256 Audit Tape**: Dedicated OS-thread group-commit (`sync_data()`) hash-chained `keelway-tape.jsonl` writer that fails closed (`-32001`) on persistence errors and verifies the full chain in O(1) memory on startup.
- **Offline Policy Testbench**: `keelway init`, `keelway policy test`, `keelway attack simulate`, `keelway trace inspect`, and `keelway replay --dry-run`.

[Unreleased]: https://github.com/creova-gif/keelway-mcp-gateway/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/creova-gif/keelway-mcp-gateway/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/creova-gif/keelway-mcp-gateway/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/creova-gif/keelway-mcp-gateway/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/creova-gif/keelway-mcp-gateway/releases/tag/v0.1.0
