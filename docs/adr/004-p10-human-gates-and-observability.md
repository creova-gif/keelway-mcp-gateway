# ADR-004: P-10 Human-in-the-Loop Approval Gates & Real-Time Observability
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Two operational gaps remain when autonomous agents execute high-impact MCP tool calls through Keelway:
1. **High-Impact Tool Sign-Off (P-10 Gates):** Certain sensitive or irreversible tool calls (e.g., `cloud.deploy`, `github.create_pull_request`) may satisfy static typed argument validators and Amazon Cedar authorization policies, yet still require explicit human-in-the-loop (HITL) operator sign-off (`AWAITING` state) before upstream dispatch.
2. **Real-Time Operator Visibility:** Operators and dashboards need immediate visibility into policy decisions, pending approval gates, budget denials, and gateway health without polling `keelway-tape.jsonl` on disk or parsing unstructured stdout logs.

## Decision
1. **P-10 Human-in-the-Loop Approval Gates (`P10GateManager`):**
   - Support `approval_required` rules (`org_id`, `agent_id`, `server`, `tool`, `timeout_ms`) evaluated after Cedar `ALLOW` and `BudgetTracker`.
   - When a tool call matches an `approval_required` rule, the gateway appends an `AWAITING` receipt to `keelway-tape.jsonl`, registers an in-memory `oneshot` channel in `P10GateManager`, and suspends the request until an operator resolves it or `timeout_ms` elapses.
   - Operators inspect pending gates via `GET /p10/pending` and approve or deny them via authenticated `POST /p10/resolve`.
   - Upon approval, the gateway transitions the call to `SEALED` (appending the resolution receipt) and dispatches the call upstream. Upon explicit denial or timeout, the gateway fails closed: it appends a `BLOCKED` receipt and returns JSON-RPC `-32005 ApprovalDenied` without invoking the upstream server.
2. **Real-Time Observability Endpoints:**
   - Expose `GET /healthz` for liveness/readiness health checks.
   - Expose `GET /metrics` in Prometheus text exposition format for gateway decision, budget, latency, and approval-gate counters.
   - Expose `GET /events` as a live Server-Sent Events (SSE) stream of `LiveConsoleEvent`s so operators and UI consoles can observe gateway decisions and `AWAITING` gate transitions in real time without polling JSONL files.

## Alternatives Considered
- **Async webhook / callback-only approvals (returning a job ID to the agent):** Rejected as the primary mechanism because standard MCP `tools/call` clients expect a synchronous JSON-RPC response; holding the request on an in-memory `oneshot` gate preserves MCP protocol compatibility while keeping approval enforcement fail-closed.
- **Polling `keelway-tape.jsonl` for live console updates:** Rejected because disk polling introduces latency, unnecessary I/O contention, and misses transient in-memory `AWAITING` gate state transitions.
- **Approving via Cedar policy hot-reload alone:** Rejected because single-call human sign-off is ephemeral per invocation and should not mutate static `.cedar` policy files.

## Consequences & Failure Modes
- **Fail-closed timeout & denial:** If no operator resolves a pending gate within `timeout_ms`, or if the operator denies it, the call is deterministically rejected with `-32005 ApprovalDenied` and recorded as `BLOCKED` on the tape.
- **In-memory `oneshot` gate lifetime:** Pending `P10GateManager` `oneshot` channels live in gateway memory; if the gateway restarts while a call is `AWAITING`, the in-flight client request fails closed and the `AWAITING` receipt remains on `keelway-tape.jsonl` for auditability.
- **Stream backpressure / slow SSE clients:** Slow `GET /events` consumers must not block the gateway hot path or `P10GateManager` resolution; broadcast lag drops/skips events for lagging subscribers rather than stalling MCP tool dispatch.
- **Authenticated resolution boundary:** `POST /p10/resolve` must remain authenticated so untrusted agents or local processes cannot self-approve their own `AWAITING` tool calls.
