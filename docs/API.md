# Keelway MCP Gateway — API Reference

This document describes the HTTP endpoints, JSON-RPC 2.0 error codes, and Cedar authorization schema exposed by `keelway-mcp-gateway`.

## HTTP Endpoints

All HTTP responses include baseline security headers (`X-Content-Type-Options: nosniff` and `Cache-Control: no-store`) via middleware unless overridden by a route handler.

| Method & Path | Authentication | Required Roles | Description |
|---|---|---|---|
| `POST /mcp` | Bearer token | Principal / JWT | Streamable HTTP MCP JSON-RPC 2.0 endpoint |
| `GET /ui` | None | — | Embedded zero-dependency Operator Console SPA |
| `GET /healthz` | None | — | Liveness probe |
| `GET /readyz` | None | — | Readiness probe (checks upstream circuit breakers) |
| `GET /metrics` | None | — | Prometheus text exposition metrics |
| `GET /events` | Bearer token | Principal / JWT | Live Server-Sent Events (SSE) decision stream |
| `GET /p10/pending` | Bearer token | `p10-approver` or `admin` | List pending P-10 human approval gates |
| `POST /p10/resolve` | Bearer token | `p10-approver` or `admin` | Approve or deny a pending P-10 gate |

### `POST /mcp`

Handles MCP JSON-RPC 2.0 requests (`initialize`, `tools/list`, `tools/call`, `resources/read`, `prompts/get`, and notifications).

- **Authentication:** `Authorization: Bearer <token>` (configured static principal token or JWT/OIDC bearer token). Missing or invalid credentials return `401 Unauthorized` with `{"error": "unauthenticated"}` and record a best-effort `DENY` receipt.
- **Tracing (`traceparent` / `x-trace-id`):** Extracts a valid 32-hex `trace_id` from an incoming W3C `traceparent` header (`00-<32-hex-trace-id>-<16-hex-span-id>-<2-hex-flags>`), or generates a fresh 32-hex UUIDv4 trace ID. Every response (including `401` and `202`) includes the `x-trace-id` header.
- **Body Limits:** Enforces an Axum body limit of `max_request_bytes + 64 KiB`, plus per-call `max_request_bytes` and `max_response_bytes` JSON-RPC checks (`-32006`).
- **Response Payloads:**
  - JSON-RPC request (contains `"id"`): `200 OK` with the JSON-RPC 2.0 response object.
  - JSON-RPC notification (no `"id"`): `202 Accepted` with an empty body.

### `GET /ui`

Serves the compile-time embedded Operator Console (`text/html; charset=utf-8`). The console itself prompts the operator for a Bearer token in the browser to subscribe to `/events` and manage `/p10/*`.

- **Security Headers:**
  - `Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'`
  - `X-Frame-Options: DENY`
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store`

### `GET /healthz`

Liveness probe for container orchestrators and load balancers.

- **Response (`200 OK`):**
  ```json
  {
    "status": "ok",
    "uptime_seconds": 42
  }
  ```

### `GET /readyz`

Readiness probe that inspects the state of all upstream server circuit breakers.

- **Responses:**
  - `200 OK` when no circuit breakers are `Open`:
    ```json
    {
      "ready": true,
      "open_circuits": 0
    }
    ```
  - `503 Service Unavailable` when one or more circuit breakers are `Open`:
    ```json
    {
      "ready": false,
      "open_circuits": 1
    }
    ```

### `GET /metrics`

Exposes gateway counters and gauges in Prometheus text exposition format (`Content-Type: text/plain; version=0.0.4; charset=utf-8`), including call outcomes, upstream timeouts/errors, `keelway_p10_pending`, `keelway_circuits_open`, active in-flight calls, and uptime.

### `GET /events` (SSE)

Streams real-time gateway decision events (`text/event-stream`) with automatic keep-alive frames.

- **Authentication:** `Authorization: Bearer <token>`. Returns `401 Unauthorized` with `{"error": "unauthenticated"}` or `{"error": "token expired"}` if invalid or expired.
- **Tenant Isolation & Lifecycle:** Events are filtered to the authenticated principal's `org_id`. The stream closes cleanly on gateway shutdown or when a JWT's `exp` timestamp is reached.
- **Event Payload (`LiveConsoleEvent` JSON):**
  ```json
  {
    "timestamp": "2026-11-26T15:00:00Z",
    "org_id": "acme",
    "agent_id": "coding-agent",
    "server": "github",
    "tool": "create_issue",
    "decision": "Allow",
    "state": "Sealed",
    "outcome": "Allowed",
    "reason": "permitted by policy1"
  }
  ```

### `GET /p10/pending`

Lists active P-10 human-in-the-loop approval gates waiting for operator resolution within the caller's `org_id`.

- **Authentication & Authorization:** Requires `Authorization: Bearer <token>` (`401 Unauthorized` if missing/invalid) and role `p10-approver` or `admin` (`403 Forbidden` with `{"error": "p10-approver or admin role required"}` otherwise).
- **Response (`200 OK`):**
  ```json
  {
    "pending": [
      {
        "approval_id": "550e8400-e29b-41d4-a716-446655440000",
        "org_id": "acme",
        "agent_id": "coding-agent",
        "server": "github",
        "tool": "delete_branch",
        "redacted_args": { "branch": "feature/old" },
        "created_at": "2026-11-26T15:00:00Z"
      }
    ]
  }
  ```

### `POST /p10/resolve`

Approves or denies a pending P-10 gate, unblocking the waiting `/mcp` call.

- **Authentication & Authorization:** Requires `Authorization: Bearer <token>` (`401`) and role `p10-approver` or `admin` (`403`). Cross-organization resolution or invalid approver authorization returns `403 Forbidden`.
- **Request Body:**
  ```json
  {
    "approval_id": "550e8400-e29b-41d4-a716-446655440000",
    "approved": true
  }
  ```
- **Responses:**
  - `200 OK`: `{"resolved": true}`
  - `403 Forbidden`: `{"error": "<reason>"}`
  - `404 Not Found`: `{"error": "<reason>"}` (gate unknown or already timed out/resolved)

---

## JSON-RPC 2.0 Error Codes

Gateway-enforced errors on `POST /mcp` use standard JSON-RPC 2.0 error responses with the following application-defined codes:

| Code | Name | Meaning |
|---|---|---|
| `-32000` | `PolicyDenied` | Call blocked by Cedar policy (default-deny or explicit `forbid` rule). |
| `-32001` | `TapePersistenceError` | Fail-closed: audit receipt could not be persisted to `keelway-tape.jsonl` before upstream dispatch. |
| `-32002` | `UpstreamTimeout` | Upstream MCP call exceeded its configured `timeout_ms`. |
| `-32003` | `UpstreamUnavailable` | Upstream MCP server is unreachable, crashed (`stdio`), or its circuit breaker is `Open`. |
| `-32004` | `BudgetExceeded` | Per-principal / per-server `max_calls_per_minute` or `max_concurrent_calls` limit exceeded. |
| `-32005` | `ApprovalDenied` | P-10 human approval gate was explicitly denied or timed out. |
| `-32006` | `PayloadTooLarge` | Request arguments exceeded `max_request_bytes` or upstream response exceeded `max_response_bytes`. |

---

## Cedar Authorization Schema

Keelway compiles an in-memory Cedar schema directly from `keelway.yaml` validator bindings at startup and on hot reload, eliminating schema drift.

### Entities

```cedarschema
entity Role;

entity Agent in [Role] {
    org_id: String,
    agent_id: String,
};

entity Tool {
    server: String,
    name: String,
};
```

- **`Agent` UID:** `<percent_encoded_org_id>/<percent_encoded_agent_id>` (collision-free encoding; `Agent` entities are constructed per request so stateless JWT callers cannot inherit static config roles).
- **`Tool` UID:** `<server>/<tool>`.

### Actions

| Action | Principal | Resource | Context |
|---|---|---|---|
| `list_tool` | `[Agent]` | `[Tool]` | Empty |
| `call_tool` | `[Agent]` | `[Tool]` | `{ arg_checks: { ... } }` |
| `read_resource` | `[Agent]` | `[Tool]` | `{ arg_checks: { ... } }` |
| `get_prompt` | `[Agent]` | `[Tool]` | `{ arg_checks: { ... } }` |

### `context.arg_checks` Validators

Each entry in `keelway.yaml` under `validators` generates a `Bool` field `context.arg_checks.<validator_id>` in the Cedar schema. Stage-1 deterministic validators run before Cedar evaluation and fail closed (`false`) if the target argument is missing, not a string, or fails validation:

| Validator Type | Behavior |
|---|---|
| `path_within` | Lexically normalizes the path argument and checks it stays within `root`. |
| `glob` | Matches the string argument against a compiled glob `pattern`. |
| `regex` | Matches the string argument against a compiled regular expression `pattern`. |
| `sql_readonly` | Parses the SQL argument with `sqlparser` AST and permits only read-only queries. |
| `repo_allowlist` | Checks the repository argument (case-insensitive, trimmed) against `repos`. |

Example Cedar rule using `context.arg_checks`:

```cedar
permit (
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"filesystem/read_file"
) when {
    context.arg_checks.workspace_path
};
```
