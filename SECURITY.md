# Security Policy

## Security Boundary Philosophy

> **Agents can reason freely, but their ability to act must be explicitly authorized, observable, and controlled.**

Keelway MCP Gateway is designed as a deterministic, fail-closed execution boundary between autonomous AI agents (MCP clients) and external tools (upstream MCP servers). Prompt injection, model misalignment, and compromised agent context are treated as expected runtime conditions—not edge cases. Security enforcement happens outside the model context in pure Rust before any upstream tool call is dispatched and before any response or receipt leaves the gateway.

## Threat Model & Trust Boundaries

Keelway's assets, trust boundaries, and mitigations are documented in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md):

- **Protected Assets:** Upstream API credentials (`secret://env/...`, `secret://file/...`), tenant/principal identity (`org_id`), tamper-evident execution logs (`keelway-tape.jsonl`), and downstream MCP tools/data.
- **Trust Boundaries:** `MCP Client -> Keelway Gateway (Auth + Policy + Scrubber + Tape) -> Upstream MCP Server / Secret Store`.
- **Untrusted Inputs:** All MCP client tool-call arguments, tool names, and upstream MCP server `stdout`/`stderr`/SSE responses are treated as untrusted until validated or scrubbed.

## Fail-Closed Invariants

Keelway enforces the following fail-closed guarantees across its execution path:

1. **Authentication & Default-Deny Authorization:**
   - Unauthenticated or unknown principals are rejected when auth is enabled.
   - Policy evaluation is strictly **default-deny**: every `tools/call` must be explicitly permitted by Amazon Cedar policies after Stage 1 typed argument validators (`path_within`, `glob`, `regex`, `sql_readonly`, `repo_allowlist`) execute.
2. **Schema-Validated Policy Loading (`Validator::validate`):**
   - On startup and hot reload, Cedar policies are compiled and validated against the gateway's Cedar schema via `cedar_policy::Validator::validate`. Invalid schemas, malformed policies, or type errors abort loading and preserve the last known-good policy state (or fail startup).
3. **Fail-Closed Tape Persistence (`-32001`):**
   - Every tool decision and execution receipt must be persisted and `sync_data()`-flushed to the hash-chained execution tape (`keelway-tape.jsonl`) by the dedicated OS-thread writer.
   - If the tape writer fails or cannot durably persist a receipt, the gateway fails closed and returns JSON-RPC `-32001` rather than allowing unlogged execution.
4. **Startup SHA-256 Chain Verification:**
   - On startup, Keelway verifies the existing `keelway-tape.jsonl` `prev_hash` / `entry_hash` SHA-256 chain in O(1) memory before accepting traffic. Any truncation, modification, or chain break halts startup.

## Secret Scrubbing Scope & Limitations

Keelway resolves gateway-managed credentials (`secret://env/...` and `secret://file/...`) inside the gateway process so upstream secrets are never exposed to the MCP client configuration. Before any payload is returned to the client, written to the tape, or emitted to console/`stderr`, the Aho-Corasick secret scrubber redacts registered secrets.

- **Covered Scope:** Registered gateway-managed secret values of **>= 8 bytes** across **raw**, **JSON-escaped**, **URL-encoded**, and **Base64** representations—including across SSE chunk boundaries, upstream `stderr`, console logs, and persisted receipts.
- **Explicit Limitation:** Unregistered secrets (for example, arbitrary credentials not declared via `secret://` in gateway configuration, or values shorter than 8 bytes) are **not** auto-discovered via heuristic entropy or regex scanning. Operators must register sensitive credentials through Keelway's secret references to guarantee redaction.

## Reporting a Vulnerability

Please **do not** open public GitHub issues for suspected security vulnerabilities, policy bypasses, or credential leakage.

Instead, report vulnerabilities privately via:
- **GitHub Security Advisories:** Open a private advisory under the repository's **Security -> Advisories** tab (`https://github.com/creova-gif/keelway-mcp-gateway/security/advisories/new`).
- If GitHub Security Advisories are unavailable, open a minimal private contact request without exploit details and wait for a maintainer response before sharing reproduction steps.

When reporting, please include:
1. Affected version/commit SHA and target platform (`aarch64-apple-darwin`, `x86_64-unknown-linux-gnu`, etc.).
2. Minimal reproduction steps, Cedar policy / `keelway.yaml` snippet, or `keelway attack simulate` scenario.
3. Expected fail-closed behavior vs. observed behavior.

We will acknowledge reports within 48 hours and coordinate a fix and advisory before public disclosure.
