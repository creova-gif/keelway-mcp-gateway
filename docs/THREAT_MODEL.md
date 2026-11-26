# Threat Model: Keelway MCP Gateway

## 1. System Overview & Assets
Keelway MCP Gateway (`keelway-engine`, `keelway-cli`) is a local-first, default-deny Model Context Protocol (MCP) policy enforcement point and execution ledger.

| Asset | Sensitivity | Location / Component |
| :--- | :--- | :--- |
| **Upstream API Credentials & Tokens** | Critical | `SecretProvider` (`secret://env/`, `secret://file/`), `UpstreamDriver` (`resolved_env`, `resolved_headers`), `SecretScrubber` |
| **Gateway Principal Bearer Tokens** | High | `GatewayConfig` / `GatewayRuntime::token_map` (`org_id`, `agent_id`) |
| **Execution Receipt Ledger (`keelway-tape.jsonl`)** | High (Integrity) | `TapeWriter` (dedicated OS thread, SHA-256 `prev_hash`/`entry_hash` chain) |
| **Authorization Policy & Schema** | High (Integrity) | `keelway.yaml`, `.cedar` policy files, `ArcSwap<PolicySnapshot>` |
| **Downstream Tools & Host / Tenant Data** | High | Local `stdio` child processes (`UpstreamTransport::Stdio`), remote Streamable HTTP MCP servers (`UpstreamTransport::StreamableHttp`) |

---

## 2. Trust Boundaries

```text
  [Untrusted / Prompt-Injectable Agent Client]
                     │
                     │  (1) MCP JSON-RPC over Streamable HTTP (/mcp) or stdio
                     ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Boundary A: Gateway Ingress & Principal Authentication             │
  │  - Bearer token -> Principal (org_id, agent_id)                     │
  │  - 2-Stage PolicyEngine: 5 Typed Validators -> Cedar Authorizer     │
  │  - Per-Principal / Per-Server BudgetRule & RAII BudgetLease         │
  │  - Pre-dispatch SecretScrubber + TapeWriter (fail-closed -32001)    │
  └──────────────────┬───────────────────────────────┬──────────────────┘
                     │                               │
       (2a) Local stdio (env_clear +                 │ (2b) Streamable HTTP
            explicit server.transport.env)           │      + resolved_headers
                     ▼                               ▼
  ┌──────────────────────────────────┐  ┌───────────────────────────────┐
  │ Boundary B1: Local Stdio Child   │  │ Boundary B2: Remote MCP       │
  │ (Semi-trusted / Untrusted Tool)  │  │ (Untrusted Network Upstream)  │
  │ - stdout/stderr piped & scrubbed │  │ - SSE stream scrubbed via     │
  └──────────────────────────────────┘  │   StreamingScrubber           │
                                        └───────────────────────────────┘
                     │
                     │  (3) Audit & Secret Resolution
                     ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Boundary C: Secret Manager & Local Storage                         │
  │  - DefaultSecretProvider (env/file; GCP Secret Manager + OIDC M2+)  │
  │  - Append-only SHA-256 hash-chained keelway-tape.jsonl              │
  └─────────────────────────────────────────────────────────────────────┘
```

1. **Client -> Gateway (Boundary A):** Agent clients are treated as untrusted/compromisable (e.g., via indirect prompt injection in fetched web pages, issues, or tool outputs). All `tools/call` requests are authenticated, schema-checked, policy-evaluated, budget-checked, and persisted to the tape before upstream dispatch.
2. **Gateway -> Upstream / Sandbox (Boundaries B1 & B2):** Upstream MCP servers (both local `stdio` subprocesses and remote HTTP servers) are treated as untrusted sinks and untrusted response sources. They must never receive ambient host credentials or inject unredacted secrets back into agent-visible channels.
3. **Gateway -> Secret Manager / Tape (Boundary C):** Gateway-managed secrets are resolved exclusively through `SecretProvider` and scrubbed before hitting `keelway-tape.jsonl` or operator logs.

---

## 3. Threat Matrix

| Threat Vector | Attack Scenario | Implemented Mitigations (Milestone 1 / ADR-001..003) | Residual Risks (Milestone 2+ Roadmap) |
| :--- | :--- | :--- | :--- |
| **Prompt-Injection Tool Abuse** | Indirect prompt injection coerces an agent into invoking destructive, unapproved, or cross-tenant MCP tools (e.g., `delete_repo`, `exec_shell`, wrong `org_id` scope). | • Pure-Rust `cedar-policy` default-deny evaluation (`forbid` overrides `permit`).<br>• Principal scoping (`org_id`, `agent_id`) mapped server-side from bearer tokens.<br>• Schema validation via `cedar_policy::Validator::validate` on load/reload.<br>• Fail-closed `-32000 PolicyDenied` and `DENY` (`BLOCKED`) receipt on `keelway-tape.jsonl`. | • **No semantic/IoRa taint tracking:** Gateway cannot distinguish whether a permitted tool's arguments originated from trusted user intent vs. untrusted tool output.<br>• **Milestone 2+:** IoRa taint tracking and `AWAITING` human-in-the-loop approval gates (P-10). |
| **Credential Exfiltration (Args, Responses, SSE, `stderr`, Child Env)** | Agent or compromised upstream echoes `secret://` values in tool arguments, JSON responses, chunk-straddling SSE frames, child `stderr`, or reads ambient host env vars (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`). | • `SecretScrubber` (Aho-Corasick) scrubs registered gateway-managed secrets (`>= 8` bytes) across raw, JSON-escaped, URL-encoded, and Base64 forms.<br>• `StreamingScrubber` (`max_secret_len - 1` sliding window) scrubs chunk-straddling SSE streams.<br>• `spawn_stdio_child` pipes and scrubs child `stderr` before `tracing::warn!`.<br>• Clean-env `stdio` isolation (`env_clear()` + minimal baseline `PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL` + explicit `server.transport.env`, per ADR-003).<br>• Pre-persistence scrubbing (`redacted_args`, `redacted_fields`) before `keelway-tape.jsonl` write. | • **Unregistered / short secrets:** Secrets `< 8` bytes or not registered via `secret://` are not scrubbed (no heuristic/entropy auto-discovery).<br>• **Direct host network/filesystem exfiltration by local `stdio` child:** Without OS sandboxing, a malicious `stdio` binary can still read local files accessible to the gateway UID or exfiltrate over the network.<br>• **Milestone 2+:** OS container/namespace sandboxing (`bwrap`/containers), network egress pinning, and GCP Secret Manager + OIDC. |
| **Execution Tape Tampering & Audit Evasion** | Attacker modifies, truncates, or forks `keelway-tape.jsonl`, or triggers an upstream tool call while blocking disk audit persistence. | • Single-writer OS-thread `TapeWriter` with strictly monotonic `seq` and linear SHA-256 `prev_hash -> entry_hash` chaining.<br>• Fail-closed persistence: `ALLOW` receipt must `sync_data()` before upstream dispatch (`-32001 TapePersistenceError`).<br>• Startup O(1)-memory `BufReader` chain verification refuses to boot on corruption.<br>• `keelway replay --dry-run` marks policies touching `redacted_fields` as `INDETERMINATE` rather than forging verdicts. | • **Full-file replacement / truncation with re-hashing:** A local attacker with write access to `keelway-tape.jsonl` can recompute the entire SHA-256 chain from `seq 0` unless anchored externally.<br>• **Milestone 2+:** External WORM/remote log anchoring or periodic signed Merkle checkpoints. |
| **Runaway Agent Loops & Resource Exhaustion** | Prompt-injected or stuck agent enters a tight `tools/call` loop, exhausting upstream API quotas, billing limits, or gateway concurrency. | • Per-principal / per-server `BudgetRule` (`max_calls_per_minute`, `max_concurrent_calls`) enforced via RAII `BudgetLease` before upstream dispatch (ADR-003).<br>• Returns `-32004 BudgetExceeded` and logs `DENY` receipt.<br>• Per-server `timeout_ms` bounds hung upstream calls (`-32002`). | • **Process-local state:** Budget counters reside in gateway memory and reset on restart; not shared across horizontally scaled instances.<br>• **Milestone 2+:** Distributed/persisted budget store and cost-weighted token budgets. |
| **Path Traversal & SQL Injection in Tool Arguments** | Agent supplies `../../etc/passwd` to filesystem tools or `SELECT 1; DROP TABLE users;` / write CTEs (`WITH d AS (DELETE FROM ...)`) to SQL tools. | • `ValidatorKind::PathWithin` performs pure lexical path normalization against configured `root` before Cedar evaluation.<br>• `ValidatorKind::SqlReadonly` parses SQL via `sqlparser` AST, requiring a single `Statement::Query` with zero write CTEs.<br>• `ValidatorKind::Glob`, `Regex`, and `RepoAllowlist` constrain string/repo parameters deterministically. | • **Symlink escape:** `path_within` is purely lexical (for deterministic offline `keelway replay --dry-run`) and does not `realpath()`-resolve symlinks inside `root` on the host filesystem.<br>• **Milestone 2+:** OS container/namespace bind-mount sandboxing (`O_NOFOLLOW` / chroot / container rootfs) to enforce physical filesystem confinement. |

---

## 4. Verification & CI Controls
- **Static Analysis & Hygiene:** `cargo fmt --check`, `cargo clippy -- -D warnings` (workspace lints forbid `clippy::unwrap_used` and `clippy::expect_used` in production paths), `cargo audit`, and `gitleaks` in CI.
- **Adversarial & E2E Testing:** `keelway attack simulate` and `crates/keelway-engine/tests/gateway_e2e.rs` verify default-deny Cedar enforcement, SQL/path validator rejections, secret scrubbing across SSE/stderr/tape, and fail-closed tape persistence.
