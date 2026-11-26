# ADR-003: Per-Principal Execution Budgets & Clean-Environment Stdio Isolation
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Two operational and security failure modes arise when mediating agent tool calls across local and remote MCP servers:
1. **Runaway Agent Loops & Quota Saturation:** Unbounded or prompt-injected agent tool loops can exhaust upstream API quotas, trigger runaway billing, or saturate gateway concurrency before human intervention.
2. **Ambient Credential Leakage to `stdio` Children:** Spawning local `stdio` MCP child processes (`UpstreamTransport::Stdio`) with inherited host environment variables risks leaking operator credentials (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, cloud ADC paths, etc.) to untrusted or third-party child binaries, bypassing `SecretProvider` and `SecretScrubber` boundaries.

## Decision
1. **Deterministic Per-Principal / Per-Server Execution Budgets (`BudgetRule` & `BudgetLease`):**
   - Enforce `BudgetRule` limits (`max_calls_per_minute`, `max_concurrent_calls`) keyed by `(principal, server)` before upstream MCP dispatch.
   - Acquire an RAII `BudgetLease` guard prior to invoking the upstream driver so concurrency slots are deterministically released on normal return, upstream timeout (`-32002`), upstream failure (`-32003`), or task cancellation/drop.
   - When a rate or concurrency budget is exceeded, fail closed before upstream dispatch: return JSON-RPC `-32004 BudgetExceeded` and append a `DENY` receipt (`state: BLOCKED`) to `keelway-tape.jsonl` so budget denials are auditable alongside Cedar policy denials.
2. **Clean-Environment `stdio` Child Spawning (`env_clear()`):**
   - Clear all inherited host environment variables via `Command::env_clear()` when spawning local `stdio` MCP child processes in `spawn_stdio_child`.
   - Forward only a minimal safe baseline (`PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL`, when present in the gateway process environment) plus explicitly declared `server.transport.env` entries whose `secret://...` references are resolved at build/reload time by `SecretProvider` and registered with `SecretScrubber`.

## Alternatives Considered
- **Stateless external rate-limiter proxy only:** Rejected because an external HTTP proxy cannot enforce per-principal concurrency across local `stdio` servers or record deterministic `DENY` receipts on `keelway-tape.jsonl`.
- **Denylist filtering of host environment variables (e.g., stripping `AWS_*`, `GITHUB_*`):** Rejected because denylists are brittle against vendor-specific or custom credential variable names; `env_clear()` with an explicit baseline allowlist is fail-closed by default.
- **Full OS container/namespace isolation in Milestone 1:** Deferred to Milestone 2+ (sandboxing) to preserve Milestone 1 zero-dependency local-first single-binary UX while eliminating ambient environment leakage immediately.

## Consequences & Failure Modes
- **Clean-env breakage for implicit host tools:** Local `stdio` MCP servers that rely on non-baseline host environment variables (e.g., `XDG_CONFIG_HOME`, `VIRTUAL_ENV`, `SSH_AUTH_SOCK`, or custom SDK vars) must explicitly declare them under `server.transport.env` in `keelway.yaml`.
- **In-memory budget state:** Per-principal sliding-window / concurrency counters live in gateway memory; restarting the gateway resets rate windows, and multi-instance deployments require shared budget state in Milestone 2+.
- **RAII leak-resistance:** Using `BudgetLease` (`Drop`) prevents permanent concurrency-slot exhaustion when upstream calls time out or client connections drop mid-flight.
