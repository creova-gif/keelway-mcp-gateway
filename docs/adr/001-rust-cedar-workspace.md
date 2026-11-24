# ADR-001: 2-Crate Rust Workspace & Pure-Rust Cedar 2-Stage Policy Engine
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Keelway MCP Gateway targets a single local-first binary with `< 5 ms` p95 processing overhead, formally sound default-deny authorization, and zero direct credential exposure across federated MCP servers. The repository started with a 2-line Python healthcheck stub (`src/keelway_mcp_gateway/__init__.py`), while the target architecture requires Rust (`rustfmt`, `cargo clippy -- -D warnings`, `cargo audit`, zero `.unwrap()`/`.expect()` in production paths).

## Decision
1. **2-Crate Rust Workspace (`keelway-engine` + `keelway-cli`):**
   - `keelway-engine` exposes a single deep public facade (`GatewayEngine`) while encapsulating `core`, `policy`, `tape`, `secrets`, and `mcp` behind `pub(crate)` boundaries so callers cannot violate ordering invariants (e.g., dispatching upstream calls before `ALLOW` receipt persistence).
   - `keelway-cli` provides the single binary `keelway` (`init`, `gateway up`, `policy test`, `attack simulate`, `trace inspect`, `replay --dry-run`).
   - Workspace lints forbid `clippy::unwrap_used` and `clippy::expect_used` in production code.
2. **2-Stage Deterministic Policy Pipeline (`cedar-policy` + 5 Typed Validators):**
   - **Stage 1:** Evaluate 5 typed argument validators (`path_within` via pure lexical normalization, `glob`, `regex`, `sql_readonly` via `sqlparser` AST requiring a single `Statement::Query` with zero write CTEs, and `repo_allowlist`) and inject their boolean results into Cedar `Context`.
   - **Stage 2:** Evaluate pure-Rust `cedar-policy` (`permit`/`forbid`, default-deny, forbid-overrides-permit) using a shared `Authorizer::new()`, infallible `EntityUid::from_type_name_and_id`, and pre-built `Entities` cached behind `arc-swap::ArcSwap<PolicySnapshot>`.
   - Auto-generate the Cedar schema in-memory from `keelway.yaml` and run `cedar_policy::Validator::validate` before every load or hot reload.
3. **Streamable HTTP (`/mcp`) + Local `stdio` Only for Milestone 1:**
   - Standardize remote HTTP transport on MCP Streamable HTTP (`/mcp`) and defer legacy 2024 dual-endpoint SSE (`/sse` + `/messages`) to Milestone 2+.
   - Enforce strict `stderr`-only logging and console output when `--transport stdio` is active.

## Alternatives Considered
- **6-crate workspace upfront:** Rejected during Engineering Review (D1) due to Cargo manifest duplication and slower iteration before any external repo imports a sub-crate.
- **Custom YAML policy language:** Rejected because rolling a custom policy DSL creates long-term precedence and negation edge-case debt.
- **Python Milestone 1 prototype:** Rejected to avoid a throwaway rewrite to hit the single-binary and `< 5 ms` p95 overhead targets.

## Consequences & Failure Modes
- Invalid `.cedar` files or validator name typos fail closed at startup/reload via `Validator::validate` while keeping the last known-good snapshot live.
- `path_within` lexical normalization guarantees 100% deterministic offline replay, while host OS symlink confinement is explicitly deferred to Milestone 2+ sandboxing.
- Splitting `keelway-engine` into standalone crates later remains mechanical because internal module boundaries are enforced via `pub(crate)`.
