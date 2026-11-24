# ADR-002: Single-Writer OS-Thread SHA-256 Hash-Chained Execution Tape
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Every mediated MCP tool invocation (`ALLOW` or `DENY`) must produce a tamper-evident execution receipt aligned with the Keelway Sovereign Agent Platform (`kora-sable.vercel.app`) and support side-effect-free offline `keelway replay --dry-run`. Concurrent Streamable HTTP requests must never fork the hash chain or stall Tokio async worker threads on synchronous `sync_data()` calls.

## Decision
1. **Canonical Append-Only JSONL Tape (`keelway-tape.jsonl`):**
   - Each `Receipt` records `seq`, `prev_hash`, `entry_hash` (`SHA-256` over canonical receipt payload + `prev_hash`), `timestamp`, `org_id`, `agent_id`, `server`, `tool`, `redacted_args`, `redacted_fields` (JSON Pointer paths of any scrubbed argument fields), `decision`, `explanation`, `policy_digest`, `state` (`SEALED` | `BLOCKED` | future `AWAITING` for P-10 human gates), and optional `outcome` (`ok` | `timeout` | `crashed`).
2. **Dedicated OS-Thread Group-Commit Writer:**
   - `TapeWriter` runs on a dedicated OS thread (`std::thread::spawn` + `tokio::sync::mpsc::Receiver::blocking_recv()`), draining immediately queued receipts, assigning strictly monotonic `seq` and linear `prev_hash -> entry_hash`, issuing one `File::sync_data()` per batch, and acknowledging each caller via oneshot channel.
3. **Fail-Closed Durability & Startup Integrity:**
   - An `ALLOW` receipt must be durably persisted before upstream MCP dispatch; persistence failure returns JSON-RPC `-32001 TapePersistenceError` without invoking the upstream tool.
   - Startup verifies any existing tape via O(1)-memory `BufReader` streaming and refuses to start if chain verification fails.
4. **Honest Offline Replay (`redacted_fields`):**
   - `keelway replay --dry-run` streams receipts via `BufReader` and evaluates the exact same `PolicyEngine::evaluate` function. If a policy constraint inspects a path in `redacted_fields`, replay marks that verdict `INDETERMINATE (redacted_field_touched)` instead of emitting a false `ALLOW` or `DENY`.

## Alternatives Considered
- **Calling `sync_data()` directly inside `tokio::spawn`:** Rejected because blocking disk fsyncs stall Tokio async worker threads under concurrent HTTP load.
- **SQLite-only binary ledger:** Rejected for Milestone 1 because append-only JSONL is human-inspectable, git/diff-friendly, stream-verifiable in O(1) memory, and directly matches Keelway's sealed receipt tape.

## Consequences & Failure Modes
- Group-commit batching preserves fail-closed durability while amortizing APFS/ext4 fsync cost under concurrent bursts.
- Disk-full or permission errors fail closed immediately (`-32001`) instead of silently dropping audit records.
