# ADR-006: Ed25519 Audit Tape Provenance & Offline `keelway doctor` Diagnostics
- **Status:** Proposed
- **Owner:** Justin Mafie

## Context
Two operational gaps remain before Keelway MCP Gateway deployments can be audited across multi-service boundaries and validated safely prior to production rollout:
1. **Cryptographic Non-Repudiation & Distributed Trace Correlation on `keelway-tape.jsonl`:** While ADR-002 established a local SHA-256 hash chain (`prev_hash -> entry_hash`), a hash chain alone does not prove which gateway key produced a receipt if an attacker or misconfigured process has write access to the tape file, nor does it link gateway receipts to upstream/downstream distributed traces.
2. **Pre-Flight Production Readiness Verification:** Operators currently discover missing secret references, unreadable or invalid `.cedar` policy files, permissive bind addresses, or corrupted tape files only at runtime when starting `keelway serve`.

## Decision
1. **Ed25519 Receipt Provenance (`TapeSigner` / `ReceiptProvenance`) & W3C `traceparent` Correlation:**
   - Introduce `keelway-engine::provenance::TapeSigner` wrapping `ed25519_dalek::SigningKey`, initialized from a 32-byte seed encoded as 64-character hex or base64 (`TapeSigner::from_seed_str`).
   - Derive a deterministic `key_id` from the first 16 lowercase hex characters of `SHA-256(verifying_key_bytes)`.
   - Sign receipt `entry_hash` payloads with `sign_hex` and verify offline with `verify_hex`, populating the `Receipt.provenance` (`ReceiptProvenance` / `Provenance`) slot with signature metadata (`key_id`, `verifying_key_hex`, `signature_hex`) and `trace_id`.
   - Extract 32-hex W3C `trace_id` values from inbound `traceparent` headers (`00-<32-hex-trace-id>-<16-hex-span-id>-<2-hex-flags>`), falling back to a freshly generated UUIDv4 hex string when absent or malformed (`extract_or_generate_trace_id`).
2. **Offline Pre-Flight Readiness (`keelway doctor`):**
   - Provide an offline `keelway doctor` diagnostic workflow that inspects `keelway.yaml`, validates referenced `.cedar` policy compilation, checks `secret://...` bindings, verifies existing `keelway-tape.jsonl` hash-chain and Ed25519 provenance integrity, and flags production-readiness hazards without starting network listeners or spawning upstream MCP servers.

## Alternatives Considered
- **HMAC-SHA256 symmetric signing:** Rejected because symmetric MAC keys cannot be safely shared with external auditors or read-only verification pipelines without granting them the ability to forge receipts.
- **Runtime-only readiness checks in `keelway serve`:** Rejected because CI/CD pipelines and operators need a zero-side-effect, offline pre-flight check (`keelway doctor`) that exits non-zero before deployment.

## Consequences & Failure Modes
- **Key rotation & verification:** Verifiers must retain historical `verifying_key_hex` values indexed by `key_id` when rotating signing seeds so older tape segments remain verifiable.
- **Malformed `traceparent` headers:** Invalid or all-zero W3C `traceparent` headers are never trusted as-is; `extract_or_generate_trace_id` falls back to a fresh 32-hex UUIDv4 trace ID so every receipt still carries a valid correlation identifier.
- **Strict error handling:** Seed parsing and signature verification return `KeelwayError` without `.unwrap()`, `.expect()`, or `panic!`, preserving fail-closed behavior.
