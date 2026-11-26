# ADR-005: Bounded Payload Limits & Built-In Egress Credential Scrubbing
- **Status:** Proposed
- **Owner:** Justin Mafie

## Context
Two classes of production risk remain on the ingress and egress data paths of Keelway MCP Gateway:
1. **Unbounded Payload Memory & Parser Exhaustion:** Without explicit byte ceilings on inbound JSON-RPC requests and upstream MCP responses, a misbehaving agent or compromised upstream server can send multi-megabyte payloads that spike gateway memory, stall `serde_json` / `SecretScrubber` / `sqlparser` CPU budgets, or bloat `keelway-tape.jsonl`.
2. **Unregistered Credential Leakage on Egress:** `SecretScrubber` currently redacts only secrets explicitly declared via `secret://...` bindings in `keelway.yaml`. If an upstream tool reads a local file, environment variable, or database row containing credentials that were never registered with `SecretProvider` (e.g., AWS IAM access keys, GitHub personal access tokens, or PEM-encoded private keys), those credentials pass through `SecretScrubber` unredacted into agent context and audit logs.

## Decision
1. **Configurable Request & Response Payload Limits (`-32006 PayloadTooLarge`):**
   - Introduce `max_request_bytes` and `max_response_bytes` configuration fields (with safe production defaults) enforced at the MCP gateway boundary.
   - Reject inbound `tools/call` requests exceeding `max_request_bytes` prior to policy evaluation and upstream dispatch, returning JSON-RPC `-32006 PayloadTooLarge` and appending a `DENY` (`BLOCKED`) receipt to `keelway-tape.jsonl`.
   - Reject or truncate-and-fail-closed upstream responses exceeding `max_response_bytes` before buffering unbounded payloads into memory or forwarding to the agent, returning `-32006 PayloadTooLarge` and recording the failure on the audit tape.
2. **Built-In Unregistered Credential Pattern Detectors on All Egress Paths:**
   - Extend `SecretScrubber` (and `StreamingScrubber`) with built-in, zero-config pattern detectors for high-confidence credential formats—specifically AWS access key IDs (`AKIA...` / `ASIA...`), GitHub PATs (`ghp_...`, `gho_...`, `github_pat_...`), and PEM private key blocks (`-----BEGIN ... PRIVATE KEY-----`).
   - Apply both registered Aho-Corasick literal matches and built-in pattern detectors uniformly across all egress paths (synchronous `tools/call` responses, streaming SSE chunks, error messages, and persisted tape payloads) so unregistered secrets are replaced with `REDACTED_PLACEHOLDER`.

## Alternatives Considered
- **HTTP reverse-proxy body limit only (e.g., `tower_http::limit::RequestBodyLimitLayer`):** Rejected because HTTP-layer limits do not protect `stdio` transport responses, cannot emit structured JSON-RPC `-32006` errors with `keelway-tape.jsonl` receipts, and cannot bound per-tool response sizes uniformly across transports.
- **Relying solely on `SecretProvider`-registered literals:** Rejected because upstream tools (filesystem readers, log query tools, repository scanners) routinely encounter third-party or ambient credentials unknown to the gateway's `keelway.yaml` secret manifest.
- **Arbitrary user-supplied regexes in the hot path without bounds:** Deferred/constrained in favor of curated, linear-time built-in detectors (`regex` / `aho-corasick` DFA) to avoid catastrophic backtracking (ReDoS) on untrusted tool output.

## Consequences & Failure Modes
- **Legitimate large-payload tool calls:** Workflows that intentionally transfer large blobs (e.g., base64 artifacts or large query dumps) must raise `max_request_bytes` / `max_response_bytes` explicitly in `keelway.yaml` or stream via out-of-band references.
- **False positives on synthetic/test tokens:** Built-in detectors may redact documentation examples or test fixtures that match real AWS, GitHub, or PEM prefixes; patterns must balance high precision with fail-closed safety, and `REDACTED_PLACEHOLDER` substitution must remain deterministic.
- **Streaming boundary splits:** In `StreamingScrubber`, credential tokens or PEM headers split across SSE chunk boundaries require bounded tail-overlap buffering so partial matches are not leaked between chunks.
