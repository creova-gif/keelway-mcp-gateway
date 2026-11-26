# ADR-009: Stateless JWT/OIDC Principal Federation
- **Status:** Accepted
- **Owner:** Justin Mafie

## Context
Previously, Keelway MCP Gateway authenticated callers using static `principals` entries configured in `keelway.yaml`. While suitable for local stdio sessions and small deployments, enterprise multi-tenant environments require federating caller identity from external Identity Providers (IdPs) and OIDC issuers (Okta, Auth0, Entra ID, Google Workspace, internal workload STS) without synchronizing static principal lists or maintaining server-side session state.

## Decision
1. **Stateless Bearer JWT Verification (`keelway_engine::auth`):**
   - Introduce `JwtConfig` and `JwtVerifier` in `crates/keelway-engine/src/auth.rs` backed by `jsonwebtoken` v9.
   - Support three signature verification modes:
     - **HS256 shared secret** (`hs256_secret`) for symmetric service-to-service tokens.
     - **EdDSA (Ed25519) public key** (`ed25519_public_key_hex`), accepting raw 32-byte hex keys, SPKI DER (hex-encoded), or PEM-encoded keys.
     - **Remote OIDC JWKS endpoint** (`jwks_url`) with `reqwest` (5-second request timeout) and a bounded in-memory JWK cache (max 64 keys, 300-second TTL) keyed by JWT header `kid`.
2. **Strict Header & Claim Validation (Fail-Closed):**
   - Inspect JWT header `alg` and `kid` before signature verification; reject tokens whose `alg` does not match configured key material.
   - Enforce `iss` (exact match to configured `issuer`), `aud` (exact match to configured `audience`), and `exp` (required, zero-leeway expiration check).
   - Map configurable JWT claims (`org_claim`, `agent_claim`, `roles_claim`) to `Principal { org_id, agent_id, roles }`. Missing, non-string, or empty `org_id` / `agent_id` claims fail closed with `KeelwayError::Auth`.

## Alternatives Considered
- **Opaque Token Introspection (RFC 7662):** Rejected as the primary path because per-request IdP network round-trips add tail latency and introduce an availability dependency on the IdP for every MCP tool call.
- **Unbounded JWKS Cache:** Rejected because an attacker sending arbitrary `kid` values could trigger unbounded memory growth or repeated cache-miss fetches; bounding cache capacity and TTL prevents memory exhaustion.

## Consequences & Failure Modes
- **IdP Outage During Cold Cache or Key Rotation:** If `jwks_url` is unreachable or times out (>5s) on a `kid` cache miss, `verify_token` fails closed with `KeelwayError::Auth`.
- **Clock Skew Sensitivity:** Zero-leeway `exp` enforcement requires NTP-synchronized clocks between the IdP and gateway hosts.
- **Key Rotation Lag:** Cached JWKs remain valid until their 300-second TTL expires; compromised keys should be rotated at the IdP with short token `exp` lifetimes.
