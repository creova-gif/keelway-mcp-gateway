# Keelway MCP Gateway — Benchmark & Competitor DX Notes

## 1. Measured Keelway Policy + Scrubbing Overhead (Local Release Benchmark)

Command: `cargo bench -p keelway-engine --bench gateway_overhead`
Date: `2026-11-24` | Platform: `macOS (Apple Silicon)` | Rust: `rustc 1.100.0` | Sample size: `N = 2,000` (after `200` warmup iterations)

| Hot Path (excluding upstream MCP network/process I/O & disk fsync) | p50 | p95 | p99 | Target |
|---|---:|---:|---:|---:|
| `scrub_json` (Aho-Corasick) + Cedar + `repo_allowlist` | `0.021 ms` | `0.053 ms` | `0.142 ms` | `< 5.0 ms` p95 |
| `scrub_json` (Aho-Corasick) + Cedar + `sqlparser` AST (`sql_readonly`) | `0.031 ms` | `0.055 ms` | `0.105 ms` | `< 5.0 ms` p95 |

*(Note: Disk `sync_data()` latency in `TapeWriter` varies by filesystem/NVMe and is amortized via group-commit batching under concurrent load.)*

## 2. Hands-On Comparative DX Rubric (Agentgateway vs ToolHive vs Keelway)

Fill in the `[pending hands-on run]` cells during the 90-minute local side-by-side comparison against one real MCP server.

| Dimension | Keelway (M1) | Agentgateway | Stacklok ToolHive |
|---|---|---|---|
| Time to first federated 3-server policy block | `keelway init` + `policy test` / `attack simulate` (< 1 min) | `[pending hands-on run]` | `[pending hands-on run]` |
| Policy language & validation | Pure-Rust Cedar + 5 typed validators + in-memory schema `Validator` | CEL / external `ext_authz` (`[verify version]`) | Amazon Cedar (`[verify version]`) |
| Argument-level denial explanation | Structured `Explanation` (`rule_ids`, `validator_outcomes`, `policy_digest`) | `[pending hands-on run]` | `[pending hands-on run]` |
| Offline policy unit tests (`CI exit code`) | `keelway policy test` (built-in) | `[pending hands-on run]` | `[pending hands-on run]` |
| Side-effect-free offline replay against edited policy | `keelway replay --dry-run` (with `INDETERMINATE` redacted-field guard) | `[pending hands-on run]` | `[pending hands-on run]` |
| Tamper-evident execution receipt tape | SHA-256 hash-chained `keelway-tape.jsonl` (`keelway trace inspect`) | `[pending hands-on run]` | `[pending hands-on run]` |
