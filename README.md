# Keelway MCP Gateway

[![CI](https://github.com/creova-gif/keelway-mcp-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/creova-gif/keelway-mcp-gateway/actions/workflows/ci.yml)
[![Release](https://img.shields.io/badge/release-v0.1.2-blue.svg)](https://github.com/creova-gif/keelway-mcp-gateway/releases/tag/v0.1.2)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

Keelway is a single-binary, fail-closed Rust execution gateway and offline policy testbench for autonomous AI agents interacting with Model Context Protocol (MCP) servers. It federates local `stdio` and remote Streamable HTTP (`/mcp`) servers behind one authenticated boundary, enforces two-stage deterministic authorization (typed argument validators + schema-validated Amazon Cedar), scrubs gateway-managed credentials from all egress paths, and records every decision to a SHA-256 hash-chained execution tape.

> **Defining principle:** Agents can reason freely, but their ability to act must be explicitly authorized, observable, and controlled.

## Architecture

```text
+------------+     +---------------------+     +---------------------------------------+
| MCP Client | --> | Auth & Federation   | --> | 2-Stage Policy Engine                 |
| (Agent)    |     | - Principal / org_id|     | 1. Typed Validators (AST, path, glob) |
+------------+     | - tools/list filter |     | 2. Cedar Evaluator (default-deny)     |
      ^            | - alias__tool route |     +---------------------------------------+
      |            +---------------------+                         |
      |                                                            v
+------------+     +---------------------+     +---------------------------------------+
| Secret     | <-- | Upstream MCP Server | <-- | OS-Thread SHA-256 Tape                |
| Scrubber   |     | (stdio / HTTP /mcp) |     | - Group-commit sync_data()            |
| (>= 8B AC) |     +---------------------+     | - Fail-closed (-32001 on write error) |
+------------+                                 +---------------------------------------+
```

- **Auth & Federation:** Exposes multiple upstream MCP servers under canonical `<server_alias>__<sanitized_tool_name>` identifiers with per-principal `tools/list` filtering.
- **2-Stage Cedar + Typed Validators:** Stage 1 runs deterministic argument validators (`path_within`, `glob`, `regex`, `sql_readonly` via `sqlparser` AST, `repo_allowlist`) and injects results into `context.arg_checks.*`; Stage 2 evaluates schema-validated (`Validator::validate`) Amazon Cedar policies with lock-free `ArcSwap` hot reload.
- **OS-Thread SHA-256 Tape:** A dedicated OS thread batches and `sync_data()`-flushes hash-chained (`prev_hash` / `entry_hash`) JSONL receipts to `keelway-tape.jsonl`, failing closed (`-32001`) if persistence fails and verifying the full chain in O(1) memory on startup.
- **Secret Scrubber:** Resolves `secret://env/...` and `secret://file/...` strictly inside the gateway and redacts registered secrets (`>= 8` bytes across raw, JSON-escaped, URL-encoded, and Base64 forms) via Aho-Corasick across responses, SSE chunk boundaries, `stderr`, console logs, and receipts.

## Installation

**Prebuilt binary** (`aarch64-apple-darwin` and `x86_64-unknown-linux-gnu` glibc):

```sh
curl -fsSL https://raw.githubusercontent.com/creova-gif/keelway-mcp-gateway/main/install.sh | sh
```

**Build from source** with Cargo (Rust `1.85+`):

```sh
cargo install --git https://github.com/creova-gif/keelway-mcp-gateway keelway-cli
```

## Quick Start

Initialize a workspace, run deterministic policy unit tests, and simulate prompt-injection attacks offline with zero external side effects:

```sh
keelway init --dir ./demo
keelway policy test --config ./demo/keelway.yaml --tests ./demo/policies/tests.yaml
keelway attack simulate --config ./demo/keelway.yaml --scenarios ./demo/attacks/prompt-injection.yaml
```

Sample `keelway attack simulate` output (from [`examples/three-server-demo`](examples/three-server-demo)):

```text
Keelway Attack Simulation (offline, zero external side effects)
------------------------------------------------------------------------
[OK    ] github.delete_repository     coding-agent     BLOCKED  | explicit forbid by rules: policy2
[OK    ] github.read_repository       coding-agent     BLOCKED  | default-deny: no matching permit rule | failed validators: allowed_repo(repo)=repo 'corp/private-secrets' is outside permitted scope
[OK    ] database.query_readonly      research-agent   BLOCKED  | default-deny: no matching permit rule | failed validators: readonly_sql(sql)=SQL parse error (fail-closed): sql parser error: Expected: SELECT, VALUES, or a subquery in the query body, found: DELETE at Line: 1, Column 12
[OK    ] filesystem.read_file         coding-agent     BLOCKED  | default-deny: no matching permit rule | failed validators: workspace_path(path)=path '/etc/shadow' escapes root '/workspace'
------------------------------------------------------------------------
Simulation summary: 4/4 defenses held
```

Additional lifecycle commands:
- `keelway gateway up --config ./demo/keelway.yaml` — start the federated MCP gateway
- `keelway trace inspect --tape ./demo/keelway-tape.jsonl` — verify and inspect the SHA-256 receipt chain
- `keelway replay --dry-run` — replay recorded receipts offline against candidate `.cedar` policies (flags `INDETERMINATE` if a validator inspects a scrubbed field)

## Benchmarks

Measured local release benchmarks (`cargo bench -p keelway-engine --bench gateway_overhead`, `macOS Apple Silicon`, `rustc 1.100.0`, `2026-11-25`):

| Path Measured | Sample Size | p50 | p95 | p99 | Target / Notes |
|---|---:|---:|---:|---:|---|
| `scrub_json` (Aho-Corasick) + Cedar + `repo_allowlist` | `N = 2,000` | `0.021 ms` | `0.052 ms` | `0.129 ms` | `< 5.0 ms` p95 (in-memory hot path) |
| `scrub_json` (Aho-Corasick) + Cedar + `sqlparser` AST (`sql_readonly`) | `N = 2,000` | `0.032 ms` | `0.121 ms` | `0.300 ms` | `< 5.0 ms` p95 (in-memory hot path) |
| `TapeWriter::append` 50-way concurrent burst (`sync_data()` + SHA-256 chain) | `N = 500` (`10x50`) | `3.906 ms` | `11.855 ms` | `11.857 ms` | Dedicated OS-thread group-commit (`<= 128` receipts/fsync) + full chain verification |

See [benchmarks/competitor-dx-notes.md](benchmarks/competitor-dx-notes.md) for methodology and comparative DX notes.

## Documentation & Governance

- **Architecture & M1 Design:** [docs/designs/keelway-mcp-gateway-m1.md](docs/designs/keelway-mcp-gateway-m1.md)
- **Threat Model:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- **Architecture Decision Records:** [docs/adr/](docs/adr/)
- **Security Policy & Disclosure:** [SECURITY.md](SECURITY.md)
- **Contributing & Quality Gates:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **License:** [Apache-2.0](LICENSE)
