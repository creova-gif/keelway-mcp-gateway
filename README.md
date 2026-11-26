# Keelway MCP Gateway

Programmable, security-first Rust execution gateway and policy testbench for autonomous AI agents interacting with MCP servers.

**Defining principle:** Agents can reason freely, but their ability to act must be explicitly authorized, observable, and controlled.

## Milestone 1 Capabilities

- **Single Rust binary (`keelway`):** Local `stdio` and remote Streamable HTTP (`/mcp`) MCP connectivity.
- **Multi-server federation:** Expose multiple MCP servers behind one endpoint with canonical `<server_alias>__<sanitized_tool_name>` routing and per-principal `tools/list` filtering.
- **Deterministic default-deny authorization:** Pure-Rust Amazon Cedar (`cedar-policy`) paired with 5 typed argument validators (`path_within`, `glob`, `regex`, `sql_readonly` via `sqlparser` AST, `repo_allowlist`) and lock-free `ArcSwap` hot reload.
- **Gateway-managed credential isolation:** Resolve `secret://env/...` and `secret://file/...` inside the gateway only; scrub secrets (`>= 8B`, raw/JSON/URL/Base64) across responses, SSE chunk boundaries, `stderr`, console output, and receipts.
- **SHA-256 hash-chained execution tape:** Dedicated OS-thread group-commit writer (`keelway-tape.jsonl`) with fail-closed persistence and O(1)-memory chain verification.
- **Offline security development lifecycle:** `keelway init`, `keelway gateway up`, `keelway policy test`, `keelway attack simulate`, `keelway trace inspect`, and `keelway replay --dry-run`.

## Installation

**One-line installer** (macOS Apple Silicon & Linux x86_64):

```sh
curl -fsSL https://raw.githubusercontent.com/creova-gif/keelway-mcp-gateway/main/install.sh | sh
```

**Build from source** with Cargo:

```sh
cargo install --git https://github.com/creova-gif/keelway-mcp-gateway keelway-cli
```

## Quick Start

```bash
cargo run -p keelway-cli -- init --dir ./demo
cargo run -p keelway-cli -- policy test --config ./demo/keelway.yaml --tests ./demo/policies/tests.yaml
cargo run -p keelway-cli -- attack simulate --config ./demo/keelway.yaml --scenarios ./demo/attacks/prompt-injection.yaml
```

## Documentation & Standards

- **Design Doc:** [docs/designs/keelway-mcp-gateway-m1.md](docs/designs/keelway-mcp-gateway-m1.md)
- **Threat Model:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- **Architecture Decision Records:** [docs/adr/001-rust-cedar-workspace.md](docs/adr/001-rust-cedar-workspace.md), [docs/adr/002-hash-chained-tape.md](docs/adr/002-hash-chained-tape.md)
- **Engineering Standards:** [AGENTS.md](AGENTS.md)
