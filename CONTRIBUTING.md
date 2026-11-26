# Contributing to Keelway MCP Gateway

Thank you for contributing to Keelway! Keelway is a security-critical Rust execution boundary; every change is held to strict static analysis, fail-closed correctness, and deterministic testing standards.

## Prerequisites

- **Rust toolchain:** `rustup` with **stable Rust 1.85+** (workspace uses Rust Edition 2024)
  ```sh
  rustup toolchain install stable
  rustup component add rustfmt clippy
  ```
- **Security & Secret Scanning:**
  - `cargo-audit` (`cargo install cargo-audit`)
  - `gitleaks` (for local secret scanning matching CI)

## Quality Gates

All pull requests must pass the same checks enforced in [AGENTS.md](AGENTS.md) and `.github/workflows/ci.yml`:

```sh
# 1. Formatting
cargo fmt --all -- --check

# 2. Linting (zero warnings; workspace denies unwrap/expect/panic/todo/unimplemented)
cargo clippy --workspace --all-targets -- -D warnings

# 3. Deterministic unit & integration tests
cargo test --workspace

# 4. Dependency vulnerability audit
cargo audit
```

### Production Code Rules
- **Zero `.unwrap()`, `.expect()`, `panic!`, `todo!`, or `unimplemented!`** in production code paths (enforced at compile time via `[workspace.lints.clippy]` in `Cargo.toml`). Propagate errors explicitly using `thiserror` and `Result`.
- **No bare error swallowing:** Never ignore `Result` values or silently discard I/O, policy, or persistence errors.
- **Deterministic tests:** Every bug fix or feature must include deterministic unit/integration tests that run offline without external network dependencies.
- **No secrets or PII/PHI:** Never commit `.env` files, real API keys, or sensitive fixtures (`gitleaks` runs on full git history in CI).

## Architecture Decision Records (ADRs)

Per [AGENTS.md](AGENTS.md), every non-trivial architectural or security-boundary change must be accompanied by an ADR in `docs/adr/` using [docs/adr/000-template.md](docs/adr/000-template.md).

## Pull Request Checklist

Before opening a PR, verify:
- [ ] `cargo fmt --all -- --check` passes cleanly.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes with zero warnings.
- [ ] `cargo test --workspace` passes with all new and existing tests deterministic.
- [ ] No `.unwrap()`, `.expect()`, or `panic!` introduced in production paths.
- [ ] `docs/adr/` updated if the change alters architecture, policy semantics, or trust boundaries.
- [ ] `docs/THREAT_MODEL.md` / `SECURITY.md` reviewed if the change touches auth, secret scrubbing, or tape persistence.
