## Summary

<!-- Concise description of what this PR changes and why. -->

## Type of Change

- [ ] Bug fix (non-breaking)
- [ ] Feature / enhancement
- [ ] Security boundary / policy / scrubber change
- [ ] Documentation / ADR / benchmarks

## Verification & Quality Gates

- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes (deterministic, offline)
- [ ] Zero `.unwrap()`, `.expect()`, or `panic!` added in production paths
- [ ] No secrets, `.env` files, or PII/PHI fixtures committed

## Architecture & Security Review

- [ ] ADR added/updated in `docs/adr/` (if non-trivial architectural change)
- [ ] Fail-closed invariants preserved (auth, `Validator::validate`, `-32001` tape persistence, startup SHA-256 chain check)
