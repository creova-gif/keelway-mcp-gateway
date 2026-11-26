pub use keelway_engine::core;
pub use keelway_engine::provenance;

mod policy {
    use crate::core::{KeelwayError, PolicyDecision, Principal, ToolCall};

    pub struct PolicyEngine;

    impl PolicyEngine {
        pub fn inspected_arg_pointers(&self, _server: &str, _tool: &str) -> Vec<String> {
            Vec::new()
        }

        pub fn evaluate_action(
            &self,
            _principal: &Principal,
            _action_name: &str,
            _tool_call: &ToolCall,
        ) -> Result<PolicyDecision, KeelwayError> {
            Err(KeelwayError::Policy("unused in tape bench".to_owned()))
        }
    }
}

#[allow(dead_code, unused_imports)]
#[path = "../src/tape.rs"]
mod tape;

use chrono::Utc;
use keelway_engine::core::{
    Decision, ExecutionOutcome, Explanation, GatewayConfig, KeelwayError, Principal, ReceiptState,
    ToolCall, UnsealedReceipt,
};
use keelway_engine::{
    GatewayEngine, PrincipalConfig, SecretScrubber, ServerConfig, UpstreamTransport,
    ValidatorBinding, ValidatorKind,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tokio::sync::Barrier;

const BENCH_CEDAR: &str = r#"
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"github/read_repository"
) when {
    context.arg_checks.allowed_repo
};
forbid(
    principal,
    action == Action::"call_tool",
    resource == Tool::"github/delete_repository"
);
permit(
    principal in Role::"researcher",
    action == Action::"call_tool",
    resource == Tool::"database/query_readonly"
) when {
    context.arg_checks.readonly_sql
};
"#;

fn percentile_us(sorted_us: &[u128], pct: f64) -> f64 {
    if sorted_us.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_us.len() - 1) as f64 * pct).round() as usize;
    sorted_us[idx.min(sorted_us.len() - 1)] as f64
}

fn run_bench() -> Result<(), KeelwayError> {
    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: PathBuf::from("unused.jsonl"),
        policy_files: vec![],
        budgets: vec![],
        approval_required: vec![],
        principals: vec![
            PrincipalConfig {
                org_id: "acme".to_owned(),
                agent_id: "coding-agent".to_owned(),
                roles: vec!["developer".to_owned()],
                token_ref: None,
            },
            PrincipalConfig {
                org_id: "acme".to_owned(),
                agent_id: "research-agent".to_owned(),
                roles: vec!["researcher".to_owned()],
                token_ref: None,
            },
        ],
        servers: vec![
            ServerConfig {
                alias: "github".to_owned(),
                timeout_ms: 30_000,
                tools: vec!["read_repository".to_owned(), "delete_repository".to_owned()],
                transport: UpstreamTransport::Stdio {
                    command: "echo".to_owned(),
                    args: vec![],
                    env: BTreeMap::new(),
                },
            },
            ServerConfig {
                alias: "database".to_owned(),
                timeout_ms: 30_000,
                tools: vec!["query_readonly".to_owned()],
                transport: UpstreamTransport::Stdio {
                    command: "echo".to_owned(),
                    args: vec![],
                    env: BTreeMap::new(),
                },
            },
        ],
        validators: vec![
            ValidatorBinding {
                id: "allowed_repo".to_owned(),
                server: "github".to_owned(),
                tool: "read_repository".to_owned(),
                arg_name: "repo".to_owned(),
                kind: ValidatorKind::RepoAllowlist {
                    repos: vec!["sorvex/keelway".to_owned()],
                },
            },
            ValidatorBinding {
                id: "readonly_sql".to_owned(),
                server: "database".to_owned(),
                tool: "query_readonly".to_owned(),
                arg_name: "sql".to_owned(),
                kind: ValidatorKind::SqlReadonly,
            },
        ],
        ..Default::default()
    };

    let engine = GatewayEngine::from_in_memory(cfg, BENCH_CEDAR)?;
    let scrubber = SecretScrubber::new([
        "ghp_benchmark_secret_token_000001", // gitleaks:allow
        "sk_live_benchmark_secret_000002",   // gitleaks:allow
        "postgres_password_secret_000003",   // gitleaks:allow
    ])?;

    let dev = Principal {
        org_id: "acme".to_owned(),
        agent_id: "coding-agent".to_owned(),
        roles: vec!["developer".to_owned()],
    };
    let researcher = Principal {
        org_id: "acme".to_owned(),
        agent_id: "research-agent".to_owned(),
        roles: vec!["researcher".to_owned()],
    };

    let allow_call = ToolCall {
        server: "github".to_owned(),
        tool: "read_repository".to_owned(),
        arguments: json!({ "repo": "sorvex/keelway" }),
    };
    let sql_call = ToolCall {
        server: "database".to_owned(),
        tool: "query_readonly".to_owned(),
        arguments: json!({ "sql": "SELECT id, title FROM issues WHERE org_id = 'acme' LIMIT 50" }),
    };

    const WARMUP: usize = 200;
    const N: usize = 2_000;

    for _ in 0..WARMUP {
        let _ = engine.evaluate_call(&dev, &allow_call)?;
        let _ = engine.evaluate_call(&researcher, &sql_call)?;
    }

    let mut allow_lat = Vec::with_capacity(N);
    for _ in 0..N {
        let t0 = Instant::now();
        let (_scrubbed, _fields) = scrubber.scrub_json(&allow_call.arguments);
        let _ = engine.evaluate_call(&dev, &allow_call)?;
        allow_lat.push(t0.elapsed().as_micros());
    }
    allow_lat.sort_unstable();

    let mut sql_lat = Vec::with_capacity(N);
    for _ in 0..N {
        let t0 = Instant::now();
        let (_scrubbed, _fields) = scrubber.scrub_json(&sql_call.arguments);
        let _ = engine.evaluate_call(&researcher, &sql_call)?;
        sql_lat.push(t0.elapsed().as_micros());
    }
    sql_lat.sort_unstable();

    println!("Keelway Gateway Overhead Benchmark (release, N={N}, warmup={WARMUP})");
    println!(
        "  scrub + Cedar + repo_allowlist : p50 = {:.3} ms | p95 = {:.3} ms | p99 = {:.3} ms",
        percentile_us(&allow_lat, 0.50) / 1000.0,
        percentile_us(&allow_lat, 0.95) / 1000.0,
        percentile_us(&allow_lat, 0.99) / 1000.0,
    );
    println!(
        "  scrub + Cedar + sqlparser AST  : p50 = {:.3} ms | p95 = {:.3} ms | p99 = {:.3} ms",
        percentile_us(&sql_lat, 0.50) / 1000.0,
        percentile_us(&sql_lat, 0.95) / 1000.0,
        percentile_us(&sql_lat, 0.99) / 1000.0,
    );

    const TAPE_BURSTS: usize = 10;
    const TAPE_CONCURRENCY: usize = 50;
    const TAPE_TOTAL: usize = TAPE_BURSTS * TAPE_CONCURRENCY;

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let mut tape_lat = rt.block_on(async {
        let dir = tempdir()?;
        let tape_path = dir.path().join("keelway-tape.jsonl");
        let writer = tape::TapeWriter::open(tape_path.clone())?;
        let mut latencies_us = Vec::with_capacity(TAPE_TOTAL);

        for burst in 0..TAPE_BURSTS {
            let barrier = Arc::new(Barrier::new(TAPE_CONCURRENCY));
            let mut handles = Vec::with_capacity(TAPE_CONCURRENCY);
            for slot in 0..TAPE_CONCURRENCY {
                let w = writer.clone();
                let b = Arc::clone(&barrier);
                let idx = burst * TAPE_CONCURRENCY + slot;
                handles.push(tokio::spawn(async move {
                    let unsealed = UnsealedReceipt {
                        timestamp: Utc::now(),
                        org_id: "acme".to_owned(),
                        agent_id: "coding-agent".to_owned(),
                        server: "github".to_owned(),
                        tool: "read_repository".to_owned(),
                        redacted_args: json!({ "repo": "sorvex/keelway", "seq_hint": idx }),
                        redacted_fields: vec![],
                        decision: Decision::Allow,
                        explanation: Explanation {
                            decision: Decision::Allow,
                            rule_ids: vec!["policy0".to_owned()],
                            validator_outcomes: vec![],
                            reason: "allowed by policy0".to_owned(),
                            policy_digest: "bench_digest".to_owned(),
                        },
                        policy_digest: "bench_digest".to_owned(),
                        state: ReceiptState::Sealed,
                        outcome: Some(ExecutionOutcome::Ok),
                        provenance: None,
                    };
                    b.wait().await;
                    let t0 = Instant::now();
                    let _ = w.append(unsealed).await?;
                    Ok::<u128, KeelwayError>(t0.elapsed().as_micros())
                }));
            }
            for h in handles {
                let elapsed = h.await.map_err(|e| {
                    KeelwayError::Tape(format!("benchmark task join failed: {e}"))
                })??;
                latencies_us.push(elapsed);
            }
        }
        drop(writer);
        let verified = tape::verify_tape(&tape_path)?;
        if !verified.valid || verified.count != TAPE_TOTAL as u64 {
            return Err(KeelwayError::Tape(format!(
                "unexpected tape verification count={} valid={}",
                verified.count, verified.valid
            )));
        }
        Ok::<Vec<u128>, KeelwayError>(latencies_us)
    })?;
    tape_lat.sort_unstable();

    println!(
        "  TapeWriter 50-way burst fsync  : p50 = {:.3} ms | p95 = {:.3} ms | p99 = {:.3} ms (N={TAPE_TOTAL}, {TAPE_BURSTS}x{TAPE_CONCURRENCY})",
        percentile_us(&tape_lat, 0.50) / 1000.0,
        percentile_us(&tape_lat, 0.95) / 1000.0,
        percentile_us(&tape_lat, 0.99) / 1000.0,
    );
    Ok(())
}

fn main() {
    if let Err(e) = run_bench() {
        eprintln!("benchmark failed: {e}");
        std::process::exit(1);
    }
}
