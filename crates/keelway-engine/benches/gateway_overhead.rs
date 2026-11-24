use keelway_engine::core::{GatewayConfig, KeelwayError, Principal, ToolCall};
use keelway_engine::{
    GatewayEngine, PrincipalConfig, SecretScrubber, ServerConfig, UpstreamTransport,
    ValidatorBinding, ValidatorKind,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

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
    };

    let engine = GatewayEngine::from_in_memory(cfg, BENCH_CEDAR)?;
    let scrubber = SecretScrubber::new([
        "ghp_benchmark_secret_token_000001",
        "sk_live_benchmark_secret_000002",
        "postgres_password_secret_000003",
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
    Ok(())
}

fn main() {
    if let Err(e) = run_bench() {
        eprintln!("benchmark failed: {e}");
        std::process::exit(1);
    }
}
