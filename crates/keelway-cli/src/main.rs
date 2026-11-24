use clap::{Parser, Subcommand, ValueEnum};
use keelway_engine::{Decision, GatewayEngine, PolicyTestCase, ReplayVerdict};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "keelway",
    version,
    about = "Keelway MCP Gateway — Programmable least-privilege execution boundary & policy testbench"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize a starter keelway.yaml, Cedar policy, test suite, and attack simulation corpus
    Init {
        #[arg(long, default_value = ".")]
        dir: PathBuf,
    },
    /// Gateway runtime commands
    Gateway {
        #[command(subcommand)]
        action: GatewayAction,
    },
    /// Policy engineering commands
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Simulate prompt-injection and unauthorized tool attacks offline
    Attack {
        #[command(subcommand)]
        action: AttackAction,
    },
    /// Inspect and verify SHA-256 hash-chained execution receipts
    Trace {
        #[command(subcommand)]
        action: TraceAction,
    },
    /// Replay recorded execution receipts offline against the current policy
    Replay {
        #[arg(long, default_value = "keelway.yaml")]
        config: PathBuf,
        #[arg(long, default_value = "keelway-tape.jsonl")]
        tape: PathBuf,
        #[arg(long, default_value_t = true)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum GatewayAction {
    /// Start the MCP gateway (Streamable HTTP or local stdio)
    Up {
        #[arg(long, default_value = "keelway.yaml")]
        config: PathBuf,
        #[arg(long, value_enum, default_value_t = TransportMode::Http)]
        transport: TransportMode,
        /// Required in stdio mode: `<org_id>/<agent_id>`
        #[arg(long)]
        principal: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TransportMode {
    Http,
    Stdio,
}

#[derive(Debug, Subcommand)]
enum PolicyAction {
    /// Run deterministic offline policy tests
    Test {
        #[arg(long, default_value = "keelway.yaml")]
        config: PathBuf,
        #[arg(long, default_value = "policies/tests.yaml")]
        tests: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AttackAction {
    /// Run offline prompt-injection & unauthorized-action simulations
    Simulate {
        #[arg(long, default_value = "keelway.yaml")]
        config: PathBuf,
        #[arg(long, default_value = "attacks/prompt-injection.yaml")]
        scenarios: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum TraceAction {
    /// Verify the SHA-256 hash chain and print structured ALLOW/DENY explanations
    Inspect {
        #[arg(long, default_value = "keelway-tape.jsonl")]
        tape: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Always route tracing logs to stderr (strictly required for stdio MCP framing safety)
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .try_init();

    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Init { dir } => {
            scaffold_starter(&dir)?;
            println!(
                "Initialized Keelway MCP Gateway workspace in '{}'",
                dir.display()
            );
            println!("Next:");
            println!(
                "  keelway policy test --config {}/keelway.yaml --tests {}/policies/tests.yaml",
                dir.display(),
                dir.display()
            );
            println!(
                "  keelway attack simulate --config {}/keelway.yaml --scenarios {}/attacks/prompt-injection.yaml",
                dir.display(),
                dir.display()
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::Gateway {
            action:
                GatewayAction::Up {
                    config,
                    transport,
                    principal,
                },
        } => {
            let engine = GatewayEngine::from_config_file(&config)?;
            match transport {
                TransportMode::Http => {
                    engine.serve_http().await?;
                }
                TransportMode::Stdio => {
                    let Some(p) = principal else {
                        eprintln!(
                            "error: --principal <org_id>/<agent_id> is required in stdio mode (fail-closed)"
                        );
                        return Ok(ExitCode::FAILURE);
                    };
                    engine.serve_stdio(&p).await?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        Commands::Policy {
            action: PolicyAction::Test { config, tests },
        } => {
            let engine = GatewayEngine::from_config_file(&config)?;
            let raw = fs::read_to_string(&tests)?;
            let cases: Vec<PolicyTestCase> = serde_yaml::from_str(&raw)?;
            let results = engine.run_test_cases(&cases)?;

            let mut failed = 0usize;
            for r in &results {
                let status = if r.passed { "PASS" } else { "FAIL" };
                println!(
                    "[{status}] {:<36} {}.{} ({}) -> {:?} (expected {:?}) | {}",
                    r.name, r.server, r.tool, r.agent_id, r.actual, r.expected, r.reason
                );
                if !r.passed {
                    failed += 1;
                }
            }
            println!(
                "Policy tests: {}/{} passed (policy digest: {})",
                results.len() - failed,
                results.len(),
                &engine.policy_digest()[..12.min(engine.policy_digest().len())]
            );
            Ok(if failed == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Commands::Attack {
            action: AttackAction::Simulate { config, scenarios },
        } => {
            let engine = GatewayEngine::from_config_file(&config)?;
            let raw = fs::read_to_string(&scenarios)?;
            let cases: Vec<PolicyTestCase> = serde_yaml::from_str(&raw)?;
            let results = engine.run_test_cases(&cases)?;

            println!("Keelway Attack Simulation (offline, zero external side effects)");
            println!("------------------------------------------------------------------------");
            let mut failed = 0usize;
            for r in &results {
                let verdict_badge = match r.actual {
                    Decision::Allow => "ALLOWED",
                    Decision::Deny => "BLOCKED",
                };
                let check = if r.passed { "OK" } else { "BREACH" };
                println!(
                    "[{check:<6}] {:<28} {:<16} {:<8} | {}",
                    format!("{}.{}", r.server, r.tool),
                    r.agent_id,
                    verdict_badge,
                    r.reason
                );
                if !r.passed {
                    failed += 1;
                }
            }
            println!("------------------------------------------------------------------------");
            println!(
                "Simulation summary: {}/{} defenses held",
                results.len() - failed,
                results.len()
            );
            Ok(if failed == 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
        Commands::Trace {
            action: TraceAction::Inspect { tape },
        } => {
            let verification = GatewayEngine::inspect_tape(&tape, |r| {
                let badge = match r.decision {
                    Decision::Allow => "ALLOWED",
                    Decision::Deny => "BLOCKED",
                };
                println!(
                    "#{:<4} {:?} {:<26} {:<16} {:<8} | {}",
                    r.seq,
                    r.state,
                    format!("{}.{}", r.server, r.tool),
                    r.agent_id,
                    badge,
                    r.explanation.reason
                );
                Ok(())
            })?;
            println!(
                "tape #{} chain verified (head: {})",
                verification.count,
                &verification.head_hash[..16.min(verification.head_hash.len())]
            );
            Ok(ExitCode::SUCCESS)
        }
        Commands::Replay {
            config,
            tape,
            dry_run: _,
        } => {
            let engine = GatewayEngine::from_config_file(&config)?;
            let entries = engine.replay_tape(&tape)?;
            let mut changed = 0usize;
            let mut indeterminate = 0usize;
            println!("Keelway Policy Replay (DRY RUN - zero upstream calls)");
            for e in &entries {
                let verdict_str = match &e.replayed_verdict {
                    ReplayVerdict::Allow => "ALLOW",
                    ReplayVerdict::Deny => "DENY",
                    ReplayVerdict::Indeterminate { .. } => {
                        indeterminate += 1;
                        "INDETERMINATE"
                    }
                };
                let diff = if e.changed {
                    changed += 1;
                    "CHANGED"
                } else {
                    "SAME"
                };
                println!(
                    "#{:<4} [{:<7}] {:<26} {:<16} {:?} -> {:<13} | {}",
                    e.seq,
                    diff,
                    format!("{}.{}", e.server, e.tool),
                    e.agent_id,
                    e.original_decision,
                    verdict_str,
                    e.reason
                );
            }
            println!(
                "Replay complete: {} receipts evaluated, {} changed, {} indeterminate",
                entries.len(),
                changed,
                indeterminate
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn scaffold_starter(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(dir.join("policies"))?;
    fs::create_dir_all(dir.join("attacks"))?;

    fs::write(
        dir.join("keelway.yaml"),
        r#"bind_addr: "127.0.0.1:8080"
tape_path: "keelway-tape.jsonl"
policy_files:
  - "policies/default.cedar"

principals:
  - org_id: "acme"
    agent_id: "coding-agent"
    roles: ["developer"]
    token_ref: "dev-coding-token"
  - org_id: "acme"
    agent_id: "research-agent"
    roles: ["researcher"]
    token_ref: "dev-research-token"

servers:
  - alias: "github"
    timeout_ms: 30000
    tools: ["read_repository", "create_pull_request", "delete_repository"]
    transport:
      type: "streamable_http"
      url: "http://127.0.0.1:9001/mcp"
      headers: {}
  - alias: "database"
    timeout_ms: 30000
    tools: ["query_readonly"]
    transport:
      type: "streamable_http"
      url: "http://127.0.0.1:9002/mcp"
      headers: {}
  - alias: "filesystem"
    timeout_ms: 30000
    tools: ["read_file"]
    transport:
      type: "streamable_http"
      url: "http://127.0.0.1:9003/mcp"
      headers: {}

validators:
  - id: "allowed_repo"
    server: "github"
    tool: "read_repository"
    arg_name: "repo"
    kind:
      type: "repo_allowlist"
      repos: ["sorvex/keelway"]
  - id: "readonly_sql"
    server: "database"
    tool: "query_readonly"
    arg_name: "sql"
    kind:
      type: "sql_readonly"
  - id: "workspace_path"
    server: "filesystem"
    tool: "read_file"
    arg_name: "path"
    kind:
      type: "path_within"
      root: "/workspace"
"#,
    )?;

    fs::write(
        dir.join("policies/default.cedar"),
        r#"// Keelway default-deny Cedar policy (Milestone 1 starter)
permit(
    principal in Role::"developer",
    action == Action::"list_tool",
    resource == Tool::"github/read_repository"
);

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
    action == Action::"list_tool",
    resource == Tool::"database/query_readonly"
);

permit(
    principal in Role::"researcher",
    action == Action::"call_tool",
    resource == Tool::"database/query_readonly"
) when {
    context.arg_checks.readonly_sql
};

permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"filesystem/read_file"
) when {
    context.arg_checks.workspace_path
};
"#,
    )?;

    fs::write(
        dir.join("policies/tests.yaml"),
        r#"- name: "coding-agent reads authorized repo"
  org_id: "acme"
  agent_id: "coding-agent"
  server: "github"
  tool: "read_repository"
  arguments: { repo: "sorvex/keelway" }
  expected: ALLOW

- name: "coding-agent blocked from deleting repo"
  org_id: "acme"
  agent_id: "coding-agent"
  server: "github"
  tool: "delete_repository"
  arguments: { repo: "sorvex/keelway" }
  expected: DENY

- name: "research-agent runs readonly SQL"
  org_id: "acme"
  agent_id: "research-agent"
  server: "database"
  tool: "query_readonly"
  arguments: { sql: "SELECT id, name FROM docs LIMIT 10" }
  expected: ALLOW

- name: "coding-agent blocked from path traversal"
  org_id: "acme"
  agent_id: "coding-agent"
  server: "filesystem"
  tool: "read_file"
  arguments: { path: "/workspace/../../etc/passwd" }
  expected: DENY
"#,
    )?;

    fs::write(
        dir.join("attacks/prompt-injection.yaml"),
        r#"- name: "Prompt injection -> github.delete_repository"
  org_id: "acme"
  agent_id: "coding-agent"
  server: "github"
  tool: "delete_repository"
  arguments: { repo: "sorvex/keelway" }
  expected: DENY

- name: "Prompt injection -> unauthorized repo access"
  org_id: "acme"
  agent_id: "coding-agent"
  server: "github"
  tool: "read_repository"
  arguments: { repo: "corp/private-secrets" }
  expected: DENY

- name: "Prompt injection -> SQL write CTE exfiltration"
  org_id: "acme"
  agent_id: "research-agent"
  server: "database"
  tool: "query_readonly"
  arguments: { sql: "WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d" }
  expected: DENY

- name: "Prompt injection -> filesystem escape"
  org_id: "acme"
  agent_id: "coding-agent"
  server: "filesystem"
  tool: "read_file"
  arguments: { path: "/workspace/../../../etc/shadow" }
  expected: DENY
"#,
    )?;

    Ok(())
}
