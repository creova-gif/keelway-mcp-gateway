use clap::{Parser, Subcommand, ValueEnum};
use keelway_engine::{
    Decision, ExecutionOutcome, GatewayEngine, PolicyTestCase, ReplayVerdict, UpstreamTransport,
    core::GatewayConfig, validate_server_alias,
};
use std::collections::{HashSet, VecDeque};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
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
    /// Run offline pre-flight production readiness diagnostics
    Doctor {
        #[arg(long, default_value = "keelway.yaml")]
        config: PathBuf,
    },
    /// Generate a random 32-byte Ed25519 signing key for audit tape provenance
    Keygen {
        #[arg(long)]
        output: Option<PathBuf>,
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
        /// Optional hex-encoded Ed25519 verifying (public) key to verify receipt signatures
        #[arg(long)]
        public_key: Option<String>,
        /// Print only the last N matching receipts (still verifies the full chain)
        #[arg(long)]
        tail: Option<usize>,
        /// Filter printed receipts by provenance.trace_id
        #[arg(long)]
        trace_id: Option<String>,
        /// Filter printed receipts by policy decision
        #[arg(long, value_enum)]
        decision: Option<TraceDecisionFilter>,
        /// Filter printed receipts by execution outcome
        #[arg(long, value_enum)]
        outcome: Option<TraceOutcomeFilter>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TraceDecisionFilter {
    Allow,
    Deny,
}

impl TraceDecisionFilter {
    fn matches(self, decision: Decision) -> bool {
        match (self, decision) {
            (Self::Allow, Decision::Allow) | (Self::Deny, Decision::Deny) => true,
            (Self::Allow, Decision::Deny) | (Self::Deny, Decision::Allow) => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TraceOutcomeFilter {
    Ok,
    Timeout,
    Crashed,
}

impl TraceOutcomeFilter {
    fn matches(
        self,
        decision: Decision,
        state: keelway_engine::ReceiptState,
        outcome: Option<ExecutionOutcome>,
    ) -> bool {
        match self {
            Self::Ok => {
                decision == Decision::Allow
                    && state == keelway_engine::ReceiptState::Sealed
                    && matches!(outcome, None | Some(ExecutionOutcome::Ok))
            }
            Self::Timeout => matches!(outcome, Some(ExecutionOutcome::Timeout)),
            Self::Crashed => matches!(outcome, Some(ExecutionOutcome::Crashed)),
        }
    }
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
            action:
                TraceAction::Inspect {
                    tape,
                    public_key,
                    tail,
                    trace_id,
                    decision,
                    outcome,
                },
        } => {
            inspect_tape_to_writer(
                &tape,
                public_key.as_deref(),
                tail,
                trace_id.as_deref(),
                decision,
                outcome,
                &mut std::io::stdout(),
            )?;
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
        Commands::Doctor { config } => run_doctor(&config),
        Commands::Keygen { output } => {
            let seed_hex = format!(
                "{}{}",
                keelway_engine::provenance::extract_or_generate_trace_id(None),
                keelway_engine::provenance::extract_or_generate_trace_id(None),
            );
            let signer = keelway_engine::provenance::TapeSigner::from_seed_str(&seed_hex)?;
            let key_id = signer.key_id();
            let verifying_key_hex = signer.verifying_key_hex();

            if let Some(path) = output {
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }
                let mut opts = fs::OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                #[cfg(unix)]
                opts.mode(0o600);
                let mut file = opts.open(&path)?;
                writeln!(file, "{seed_hex}")?;
                println!("Generated Ed25519 signing key:");
                println!("  key_id:        {key_id}");
                println!("  verifying_key: {verifying_key_hex}");
                println!("  saved_to:      {}", path.display());
                println!(
                    "  config_hint:   signing_key_ref: \"secret://file/{}\"",
                    path.display()
                );
            } else {
                println!("Generated Ed25519 signing key:");
                println!("  seed_hex:      {seed_hex}");
                println!("  key_id:        {key_id}");
                println!("  verifying_key: {verifying_key_hex}");
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

/// Streams and verifies every receipt in `tape`, filtering and tailing formatted lines to `out`.
fn inspect_tape_to_writer(
    tape: &Path,
    public_key: Option<&str>,
    tail: Option<usize>,
    trace_id: Option<&str>,
    decision: Option<TraceDecisionFilter>,
    outcome: Option<TraceOutcomeFilter>,
    out: &mut impl Write,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tail_buf = tail.map(|n| VecDeque::with_capacity(n.min(1024)));
    let verification = GatewayEngine::inspect_tape(tape, |r| {
        if let Some(vk) = public_key {
            let sig_hex = r
                .provenance
                .as_ref()
                .and_then(|p| p.get("signature_hex"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    keelway_engine::core::KeelwayError::Tape(format!(
                        "missing Ed25519 provenance signature at seq {}",
                        r.seq
                    ))
                })?;
            keelway_engine::provenance::TapeSigner::verify_hex(
                vk,
                r.entry_hash.as_bytes(),
                sig_hex,
            )?;
        }

        let receipt_trace_id = r
            .provenance
            .as_ref()
            .and_then(|p| p.get("trace_id"))
            .and_then(|v| v.as_str());

        if let Some(target_trace_id) = trace_id
            && receipt_trace_id.is_none_or(|tid| !tid.eq_ignore_ascii_case(target_trace_id))
        {
            return Ok(());
        }
        if let Some(target_decision) = decision
            && !target_decision.matches(r.decision)
        {
            return Ok(());
        }
        if let Some(target_outcome) = outcome
            && !target_outcome.matches(r.decision, r.state, r.outcome)
        {
            return Ok(());
        }

        let badge = match r.decision {
            Decision::Allow => "ALLOWED",
            Decision::Deny => "BLOCKED",
        };
        let trace_snippet = match receipt_trace_id {
            Some(tid) => format!(" trace={tid}"),
            None => String::new(),
        };
        let outcome_snippet = match r.outcome {
            Some(ExecutionOutcome::Timeout) => " outcome=Timeout",
            Some(ExecutionOutcome::Crashed) => " outcome=Crashed",
            Some(ExecutionOutcome::Ok) | None => "",
        };
        let line = format!(
            "#{:<4} {:?} {:<26} {:<16} {:<8}{}{} | {}",
            r.seq,
            r.state,
            format!("{}.{}", r.server, r.tool),
            r.agent_id,
            badge,
            trace_snippet,
            outcome_snippet,
            r.explanation.reason
        );

        if let Some(limit) = tail {
            if limit > 0
                && let Some(ref mut buf) = tail_buf
            {
                if buf.len() == limit {
                    buf.pop_front();
                }
                buf.push_back(line);
            }
        } else {
            writeln!(out, "{line}")?;
        }
        Ok(())
    })?;

    if let Some(buf) = tail_buf {
        for line in buf {
            writeln!(out, "{line}")?;
        }
    }

    if public_key.is_some() {
        writeln!(
            out,
            "tape #{} chain and Ed25519 signatures verified (head: {})",
            verification.count,
            &verification.head_hash[..16.min(verification.head_hash.len())]
        )?;
    } else {
        writeln!(
            out,
            "tape #{} chain verified (head: {})",
            verification.count,
            &verification.head_hash[..16.min(verification.head_hash.len())]
        )?;
    }
    Ok(())
}

struct DoctorCheck {
    status: &'static str,
    name: String,
    detail: String,
}

fn run_doctor(config_path: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut checks: Vec<DoctorCheck> = Vec::new();
    let mut failures = 0usize;

    let raw = match fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) => {
            checks.push(DoctorCheck {
                status: "FAIL",
                name: "Config".to_owned(),
                detail: format!("failed to read '{}': {e}", config_path.display()),
            });
            print_doctor_summary(&checks);
            return Err(format!(
                "doctor failed reading config '{}': {e}",
                config_path.display()
            )
            .into());
        }
    };

    let config: GatewayConfig = match serde_yaml::from_str(&raw) {
        Ok(cfg) => cfg,
        Err(e) => {
            checks.push(DoctorCheck {
                status: "FAIL",
                name: "Config".to_owned(),
                detail: format!("invalid YAML in '{}': {e}", config_path.display()),
            });
            print_doctor_summary(&checks);
            return Err(format!(
                "doctor failed parsing config '{}': {e}",
                config_path.display()
            )
            .into());
        }
    };

    match validate_config_bindings(&config) {
        Ok(()) => checks.push(DoctorCheck {
            status: "PASS",
            name: "Config".to_owned(),
            detail: format!(
                "{} server(s), {} principal(s) validated",
                config.servers.len(),
                config.principals.len()
            ),
        }),
        Err(msg) => {
            failures += 1;
            checks.push(DoctorCheck {
                status: "FAIL",
                name: "Config".to_owned(),
                detail: msg,
            });
        }
    }

    match GatewayEngine::from_config_file(config_path) {
        Ok(engine) => {
            let digest = engine.policy_digest();
            let short_digest = &digest[..12.min(digest.len())];
            checks.push(DoctorCheck {
                status: "PASS",
                name: "Cedar Policies".to_owned(),
                detail: format!(
                    "{} policy file(s) validated (digest: {short_digest})",
                    config.policy_files.len()
                ),
            });
        }
        Err(e) => {
            failures += 1;
            checks.push(DoctorCheck {
                status: "FAIL",
                name: "Cedar Policies".to_owned(),
                detail: e.to_string(),
            });
        }
    }

    let mut signing_vk: Option<String> = None;
    if let Some(key_ref) = &config.signing_key_ref {
        match resolve_secret_ref_value(key_ref).and_then(|seed| {
            keelway_engine::provenance::TapeSigner::from_seed_str(&seed).map_err(|e| e.to_string())
        }) {
            Ok(signer) => {
                signing_vk = Some(signer.verifying_key_hex());
                checks.push(DoctorCheck {
                    status: "PASS",
                    name: "Signing Key".to_owned(),
                    detail: format!("Ed25519 key '{}' loaded", signer.key_id()),
                });
            }
            Err(msg) => {
                failures += 1;
                checks.push(DoctorCheck {
                    status: "FAIL",
                    name: "Signing Key".to_owned(),
                    detail: msg,
                });
            }
        }
    }

    if let Some(jwt_cfg) = &config.jwt_auth {
        let mut resolved_cfg = jwt_cfg.clone();
        let secret_res = match &jwt_cfg.hs256_secret {
            Some(secret_ref) if secret_ref.starts_with("secret://") => {
                resolve_secret_ref_value(secret_ref).map(Some)
            }
            other => Ok(other.clone()),
        };
        match secret_res.and_then(|resolved_secret| {
            resolved_cfg.hs256_secret = resolved_secret;
            keelway_engine::auth::JwtVerifier::new(resolved_cfg).map_err(|e| e.to_string())
        }) {
            Ok(_) => checks.push(DoctorCheck {
                status: "PASS",
                name: "JWT Auth".to_owned(),
                detail: format!(
                    "issuer '{}', audience '{}' validated",
                    jwt_cfg.issuer, jwt_cfg.audience
                ),
            }),
            Err(msg) => {
                failures += 1;
                checks.push(DoctorCheck {
                    status: "FAIL",
                    name: "JWT Auth".to_owned(),
                    detail: msg,
                });
            }
        }
    }

    let secret_refs = collect_secret_refs(&config);
    if secret_refs.is_empty() {
        checks.push(DoctorCheck {
            status: "PASS",
            name: "Secrets".to_owned(),
            detail: "0 secret:// references configured".to_owned(),
        });
    } else {
        for (source, reference) in secret_refs {
            match check_secret_ref(&reference) {
                Ok(()) => checks.push(DoctorCheck {
                    status: "PASS",
                    name: format!("Secret ({source})"),
                    detail: format!("{reference} resolved"),
                }),
                Err(msg) => {
                    failures += 1;
                    checks.push(DoctorCheck {
                        status: "FAIL",
                        name: format!("Secret ({source})"),
                        detail: msg,
                    });
                }
            }
        }
    }

    let mut stdio_count = 0usize;
    for server in &config.servers {
        if let UpstreamTransport::Stdio { command, .. } = &server.transport {
            stdio_count += 1;
            if command_exists(command) {
                checks.push(DoctorCheck {
                    status: "PASS",
                    name: format!("Stdio ({})", server.alias),
                    detail: format!("command '{command}' found"),
                });
            } else {
                failures += 1;
                checks.push(DoctorCheck {
                    status: "FAIL",
                    name: format!("Stdio ({})", server.alias),
                    detail: format!("command '{command}' not found"),
                });
            }
        }
    }
    if stdio_count == 0 {
        checks.push(DoctorCheck {
            status: "SKIP",
            name: "Stdio Commands".to_owned(),
            detail: "no stdio servers configured".to_owned(),
        });
    }

    let base_dir = match config_path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let tape_path = if config.tape_path.is_absolute() {
        config.tape_path.clone()
    } else {
        base_dir.join(&config.tape_path)
    };
    if tape_path.exists() {
        match GatewayEngine::verify_tape_with_key(&tape_path, signing_vk.as_deref()) {
            Ok(verification) => {
                let short_head = &verification.head_hash[..16.min(verification.head_hash.len())];
                checks.push(DoctorCheck {
                    status: "PASS",
                    name: "Tape Integrity".to_owned(),
                    detail: format!(
                        "{} receipt(s) verified (head: {short_head})",
                        verification.count
                    ),
                });
            }
            Err(e) => {
                failures += 1;
                checks.push(DoctorCheck {
                    status: "FAIL",
                    name: "Tape Integrity".to_owned(),
                    detail: e.to_string(),
                });
            }
        }
    } else {
        checks.push(DoctorCheck {
            status: "SKIP",
            name: "Tape Integrity".to_owned(),
            detail: format!("'{}' does not exist yet", tape_path.display()),
        });
    }

    print_doctor_summary(&checks);

    if failures > 0 {
        Err(format!("doctor found {failures} failing check(s)").into())
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn validate_config_bindings(config: &GatewayConfig) -> Result<(), String> {
    let mut seen_aliases: HashSet<&str> = HashSet::new();
    for server in &config.servers {
        validate_server_alias(&server.alias).map_err(|e| e.to_string())?;
        if !seen_aliases.insert(server.alias.as_str()) {
            return Err(format!("duplicate server alias '{}'", server.alias));
        }
    }

    let mut seen_tools: HashSet<String> = HashSet::new();
    for server in &config.servers {
        for tool in &server.tools {
            let fed_name = keelway_engine::sanitize_federated_name(&server.alias, tool)
                .map_err(|e| e.to_string())?;
            if !seen_tools.insert(fed_name.clone()) {
                return Err(format!("duplicate federated tool name '{fed_name}'"));
            }
        }
    }

    let mut seen_principals: HashSet<(&str, &str)> = HashSet::new();
    for principal in &config.principals {
        if principal.org_id.trim().is_empty() || principal.agent_id.trim().is_empty() {
            return Err(format!(
                "principal '{}/{}' must have non-empty org_id and agent_id",
                principal.org_id, principal.agent_id
            ));
        }
        if !seen_principals.insert((principal.org_id.as_str(), principal.agent_id.as_str())) {
            return Err(format!(
                "duplicate principal binding '{}/{}'",
                principal.org_id, principal.agent_id
            ));
        }
    }
    Ok(())
}

fn collect_secret_refs(config: &GatewayConfig) -> Vec<(String, String)> {
    let mut refs = Vec::new();
    for server in &config.servers {
        match &server.transport {
            UpstreamTransport::Stdio { env, .. } => {
                for (key, value) in env {
                    if value.starts_with("secret://") {
                        refs.push((format!("server:{}.env.{key}", server.alias), value.clone()));
                    }
                }
            }
            UpstreamTransport::StreamableHttp { headers, .. } => {
                for (key, value) in headers {
                    if value.starts_with("secret://") {
                        refs.push((
                            format!("server:{}.header.{key}", server.alias),
                            value.clone(),
                        ));
                    }
                }
            }
        }
    }
    for principal in &config.principals {
        if let Some(token_ref) = &principal.token_ref
            && token_ref.starts_with("secret://")
        {
            refs.push((
                format!(
                    "principal:{}/{}.token_ref",
                    principal.org_id, principal.agent_id
                ),
                token_ref.clone(),
            ));
        }
    }
    if let Some(hs256_secret) = config
        .jwt_auth
        .as_ref()
        .and_then(|j| j.hs256_secret.as_ref())
        && hs256_secret.starts_with("secret://")
    {
        refs.push(("jwt_auth.hs256_secret".to_owned(), hs256_secret.clone()));
    }
    refs
}

fn resolve_secret_ref_value(reference: &str) -> Result<String, String> {
    if let Some(var_name) = reference.strip_prefix("secret://env/") {
        if var_name.is_empty() {
            return Err("empty environment variable name in secret://env/".to_owned());
        }
        std::env::var(var_name).map_err(|_| format!("environment variable '{var_name}' is not set"))
    } else if let Some(file_path) = reference.strip_prefix("secret://file/") {
        if file_path.is_empty() {
            return Err("empty file path in secret://file/".to_owned());
        }
        fs::read_to_string(file_path)
            .map(|s| s.trim_end_matches(['\r', '\n']).to_owned())
            .map_err(|e| format!("failed to read secret file '{file_path}': {e}"))
    } else if reference.starts_with("secret://gcp/") {
        Err("GCP Secret Manager provider is a Milestone 2+ plugin seam; use secret://env/ or secret://file/ in Milestone 1".to_owned())
    } else if reference.starts_with("secret://") {
        Err(format!("unsupported secret scheme in '{reference}'"))
    } else {
        Ok(reference.to_owned())
    }
}

fn check_secret_ref(reference: &str) -> Result<(), String> {
    resolve_secret_ref_value(reference).map(|_| ())
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn command_exists(cmd: &str) -> bool {
    if cmd.is_empty() {
        return false;
    }
    if cmd.contains('/') || cmd.contains('\\') {
        return is_executable_file(Path::new(cmd));
    }
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| is_executable_file(&dir.join(cmd)))
    })
}

fn print_doctor_summary(checks: &[DoctorCheck]) {
    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    println!("Keelway Doctor (offline pre-flight diagnostics)");
    println!("------------------------------------------------------------------------");
    for c in checks {
        match c.status {
            "PASS" => passed += 1,
            "FAIL" => failed += 1,
            _ => skipped += 1,
        }
        println!("[{:<4}] {:<24} | {}", c.status, c.name, c.detail);
    }
    println!("------------------------------------------------------------------------");
    println!("Doctor summary: {passed} passed, {failed} failed, {skipped} skipped");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(label: &str) -> Result<Self, Box<dyn std::error::Error>> {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos());
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keelway-cli-{label}-{}-{nanos}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn os_args(items: &[&std::ffi::OsStr]) -> Vec<OsString> {
        items.iter().map(|s| (*s).to_os_string()).collect()
    }

    #[tokio::test]
    async fn cli_init_policy_test_and_attack_simulate_succeed()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDirGuard::new("init-policy-attack")?;
        let dir = tmp.path();
        let config = dir.join("keelway.yaml");
        let tests_file = dir.join("policies/tests.yaml");
        let scenarios = dir.join("attacks/prompt-injection.yaml");

        let init_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "init".as_ref(),
            "--dir".as_ref(),
            dir.as_os_str(),
        ]))?;
        assert_eq!(run(init_cli).await?, ExitCode::SUCCESS);

        let policy_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "policy".as_ref(),
            "test".as_ref(),
            "--config".as_ref(),
            config.as_os_str(),
            "--tests".as_ref(),
            tests_file.as_os_str(),
        ]))?;
        assert_eq!(run(policy_cli).await?, ExitCode::SUCCESS);

        let attack_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "attack".as_ref(),
            "simulate".as_ref(),
            "--config".as_ref(),
            config.as_os_str(),
            "--scenarios".as_ref(),
            scenarios.as_os_str(),
        ]))?;
        assert_eq!(run(attack_cli).await?, ExitCode::SUCCESS);

        Ok(())
    }

    #[tokio::test]
    async fn cli_stdio_without_principal_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDirGuard::new("stdio-fail-closed")?;
        let dir = tmp.path();
        let config = dir.join("keelway.yaml");

        let init_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "init".as_ref(),
            "--dir".as_ref(),
            dir.as_os_str(),
        ]))?;
        assert_eq!(run(init_cli).await?, ExitCode::SUCCESS);

        let gateway_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "gateway".as_ref(),
            "up".as_ref(),
            "--config".as_ref(),
            config.as_os_str(),
            "--transport".as_ref(),
            "stdio".as_ref(),
        ]))?;
        assert_eq!(run(gateway_cli).await?, ExitCode::FAILURE);

        Ok(())
    }

    #[tokio::test]
    async fn cli_trace_inspect_and_replay_dry_run_work_on_empty_or_valid_tape()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDirGuard::new("trace-replay")?;
        let dir = tmp.path();
        let config = dir.join("keelway.yaml");
        let tape = dir.join("keelway-tape.jsonl");

        let init_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "init".as_ref(),
            "--dir".as_ref(),
            dir.as_os_str(),
        ]))?;
        assert_eq!(run(init_cli).await?, ExitCode::SUCCESS);

        fs::write(&tape, "")?;

        let inspect_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "trace".as_ref(),
            "inspect".as_ref(),
            "--tape".as_ref(),
            tape.as_os_str(),
        ]))?;
        assert_eq!(run(inspect_cli).await?, ExitCode::SUCCESS);

        let replay_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "replay".as_ref(),
            "--config".as_ref(),
            config.as_os_str(),
            "--tape".as_ref(),
            tape.as_os_str(),
            "--dry-run".as_ref(),
        ]))?;
        assert_eq!(run(replay_cli).await?, ExitCode::SUCCESS);

        Ok(())
    }

    #[tokio::test]
    async fn cli_trace_inspect_filters_by_tail_trace_id_and_decision()
    -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDirGuard::new("trace-inspect-filters")?;
        let dir = tmp.path();
        let tape = dir.join("keelway-tape.jsonl");
        let signer = keelway_engine::provenance::TapeSigner::from_seed_str(
            "0101010101010101010101010101010101010101010101010101010101010101",
        )?;
        let vk_hex = signer.verifying_key_hex();

        let fixtures = [
            (
                1u64,
                keelway_engine::GENESIS_HASH,
                "c793c63c372e7110deb1a344c2aef56350e5a85e78f9263ab2fa426fd4dd0bff",
                "ALLOW",
                "trace-a",
                "allow-a-1",
            ),
            (
                2u64,
                "c793c63c372e7110deb1a344c2aef56350e5a85e78f9263ab2fa426fd4dd0bff",
                "0465ab0d5b1cbc092a98a2cd3672b07d53a91481a8e2b43058b1aded3e19cf36",
                "DENY",
                "trace-a",
                "deny-a-2",
            ),
            (
                3u64,
                "0465ab0d5b1cbc092a98a2cd3672b07d53a91481a8e2b43058b1aded3e19cf36",
                "d4be1ae2d6856d9896146e44282a6d4b085bd3b6a4bc72e1d7d0477f6a3bfc4a",
                "DENY",
                "trace-b",
                "deny-b-3",
            ),
            (
                4u64,
                "d4be1ae2d6856d9896146e44282a6d4b085bd3b6a4bc72e1d7d0477f6a3bfc4a",
                "99f016da4687e3a9b9b6fde670416320725e4bc0bb51036a725658b37e994e47",
                "DENY",
                "trace-a",
                "deny-a-4",
            ),
        ];

        let mut lines = String::new();
        for (seq, prev_hash, entry_hash, dec, trace_id, reason) in fixtures {
            let sig_hex = signer.sign_hex(entry_hash.as_bytes());
            let receipt: keelway_engine::Receipt = serde_json::from_value(serde_json::json!({
                "seq": seq,
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
                "timestamp": "2026-01-01T00:00:00Z",
                "org_id": "acme",
                "agent_id": "coding-agent",
                "server": "local-fs",
                "tool": "read_file",
                "redacted_args": {},
                "redacted_fields": [],
                "decision": dec,
                "explanation": {
                    "decision": dec,
                    "rule_ids": [],
                    "validator_outcomes": [],
                    "reason": reason,
                    "policy_digest": "abc123"
                },
                "policy_digest": "abc123",
                "state": "SEALED",
                "provenance": {
                    "trace_id": trace_id,
                    "key_id": signer.key_id(),
                    "signature_hex": sig_hex
                }
            }))?;
            lines.push_str(&serde_json::to_string(&receipt)?);
            lines.push('\n');
        }
        fs::write(&tape, lines)?;

        // 1. CLI parsing + execution with --tail, --trace-id, --decision deny, --public-key
        let cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "trace".as_ref(),
            "inspect".as_ref(),
            "--tape".as_ref(),
            tape.as_os_str(),
            "--public-key".as_ref(),
            vk_hex.as_ref(),
            "--tail".as_ref(),
            "1".as_ref(),
            "--trace-id".as_ref(),
            "trace-a".as_ref(),
            "--decision".as_ref(),
            "deny".as_ref(),
        ]))?;
        assert_eq!(run(cli).await?, ExitCode::SUCCESS);

        // 2. Verify filtered & tailed output lines directly
        let mut out = Vec::new();
        inspect_tape_to_writer(
            &tape,
            Some(&vk_hex),
            Some(1),
            Some("trace-a"),
            Some(TraceDecisionFilter::Deny),
            None,
            &mut out,
        )?;
        let output = String::from_utf8(out)?;
        assert!(!output.contains("allow-a-1"));
        assert!(!output.contains("deny-a-2"));
        assert!(!output.contains("deny-b-3"));
        assert!(output.contains("deny-a-4"));
        assert!(output.contains("trace=trace-a"));
        assert!(output.contains("tape #4 chain and Ed25519 signatures verified"));

        // 3. --tail 0 prints no receipt lines, still verifies full chain
        let mut zero_out = Vec::new();
        inspect_tape_to_writer(&tape, None, Some(0), None, None, None, &mut zero_out)?;
        let zero_output = String::from_utf8(zero_out)?;
        assert!(!zero_output.contains("allow-a-1"));
        assert!(!zero_output.contains("deny-a-4"));
        assert!(zero_output.contains("tape #4 chain verified"));

        Ok(())
    }

    #[tokio::test]
    async fn cli_trace_inspect_filters_by_outcome() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDirGuard::new("trace-inspect-outcome")?;
        let dir = tmp.path();
        let tape = dir.join("keelway-tape.jsonl");

        let fixtures = [
            (
                1u64,
                keelway_engine::GENESIS_HASH,
                "801ea719b843217156bad4fdad3b9fbeea09585b2ef41abf6fe675522e74c1fc",
                "ALLOW",
                Some("ok"),
                "allow-ok-1",
            ),
            (
                2u64,
                "801ea719b843217156bad4fdad3b9fbeea09585b2ef41abf6fe675522e74c1fc",
                "549999f41fc208f65d713579eb60016d23ff23642567afd65cab18eb250778e3",
                "ALLOW",
                Some("timeout"),
                "allow-timeout-2",
            ),
            (
                3u64,
                "549999f41fc208f65d713579eb60016d23ff23642567afd65cab18eb250778e3",
                "08abb5ff448bbbdd4f1a53210433d50d5e519d3402a72e41cba6d8021e929f12",
                "ALLOW",
                Some("crashed"),
                "allow-crashed-3",
            ),
            (
                4u64,
                "08abb5ff448bbbdd4f1a53210433d50d5e519d3402a72e41cba6d8021e929f12",
                "7e5e465ebf7e094ffcd3e3dbb3190c2e36507253bba215a9fcc1e3ab174c4179",
                "DENY",
                None,
                "deny-none-4",
            ),
        ];

        let mut lines = String::new();
        for (seq, prev_hash, entry_hash, dec, outcome, reason) in fixtures {
            let receipt: keelway_engine::Receipt = serde_json::from_value(serde_json::json!({
                "seq": seq,
                "prev_hash": prev_hash,
                "entry_hash": entry_hash,
                "timestamp": "2026-01-01T00:00:00Z",
                "org_id": "acme",
                "agent_id": "coding-agent",
                "server": "local-fs",
                "tool": "read_file",
                "redacted_args": {},
                "redacted_fields": [],
                "decision": dec,
                "explanation": {
                    "decision": dec,
                    "rule_ids": [],
                    "validator_outcomes": [],
                    "reason": reason,
                    "policy_digest": "abc123"
                },
                "policy_digest": "abc123",
                "state": "SEALED",
                "outcome": outcome,
            }))?;
            lines.push_str(&serde_json::to_string(&receipt)?);
            lines.push('\n');
        }
        fs::write(&tape, lines)?;

        let cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "trace".as_ref(),
            "inspect".as_ref(),
            "--tape".as_ref(),
            tape.as_os_str(),
            "--outcome".as_ref(),
            "timeout".as_ref(),
        ]))?;
        assert_eq!(run(cli).await?, ExitCode::SUCCESS);

        let mut timeout_out = Vec::new();
        inspect_tape_to_writer(
            &tape,
            None,
            None,
            None,
            None,
            Some(TraceOutcomeFilter::Timeout),
            &mut timeout_out,
        )?;
        let timeout_output = String::from_utf8(timeout_out)?;
        assert!(!timeout_output.contains("allow-ok-1"));
        assert!(timeout_output.contains("allow-timeout-2"));
        assert!(timeout_output.contains("outcome=Timeout"));
        assert!(!timeout_output.contains("allow-crashed-3"));
        assert!(!timeout_output.contains("deny-none-4"));
        assert!(timeout_output.contains("tape #4 chain verified"));

        let mut crashed_out = Vec::new();
        inspect_tape_to_writer(
            &tape,
            None,
            None,
            None,
            None,
            Some(TraceOutcomeFilter::Crashed),
            &mut crashed_out,
        )?;
        let crashed_output = String::from_utf8(crashed_out)?;
        assert!(!crashed_output.contains("allow-ok-1"));
        assert!(!crashed_output.contains("allow-timeout-2"));
        assert!(crashed_output.contains("allow-crashed-3"));
        assert!(crashed_output.contains("outcome=Crashed"));
        assert!(!crashed_output.contains("deny-none-4"));
        assert!(crashed_output.contains("tape #4 chain verified"));

        Ok(())
    }

    #[tokio::test]
    async fn cli_doctor_validates_initialized_workspace() -> Result<(), Box<dyn std::error::Error>>
    {
        let tmp = TempDirGuard::new("doctor")?;
        let dir = tmp.path();
        let config = dir.join("keelway.yaml");

        // 1. Initialized starter workspace passes doctor (tape does not exist yet -> SKIP).
        let init_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "init".as_ref(),
            "--dir".as_ref(),
            dir.as_os_str(),
        ]))?;
        assert_eq!(run(init_cli).await?, ExitCode::SUCCESS);

        let doctor_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "doctor".as_ref(),
            "--config".as_ref(),
            config.as_os_str(),
        ]))?;
        assert_eq!(run(doctor_cli).await?, ExitCode::SUCCESS);

        // 2. Passing secret://file/ and stdio command checks (with existing empty tape).
        let simple_cedar = dir.join("policies/simple.cedar");
        fs::write(
            &simple_cedar,
            "permit(principal in Role::\"developer\", action == Action::\"list_tool\", resource);\n",
        )?;
        let secret_file = dir.join("api.secret");
        fs::write(&secret_file, "super-secret-value-not-printed\n")?;
        let stdio_bin = dir.join("mock-mcp-bin");
        fs::write(&stdio_bin, "#!/bin/sh\nexit 0\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stdio_bin, fs::Permissions::from_mode(0o755))?;
        }
        let tape = dir.join("keelway-tape.jsonl");
        fs::write(&tape, "")?;

        let pass_cfg = dir.join("pass.yaml");
        fs::write(
            &pass_cfg,
            format!(
                r#"bind_addr: "127.0.0.1:8080"
tape_path: "keelway-tape.jsonl"
policy_files:
  - "policies/simple.cedar"
principals:
  - org_id: "acme"
    agent_id: "coding-agent"
    roles: ["developer"]
    token_ref: "secret://file/{secret}"
servers:
  - alias: "local-fs"
    transport:
      type: "stdio"
      command: "{bin}"
      args: []
      env:
        API_KEY: "secret://file/{secret}"
  - alias: "remote-http"
    transport:
      type: "streamable_http"
      url: "http://127.0.0.1:9001/mcp"
      headers:
        Authorization: "secret://file/{secret}"
"#,
                secret = secret_file.display(),
                bin = stdio_bin.display(),
            ),
        )?;

        let pass_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "doctor".as_ref(),
            "--config".as_ref(),
            pass_cfg.as_os_str(),
        ]))?;
        assert_eq!(run(pass_cli).await?, ExitCode::SUCCESS);

        // 3. Failing secret check returns Err.
        let fail_secret_cfg = dir.join("fail-secret.yaml");
        fs::write(
            &fail_secret_cfg,
            r#"bind_addr: "127.0.0.1:8080"
tape_path: "keelway-tape.jsonl"
policy_files:
  - "policies/simple.cedar"
principals:
  - org_id: "acme"
    agent_id: "coding-agent"
    roles: ["developer"]
    token_ref: "secret://env/KEELWAY_DOCTOR_DEFINITELY_MISSING_SECRET_XYZ"
servers: []
"#,
        )?;
        let fail_secret_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "doctor".as_ref(),
            "--config".as_ref(),
            fail_secret_cfg.as_os_str(),
        ]))?;
        assert!(run(fail_secret_cli).await.is_err());

        // 4. Failing stdio command check returns Err.
        let fail_stdio_cfg = dir.join("fail-stdio.yaml");
        fs::write(
            &fail_stdio_cfg,
            r#"bind_addr: "127.0.0.1:8080"
tape_path: "keelway-tape.jsonl"
policy_files:
  - "policies/simple.cedar"
principals:
  - org_id: "acme"
    agent_id: "coding-agent"
    roles: ["developer"]
servers:
  - alias: "broken-stdio"
    transport:
      type: "stdio"
      command: "/nonexistent/keelway-missing-binary-xyz"
      args: []
      env: {}
"#,
        )?;
        let fail_stdio_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "doctor".as_ref(),
            "--config".as_ref(),
            fail_stdio_cfg.as_os_str(),
        ]))?;
        assert!(run(fail_stdio_cli).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn cli_keygen_and_trace_inspect_public_key_work() -> Result<(), Box<dyn std::error::Error>>
    {
        let tmp = TempDirGuard::new("keygen-trace-inspect")?;
        let dir = tmp.path();
        let key_file = dir.join("keys/signing.key");

        let keygen_stdout_cli =
            Cli::try_parse_from(os_args(&["keelway".as_ref(), "keygen".as_ref()]))?;
        assert_eq!(run(keygen_stdout_cli).await?, ExitCode::SUCCESS);

        let keygen_out_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "keygen".as_ref(),
            "--output".as_ref(),
            key_file.as_os_str(),
        ]))?;
        assert_eq!(run(keygen_out_cli).await?, ExitCode::SUCCESS);

        let raw_seed = fs::read_to_string(&key_file)?;
        assert!(raw_seed.ends_with('\n'));
        let seed_hex = raw_seed.trim();
        assert_eq!(seed_hex.len(), 64);
        assert!(seed_hex.bytes().all(|b| b.is_ascii_hexdigit()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_file)?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let signer = keelway_engine::provenance::TapeSigner::from_seed_str(seed_hex)?;
        let vk_hex = signer.verifying_key_hex();
        let entry_hash = "421425e932601c4b85ddc231d0b35778e1e4ede107423fa77036f325ffe09154";
        let sig_hex = signer.sign_hex(entry_hash.as_bytes());

        let signed_tape = dir.join("signed-tape.jsonl");
        let signed_receipt: keelway_engine::Receipt = serde_json::from_value(serde_json::json!({
            "seq": 1,
            "prev_hash": keelway_engine::GENESIS_HASH,
            "entry_hash": entry_hash,
            "timestamp": "2026-01-01T00:00:00Z",
            "org_id": "acme",
            "agent_id": "coding-agent",
            "server": "local-fs",
            "tool": "read_file",
            "redacted_args": {},
            "redacted_fields": [],
            "decision": "ALLOW",
            "explanation": {
                "decision": "ALLOW",
                "rule_ids": [],
                "validator_outcomes": [],
                "reason": "test",
                "policy_digest": "abc123"
            },
            "policy_digest": "abc123",
            "state": "SEALED",
            "provenance": {
                "key_id": signer.key_id(),
                "signature_hex": sig_hex
            }
        }))?;
        fs::write(
            &signed_tape,
            format!("{}\n", serde_json::to_string(&signed_receipt)?),
        )?;

        let inspect_ok = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "trace".as_ref(),
            "inspect".as_ref(),
            "--tape".as_ref(),
            signed_tape.as_os_str(),
            "--public-key".as_ref(),
            vk_hex.as_ref(),
        ]))?;
        assert_eq!(run(inspect_ok).await?, ExitCode::SUCCESS);

        let wrong_signer = keelway_engine::provenance::TapeSigner::from_seed_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        )?;
        let wrong_vk = wrong_signer.verifying_key_hex();
        let inspect_wrong_key = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "trace".as_ref(),
            "inspect".as_ref(),
            "--tape".as_ref(),
            signed_tape.as_os_str(),
            "--public-key".as_ref(),
            wrong_vk.as_ref(),
        ]))?;
        assert!(run(inspect_wrong_key).await.is_err());

        let unsigned_tape = dir.join("unsigned-tape.jsonl");
        let unsigned_receipt: keelway_engine::Receipt =
            serde_json::from_value(serde_json::json!({
                "seq": 1,
                "prev_hash": keelway_engine::GENESIS_HASH,
                "entry_hash": entry_hash,
                "timestamp": "2026-01-01T00:00:00Z",
                "org_id": "acme",
                "agent_id": "coding-agent",
                "server": "local-fs",
                "tool": "read_file",
                "redacted_args": {},
                "redacted_fields": [],
                "decision": "ALLOW",
                "explanation": {
                    "decision": "ALLOW",
                    "rule_ids": [],
                    "validator_outcomes": [],
                    "reason": "test",
                    "policy_digest": "abc123"
                },
                "policy_digest": "abc123",
                "state": "SEALED"
            }))?;
        fs::write(
            &unsigned_tape,
            format!("{}\n", serde_json::to_string(&unsigned_receipt)?),
        )?;
        let inspect_unsigned = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "trace".as_ref(),
            "inspect".as_ref(),
            "--tape".as_ref(),
            unsigned_tape.as_os_str(),
            "--public-key".as_ref(),
            vk_hex.as_ref(),
        ]))?;
        assert!(run(inspect_unsigned).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn cli_doctor_validates_jwt_auth_config() -> Result<(), Box<dyn std::error::Error>> {
        let tmp = TempDirGuard::new("doctor-jwt")?;
        let dir = tmp.path();
        fs::create_dir_all(dir.join("policies"))?;
        fs::write(
            dir.join("policies/simple.cedar"),
            "permit(principal in Role::\"developer\", action == Action::\"list_tool\", resource);\n",
        )?;

        let secret_file = dir.join("jwt.secret");
        fs::write(&secret_file, "a".repeat(32))?;

        let pass_cfg = dir.join("jwt-pass.yaml");
        fs::write(
            &pass_cfg,
            format!(
                r#"bind_addr: "127.0.0.1:8080"
tape_path: "keelway-tape.jsonl"
policy_files:
  - "policies/simple.cedar"
jwt_auth:
  issuer: "https://issuer.example.com"
  audience: "keelway-gateway"
  hs256_secret: "secret://file/{secret}"
"#,
                secret = secret_file.display()
            ),
        )?;

        let pass_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "doctor".as_ref(),
            "--config".as_ref(),
            pass_cfg.as_os_str(),
        ]))?;
        assert_eq!(run(pass_cli).await?, ExitCode::SUCCESS);

        fs::write(&secret_file, format!("{}\n", "a".repeat(32)))?;
        let pass_newline_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "doctor".as_ref(),
            "--config".as_ref(),
            pass_cfg.as_os_str(),
        ]))?;
        assert_eq!(run(pass_newline_cli).await?, ExitCode::SUCCESS);

        let weak_cfg = dir.join("jwt-weak.yaml");
        fs::write(
            &weak_cfg,
            r#"bind_addr: "127.0.0.1:8080"
tape_path: "keelway-tape.jsonl"
policy_files:
  - "policies/simple.cedar"
jwt_auth:
  issuer: "https://issuer.example.com"
  audience: "keelway-gateway"
  hs256_secret: "too-short"
"#,
        )?;

        let weak_cli = Cli::try_parse_from(os_args(&[
            "keelway".as_ref(),
            "doctor".as_ref(),
            "--config".as_ref(),
            weak_cfg.as_os_str(),
        ]))?;
        assert!(run(weak_cli).await.is_err());

        Ok(())
    }
}
