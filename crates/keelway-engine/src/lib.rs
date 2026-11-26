pub mod auth;
pub(crate) mod budget;
pub mod circuit;
pub mod core;
pub(crate) mod mcp;
pub(crate) mod metrics;
pub(crate) mod p10;
pub(crate) mod policy;
pub mod provenance;
pub(crate) mod secrets;
pub(crate) mod tape;
mod upstream;

use crate::core::{GatewayConfig, KeelwayError, PolicyDecision, Principal, ToolCall};
use crate::mcp::{GatewayRuntime, build_http_router, serve_stdio_loop};
use crate::policy::PolicyEngine;
use crate::secrets::DefaultSecretProvider;
use crate::tape::{ReplayEntry, TapeVerification, TapeWriter};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub use crate::core::{
    ApprovalRule, BudgetConfig, BudgetRule, Decision, ExecutionOutcome, Explanation,
    PrincipalConfig, Receipt, ReceiptState, ServerConfig, UpstreamTransport, ValidatorBinding,
    ValidatorKind, ValidatorOutcome, sanitize_federated_name, validate_server_alias,
};
pub use crate::secrets::{REDACTED_PLACEHOLDER, SecretProvider, SecretScrubber, StreamingScrubber};
pub use crate::tape::{GENESIS_HASH, ReplayVerdict};

/// Offline policy test case (loaded from YAML for `keelway policy test` or `attack simulate`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTestCase {
    pub name: String,
    pub org_id: String,
    pub agent_id: String,
    pub server: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
    pub expected: Decision,
}

/// Result of running a single offline policy test or attack simulation case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTestResult {
    pub name: String,
    pub server: String,
    pub tool: String,
    pub agent_id: String,
    pub expected: Decision,
    pub actual: Decision,
    pub passed: bool,
    pub reason: String,
}

/// Deep public facade for Keelway MCP Gateway.
/// Encapsulates Cedar policy evaluation, OS-thread hash-chained tape, secret scrubbing, and MCP federation.
pub struct GatewayEngine {
    config: GatewayConfig,
    base_dir: PathBuf,
    policy: Arc<PolicyEngine>,
    roles_by_principal: HashMap<(String, String), Vec<String>>,
    initial_policy_mtimes: Vec<Option<std::time::SystemTime>>,
}

impl GatewayEngine {
    /// Loads `keelway.yaml` and compiles/validates all referenced `.cedar` policy files.
    pub fn from_config_file(config_path: &Path) -> Result<Self, KeelwayError> {
        let raw = fs::read_to_string(config_path).map_err(|e| {
            KeelwayError::Config(format!(
                "failed to read config '{}': {e}",
                config_path.display()
            ))
        })?;
        let config: GatewayConfig = serde_yaml::from_str(&raw)?;
        let base_dir = config_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let policy_paths: Vec<PathBuf> = config
            .policy_files
            .iter()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    base_dir.join(p)
                }
            })
            .collect();
        let initial_policy_mtimes = read_policy_mtimes(&policy_paths);
        let policy = Arc::new(PolicyEngine::from_config_files(&config, &base_dir)?);
        let roles_by_principal = config
            .principals
            .iter()
            .map(|p| ((p.org_id.clone(), p.agent_id.clone()), p.roles.clone()))
            .collect();
        Ok(Self {
            config,
            base_dir,
            policy,
            roles_by_principal,
            initial_policy_mtimes,
        })
    }

    /// Constructs an engine directly from in-memory `GatewayConfig` and Cedar source (ideal for tests/embedding).
    pub fn from_in_memory(config: GatewayConfig, cedar_source: &str) -> Result<Self, KeelwayError> {
        let policy = Arc::new(PolicyEngine::from_config_and_cedar(&config, cedar_source)?);
        let roles_by_principal = config
            .principals
            .iter()
            .map(|p| ((p.org_id.clone(), p.agent_id.clone()), p.roles.clone()))
            .collect();
        Ok(Self {
            config,
            base_dir: PathBuf::from("."),
            policy,
            roles_by_principal,
            initial_policy_mtimes: Vec::new(),
        })
    }

    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    pub fn policy_digest(&self) -> String {
        self.policy.current_digest()
    }

    /// Evaluates a single tool call deterministically (zero side effects).
    pub fn evaluate_call(
        &self,
        principal: &Principal,
        tool_call: &ToolCall,
    ) -> Result<PolicyDecision, KeelwayError> {
        self.policy.evaluate(principal, tool_call)
    }

    /// Atomically hot-reloads policies from disk; rejects invalid edits while keeping last-good snapshot live.
    pub fn hot_reload(&self) -> Result<String, KeelwayError> {
        self.policy
            .hot_reload_from_files(&self.config, &self.base_dir)
    }

    /// Runs a suite of offline policy test cases or prompt-injection attack simulations.
    pub fn run_test_cases(
        &self,
        cases: &[PolicyTestCase],
    ) -> Result<Vec<PolicyTestResult>, KeelwayError> {
        let mut results = Vec::with_capacity(cases.len());
        for c in cases {
            let roles = self
                .roles_by_principal
                .get(&(c.org_id.clone(), c.agent_id.clone()))
                .cloned()
                .unwrap_or_default();
            let principal = Principal {
                org_id: c.org_id.clone(),
                agent_id: c.agent_id.clone(),
                roles,
            };
            let eval = self.policy.evaluate(
                &principal,
                &ToolCall {
                    server: c.server.clone(),
                    tool: c.tool.clone(),
                    arguments: c.arguments.clone(),
                },
            )?;
            results.push(PolicyTestResult {
                name: c.name.clone(),
                server: c.server.clone(),
                tool: c.tool.clone(),
                agent_id: c.agent_id.clone(),
                expected: c.expected,
                actual: eval.decision,
                passed: eval.decision == c.expected,
                reason: eval.explanation.reason,
            });
        }
        Ok(results)
    }

    /// Replays a recorded `keelway-tape.jsonl` offline against the current policy engine.
    pub fn replay_tape(&self, tape_path: &Path) -> Result<Vec<ReplayEntry>, KeelwayError> {
        let lookup = |org: &str, agent: &str| {
            self.roles_by_principal
                .get(&(org.to_owned(), agent.to_owned()))
                .cloned()
                .unwrap_or_default()
        };
        tape::replay_tape(tape_path, &self.policy, &lookup)
    }

    /// Verifies a tape's SHA-256 hash chain in O(1) memory.
    pub fn verify_tape(tape_path: &Path) -> Result<TapeVerification, KeelwayError> {
        tape::verify_tape(tape_path)
    }

    /// Verifies a tape's SHA-256 hash chain and Ed25519 signatures.
    pub fn verify_tape_with_key(
        tape_path: &Path,
        verifying_key_hex: Option<&str>,
    ) -> Result<TapeVerification, KeelwayError> {
        tape::verify_tape_with_key(tape_path, verifying_key_hex)
    }

    fn open_tape_for_config(
        &self,
        tape_path: PathBuf,
        secrets: &dyn SecretProvider,
    ) -> Result<TapeWriter, KeelwayError> {
        let signer = match self.config.signing_key_ref.as_deref() {
            Some(key_ref) => {
                let seed = secrets.resolve(key_ref)?;
                Some(provenance::TapeSigner::from_seed_str(&seed)?)
            }
            None => None,
        };
        TapeWriter::open_with_signer(tape_path, signer)
    }

    /// Streams verified receipts from a tape in O(1) memory.
    pub fn inspect_tape<F>(tape_path: &Path, visitor: F) -> Result<TapeVerification, KeelwayError>
    where
        F: FnMut(Receipt) -> Result<(), KeelwayError>,
    {
        tape::stream_receipts(tape_path, visitor)
    }

    /// Starts the Streamable HTTP (`/mcp`) gateway server.
    pub async fn serve_http(&self) -> Result<(), KeelwayError> {
        let tape_path = self.resolve_tape_path();
        let tape = self.open_tape_for_config(tape_path, &DefaultSecretProvider)?;
        let runtime = Arc::new(GatewayRuntime::build(
            &self.config,
            self.policy.clone(),
            tape,
            &DefaultSecretProvider,
            false,
        )?);
        let app = build_http_router(runtime.clone());
        self.spawn_hot_reload_watcher();
        let listener = tokio::net::TcpListener::bind(&self.config.bind_addr).await?;
        tracing::info!(
            "keelway MCP gateway listening on http://{}/mcp",
            self.config.bind_addr
        );
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal(runtime))
            .await
            .map_err(|e| KeelwayError::Mcp(format!("http server error: {e}")))
    }

    /// Builds an in-process Axum `Router` for deterministic E2E integration testing.
    pub fn build_test_http_router(
        &self,
        tape_path: PathBuf,
        secrets: &dyn SecretProvider,
    ) -> Result<axum::Router, KeelwayError> {
        let tape = self.open_tape_for_config(tape_path, secrets)?;
        let runtime = Arc::new(GatewayRuntime::build(
            &self.config,
            self.policy.clone(),
            tape,
            secrets,
            true,
        )?);
        Ok(build_http_router(runtime))
    }

    /// Starts the local `stdio` MCP gateway for an explicitly bound `<org_id>/<agent_id>` principal.
    pub async fn serve_stdio(&self, principal_id: &str) -> Result<(), KeelwayError> {
        let principal = self.resolve_principal_id(principal_id)?;
        let tape_path = self.resolve_tape_path();
        let tape = self.open_tape_for_config(tape_path, &DefaultSecretProvider)?;
        let runtime = Arc::new(GatewayRuntime::build(
            &self.config,
            self.policy.clone(),
            tape,
            &DefaultSecretProvider,
            true, // Strict stderr-only console output in stdio mode
        )?);
        self.spawn_hot_reload_watcher();
        serve_stdio_loop(runtime, principal).await
    }

    /// Spawns a background Tokio task that polls `policy_files` mtimes every 1 second
    /// (and listens for `SIGHUP` on Unix) to atomically hot-reload Cedar policies.
    fn spawn_hot_reload_watcher(&self) {
        let config = self.config.clone();
        let base_dir = self.base_dir.clone();
        let policy = Arc::clone(&self.policy);
        let policy_paths: Vec<PathBuf> = config
            .policy_files
            .iter()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    base_dir.join(p)
                }
            })
            .collect();

        let mut last_mtimes = if self.initial_policy_mtimes.len() == policy_paths.len() {
            self.initial_policy_mtimes.clone()
        } else {
            read_policy_mtimes(&policy_paths)
        };

        // Register SIGHUP synchronously before spawning so early reload signals cannot terminate the process.
        #[cfg(unix)]
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(sig) => Some(sig),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to register SIGHUP handler for policy hot-reload"
                );
                None
            }
        };

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Consume the immediate initial tick so polling begins after 1 second.
            interval.tick().await;

            loop {
                #[cfg(unix)]
                {
                    tokio::select! {
                        _ = interval.tick() => {
                            if !policy_paths.is_empty() {
                                let current_mtimes = read_policy_mtimes(&policy_paths);
                                if current_mtimes != last_mtimes {
                                    last_mtimes = current_mtimes;
                                    perform_hot_reload(&policy, &config, &base_dir, "poll");
                                }
                            }
                        }
                        recv = async {
                            match sighup.as_mut() {
                                Some(sig) => sig.recv().await,
                                None => std::future::pending().await,
                            }
                        } => {
                            if recv.is_none() {
                                sighup = None;
                            } else {
                                last_mtimes = read_policy_mtimes(&policy_paths);
                                perform_hot_reload(&policy, &config, &base_dir, "sighup");
                            }
                        }
                    }
                }

                #[cfg(not(unix))]
                {
                    interval.tick().await;
                    if !policy_paths.is_empty() {
                        let current_mtimes = read_policy_mtimes(&policy_paths);
                        if current_mtimes != last_mtimes {
                            last_mtimes = current_mtimes;
                            perform_hot_reload(&policy, &config, &base_dir, "poll");
                        }
                    }
                }
            }
        });
    }

    fn resolve_principal_id(&self, principal_id: &str) -> Result<Principal, KeelwayError> {
        let Some((org, agent)) = principal_id.split_once('/') else {
            return Err(KeelwayError::Auth(format!(
                "invalid --principal '{principal_id}': expected '<org_id>/<agent_id>'"
            )));
        };
        let found = self
            .config
            .principals
            .iter()
            .find(|p| p.org_id == org && p.agent_id == agent);
        match found {
            Some(p) => Ok(p.to_principal()),
            None => Err(KeelwayError::Auth(format!(
                "unknown principal '{principal_id}' (fail-closed)"
            ))),
        }
    }

    fn resolve_tape_path(&self) -> PathBuf {
        if self.config.tape_path.is_absolute() {
            self.config.tape_path.clone()
        } else {
            self.base_dir.join(&self.config.tape_path)
        }
    }
}

fn read_policy_mtimes(paths: &[PathBuf]) -> Vec<Option<std::time::SystemTime>> {
    paths
        .iter()
        .map(|p| fs::metadata(p).and_then(|m| m.modified()).ok())
        .collect()
}

fn perform_hot_reload(
    policy: &PolicyEngine,
    config: &GatewayConfig,
    base_dir: &Path,
    trigger: &str,
) {
    match policy.hot_reload_from_files(config, base_dir) {
        Ok(digest) => {
            tracing::info!(
                trigger = trigger,
                policy_digest = %digest,
                "hot-reloaded Cedar policies"
            );
        }
        Err(err) => {
            tracing::warn!(
                trigger = trigger,
                error = %err,
                "hot-reload rejected; keeping last known-good policy snapshot live"
            );
        }
    }
}

async fn shutdown_signal(runtime: Arc<GatewayRuntime>) {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::warn!(error = %err, "failed to install Ctrl+C shutdown handler");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(err) => {
                tracing::warn!(error = %err, "failed to install SIGTERM shutdown handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received SIGINT (Ctrl+C); draining HTTP connections"),
        _ = terminate => tracing::info!("received SIGTERM; draining HTTP connections"),
    }
    runtime.signal_shutdown();
}
