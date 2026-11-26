use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use thiserror::Error;

/// Top-level error type for Keelway MCP Gateway.
#[derive(Debug, Error)]
pub enum KeelwayError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("tape persistence or integrity error: {0}")]
    Tape(String),
    #[error("secret resolution error: {0}")]
    Secret(String),
    #[error("mcp protocol error: {0}")]
    Mcp(String),
    #[error("upstream timeout after {0}ms")]
    UpstreamTimeout(u64),
    #[error("upstream unavailable: {0}")]
    UpstreamUnavailable(String),
    #[error("execution budget exceeded: {0}")]
    BudgetExceeded(String),
    #[error("human approval denied: {0}")]
    ApprovalDenied(String),
    #[error("human approval timed out after {0}ms")]
    ApprovalTimeout(u64),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Authenticated caller identity scoped by tenant (`org_id`) and agent (`agent_id`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Principal {
    pub org_id: String,
    pub agent_id: String,
    #[serde(default)]
    pub roles: Vec<String>,
}

impl Principal {
    /// Canonical principal identifier `<org_id>/<agent_id>`.
    pub fn canonical_id(&self) -> String {
        format!("{}/{}", self.org_id, self.agent_id)
    }
}

/// Mediated tool invocation request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub server: String,
    pub tool: String,
    #[serde(default)]
    pub arguments: Value,
}

/// Authorization verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Decision {
    Allow,
    Deny,
}

/// Result of a single Stage 1 typed argument validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorOutcome {
    pub validator_id: String,
    pub arg_name: String,
    pub passed: bool,
    pub reason: String,
}

/// Structured explanation attached to every authorization verdict and receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Explanation {
    pub decision: Decision,
    pub rule_ids: Vec<String>,
    pub validator_outcomes: Vec<ValidatorOutcome>,
    pub reason: String,
    pub policy_digest: String,
}

/// Output of `PolicyEngine::evaluate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub explanation: Explanation,
}

/// Receipt lifecycle state aligned with Keelway Sovereign Agent Platform (`kora-sable.vercel.app`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReceiptState {
    Sealed,
    Blocked,
    Awaiting,
}

/// Optional execution outcome for upstream calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionOutcome {
    Ok,
    Timeout,
    Crashed,
}

/// Append-only, SHA-256 hash-chained execution receipt persisted to `keelway-tape.jsonl`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub seq: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub timestamp: DateTime<Utc>,
    pub org_id: String,
    pub agent_id: String,
    pub server: String,
    pub tool: String,
    pub redacted_args: Value,
    #[serde(default)]
    pub redacted_fields: Vec<String>,
    pub decision: Decision,
    pub explanation: Explanation,
    pub policy_digest: String,
    pub state: ReceiptState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<ExecutionOutcome>,
    /// Reserved provenance slot for future IoRa information-flow integration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Value>,
}

/// Unsealed receipt payload submitted to `TapeWriter`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsealedReceipt {
    pub timestamp: DateTime<Utc>,
    pub org_id: String,
    pub agent_id: String,
    pub server: String,
    pub tool: String,
    pub redacted_args: Value,
    pub redacted_fields: Vec<String>,
    pub decision: Decision,
    pub explanation: Explanation,
    pub policy_digest: String,
    pub state: ReceiptState,
    pub outcome: Option<ExecutionOutcome>,
    pub provenance: Option<Value>,
}

/// Root configuration loaded from `keelway.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_tape_path")]
    pub tape_path: PathBuf,
    #[serde(default)]
    pub policy_files: Vec<PathBuf>,
    #[serde(default)]
    pub principals: Vec<PrincipalConfig>,
    #[serde(default)]
    pub servers: Vec<ServerConfig>,
    #[serde(default)]
    pub validators: Vec<ValidatorBinding>,
    #[serde(default)]
    pub budgets: Vec<BudgetRule>,
    #[serde(default)]
    pub approval_required: Vec<ApprovalRule>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_bind_addr(),
            tape_path: default_tape_path(),
            policy_files: Vec::new(),
            principals: Vec::new(),
            servers: Vec::new(),
            validators: Vec::new(),
            budgets: Vec::new(),
            approval_required: Vec::new(),
        }
    }
}

/// Per-principal, per-tool P-10 human-in-the-loop approval rule configured in `keelway.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRule {
    pub org_id: String,
    /// Agent identifier, or `"*"` for an org-wide rule.
    #[serde(default = "default_wildcard")]
    pub agent_id: String,
    pub server: String,
    pub tool: String,
    #[serde(default = "default_approval_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_approval_timeout_ms() -> u64 {
    60_000
}

/// Per-principal, per-server execution budget rule configured in `keelway.yaml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetRule {
    pub org_id: String,
    /// Agent identifier, or `"*"` for an org-wide default.
    #[serde(default = "default_wildcard")]
    pub agent_id: String,
    /// Server alias, or `"*"` for all servers.
    #[serde(default = "default_wildcard")]
    pub server: String,
    #[serde(default)]
    pub max_calls_per_minute: Option<u32>,
    #[serde(default)]
    pub max_concurrent_calls: Option<u32>,
}

/// Alias for [`BudgetRule`].
pub type BudgetConfig = BudgetRule;

fn default_wildcard() -> String {
    "*".to_owned()
}

fn default_bind_addr() -> String {
    "127.0.0.1:8080".to_owned()
}

fn default_tape_path() -> PathBuf {
    PathBuf::from("keelway-tape.jsonl")
}

/// Configured principal and authentication token binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrincipalConfig {
    pub org_id: String,
    pub agent_id: String,
    #[serde(default)]
    pub roles: Vec<String>,
    /// Secret reference (`secret://env/...` or `secret://file/...`) or literal token for local dev.
    #[serde(default)]
    pub token_ref: Option<String>,
}

impl PrincipalConfig {
    pub fn to_principal(&self) -> Principal {
        Principal {
            org_id: self.org_id.clone(),
            agent_id: self.agent_id.clone(),
            roles: self.roles.clone(),
        }
    }
}

/// Upstream MCP server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub alias: String,
    pub transport: UpstreamTransport,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Optional static tool catalog used for offline `policy test` / `attack simulate` / `replay`.
    #[serde(default)]
    pub tools: Vec<String>,
}

fn default_timeout_ms() -> u64 {
    30_000
}

/// Supported Milestone 1 upstream transports (local stdio + remote Streamable HTTP).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum UpstreamTransport {
    Stdio {
        command: String,
        #[serde(default)]
        args: Vec<String>,
        /// Environment variables injected into the child process (`secret://...` resolved by gateway).
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    StreamableHttp {
        url: String,
        /// HTTP headers injected into upstream requests (`secret://...` resolved by gateway).
        #[serde(default)]
        headers: BTreeMap<String, String>,
    },
}

/// Binding of one of the 5 Milestone 1 typed argument validators to `(server, tool, arg_name)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorBinding {
    pub id: String,
    pub server: String,
    pub tool: String,
    pub arg_name: String,
    pub kind: ValidatorKind,
}

/// Exactly five Milestone 1 typed argument validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidatorKind {
    PathWithin { root: String },
    Glob { pattern: String },
    Regex { pattern: String },
    SqlReadonly,
    RepoAllowlist { repos: Vec<String> },
}

/// Validates `server_alias` matches `^[a-z0-9-]+$` (never containing `__`).
pub fn validate_server_alias(alias: &str) -> Result<(), KeelwayError> {
    if alias.is_empty()
        || !alias
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(KeelwayError::Config(format!(
            "invalid server alias '{alias}': must match ^[a-z0-9-]+$"
        )));
    }
    Ok(())
}

/// Produces canonical wire federated tool name `<server_alias>__<sanitized_tool_name>`
/// strictly matching `[a-zA-Z0-9_-]`.
pub fn sanitize_federated_name(
    server_alias: &str,
    upstream_tool_name: &str,
) -> Result<String, KeelwayError> {
    validate_server_alias(server_alias)?;
    if upstream_tool_name.is_empty() {
        return Err(KeelwayError::Config(
            "upstream tool name cannot be empty".to_owned(),
        ));
    }
    let sanitized: String = upstream_tool_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(format!("{server_alias}__{sanitized}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_federated_name_handles_dots_and_slashes() -> Result<(), KeelwayError> {
        let name = sanitize_federated_name("github", "repos.v1/read_repository")?;
        assert_eq!(name, "github__repos_v1_read_repository");
        assert!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        );
        Ok(())
    }

    #[test]
    fn invalid_server_alias_rejected() {
        assert!(validate_server_alias("bad__alias").is_err());
        assert!(validate_server_alias("BadUpper").is_err());
        assert!(validate_server_alias("").is_err());
        assert!(validate_server_alias("git-hub-1").is_ok());
    }
}
