use crate::budget::BudgetTracker;
use crate::core::{
    Decision, ExecutionOutcome, Explanation, GatewayConfig, KeelwayError, Principal, ReceiptState,
    ServerConfig, ToolCall, UnsealedReceipt, UpstreamTransport, sanitize_federated_name,
    validate_server_alias,
};
use crate::metrics::{EventOutcome, GatewayMetrics, LiveConsoleEvent};
use crate::p10::P10GateManager;
use crate::policy::PolicyEngine;
use crate::provenance::extract_or_generate_trace_id;
use crate::secrets::{SecretProvider, SecretScrubber};
use crate::tape::TapeWriter;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

pub const JSONRPC_POLICY_DENIED: i64 = -32000;
pub const JSONRPC_TAPE_PERSISTENCE_ERR: i64 = -32001;
pub const JSONRPC_UPSTREAM_TIMEOUT: i64 = -32002;
pub const JSONRPC_UPSTREAM_UNAVAILABLE: i64 = -32003;
pub const JSONRPC_BUDGET_EXCEEDED: i64 = -32004;
pub const JSONRPC_APPROVAL_DENIED: i64 = -32005;
pub const JSONRPC_PAYLOAD_TOO_LARGE: i64 = -32006;

/// Metadata for a federated upstream MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedTool {
    pub federated_name: String,
    pub server_alias: String,
    pub upstream_name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

/// Unambiguous bidirectional routing table `federated_name <-> (server_alias, exact_upstream_tool)`.
#[derive(Debug, Default, Clone)]
pub struct ToolRegistry {
    by_federated: BTreeMap<String, FederatedTool>,
}

impl ToolRegistry {
    pub fn build(tools: Vec<FederatedTool>) -> Result<Self, KeelwayError> {
        let mut by_federated = BTreeMap::new();
        for t in tools {
            validate_server_alias(&t.server_alias)?;
            let expected = sanitize_federated_name(&t.server_alias, &t.upstream_name)?;
            if t.federated_name != expected {
                return Err(KeelwayError::Config(format!(
                    "federated tool name '{}' does not match canonical '{}'",
                    t.federated_name, expected
                )));
            }
            if by_federated.contains_key(&t.federated_name) {
                return Err(KeelwayError::Config(format!(
                    "federated tool collision after sanitization: '{}'",
                    t.federated_name
                )));
            }
            by_federated.insert(t.federated_name.clone(), t);
        }
        Ok(Self { by_federated })
    }

    pub fn resolve(&self, federated_name: &str) -> Option<&FederatedTool> {
        self.by_federated.get(federated_name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &FederatedTool> {
        self.by_federated.values()
    }
}

/// Live stdio child process handle with bounded exponential-backoff restart.
struct StdioProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

enum UpstreamDriver {
    Stdio {
        command: String,
        args: Vec<String>,
        resolved_env: BTreeMap<String, String>,
        timeout_ms: u64,
        process: Box<Mutex<Option<StdioProcess>>>,
    },
    StreamableHttp {
        url: String,
        resolved_headers: BTreeMap<String, String>,
        timeout_ms: u64,
        client: reqwest::Client,
    },
}

impl UpstreamDriver {
    fn from_server_config(
        server: &ServerConfig,
        secrets: &dyn SecretProvider,
        collected_secrets: &mut Vec<String>,
    ) -> Result<Self, KeelwayError> {
        match &server.transport {
            UpstreamTransport::Stdio { command, args, env } => {
                let mut resolved_env = BTreeMap::new();
                for (k, v) in env {
                    let val = secrets.resolve(v)?;
                    if v.starts_with("secret://") {
                        collected_secrets.push(val.clone());
                    }
                    resolved_env.insert(k.clone(), val);
                }
                Ok(Self::Stdio {
                    command: command.clone(),
                    args: args.clone(),
                    resolved_env,
                    timeout_ms: server.timeout_ms,
                    process: Box::new(Mutex::new(None)),
                })
            }
            UpstreamTransport::StreamableHttp { url, headers } => {
                let mut resolved_headers = BTreeMap::new();
                for (k, v) in headers {
                    let val = secrets.resolve(v)?;
                    if v.starts_with("secret://") {
                        collected_secrets.push(val.clone());
                    }
                    resolved_headers.insert(k.clone(), val);
                }
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_millis(server.timeout_ms))
                    .build()
                    .map_err(|e| KeelwayError::Mcp(format!("http client build failed: {e}")))?;
                Ok(Self::StreamableHttp {
                    url: url.clone(),
                    resolved_headers,
                    timeout_ms: server.timeout_ms,
                    client,
                })
            }
        }
    }

    async fn call_tool(
        &self,
        upstream_tool: &str,
        arguments: &Value,
        scrubber: &Arc<SecretScrubber>,
        max_response_bytes: usize,
        trace_id: Option<&str>,
    ) -> Result<Value, KeelwayError> {
        self.call_method(
            "tools/call",
            json!({
                "name": upstream_tool,
                "arguments": arguments,
            }),
            scrubber,
            max_response_bytes,
            trace_id,
        )
        .await
    }

    async fn call_method(
        &self,
        method: &str,
        params: Value,
        scrubber: &Arc<SecretScrubber>,
        max_response_bytes: usize,
        trace_id: Option<&str>,
    ) -> Result<Value, KeelwayError> {
        let req_id = uuid::Uuid::new_v4().to_string();
        let rpc_body = json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        });

        match self {
            Self::Stdio {
                command,
                args,
                resolved_env,
                timeout_ms,
                process,
            } => {
                let mut guard = process.lock().await;
                if guard.is_none() {
                    let spawned = spawn_stdio_child(command, args, resolved_env, scrubber.clone())?;
                    *guard = Some(spawned);
                }
                let fut = async {
                    let Some(proc_handle) = guard.as_mut() else {
                        return Err(KeelwayError::UpstreamUnavailable(
                            "stdio child unavailable".to_owned(),
                        ));
                    };
                    let mut line = serde_json::to_string(&rpc_body)?;
                    line.push('\n');
                    proc_handle
                        .stdin
                        .write_all(line.as_bytes())
                        .await
                        .map_err(|e| {
                            KeelwayError::UpstreamUnavailable(format!("stdio write: {e}"))
                        })?;
                    proc_handle.stdin.flush().await.map_err(|e| {
                        KeelwayError::UpstreamUnavailable(format!("stdio flush: {e}"))
                    })?;

                    let mut resp_line = String::new();
                    let n = proc_handle
                        .stdout
                        .read_line(&mut resp_line)
                        .await
                        .map_err(|e| {
                            KeelwayError::UpstreamUnavailable(format!("stdio read: {e}"))
                        })?;
                    if n == 0 {
                        return Err(KeelwayError::UpstreamUnavailable(
                            "stdio child exited unexpectedly (EOF)".to_owned(),
                        ));
                    }
                    if resp_line.len() > max_response_bytes {
                        return Err(KeelwayError::Mcp(format!(
                            "PayloadTooLarge: upstream response ({} bytes) exceed max_response_bytes ({max_response_bytes})",
                            resp_line.len()
                        )));
                    }
                    let scrubbed = scrubber.scrub_str(&resp_line);
                    let parsed: Value = serde_json::from_str(&scrubbed)?;
                    Ok(parsed.get("result").cloned().unwrap_or(parsed))
                };

                match tokio::time::timeout(Duration::from_millis(*timeout_ms), fut).await {
                    Ok(Ok(val)) => Ok(val),
                    Ok(Err(e)) => {
                        // Drop crashed handle so next request triggers bounded restart
                        if let Some(mut dead) = guard.take() {
                            let _ = dead.child.kill().await;
                        }
                        Err(e)
                    }
                    Err(_) => {
                        if let Some(mut hung) = guard.take() {
                            let _ = hung.child.kill().await;
                        }
                        Err(KeelwayError::UpstreamTimeout(*timeout_ms))
                    }
                }
            }
            Self::StreamableHttp {
                url,
                resolved_headers,
                timeout_ms,
                client,
            } => {
                let mut req = client.post(url).json(&rpc_body);
                if let Some(tid) = trace_id {
                    let span_id = &uuid::Uuid::new_v4().simple().to_string()[..16];
                    req = req.header("traceparent", format!("00-{tid}-{span_id}-01"));
                }
                for (k, v) in resolved_headers {
                    req = req.header(k, v);
                }
                let resp = match tokio::time::timeout(
                    Duration::from_millis(*timeout_ms),
                    req.send(),
                )
                .await
                {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        return Err(KeelwayError::UpstreamUnavailable(format!(
                            "upstream HTTP error: {e}"
                        )));
                    }
                    Err(_) => return Err(KeelwayError::UpstreamTimeout(*timeout_ms)),
                };

                if !resp.status().is_success() {
                    return Err(KeelwayError::UpstreamUnavailable(format!(
                        "upstream returned HTTP {}",
                        resp.status()
                    )));
                }

                // Stream body through sliding-window Aho-Corasick scrubber to catch SSE chunk-straddling secrets
                let mut streaming_scrubber = scrubber.streaming();
                let mut byte_stream = resp.bytes_stream();
                let mut assembled = String::new();
                let mut total_bytes = 0usize;
                while let Some(chunk_res) = byte_stream.next().await {
                    let chunk = chunk_res.map_err(|e| {
                        KeelwayError::UpstreamUnavailable(format!("stream read error: {e}"))
                    })?;
                    total_bytes = total_bytes.saturating_add(chunk.len());
                    if total_bytes > max_response_bytes {
                        return Err(KeelwayError::Mcp(format!(
                            "PayloadTooLarge: upstream response ({total_bytes} bytes) exceed max_response_bytes ({max_response_bytes})"
                        )));
                    }
                    let chunk_str = String::from_utf8_lossy(&chunk);
                    assembled.push_str(&streaming_scrubber.push_chunk(&chunk_str));
                }
                assembled.push_str(&streaming_scrubber.finish());

                let parsed: Value = serde_json::from_str(&assembled).unwrap_or_else(
                    |_| json!({ "content": [{ "type": "text", "text": assembled }] }),
                );
                Ok(parsed.get("result").cloned().unwrap_or(parsed))
            }
        }
    }
}

fn spawn_stdio_child(
    command: &str,
    args: &[String],
    resolved_env: &BTreeMap<String, String>,
    scrubber: Arc<SecretScrubber>,
) -> Result<StdioProcess, KeelwayError> {
    let mut cmd = Command::new(command);
    cmd.args(args)
        // Clear inherited host env so operator secrets never leak to untrusted stdio children (ADR-003).
        .env_clear();
    for safe_key in ["PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"] {
        if let Ok(val) = std::env::var(safe_key) {
            cmd.env(safe_key, val);
        }
    }
    cmd.envs(resolved_env)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        KeelwayError::UpstreamUnavailable(format!("failed to spawn stdio server '{command}': {e}"))
    })?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| KeelwayError::UpstreamUnavailable("missing child stdin".to_owned()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| KeelwayError::UpstreamUnavailable("missing child stdout".to_owned()))?;

    // Capture and scrub child stderr continuously so secrets never leak to operator logs
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            while let Ok(n) = reader.read_line(&mut line).await {
                if n == 0 {
                    break;
                }
                let scrubbed = scrubber.scrub_str(line.trim_end());
                tracing::warn!(target: "keelway_upstream_stderr", "{}", scrubbed);
                line.clear();
            }
        });
    }

    Ok(StdioProcess {
        child,
        stdin,
        stdout: BufReader::new(stdout),
    })
}

/// Shared runtime state for the MCP Gateway.
pub struct GatewayRuntime {
    pub policy: Arc<PolicyEngine>,
    pub tape: TapeWriter,
    pub scrubber: Arc<SecretScrubber>,
    pub registry: ToolRegistry,
    budgets: BudgetTracker,
    p10: P10GateManager,
    metrics: Arc<GatewayMetrics>,
    token_map: HashMap<String, Principal>,
    upstreams: HashMap<String, UpstreamDriver>,
    console_to_stderr: bool,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl GatewayRuntime {
    pub fn build(
        config: &GatewayConfig,
        policy: Arc<PolicyEngine>,
        tape: TapeWriter,
        secrets: &dyn SecretProvider,
        console_to_stderr: bool,
    ) -> Result<Self, KeelwayError> {
        let mut collected_secrets = Vec::new();
        let mut token_map = HashMap::new();

        for p in &config.principals {
            if let Some(ref tref) = p.token_ref {
                let tok = secrets.resolve(tref)?;
                if tref.starts_with("secret://") {
                    collected_secrets.push(tok.clone());
                }
                token_map.insert(tok, p.to_principal());
            }
        }

        let mut upstreams = HashMap::new();
        let mut federated_tools = Vec::new();

        for s in &config.servers {
            validate_server_alias(&s.alias)?;
            let driver = UpstreamDriver::from_server_config(s, secrets, &mut collected_secrets)?;
            upstreams.insert(s.alias.clone(), driver);

            for t in &s.tools {
                let fed_name = sanitize_federated_name(&s.alias, t)?;
                federated_tools.push(FederatedTool {
                    federated_name: fed_name,
                    server_alias: s.alias.clone(),
                    upstream_name: t.clone(),
                    description: Some(format!("Federated tool {}.{t}", s.alias)),
                    input_schema: json!({ "type": "object" }),
                });
            }
        }

        let registry = ToolRegistry::build(federated_tools)?;
        let scrubber = Arc::new(
            SecretScrubber::new(&collected_secrets)?
                .with_pattern_scrubbing(config.egress_pattern_scrubbing),
        );
        let budgets = BudgetTracker::new(config.budgets.clone());
        let p10 = P10GateManager::new(config.approval_required.clone());
        let metrics = Arc::new(GatewayMetrics::new());

        Ok(Self {
            policy,
            tape,
            scrubber,
            registry,
            budgets,
            p10,
            metrics,
            token_map,
            upstreams,
            console_to_stderr,
            max_request_bytes: config.max_request_bytes,
            max_response_bytes: config.max_response_bytes,
        })
    }

    pub fn authenticate_bearer(&self, auth_header: Option<&str>) -> Option<Principal> {
        let header = auth_header?;
        let token = header.strip_prefix("Bearer ")?.trim();
        if token.is_empty() {
            return None;
        }
        self.token_map.get(token).cloned()
    }

    /// Processes a single MCP JSON-RPC 2.0 request for an authenticated `principal`.
    pub async fn handle_rpc_request(&self, principal: &Principal, req: Value) -> Value {
        self.handle_rpc_request_with_trace(principal, req, None)
            .await
    }

    /// Processes a single MCP JSON-RPC 2.0 request with optional W3C `trace_id` provenance correlation.
    pub async fn handle_rpc_request_with_trace(
        &self,
        principal: &Principal,
        req: Value,
        trace_id: Option<&str>,
    ) -> Value {
        let base_provenance = trace_id.map(|tid| json!({ "trace_id": tid }));
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");

        match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "serverInfo": { "name": "keelway-mcp-gateway", "version": env!("CARGO_PKG_VERSION") },
                    "capabilities": { "tools": {}, "resources": {}, "prompts": {} }
                }
            }),
            "ping" | "notifications/initialized" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {}
            }),
            "resources/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "resources": [] }
            }),
            "prompts/list" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "prompts": [] }
            }),
            "tools/list" => {
                let visible: Vec<Value> = self
                    .registry
                    .iter()
                    .filter(|t| {
                        self.policy
                            .can_list_tool(principal, &t.server_alias, &t.upstream_name)
                    })
                    .map(|t| {
                        json!({
                            "name": t.federated_name,
                            "description": t.description,
                            "inputSchema": t.input_schema
                        })
                    })
                    .collect();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tools": visible }
                })
            }
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let fed_name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));

                let req_bytes = serde_json::to_vec(&arguments)
                    .map(|v| v.len())
                    .unwrap_or(usize::MAX);
                if req_bytes > self.max_request_bytes {
                    let reason = format!(
                        "PayloadTooLarge: request arguments ({req_bytes} bytes) exceed max_request_bytes ({})",
                        self.max_request_bytes
                    );
                    let _ = self
                        .tape
                        .append(UnsealedReceipt {
                            timestamp: Utc::now(),
                            org_id: principal.org_id.clone(),
                            agent_id: principal.agent_id.clone(),
                            server: fed_name.to_owned(),
                            tool: fed_name.to_owned(),
                            redacted_args: Value::Null,
                            redacted_fields: vec![],
                            decision: Decision::Deny,
                            explanation: Explanation {
                                decision: Decision::Deny,
                                rule_ids: vec!["payload_limit".to_owned()],
                                validator_outcomes: vec![],
                                reason: reason.clone(),
                                policy_digest: String::new(),
                            },
                            policy_digest: String::new(),
                            state: ReceiptState::Blocked,
                            outcome: None,
                            provenance: base_provenance.clone(),
                        })
                        .await;
                    return jsonrpc_error(id, JSONRPC_PAYLOAD_TOO_LARGE, &reason, None);
                }

                let Some(tool_meta) = self.registry.resolve(fed_name) else {
                    return jsonrpc_error(
                        id,
                        -32602,
                        &format!("unknown federated tool '{fed_name}'"),
                        None,
                    );
                };

                let (redacted_args, redacted_fields) = self.scrubber.scrub_json(&arguments);
                let tool_call = ToolCall {
                    server: tool_meta.server_alias.clone(),
                    tool: tool_meta.upstream_name.clone(),
                    arguments: arguments.clone(),
                };

                let eval = match self.policy.evaluate(principal, &tool_call) {
                    Ok(d) => d,
                    Err(e) => {
                        return jsonrpc_error(
                            id,
                            JSONRPC_POLICY_DENIED,
                            &format!("policy evaluation error (fail-closed): {e}"),
                            None,
                        );
                    }
                };

                let mut scrubbed_explanation = eval.explanation.clone();
                scrubbed_explanation.reason = self.scrubber.scrub_str(&scrubbed_explanation.reason);
                for vo in &mut scrubbed_explanation.validator_outcomes {
                    vo.reason = self.scrubber.scrub_str(&vo.reason);
                }

                if eval.decision == Decision::Deny {
                    let unsealed = UnsealedReceipt {
                        timestamp: Utc::now(),
                        org_id: principal.org_id.clone(),
                        agent_id: principal.agent_id.clone(),
                        server: tool_meta.server_alias.clone(),
                        tool: tool_meta.upstream_name.clone(),
                        redacted_args,
                        redacted_fields,
                        decision: eval.decision,
                        explanation: scrubbed_explanation.clone(),
                        policy_digest: scrubbed_explanation.policy_digest.clone(),
                        state: ReceiptState::Blocked,
                        outcome: None,
                        provenance: base_provenance.clone(),
                    };

                    // Fail-closed: receipt MUST persist before returning decision
                    if let Err(e) = self.tape.append(unsealed).await {
                        return jsonrpc_error(
                            id,
                            JSONRPC_TAPE_PERSISTENCE_ERR,
                            &format!("TapePersistenceError (fail-closed): {e}"),
                            None,
                        );
                    }

                    self.metrics.record_event(LiveConsoleEvent {
                        timestamp: Utc::now(),
                        org_id: principal.org_id.clone(),
                        agent_id: principal.agent_id.clone(),
                        server: tool_meta.server_alias.clone(),
                        tool: tool_meta.upstream_name.clone(),
                        decision: eval.decision,
                        state: ReceiptState::Blocked,
                        outcome: EventOutcome::DeniedPolicy,
                        reason: scrubbed_explanation.reason.clone(),
                    });

                    self.emit_console_line(
                        &format!("{}.{}", tool_meta.server_alias, tool_meta.upstream_name),
                        &principal.agent_id,
                        eval.decision,
                        &scrubbed_explanation.reason,
                    );

                    return jsonrpc_error(
                        id,
                        JSONRPC_POLICY_DENIED,
                        "PolicyDenied",
                        Some(serde_json::to_value(&scrubbed_explanation).unwrap_or(Value::Null)),
                    );
                }

                // Enforce per-principal/per-server execution budget before P-10 or upstream dispatch (ADR-003).
                let _budget_lease = match self.budgets.acquire(principal, &tool_meta.server_alias) {
                    Ok(lease) => lease,
                    Err(e) => {
                        let reason = e.to_string();
                        let budget_explanation = Explanation {
                            decision: Decision::Deny,
                            rule_ids: vec!["budget".to_owned()],
                            validator_outcomes: vec![],
                            reason: reason.clone(),
                            policy_digest: scrubbed_explanation.policy_digest.clone(),
                        };
                        let _ = self
                            .tape
                            .append(UnsealedReceipt {
                                timestamp: Utc::now(),
                                org_id: principal.org_id.clone(),
                                agent_id: principal.agent_id.clone(),
                                server: tool_meta.server_alias.clone(),
                                tool: tool_meta.upstream_name.clone(),
                                redacted_args: redacted_args.clone(),
                                redacted_fields: redacted_fields.clone(),
                                decision: Decision::Deny,
                                explanation: budget_explanation.clone(),
                                policy_digest: budget_explanation.policy_digest.clone(),
                                state: ReceiptState::Blocked,
                                outcome: None,
                                provenance: base_provenance.clone(),
                            })
                            .await;
                        self.metrics.record_event(LiveConsoleEvent {
                            timestamp: Utc::now(),
                            org_id: principal.org_id.clone(),
                            agent_id: principal.agent_id.clone(),
                            server: tool_meta.server_alias.clone(),
                            tool: tool_meta.upstream_name.clone(),
                            decision: Decision::Deny,
                            state: ReceiptState::Blocked,
                            outcome: EventOutcome::DeniedBudget,
                            reason: reason.clone(),
                        });
                        self.emit_console_line(
                            &format!("{}.{}", tool_meta.server_alias, tool_meta.upstream_name),
                            &principal.agent_id,
                            Decision::Deny,
                            &reason,
                        );
                        return jsonrpc_error(
                            id,
                            JSONRPC_BUDGET_EXCEEDED,
                            "BudgetExceeded",
                            Some(serde_json::to_value(&budget_explanation).unwrap_or(Value::Null)),
                        );
                    }
                };

                let p10_timeout_ms = self.p10.requires_approval(
                    principal,
                    &tool_meta.server_alias,
                    &tool_meta.upstream_name,
                );

                let (state, initial_outcome) = match p10_timeout_ms {
                    Some(_) => (ReceiptState::Awaiting, EventOutcome::P10Awaiting),
                    None => (ReceiptState::Sealed, EventOutcome::Allowed),
                };

                let unsealed = UnsealedReceipt {
                    timestamp: Utc::now(),
                    org_id: principal.org_id.clone(),
                    agent_id: principal.agent_id.clone(),
                    server: tool_meta.server_alias.clone(),
                    tool: tool_meta.upstream_name.clone(),
                    redacted_args: redacted_args.clone(),
                    redacted_fields: redacted_fields.clone(),
                    decision: eval.decision,
                    explanation: scrubbed_explanation.clone(),
                    policy_digest: scrubbed_explanation.policy_digest.clone(),
                    state,
                    outcome: None,
                    provenance: base_provenance.clone(),
                };

                // Fail-closed: receipt MUST persist before dispatching any upstream side effect
                if let Err(e) = self.tape.append(unsealed).await {
                    return jsonrpc_error(
                        id,
                        JSONRPC_TAPE_PERSISTENCE_ERR,
                        &format!("TapePersistenceError (fail-closed): {e}"),
                        None,
                    );
                }

                self.metrics.record_event(LiveConsoleEvent {
                    timestamp: Utc::now(),
                    org_id: principal.org_id.clone(),
                    agent_id: principal.agent_id.clone(),
                    server: tool_meta.server_alias.clone(),
                    tool: tool_meta.upstream_name.clone(),
                    decision: eval.decision,
                    state,
                    outcome: initial_outcome,
                    reason: scrubbed_explanation.reason.clone(),
                });

                self.emit_console_line(
                    &format!("{}.{}", tool_meta.server_alias, tool_meta.upstream_name),
                    &principal.agent_id,
                    eval.decision,
                    &scrubbed_explanation.reason,
                );

                // Enforce P-10 human-in-the-loop approval gate if configured (ADR-004).
                if let Some(timeout_ms) = p10_timeout_ms {
                    let (approval_id, rx) = self.p10.create_gate(
                        principal,
                        &tool_meta.server_alias,
                        &tool_meta.upstream_name,
                        redacted_args.clone(),
                    );
                    let mut gate_guard = self.p10.guard(&approval_id);
                    let wait_res =
                        tokio::time::timeout(Duration::from_millis(timeout_ms), rx).await;
                    gate_guard.disarm();
                    let approved = match wait_res {
                        Ok(Ok(true)) => true,
                        Ok(Ok(false)) | Ok(Err(_)) => false,
                        Err(_) => {
                            self.p10.cancel(&approval_id);
                            false
                        }
                    };
                    if !approved {
                        let deny_reason = format!(
                            "P-10 human approval denied or timed out (gate_id: {approval_id})"
                        );
                        let deny_expl = Explanation {
                            decision: Decision::Deny,
                            rule_ids: vec!["p10_gate".to_owned()],
                            validator_outcomes: vec![],
                            reason: deny_reason.clone(),
                            policy_digest: scrubbed_explanation.policy_digest.clone(),
                        };
                        let _ = self
                            .tape
                            .append(UnsealedReceipt {
                                timestamp: Utc::now(),
                                org_id: principal.org_id.clone(),
                                agent_id: principal.agent_id.clone(),
                                server: tool_meta.server_alias.clone(),
                                tool: tool_meta.upstream_name.clone(),
                                redacted_args,
                                redacted_fields,
                                decision: Decision::Deny,
                                explanation: deny_expl.clone(),
                                policy_digest: deny_expl.policy_digest.clone(),
                                state: ReceiptState::Blocked,
                                outcome: None,
                                provenance: base_provenance.clone(),
                            })
                            .await;
                        self.metrics.record_event(LiveConsoleEvent {
                            timestamp: Utc::now(),
                            org_id: principal.org_id.clone(),
                            agent_id: principal.agent_id.clone(),
                            server: tool_meta.server_alias.clone(),
                            tool: tool_meta.upstream_name.clone(),
                            decision: Decision::Deny,
                            state: ReceiptState::Blocked,
                            outcome: EventOutcome::P10Denied,
                            reason: deny_reason,
                        });
                        return jsonrpc_error(
                            id,
                            JSONRPC_APPROVAL_DENIED,
                            "ApprovalDenied",
                            Some(serde_json::to_value(&deny_expl).unwrap_or(Value::Null)),
                        );
                    }

                    // Re-evaluate policy after P-10 approval in case hot reload revoked access while waiting.
                    let active_policy_digest = match self.policy.evaluate(principal, &tool_call) {
                        Ok(re_eval) if re_eval.decision == Decision::Deny => {
                            let mut re_expl = re_eval.explanation;
                            re_expl.reason = self.scrubber.scrub_str(&re_expl.reason);
                            for vo in &mut re_expl.validator_outcomes {
                                vo.reason = self.scrubber.scrub_str(&vo.reason);
                            }
                            if let Err(e) = self
                                .tape
                                .append(UnsealedReceipt {
                                    timestamp: Utc::now(),
                                    org_id: principal.org_id.clone(),
                                    agent_id: principal.agent_id.clone(),
                                    server: tool_meta.server_alias.clone(),
                                    tool: tool_meta.upstream_name.clone(),
                                    redacted_args,
                                    redacted_fields,
                                    decision: Decision::Deny,
                                    explanation: re_expl.clone(),
                                    policy_digest: re_expl.policy_digest.clone(),
                                    state: ReceiptState::Blocked,
                                    outcome: None,
                                    provenance: base_provenance.clone(),
                                })
                                .await
                            {
                                return jsonrpc_error(
                                    id,
                                    JSONRPC_TAPE_PERSISTENCE_ERR,
                                    &format!("TapePersistenceError (fail-closed): {e}"),
                                    None,
                                );
                            }
                            self.metrics.record_event(LiveConsoleEvent {
                                timestamp: Utc::now(),
                                org_id: principal.org_id.clone(),
                                agent_id: principal.agent_id.clone(),
                                server: tool_meta.server_alias.clone(),
                                tool: tool_meta.upstream_name.clone(),
                                decision: Decision::Deny,
                                state: ReceiptState::Blocked,
                                outcome: EventOutcome::DeniedPolicy,
                                reason: re_expl.reason.clone(),
                            });
                            return jsonrpc_error(
                                id,
                                JSONRPC_POLICY_DENIED,
                                "PolicyDenied",
                                Some(serde_json::to_value(&re_expl).unwrap_or(Value::Null)),
                            );
                        }
                        Err(e) => {
                            return jsonrpc_error(
                                id,
                                JSONRPC_POLICY_DENIED,
                                &format!("PolicyEvaluationError (fail-closed): {e}"),
                                None,
                            );
                        }
                        Ok(re_eval) => re_eval.explanation.policy_digest,
                    };

                    let approve_reason =
                        format!("P-10 human approval granted (gate_id: {approval_id})");
                    let seal_expl = Explanation {
                        decision: Decision::Allow,
                        rule_ids: vec!["p10_gate".to_owned()],
                        validator_outcomes: vec![],
                        reason: approve_reason.clone(),
                        policy_digest: active_policy_digest,
                    };
                    if let Err(e) = self
                        .tape
                        .append(UnsealedReceipt {
                            timestamp: Utc::now(),
                            org_id: principal.org_id.clone(),
                            agent_id: principal.agent_id.clone(),
                            server: tool_meta.server_alias.clone(),
                            tool: tool_meta.upstream_name.clone(),
                            redacted_args,
                            redacted_fields,
                            decision: Decision::Allow,
                            explanation: seal_expl.clone(),
                            policy_digest: seal_expl.policy_digest.clone(),
                            state: ReceiptState::Sealed,
                            outcome: None,
                            provenance: base_provenance.clone(),
                        })
                        .await
                    {
                        return jsonrpc_error(
                            id,
                            JSONRPC_TAPE_PERSISTENCE_ERR,
                            &format!("TapePersistenceError (fail-closed): {e}"),
                            None,
                        );
                    }
                    self.metrics.record_event(LiveConsoleEvent {
                        timestamp: Utc::now(),
                        org_id: principal.org_id.clone(),
                        agent_id: principal.agent_id.clone(),
                        server: tool_meta.server_alias.clone(),
                        tool: tool_meta.upstream_name.clone(),
                        decision: Decision::Allow,
                        state: ReceiptState::Sealed,
                        outcome: EventOutcome::P10Approved,
                        reason: approve_reason,
                    });
                }

                // Dispatch to upstream MCP server
                let Some(upstream) = self.upstreams.get(&tool_meta.server_alias) else {
                    return jsonrpc_error(
                        id,
                        JSONRPC_UPSTREAM_UNAVAILABLE,
                        "UpstreamUnavailable: server driver missing",
                        None,
                    );
                };

                match upstream
                    .call_tool(
                        &tool_meta.upstream_name,
                        &arguments,
                        &self.scrubber,
                        self.max_response_bytes,
                        trace_id,
                    )
                    .await
                {
                    Ok(result) => {
                        let resp_bytes = serde_json::to_vec(&result)
                            .map(|v| v.len())
                            .unwrap_or(usize::MAX);
                        if resp_bytes > self.max_response_bytes {
                            let reason = format!(
                                "PayloadTooLarge: upstream response ({resp_bytes} bytes) exceed max_response_bytes ({})",
                                self.max_response_bytes
                            );
                            let _ = self
                                .tape
                                .append(UnsealedReceipt {
                                    timestamp: Utc::now(),
                                    org_id: principal.org_id.clone(),
                                    agent_id: principal.agent_id.clone(),
                                    server: tool_meta.server_alias.clone(),
                                    tool: tool_meta.upstream_name.clone(),
                                    redacted_args: Value::Null,
                                    redacted_fields: vec![],
                                    decision: Decision::Deny,
                                    explanation: Explanation {
                                        decision: Decision::Deny,
                                        rule_ids: vec!["payload_limit".to_owned()],
                                        validator_outcomes: vec![],
                                        reason: reason.clone(),
                                        policy_digest: eval.explanation.policy_digest.clone(),
                                    },
                                    policy_digest: eval.explanation.policy_digest.clone(),
                                    state: ReceiptState::Blocked,
                                    outcome: None,
                                    provenance: base_provenance.clone(),
                                })
                                .await;
                            return jsonrpc_error(id, JSONRPC_PAYLOAD_TOO_LARGE, &reason, None);
                        }
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "result": result
                        })
                    }
                    Err(KeelwayError::Mcp(msg)) if msg.starts_with("PayloadTooLarge:") => {
                        let _ = self
                            .tape
                            .append(UnsealedReceipt {
                                timestamp: Utc::now(),
                                org_id: principal.org_id.clone(),
                                agent_id: principal.agent_id.clone(),
                                server: tool_meta.server_alias.clone(),
                                tool: tool_meta.upstream_name.clone(),
                                redacted_args: Value::Null,
                                redacted_fields: vec![],
                                decision: Decision::Deny,
                                explanation: Explanation {
                                    decision: Decision::Deny,
                                    rule_ids: vec!["payload_limit".to_owned()],
                                    validator_outcomes: vec![],
                                    reason: msg.clone(),
                                    policy_digest: eval.explanation.policy_digest.clone(),
                                },
                                policy_digest: eval.explanation.policy_digest.clone(),
                                state: ReceiptState::Blocked,
                                outcome: None,
                                provenance: base_provenance.clone(),
                            })
                            .await;
                        jsonrpc_error(id, JSONRPC_PAYLOAD_TOO_LARGE, &msg, None)
                    }
                    Err(KeelwayError::UpstreamTimeout(ms)) => {
                        self.metrics.inc_upstream_timeout();
                        let _ = self
                            .record_outcome(
                                principal,
                                tool_meta,
                                &eval.explanation,
                                ExecutionOutcome::Timeout,
                            )
                            .await;
                        jsonrpc_error(
                            id,
                            JSONRPC_UPSTREAM_TIMEOUT,
                            &format!("UpstreamTimeout after {ms}ms"),
                            None,
                        )
                    }
                    Err(e) => {
                        self.metrics.inc_upstream_error();
                        let _ = self
                            .record_outcome(
                                principal,
                                tool_meta,
                                &eval.explanation,
                                ExecutionOutcome::Crashed,
                            )
                            .await;
                        jsonrpc_error(
                            id,
                            JSONRPC_UPSTREAM_UNAVAILABLE,
                            &format!("UpstreamUnavailable: {e}"),
                            None,
                        )
                    }
                }
            }
            "resources/read" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let uri = params
                    .get("uri")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let Some(uri) = uri else {
                    return jsonrpc_error(id, -32602, "missing required params.uri", None);
                };
                let server = params
                    .get("server")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        uri.split_once("://")
                            .map(|(s, _)| s)
                            .filter(|s| !s.is_empty())
                    });
                let Some(server) = server else {
                    return jsonrpc_error(
                        id,
                        -32602,
                        "missing params.server and uri is not '<server>://<path>'",
                        None,
                    );
                };
                self.handle_governed_upstream_method(
                    principal,
                    id,
                    trace_id,
                    "read_resource",
                    "resources/read",
                    server,
                    uri,
                    &params,
                    json!({ "uri": uri }),
                )
                .await
            }
            "prompts/get" => {
                let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
                let server = params
                    .get("server")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let (Some(server), Some(name)) = (server, name) else {
                    return jsonrpc_error(
                        id,
                        -32602,
                        "missing required params.server or params.name",
                        None,
                    );
                };
                let upstream_params = match params.get("arguments") {
                    Some(args) => json!({ "name": name, "arguments": args }),
                    None => json!({ "name": name }),
                };
                self.handle_governed_upstream_method(
                    principal,
                    id,
                    trace_id,
                    "get_prompt",
                    "prompts/get",
                    server,
                    name,
                    &params,
                    upstream_params,
                )
                .await
            }
            _ => jsonrpc_error(id, -32601, &format!("method not found: '{method}'"), None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_governed_upstream_method(
        &self,
        principal: &Principal,
        id: Value,
        trace_id: Option<&str>,
        cedar_action: &str,
        rpc_method: &str,
        server: &str,
        target_name: &str,
        params: &Value,
        upstream_params: Value,
    ) -> Value {
        let base_provenance = trace_id.map(|tid| json!({ "trace_id": tid }));
        let req_bytes = serde_json::to_vec(params)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if req_bytes > self.max_request_bytes {
            let reason = format!(
                "PayloadTooLarge: request params ({req_bytes} bytes) exceed max_request_bytes ({})",
                self.max_request_bytes
            );
            let _ = self
                .tape
                .append(UnsealedReceipt {
                    timestamp: Utc::now(),
                    org_id: principal.org_id.clone(),
                    agent_id: principal.agent_id.clone(),
                    server: server.to_owned(),
                    tool: target_name.to_owned(),
                    redacted_args: Value::Null,
                    redacted_fields: vec![],
                    decision: Decision::Deny,
                    explanation: Explanation {
                        decision: Decision::Deny,
                        rule_ids: vec!["payload_limit".to_owned()],
                        validator_outcomes: vec![],
                        reason: reason.clone(),
                        policy_digest: String::new(),
                    },
                    policy_digest: String::new(),
                    state: ReceiptState::Blocked,
                    outcome: None,
                    provenance: base_provenance,
                })
                .await;
            return jsonrpc_error(id, JSONRPC_PAYLOAD_TOO_LARGE, &reason, None);
        }

        let (redacted_args, redacted_fields) = self.scrubber.scrub_json(params);
        let call = ToolCall {
            server: server.to_owned(),
            tool: target_name.to_owned(),
            arguments: params.clone(),
        };

        let eval = match self.policy.evaluate_action(principal, cedar_action, &call) {
            Ok(d) => d,
            Err(e) => {
                return jsonrpc_error(
                    id,
                    JSONRPC_POLICY_DENIED,
                    &format!("policy evaluation error (fail-closed): {e}"),
                    None,
                );
            }
        };

        let mut scrubbed_explanation = eval.explanation.clone();
        scrubbed_explanation.reason = self.scrubber.scrub_str(&scrubbed_explanation.reason);
        for vo in &mut scrubbed_explanation.validator_outcomes {
            vo.reason = self.scrubber.scrub_str(&vo.reason);
        }

        if eval.decision == Decision::Deny {
            let unsealed = UnsealedReceipt {
                timestamp: Utc::now(),
                org_id: principal.org_id.clone(),
                agent_id: principal.agent_id.clone(),
                server: server.to_owned(),
                tool: target_name.to_owned(),
                redacted_args,
                redacted_fields,
                decision: eval.decision,
                explanation: scrubbed_explanation.clone(),
                policy_digest: scrubbed_explanation.policy_digest.clone(),
                state: ReceiptState::Blocked,
                outcome: None,
                provenance: base_provenance,
            };
            if let Err(e) = self.tape.append(unsealed).await {
                return jsonrpc_error(
                    id,
                    JSONRPC_TAPE_PERSISTENCE_ERR,
                    &format!("TapePersistenceError (fail-closed): {e}"),
                    None,
                );
            }
            self.metrics.record_event(LiveConsoleEvent {
                timestamp: Utc::now(),
                org_id: principal.org_id.clone(),
                agent_id: principal.agent_id.clone(),
                server: server.to_owned(),
                tool: target_name.to_owned(),
                decision: eval.decision,
                state: ReceiptState::Blocked,
                outcome: EventOutcome::DeniedPolicy,
                reason: scrubbed_explanation.reason.clone(),
            });
            self.emit_console_line(
                &format!("{server}.{target_name}"),
                &principal.agent_id,
                eval.decision,
                &scrubbed_explanation.reason,
            );
            return jsonrpc_error(
                id,
                JSONRPC_POLICY_DENIED,
                "PolicyDenied",
                Some(serde_json::to_value(&scrubbed_explanation).unwrap_or(Value::Null)),
            );
        }

        let Some(upstream) = self.upstreams.get(server) else {
            return jsonrpc_error(
                id,
                JSONRPC_UPSTREAM_UNAVAILABLE,
                "UpstreamUnavailable: server driver missing",
                None,
            );
        };

        let unsealed = UnsealedReceipt {
            timestamp: Utc::now(),
            org_id: principal.org_id.clone(),
            agent_id: principal.agent_id.clone(),
            server: server.to_owned(),
            tool: target_name.to_owned(),
            redacted_args,
            redacted_fields,
            decision: eval.decision,
            explanation: scrubbed_explanation.clone(),
            policy_digest: scrubbed_explanation.policy_digest.clone(),
            state: ReceiptState::Sealed,
            outcome: None,
            provenance: base_provenance.clone(),
        };
        if let Err(e) = self.tape.append(unsealed).await {
            return jsonrpc_error(
                id,
                JSONRPC_TAPE_PERSISTENCE_ERR,
                &format!("TapePersistenceError (fail-closed): {e}"),
                None,
            );
        }

        self.metrics.record_event(LiveConsoleEvent {
            timestamp: Utc::now(),
            org_id: principal.org_id.clone(),
            agent_id: principal.agent_id.clone(),
            server: server.to_owned(),
            tool: target_name.to_owned(),
            decision: eval.decision,
            state: ReceiptState::Sealed,
            outcome: EventOutcome::Allowed,
            reason: scrubbed_explanation.reason.clone(),
        });
        self.emit_console_line(
            &format!("{server}.{target_name}"),
            &principal.agent_id,
            eval.decision,
            &scrubbed_explanation.reason,
        );

        match upstream
            .call_method(
                rpc_method,
                upstream_params,
                &self.scrubber,
                self.max_response_bytes,
                trace_id,
            )
            .await
        {
            Ok(result) => {
                let resp_bytes = serde_json::to_vec(&result)
                    .map(|v| v.len())
                    .unwrap_or(usize::MAX);
                if resp_bytes > self.max_response_bytes {
                    let reason = format!(
                        "PayloadTooLarge: upstream response ({resp_bytes} bytes) exceed max_response_bytes ({})",
                        self.max_response_bytes
                    );
                    let _ = self
                        .tape
                        .append(UnsealedReceipt {
                            timestamp: Utc::now(),
                            org_id: principal.org_id.clone(),
                            agent_id: principal.agent_id.clone(),
                            server: server.to_owned(),
                            tool: target_name.to_owned(),
                            redacted_args: Value::Null,
                            redacted_fields: vec![],
                            decision: Decision::Deny,
                            explanation: Explanation {
                                decision: Decision::Deny,
                                rule_ids: vec!["payload_limit".to_owned()],
                                validator_outcomes: vec![],
                                reason: reason.clone(),
                                policy_digest: eval.explanation.policy_digest,
                            },
                            policy_digest: scrubbed_explanation.policy_digest,
                            state: ReceiptState::Blocked,
                            outcome: None,
                            provenance: base_provenance,
                        })
                        .await;
                    return jsonrpc_error(id, JSONRPC_PAYLOAD_TOO_LARGE, &reason, None);
                }
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                })
            }
            Err(KeelwayError::Mcp(msg)) if msg.starts_with("PayloadTooLarge:") => {
                let _ = self
                    .tape
                    .append(UnsealedReceipt {
                        timestamp: Utc::now(),
                        org_id: principal.org_id.clone(),
                        agent_id: principal.agent_id.clone(),
                        server: server.to_owned(),
                        tool: target_name.to_owned(),
                        redacted_args: Value::Null,
                        redacted_fields: vec![],
                        decision: Decision::Deny,
                        explanation: Explanation {
                            decision: Decision::Deny,
                            rule_ids: vec!["payload_limit".to_owned()],
                            validator_outcomes: vec![],
                            reason: msg.clone(),
                            policy_digest: eval.explanation.policy_digest,
                        },
                        policy_digest: scrubbed_explanation.policy_digest,
                        state: ReceiptState::Blocked,
                        outcome: None,
                        provenance: base_provenance,
                    })
                    .await;
                jsonrpc_error(id, JSONRPC_PAYLOAD_TOO_LARGE, &msg, None)
            }
            Err(KeelwayError::UpstreamTimeout(ms)) => {
                self.metrics.inc_upstream_timeout();
                jsonrpc_error(
                    id,
                    JSONRPC_UPSTREAM_TIMEOUT,
                    &format!("UpstreamTimeout after {ms}ms"),
                    None,
                )
            }
            Err(e) => {
                self.metrics.inc_upstream_error();
                jsonrpc_error(
                    id,
                    JSONRPC_UPSTREAM_UNAVAILABLE,
                    &format!("UpstreamUnavailable: {e}"),
                    None,
                )
            }
        }
    }

    async fn record_outcome(
        &self,
        principal: &Principal,
        tool_meta: &FederatedTool,
        explanation: &Explanation,
        outcome: ExecutionOutcome,
    ) -> Result<(), KeelwayError> {
        let _ = self
            .tape
            .append(UnsealedReceipt {
                timestamp: Utc::now(),
                org_id: principal.org_id.clone(),
                agent_id: principal.agent_id.clone(),
                server: tool_meta.server_alias.clone(),
                tool: tool_meta.upstream_name.clone(),
                redacted_args: Value::Null,
                redacted_fields: vec![],
                decision: Decision::Allow,
                explanation: explanation.clone(),
                policy_digest: explanation.policy_digest.clone(),
                state: ReceiptState::Sealed,
                outcome: Some(outcome),
                provenance: None,
            })
            .await?;
        Ok(())
    }

    fn emit_console_line(&self, display_tool: &str, agent: &str, decision: Decision, reason: &str) {
        let badge = match decision {
            Decision::Allow => "ALLOWED",
            Decision::Deny => "BLOCKED",
        };
        let safe_reason = self.scrubber.scrub_str(reason);
        let line = format!("{display_tool:<30} {agent:<18} {badge:<8} ({safe_reason})\n");
        if self.console_to_stderr {
            let _ = std::io::stderr().write_all(line.as_bytes());
        } else {
            let _ = std::io::stdout().write_all(line.as_bytes());
        }
    }
}

fn jsonrpc_error(id: Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut err = json!({
        "code": code,
        "message": message
    });
    if let Some(d) = data
        && let Some(obj) = err.as_object_mut()
    {
        obj.insert("data".to_owned(), d);
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": err
    })
}

/// Builds the Streamable HTTP (`/mcp`) and observability/P-10 Axum router.
pub fn build_http_router(runtime: Arc<GatewayRuntime>) -> Router {
    let body_limit = runtime.max_request_bytes.saturating_add(64 * 1024);
    Router::new()
        .route("/mcp", post(http_mcp_handler))
        .layer(axum::extract::DefaultBodyLimit::max(body_limit))
        .route("/ui", get(ui_console_handler))
        .route("/healthz", get(healthz_handler))
        .route("/metrics", get(metrics_handler))
        .route("/events", get(events_sse_handler))
        .route("/p10/pending", get(p10_pending_handler))
        .route("/p10/resolve", post(p10_resolve_handler))
        .with_state(runtime)
}

const CONSOLE_HTML: &str = include_str!("ui/console.html");

async fn ui_console_handler() -> Response {
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "text/html; charset=utf-8",
            ),
            (
                axum::http::header::CONTENT_SECURITY_POLICY,
                "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
            ),
            (axum::http::header::X_FRAME_OPTIONS, "DENY"),
            (axum::http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (axum::http::header::CACHE_CONTROL, "no-store"),
        ],
        CONSOLE_HTML,
    )
        .into_response()
}

async fn healthz_handler() -> Response {
    (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response()
}

async fn metrics_handler(State(runtime): State<Arc<GatewayRuntime>>) -> Response {
    runtime
        .metrics
        .set_p10_pending(runtime.p10.pending_count() as u64);
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        runtime.metrics.render_prometheus(),
    )
        .into_response()
}

async fn events_sse_handler(
    State(runtime): State<Arc<GatewayRuntime>>,
    headers: HeaderMap,
) -> Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let Some(principal) = runtime.authenticate_bearer(auth_header) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthenticated" })),
        )
            .into_response();
    };
    let org_id = principal.org_id.clone();
    let rx_owned = runtime.metrics.subscribe();
    let sse_stream =
        futures_util::stream::unfold((rx_owned, org_id), |(mut rx, org_id)| async move {
            loop {
                match rx.recv().await {
                    Ok(ev) => {
                        if ev.org_id != org_id {
                            continue;
                        }
                        let payload =
                            serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_owned());
                        return Some((
                            Ok::<Event, std::convert::Infallible>(Event::default().data(payload)),
                            (rx, org_id),
                        ));
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
    Sse::new(sse_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

fn has_p10_approver_role(principal: &Principal) -> bool {
    principal
        .roles
        .iter()
        .any(|r| r == "p10-approver" || r == "admin")
}

async fn p10_pending_handler(
    State(runtime): State<Arc<GatewayRuntime>>,
    headers: HeaderMap,
) -> Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let Some(principal) = runtime.authenticate_bearer(auth_header) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthenticated" })),
        )
            .into_response();
    };
    if !has_p10_approver_role(&principal) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "p10-approver or admin role required" })),
        )
            .into_response();
    }
    let pending: Vec<_> = runtime
        .p10
        .list_pending()
        .into_iter()
        .filter(|p| p.org_id == principal.org_id)
        .collect();
    (StatusCode::OK, Json(json!({ "pending": pending }))).into_response()
}

#[derive(Debug, Deserialize)]
struct P10ResolveBody {
    approval_id: String,
    approved: bool,
}

async fn p10_resolve_handler(
    State(runtime): State<Arc<GatewayRuntime>>,
    headers: HeaderMap,
    Json(body): Json<P10ResolveBody>,
) -> Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let Some(principal) = runtime.authenticate_bearer(auth_header) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthenticated" })),
        )
            .into_response();
    };
    if !has_p10_approver_role(&principal) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "p10-approver or admin role required" })),
        )
            .into_response();
    }
    match runtime.p10.resolve(
        &body.approval_id,
        &principal.org_id,
        &principal.agent_id,
        body.approved,
    ) {
        Ok(()) => (StatusCode::OK, Json(json!({ "resolved": true }))).into_response(),
        Err(KeelwayError::Auth(msg)) => {
            (StatusCode::FORBIDDEN, Json(json!({ "error": msg }))).into_response()
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn http_mcp_handler(
    State(runtime): State<Arc<GatewayRuntime>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let Some(principal) = runtime.authenticate_bearer(auth_header) else {
        // Record unauthenticated DENY receipt (best-effort; always return 401 fail-closed)
        let _ = runtime
            .tape
            .append(UnsealedReceipt {
                timestamp: Utc::now(),
                org_id: "unknown".to_owned(),
                agent_id: "unauthenticated".to_owned(),
                server: "gateway".to_owned(),
                tool: body
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                redacted_args: Value::Null,
                redacted_fields: vec![],
                decision: Decision::Deny,
                explanation: Explanation {
                    decision: Decision::Deny,
                    rule_ids: vec![],
                    validator_outcomes: vec![],
                    reason: "unauthenticated".to_owned(),
                    policy_digest: runtime.policy.current_digest(),
                },
                policy_digest: runtime.policy.current_digest(),
                state: ReceiptState::Blocked,
                outcome: None,
                provenance: None,
            })
            .await;
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthenticated" })),
        )
            .into_response();
    };

    let trace_id =
        extract_or_generate_trace_id(headers.get("traceparent").and_then(|v| v.to_str().ok()));
    let resp = runtime
        .handle_rpc_request_with_trace(&principal, body, Some(&trace_id))
        .await;
    (StatusCode::OK, Json(resp)).into_response()
}

/// Runs the local stdio MCP transport loop for an explicitly bound `principal`.
/// All logging/console output MUST go to `stderr` to keep `stdout` strictly JSON-RPC.
pub async fn serve_stdio_loop(
    runtime: Arc<GatewayRuntime>,
    principal: Principal,
) -> Result<(), KeelwayError> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(trimmed) {
            Ok(req) => runtime.handle_rpc_request(&principal, req).await,
            Err(e) => jsonrpc_error(Value::Null, -32700, &format!("parse error: {e}"), None),
        };
        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        stdout.write_all(out.as_bytes()).await?;
        stdout.flush().await?;
    }
    Ok(())
}
