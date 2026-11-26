use crate::auth::JwtVerifier;
use crate::budget::BudgetTracker;
use crate::circuit::{CircuitBreaker, CircuitState};
use crate::core::{
    Decision, ExecutionOutcome, Explanation, GatewayConfig, KeelwayError, Principal, PromptConfig,
    ReceiptState, ResourceConfig, ToolCall, UnsealedReceipt, sanitize_federated_name,
    validate_server_alias,
};
use crate::metrics::{EventOutcome, GatewayMetrics, LiveConsoleEvent};
use crate::p10::P10GateManager;
use crate::policy::PolicyEngine;
use crate::provenance::extract_or_generate_trace_id;
use crate::secrets::{SecretProvider, SecretScrubber};
use crate::tape::TapeWriter;
use crate::upstream::UpstreamDriver;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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

/// Shared runtime state for the MCP Gateway.
pub struct GatewayRuntime {
    pub policy: Arc<PolicyEngine>,
    pub tape: TapeWriter,
    pub scrubber: Arc<SecretScrubber>,
    pub registry: ToolRegistry,
    budgets: BudgetTracker,
    p10: P10GateManager,
    circuit_breaker: CircuitBreaker,
    metrics: Arc<GatewayMetrics>,
    token_map: HashMap<String, Principal>,
    jwt_verifier: Option<JwtVerifier>,
    upstreams: HashMap<String, UpstreamDriver>,
    resources: Vec<(String, ResourceConfig)>,
    prompts: Vec<(String, PromptConfig)>,
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
        let mut resources = Vec::new();
        let mut prompts = Vec::new();

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
            for r in &s.resources {
                resources.push((s.alias.clone(), r.clone()));
            }
            for p in &s.prompts {
                prompts.push((s.alias.clone(), p.clone()));
            }
        }

        let jwt_verifier = match config.jwt_auth {
            Some(ref jwt_cfg) => {
                let mut resolved_cfg = jwt_cfg.clone();
                if let Some(ref secret_ref) = resolved_cfg.hs256_secret
                    && secret_ref.starts_with("secret://")
                {
                    let resolved = secrets.resolve(secret_ref)?;
                    collected_secrets.push(resolved.clone());
                    resolved_cfg.hs256_secret = Some(resolved);
                }
                Some(JwtVerifier::new(resolved_cfg)?)
            }
            None => None,
        };

        let registry = ToolRegistry::build(federated_tools)?;
        let scrubber = Arc::new(
            SecretScrubber::new(&collected_secrets)?
                .with_pattern_scrubbing(config.egress_pattern_scrubbing),
        );
        let budgets = BudgetTracker::new(config.budgets.clone());
        let p10 = P10GateManager::new(config.approval_required.clone());
        let circuit_breaker = CircuitBreaker::default();
        let metrics = Arc::new(GatewayMetrics::new());

        Ok(Self {
            policy,
            tape,
            scrubber,
            registry,
            budgets,
            p10,
            circuit_breaker,
            metrics,
            token_map,
            jwt_verifier,
            upstreams,
            resources,
            prompts,
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

    /// Authenticates static bearer tokens first, then falls back to stateless JWT/OIDC verification.
    pub async fn authenticate_bearer_async(&self, auth_header: Option<&str>) -> Option<Principal> {
        self.authenticate_bearer_with_exp(auth_header)
            .await
            .map(|(p, _)| p)
    }

    /// Authenticates static bearer tokens first (no expiry), then falls back to stateless JWT/OIDC
    /// verification returning both `Principal` and optional `exp` (Unix seconds).
    pub async fn authenticate_bearer_with_exp(
        &self,
        auth_header: Option<&str>,
    ) -> Option<(Principal, Option<u64>)> {
        if let Some(principal) = self.authenticate_bearer(auth_header) {
            return Some((principal, None));
        }
        let verifier = self.jwt_verifier.as_ref()?;
        let token = auth_header?.strip_prefix("Bearer ")?.trim();
        if token.is_empty() {
            return None;
        }
        verifier.verify_token_with_exp(token).await.ok()
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
        let base_provenance = Some(match trace_id {
            Some(tid) => json!({ "trace_id": tid, "roles": principal.roles }),
            None => json!({ "roles": principal.roles }),
        });
        let is_notification = req.get("id").is_none();
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");

        if is_notification && method == "notifications/initialized" {
            return Value::Null;
        }

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
            "resources/list" => {
                let visible: Vec<Value> = self
                    .resources
                    .iter()
                    .filter(|(server, r)| {
                        self.policy
                            .can_perform_action(principal, "read_resource", server, &r.uri)
                    })
                    .map(|(_, r)| {
                        let mut obj = serde_json::Map::new();
                        obj.insert("uri".to_owned(), json!(r.uri));
                        obj.insert(
                            "name".to_owned(),
                            json!(r.name.as_deref().unwrap_or(&r.uri)),
                        );
                        if let Some(ref desc) = r.description {
                            obj.insert("description".to_owned(), json!(desc));
                        }
                        if let Some(ref mime) = r.mime_type {
                            obj.insert("mimeType".to_owned(), json!(mime));
                        }
                        Value::Object(obj)
                    })
                    .collect();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "resources": visible }
                })
            }
            "prompts/list" => {
                let visible: Vec<Value> = self
                    .prompts
                    .iter()
                    .filter(|(server, p)| {
                        self.policy
                            .can_perform_action(principal, "get_prompt", server, &p.name)
                    })
                    .map(|(_, p)| {
                        let mut obj = serde_json::Map::new();
                        obj.insert("name".to_owned(), json!(p.name));
                        if let Some(ref desc) = p.description {
                            obj.insert("description".to_owned(), json!(desc));
                        }
                        Value::Object(obj)
                    })
                    .collect();
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "prompts": visible }
                })
            }
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

                if let Err(e) = self.circuit_breaker.before_call(&tool_meta.server_alias) {
                    self.metrics.inc_upstream_error();
                    let _ = self
                        .record_outcome(
                            principal,
                            tool_meta,
                            &eval.explanation,
                            ExecutionOutcome::Crashed,
                        )
                        .await;
                    return jsonrpc_error(
                        id,
                        JSONRPC_UPSTREAM_UNAVAILABLE,
                        &format!("UpstreamUnavailable: {e}"),
                        None,
                    );
                }

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
                        self.circuit_breaker.record_success(&tool_meta.server_alias);
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
                        self.circuit_breaker.record_failure(&tool_meta.server_alias);
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
                        if matches!(e, KeelwayError::UpstreamUnavailable(_)) {
                            self.circuit_breaker.record_failure(&tool_meta.server_alias);
                        }
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
                let explicit_server = params
                    .get("server")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let server = explicit_server
                    .or_else(|| {
                        uri.split_once("://")
                            .map(|(s, _)| s)
                            .filter(|s| !s.is_empty() && self.upstreams.contains_key(*s))
                    })
                    .or_else(|| {
                        let matches: Vec<&str> = self
                            .resources
                            .iter()
                            .filter(|(_, r)| r.uri == uri)
                            .map(|(s, _)| s.as_str())
                            .collect();
                        if matches.len() == 1 {
                            Some(matches[0])
                        } else {
                            None
                        }
                    })
                    .or_else(|| {
                        uri.split_once("://")
                            .map(|(s, _)| s)
                            .filter(|s| !s.is_empty())
                    });
                let Some(server) = server else {
                    return jsonrpc_error(
                        id,
                        -32602,
                        "missing params.server and uri could not be unambiguously routed",
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
                let name = params
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let Some(name) = name else {
                    return jsonrpc_error(id, -32602, "missing required params.name", None);
                };
                let server = params
                    .get("server")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        let matches: Vec<&str> = self
                            .prompts
                            .iter()
                            .filter(|(_, p)| p.name == name)
                            .map(|(s, _)| s.as_str())
                            .collect();
                        if matches.len() == 1 {
                            Some(matches[0])
                        } else {
                            None
                        }
                    });
                let Some(server) = server else {
                    return jsonrpc_error(
                        id,
                        -32602,
                        "missing required params.server (or ambiguous prompt name)",
                        None,
                    );
                };
                let arguments = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let upstream_params = json!({ "name": name, "arguments": arguments });
                self.handle_governed_upstream_method(
                    principal,
                    id,
                    trace_id,
                    "get_prompt",
                    "prompts/get",
                    server,
                    name,
                    &arguments,
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
        let scrubbed_target = self.scrubber.scrub_str(target_name);
        let receipt_provenance = Some(match trace_id {
            Some(tid) => {
                json!({ "trace_id": tid, "mcp_action": cedar_action, "roles": principal.roles })
            }
            None => json!({ "mcp_action": cedar_action, "roles": principal.roles }),
        });
        let req_bytes = serde_json::to_vec(params)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if req_bytes > self.max_request_bytes {
            let reason = format!(
                "PayloadTooLarge: request params ({req_bytes} bytes) exceed max_request_bytes ({})",
                self.max_request_bytes
            );
            if let Err(e) = self
                .tape
                .append(UnsealedReceipt {
                    timestamp: Utc::now(),
                    org_id: principal.org_id.clone(),
                    agent_id: principal.agent_id.clone(),
                    server: server.to_owned(),
                    tool: scrubbed_target.clone(),
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
                    provenance: receipt_provenance,
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
                tool: scrubbed_target.clone(),
                redacted_args,
                redacted_fields,
                decision: eval.decision,
                explanation: scrubbed_explanation.clone(),
                policy_digest: scrubbed_explanation.policy_digest.clone(),
                state: ReceiptState::Blocked,
                outcome: None,
                provenance: receipt_provenance,
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
                tool: scrubbed_target.clone(),
                decision: eval.decision,
                state: ReceiptState::Blocked,
                outcome: EventOutcome::DeniedPolicy,
                reason: scrubbed_explanation.reason.clone(),
            });
            self.emit_console_line(
                &format!("{server}.{scrubbed_target}"),
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

        // Enforce per-principal/per-server execution budget before upstream dispatch (ADR-003).
        let _budget_lease = match self.budgets.acquire(principal, server) {
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
                if let Err(tape_err) = self
                    .tape
                    .append(UnsealedReceipt {
                        timestamp: Utc::now(),
                        org_id: principal.org_id.clone(),
                        agent_id: principal.agent_id.clone(),
                        server: server.to_owned(),
                        tool: scrubbed_target.clone(),
                        redacted_args: redacted_args.clone(),
                        redacted_fields: redacted_fields.clone(),
                        decision: Decision::Deny,
                        explanation: budget_explanation.clone(),
                        policy_digest: budget_explanation.policy_digest.clone(),
                        state: ReceiptState::Blocked,
                        outcome: None,
                        provenance: receipt_provenance,
                    })
                    .await
                {
                    return jsonrpc_error(
                        id,
                        JSONRPC_TAPE_PERSISTENCE_ERR,
                        &format!("TapePersistenceError (fail-closed): {tape_err}"),
                        None,
                    );
                }
                self.metrics.record_event(LiveConsoleEvent {
                    timestamp: Utc::now(),
                    org_id: principal.org_id.clone(),
                    agent_id: principal.agent_id.clone(),
                    server: server.to_owned(),
                    tool: scrubbed_target.clone(),
                    decision: Decision::Deny,
                    state: ReceiptState::Blocked,
                    outcome: EventOutcome::DeniedBudget,
                    reason: reason.clone(),
                });
                self.emit_console_line(
                    &format!("{server}.{scrubbed_target}"),
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
            tool: scrubbed_target.clone(),
            redacted_args,
            redacted_fields,
            decision: eval.decision,
            explanation: scrubbed_explanation.clone(),
            policy_digest: scrubbed_explanation.policy_digest.clone(),
            state: ReceiptState::Sealed,
            outcome: None,
            provenance: receipt_provenance.clone(),
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
            tool: scrubbed_target.clone(),
            decision: eval.decision,
            state: ReceiptState::Sealed,
            outcome: EventOutcome::Allowed,
            reason: scrubbed_explanation.reason.clone(),
        });
        self.emit_console_line(
            &format!("{server}.{scrubbed_target}"),
            &principal.agent_id,
            eval.decision,
            &scrubbed_explanation.reason,
        );

        if let Err(e) = self.circuit_breaker.before_call(server) {
            self.metrics.inc_upstream_error();
            return jsonrpc_error(
                id,
                JSONRPC_UPSTREAM_UNAVAILABLE,
                &format!("UpstreamUnavailable: {e}"),
                None,
            );
        }

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
                self.circuit_breaker.record_success(server);
                let resp_bytes = serde_json::to_vec(&result)
                    .map(|v| v.len())
                    .unwrap_or(usize::MAX);
                if resp_bytes > self.max_response_bytes {
                    let reason = format!(
                        "PayloadTooLarge: upstream response ({resp_bytes} bytes) exceed max_response_bytes ({})",
                        self.max_response_bytes
                    );
                    if let Err(e) = self
                        .tape
                        .append(UnsealedReceipt {
                            timestamp: Utc::now(),
                            org_id: principal.org_id.clone(),
                            agent_id: principal.agent_id.clone(),
                            server: server.to_owned(),
                            tool: scrubbed_target,
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
                            provenance: receipt_provenance,
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
                    return jsonrpc_error(id, JSONRPC_PAYLOAD_TOO_LARGE, &reason, None);
                }
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result
                })
            }
            Err(KeelwayError::Mcp(msg)) if msg.starts_with("PayloadTooLarge:") => {
                if let Err(e) = self
                    .tape
                    .append(UnsealedReceipt {
                        timestamp: Utc::now(),
                        org_id: principal.org_id.clone(),
                        agent_id: principal.agent_id.clone(),
                        server: server.to_owned(),
                        tool: scrubbed_target,
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
                        provenance: receipt_provenance,
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
                jsonrpc_error(id, JSONRPC_PAYLOAD_TOO_LARGE, &msg, None)
            }
            Err(KeelwayError::UpstreamTimeout(ms)) => {
                self.circuit_breaker.record_failure(server);
                self.metrics.inc_upstream_timeout();
                jsonrpc_error(
                    id,
                    JSONRPC_UPSTREAM_TIMEOUT,
                    &format!("UpstreamTimeout after {ms}ms"),
                    None,
                )
            }
            Err(e) => {
                if matches!(e, KeelwayError::UpstreamUnavailable(_)) {
                    self.circuit_breaker.record_failure(server);
                }
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
        .route("/readyz", get(readyz_handler))
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

async fn readyz_handler(State(runtime): State<Arc<GatewayRuntime>>) -> Response {
    let snapshot = runtime.circuit_breaker.snapshot();
    let any_open = snapshot
        .iter()
        .any(|(_, state)| *state == CircuitState::Open);
    let circuits: BTreeMap<String, CircuitState> = snapshot.into_iter().collect();
    let status = if any_open {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (
        status,
        Json(json!({
            "ready": !any_open,
            "circuits": circuits,
        })),
    )
        .into_response()
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
    let Some((principal, exp)) = runtime.authenticate_bearer_with_exp(auth_header).await else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "unauthenticated" })),
        )
            .into_response();
    };
    if let Some(exp_ts) = exp
        && Utc::now().timestamp().max(0) as u64 >= exp_ts
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "token expired" })),
        )
            .into_response();
    }
    let org_id = principal.org_id.clone();
    let rx_owned = runtime.metrics.subscribe();
    let sse_stream = futures_util::stream::unfold(
        (rx_owned, org_id, exp),
        |(mut rx, org_id, exp)| async move {
            loop {
                if let Some(exp_ts) = exp {
                    let now = Utc::now().timestamp().max(0) as u64;
                    if now >= exp_ts {
                        return None;
                    }
                    let remaining = std::time::Duration::from_secs(exp_ts - now);
                    match tokio::time::timeout(remaining, rx.recv()).await {
                        Ok(Ok(ev)) => {
                            if ev.org_id != org_id {
                                continue;
                            }
                            let payload =
                                serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_owned());
                            return Some((
                                Ok::<Event, std::convert::Infallible>(
                                    Event::default().data(payload),
                                ),
                                (rx, org_id, exp),
                            ));
                        }
                        Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                        Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => return None,
                        Err(_) => return None,
                    }
                } else {
                    match rx.recv().await {
                        Ok(ev) => {
                            if ev.org_id != org_id {
                                continue;
                            }
                            let payload =
                                serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_owned());
                            return Some((
                                Ok::<Event, std::convert::Infallible>(
                                    Event::default().data(payload),
                                ),
                                (rx, org_id, exp),
                            ));
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                    }
                }
            }
        },
    );
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
    let Some(principal) = runtime.authenticate_bearer_async(auth_header).await else {
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
    let Some(principal) = runtime.authenticate_bearer_async(auth_header).await else {
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
    let Some(principal) = runtime.authenticate_bearer_async(auth_header).await else {
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
    let is_notification = body.get("id").is_none();
    let resp = runtime
        .handle_rpc_request_with_trace(&principal, body, Some(&trace_id))
        .await;
    if is_notification {
        return StatusCode::ACCEPTED.into_response();
    }
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
        let (is_notification, resp) = match serde_json::from_str::<Value>(trimmed) {
            Ok(req) => {
                let is_notif = req.get("id").is_none();
                (is_notif, runtime.handle_rpc_request(&principal, req).await)
            }
            Err(e) => (
                false,
                jsonrpc_error(Value::Null, -32700, &format!("parse error: {e}"), None),
            ),
        };
        if is_notification {
            continue;
        }
        let mut out = serde_json::to_string(&resp)?;
        out.push('\n');
        stdout.write_all(out.as_bytes()).await?;
        stdout.flush().await?;
    }
    Ok(())
}
