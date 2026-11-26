use crate::core::{
    Decision, Explanation, GatewayConfig, KeelwayError, PolicyDecision, Principal, ToolCall,
    ValidatorBinding, ValidatorKind, ValidatorOutcome,
};
use arc_swap::ArcSwap;
use cedar_policy::{
    Authorizer, Context, Decision as CedarDecision, Entities, Entity, EntityId, EntityTypeName,
    EntityUid, PolicySet, Request, RestrictedExpression, Schema, ValidationMode, Validator,
};
use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlparser::ast::{SetExpr, Statement};
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug)]
enum CompiledValidatorKind {
    PathWithin { root_norm: String },
    Glob { matcher: GlobMatcher, raw: String },
    Regex { regex: Regex, raw: String },
    SqlReadonly,
    RepoAllowlist { repos_lower: HashSet<String> },
}

#[derive(Debug)]
struct CompiledValidator {
    id: String,
    server: String,
    tool: String,
    arg_name: String,
    kind: CompiledValidatorKind,
}

/// Immutable compiled policy snapshot swapped atomically via `ArcSwap`.
pub struct PolicySnapshot {
    policy_set: PolicySet,
    schema: Schema,
    entities: Entities,
    validators: Vec<CompiledValidator>,
    policy_digest: String,
}

impl PolicySnapshot {
    /// Returns JSON Pointer paths (`/arg_name`) inspected by validators for `(server, tool)`.
    pub fn inspected_arg_pointers(&self, server: &str, tool: &str) -> Vec<String> {
        self.validators
            .iter()
            .filter(|v| v.server == server && v.tool == tool)
            .map(|v| {
                let escaped = v.arg_name.replace('~', "~0").replace('/', "~1");
                format!("/{escaped}")
            })
            .collect()
    }
}

/// Thread-safe, hot-reloadable 2-stage deterministic policy engine.
pub struct PolicyEngine {
    authorizer: Authorizer,
    snapshot: ArcSwap<PolicySnapshot>,
}

impl PolicyEngine {
    /// Builds a validated `PolicyEngine` from `GatewayConfig` and raw Cedar policy text.
    pub fn from_config_and_cedar(
        config: &GatewayConfig,
        cedar_source: &str,
    ) -> Result<Self, KeelwayError> {
        let snap = compile_snapshot(config, cedar_source)?;
        Ok(Self {
            authorizer: Authorizer::new(),
            snapshot: ArcSwap::from_pointee(snap),
        })
    }

    /// Loads policy files referenced by `config.policy_files` relative to `base_dir`.
    pub fn from_config_files(
        config: &GatewayConfig,
        base_dir: &Path,
    ) -> Result<Self, KeelwayError> {
        let cedar_source = read_policy_files(config, base_dir)?;
        Self::from_config_and_cedar(config, &cedar_source)
    }

    /// Atomically validates and swaps in a new policy snapshot; on error, keeps the old snapshot live.
    pub fn hot_reload_from_cedar(
        &self,
        config: &GatewayConfig,
        cedar_source: &str,
    ) -> Result<String, KeelwayError> {
        let next = compile_snapshot(config, cedar_source)?;
        let digest = next.policy_digest.clone();
        self.snapshot.store(Arc::new(next));
        Ok(digest)
    }

    pub fn hot_reload_from_files(
        &self,
        config: &GatewayConfig,
        base_dir: &Path,
    ) -> Result<String, KeelwayError> {
        let cedar_source = read_policy_files(config, base_dir)?;
        self.hot_reload_from_cedar(config, &cedar_source)
    }

    pub fn current_digest(&self) -> String {
        self.snapshot.load().policy_digest.clone()
    }

    pub fn inspected_arg_pointers(&self, server: &str, tool: &str) -> Vec<String> {
        self.snapshot.load().inspected_arg_pointers(server, tool)
    }

    /// Evaluates whether `principal` is permitted to discover `(server, tool)` in `tools/list`.
    pub fn can_list_tool(&self, principal: &Principal, server: &str, tool: &str) -> bool {
        let snap = self.snapshot.load();
        let Ok(req) = build_cedar_request(
            principal,
            "list_tool",
            server,
            tool,
            &BTreeMap::new(),
            &snap.validators,
            &snap.schema,
        ) else {
            return false;
        };
        let resp = self
            .authorizer
            .is_authorized(&req, &snap.policy_set, &snap.entities);
        matches!(resp.decision(), CedarDecision::Allow)
    }

    /// Evaluates a `tools/call` invocation through Stage 1 (5 typed validators) and Stage 2 (Cedar).
    pub fn evaluate(
        &self,
        principal: &Principal,
        tool_call: &ToolCall,
    ) -> Result<PolicyDecision, KeelwayError> {
        let snap = self.snapshot.load();

        // Stage 1: Evaluate typed argument validators bound to (server, tool)
        let mut outcomes = Vec::new();
        let mut validator_bools: BTreeMap<String, bool> = BTreeMap::new();

        for v in &snap.validators {
            if v.server == tool_call.server && v.tool == tool_call.tool {
                let arg_val = tool_call.arguments.get(&v.arg_name);
                let outcome = evaluate_validator(v, arg_val);
                validator_bools.insert(v.id.clone(), outcome.passed);
                outcomes.push(outcome);
            } else {
                // Non-matching validators default to false in context so policies cannot spoof them.
                validator_bools.insert(v.id.clone(), false);
            }
        }

        // Stage 2: Pure-Rust Cedar evaluation (default-deny, forbid-overrides-permit)
        let req = build_cedar_request(
            principal,
            "call_tool",
            &tool_call.server,
            &tool_call.tool,
            &validator_bools,
            &snap.validators,
            &snap.schema,
        )?;
        let resp = self
            .authorizer
            .is_authorized(&req, &snap.policy_set, &snap.entities);

        let decision = match resp.decision() {
            CedarDecision::Allow => Decision::Allow,
            CedarDecision::Deny => Decision::Deny,
        };

        let rule_ids: Vec<String> = resp
            .diagnostics()
            .reason()
            .map(|pid| pid.to_string())
            .collect();

        let failed_validators: Vec<String> = outcomes
            .iter()
            .filter(|o| !o.passed)
            .map(|o| format!("{}({})={}", o.validator_id, o.arg_name, o.reason))
            .collect();

        let reason = match decision {
            Decision::Allow => {
                if rule_ids.is_empty() {
                    "allowed by policy".to_owned()
                } else {
                    format!("allowed by rules: {}", rule_ids.join(", "))
                }
            }
            Decision::Deny => {
                let mut parts = Vec::new();
                if rule_ids.is_empty() {
                    parts.push("default-deny: no matching permit rule".to_owned());
                } else {
                    parts.push(format!("explicit forbid by rules: {}", rule_ids.join(", ")));
                }
                if !failed_validators.is_empty() {
                    parts.push(format!(
                        "failed validators: {}",
                        failed_validators.join("; ")
                    ));
                }
                parts.join(" | ")
            }
        };

        Ok(PolicyDecision {
            decision,
            explanation: Explanation {
                decision,
                rule_ids,
                validator_outcomes: outcomes,
                reason,
                policy_digest: snap.policy_digest.clone(),
            },
        })
    }
}

fn read_policy_files(config: &GatewayConfig, base_dir: &Path) -> Result<String, KeelwayError> {
    if config.policy_files.is_empty() {
        return Ok(String::new());
    }
    let mut combined = String::new();
    for rel in &config.policy_files {
        let full = if rel.is_absolute() {
            rel.clone()
        } else {
            base_dir.join(rel)
        };
        let content = fs::read_to_string(&full).map_err(|e| {
            KeelwayError::Policy(format!(
                "failed to read policy file '{}': {e}",
                full.display()
            ))
        })?;
        combined.push_str(&content);
        combined.push('\n');
    }
    Ok(combined)
}

fn compile_snapshot(
    config: &GatewayConfig,
    cedar_source: &str,
) -> Result<PolicySnapshot, KeelwayError> {
    let validators = compile_validators(&config.validators)?;
    let schema = build_in_memory_schema(&validators)?;
    let policy_set = PolicySet::from_str(cedar_source)
        .map_err(|e| KeelwayError::Policy(format!("cedar syntax error: {e}")))?;

    // Validate policies against auto-generated schema (fails closed on typos/type errors)
    let validator = Validator::new(schema.clone());
    let validation = validator.validate(&policy_set, ValidationMode::Strict);
    if !validation.validation_passed() {
        let errs: Vec<String> = validation
            .validation_errors()
            .map(|e| e.to_string())
            .collect();
        return Err(KeelwayError::Policy(format!(
            "cedar schema validation failed: {}",
            errs.join("; ")
        )));
    }

    let entities = build_static_entities(config, &schema)?;
    let mut hasher = Sha256::new();
    hasher.update(cedar_source.as_bytes());
    let policy_digest = hex::encode(hasher.finalize());

    Ok(PolicySnapshot {
        policy_set,
        schema,
        entities,
        validators,
        policy_digest,
    })
}

fn compile_validators(
    bindings: &[ValidatorBinding],
) -> Result<Vec<CompiledValidator>, KeelwayError> {
    let mut seen_ids = HashSet::new();
    let mut out = Vec::with_capacity(bindings.len());
    for b in bindings {
        if b.id.is_empty() || !b.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(KeelwayError::Policy(format!(
                "invalid validator id '{}': must match ^[a-zA-Z0-9_]+$",
                b.id
            )));
        }
        if !seen_ids.insert(b.id.clone()) {
            return Err(KeelwayError::Policy(format!(
                "duplicate validator id '{}'",
                b.id
            )));
        }
        let kind = match &b.kind {
            ValidatorKind::PathWithin { root } => CompiledValidatorKind::PathWithin {
                root_norm: lexical_normalize_path(root),
            },
            ValidatorKind::Glob { pattern } => {
                let matcher = Glob::new(pattern)
                    .map_err(|e| {
                        KeelwayError::Policy(format!("invalid glob '{pattern}' in '{}': {e}", b.id))
                    })?
                    .compile_matcher();
                CompiledValidatorKind::Glob {
                    matcher,
                    raw: pattern.clone(),
                }
            }
            ValidatorKind::Regex { pattern } => {
                let regex = Regex::new(pattern).map_err(|e| {
                    KeelwayError::Policy(format!("invalid regex '{pattern}' in '{}': {e}", b.id))
                })?;
                CompiledValidatorKind::Regex {
                    regex,
                    raw: pattern.clone(),
                }
            }
            ValidatorKind::SqlReadonly => CompiledValidatorKind::SqlReadonly,
            ValidatorKind::RepoAllowlist { repos } => CompiledValidatorKind::RepoAllowlist {
                repos_lower: repos
                    .iter()
                    .map(|r| r.trim().to_ascii_lowercase())
                    .collect(),
            },
        };
        out.push(CompiledValidator {
            id: b.id.clone(),
            server: b.server.clone(),
            tool: b.tool.clone(),
            arg_name: b.arg_name.clone(),
            kind,
        });
    }
    Ok(out)
}

/// Auto-generates Cedar schema in-memory from `keelway.yaml` validator bindings (zero hand-synced schema drift).
fn build_in_memory_schema(validators: &[CompiledValidator]) -> Result<Schema, KeelwayError> {
    let mut arg_check_fields = String::new();
    for v in validators {
        arg_check_fields.push_str(&format!("        {}: Bool,\n", v.id));
    }
    let schema_src = format!(
        r#"
entity Role;
entity Agent in [Role] {{
    org_id: String,
    agent_id: String,
}};
entity Tool {{
    server: String,
    name: String,
}};

action "list_tool" appliesTo {{
    principal: [Agent],
    resource: [Tool],
}};

action "call_tool" appliesTo {{
    principal: [Agent],
    resource: [Tool],
    context: {{
        arg_checks: {{
{arg_check_fields}        }},
    }},
}};
"#
    );
    let (schema, _warnings) = Schema::from_cedarschema_str(&schema_src).map_err(|e| {
        KeelwayError::Policy(format!("failed to compile in-memory cedar schema: {e}"))
    })?;
    Ok(schema)
}

/// Pre-builds static Cedar `Entities` (Agents, Roles, Tools) cached inside `PolicySnapshot`.
fn build_static_entities(
    config: &GatewayConfig,
    schema: &Schema,
) -> Result<Entities, KeelwayError> {
    let mut entities: Vec<Entity> = Vec::new();
    let mut role_set: HashSet<String> = HashSet::new();

    for p in &config.principals {
        for r in &p.roles {
            role_set.insert(r.clone());
        }
    }

    let role_type = EntityTypeName::from_str("Role")
        .map_err(|e| KeelwayError::Policy(format!("entity type Role error: {e}")))?;
    let agent_type = EntityTypeName::from_str("Agent")
        .map_err(|e| KeelwayError::Policy(format!("entity type Agent error: {e}")))?;
    let tool_type = EntityTypeName::from_str("Tool")
        .map_err(|e| KeelwayError::Policy(format!("entity type Tool error: {e}")))?;

    for role in role_set {
        let uid = EntityUid::from_type_name_and_id(role_type.clone(), EntityId::new(role));
        let ent = Entity::new(uid, HashMap::new(), HashSet::new())
            .map_err(|e| KeelwayError::Policy(format!("role entity error: {e}")))?;
        entities.push(ent);
    }

    for p in &config.principals {
        let canonical = format!("{}/{}", p.org_id, p.agent_id);
        let uid = EntityUid::from_type_name_and_id(agent_type.clone(), EntityId::new(canonical));
        let mut attrs = HashMap::new();
        attrs.insert(
            "org_id".to_owned(),
            RestrictedExpression::new_string(p.org_id.clone()),
        );
        attrs.insert(
            "agent_id".to_owned(),
            RestrictedExpression::new_string(p.agent_id.clone()),
        );
        let parents: HashSet<EntityUid> = p
            .roles
            .iter()
            .map(|r| EntityUid::from_type_name_and_id(role_type.clone(), EntityId::new(r.clone())))
            .collect();
        let ent = Entity::new(uid, attrs, parents)
            .map_err(|e| KeelwayError::Policy(format!("agent entity error: {e}")))?;
        entities.push(ent);
    }

    let mut seen_tools: HashSet<String> = HashSet::new();
    for s in &config.servers {
        for t in &s.tools {
            let tool_id = format!("{}/{t}", s.alias);
            if seen_tools.insert(tool_id.clone()) {
                let uid =
                    EntityUid::from_type_name_and_id(tool_type.clone(), EntityId::new(tool_id));
                let mut attrs = HashMap::new();
                attrs.insert(
                    "server".to_owned(),
                    RestrictedExpression::new_string(s.alias.clone()),
                );
                attrs.insert(
                    "name".to_owned(),
                    RestrictedExpression::new_string(t.clone()),
                );
                let ent = Entity::new(uid, attrs, HashSet::new())
                    .map_err(|e| KeelwayError::Policy(format!("tool entity error: {e}")))?;
                entities.push(ent);
            }
        }
    }
    // Also add any tools referenced by validators even if not listed in server.tools
    for v in &config.validators {
        let tool_id = format!("{}/{}", v.server, v.tool);
        if seen_tools.insert(tool_id.clone()) {
            let uid = EntityUid::from_type_name_and_id(tool_type.clone(), EntityId::new(tool_id));
            let mut attrs = HashMap::new();
            attrs.insert(
                "server".to_owned(),
                RestrictedExpression::new_string(v.server.clone()),
            );
            attrs.insert(
                "name".to_owned(),
                RestrictedExpression::new_string(v.tool.clone()),
            );
            let ent = Entity::new(uid, attrs, HashSet::new())
                .map_err(|e| KeelwayError::Policy(format!("tool entity error: {e}")))?;
            entities.push(ent);
        }
    }

    Entities::from_entities(entities, Some(schema))
        .map_err(|e| KeelwayError::Policy(format!("failed to build cedar entities: {e}")))
}

fn build_cedar_request(
    principal: &Principal,
    action_name: &str,
    server: &str,
    tool: &str,
    validator_bools: &BTreeMap<String, bool>,
    validators: &[CompiledValidator],
    schema: &Schema,
) -> Result<Request, KeelwayError> {
    let agent_type = EntityTypeName::from_str("Agent")
        .map_err(|e| KeelwayError::Policy(format!("entity type Agent error: {e}")))?;
    let action_type = EntityTypeName::from_str("Action")
        .map_err(|e| KeelwayError::Policy(format!("entity type Action error: {e}")))?;
    let tool_type = EntityTypeName::from_str("Tool")
        .map_err(|e| KeelwayError::Policy(format!("entity type Tool error: {e}")))?;

    // Infallible EntityUid construction (no format!().parse().unwrap())
    let principal_uid =
        EntityUid::from_type_name_and_id(agent_type, EntityId::new(principal.canonical_id()));
    let action_uid = EntityUid::from_type_name_and_id(action_type, EntityId::new(action_name));
    let resource_uid =
        EntityUid::from_type_name_and_id(tool_type, EntityId::new(format!("{server}/{tool}")));

    let context = if action_name == "call_tool" {
        let mut checks_map = serde_json::Map::new();
        for v in validators {
            let val = validator_bools.get(&v.id).copied().unwrap_or(false);
            checks_map.insert(v.id.clone(), Value::Bool(val));
        }
        let ctx_json = serde_json::json!({ "arg_checks": Value::Object(checks_map) });
        Context::from_json_value(ctx_json, Some((schema, &action_uid)))
            .map_err(|e| KeelwayError::Policy(format!("cedar context error: {e}")))?
    } else {
        Context::empty()
    };

    Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        context,
        Some(schema),
    )
    .map_err(|e| KeelwayError::Policy(format!("cedar request error: {e}")))
}

fn evaluate_validator(v: &CompiledValidator, arg_val: Option<&Value>) -> ValidatorOutcome {
    let Some(raw_str) = arg_val.and_then(Value::as_str) else {
        return ValidatorOutcome {
            validator_id: v.id.clone(),
            arg_name: v.arg_name.clone(),
            passed: false,
            reason: format!("argument '{}' missing or not a string", v.arg_name),
        };
    };

    match &v.kind {
        CompiledValidatorKind::PathWithin { root_norm } => {
            let target_norm = lexical_normalize_path(raw_str);
            let within = if root_norm == "/" {
                target_norm.starts_with('/')
            } else {
                target_norm == *root_norm || target_norm.starts_with(&format!("{root_norm}/"))
            };
            ValidatorOutcome {
                validator_id: v.id.clone(),
                arg_name: v.arg_name.clone(),
                passed: within,
                reason: if within {
                    format!("path '{target_norm}' is within '{root_norm}'")
                } else {
                    format!("path '{target_norm}' escapes root '{root_norm}'")
                },
            }
        }
        CompiledValidatorKind::Glob { matcher, raw } => {
            let ok = matcher.is_match(raw_str);
            ValidatorOutcome {
                validator_id: v.id.clone(),
                arg_name: v.arg_name.clone(),
                passed: ok,
                reason: if ok {
                    format!("matched glob '{raw}'")
                } else {
                    format!("did not match glob '{raw}'")
                },
            }
        }
        CompiledValidatorKind::Regex { regex, raw } => {
            let ok = regex.is_match(raw_str);
            ValidatorOutcome {
                validator_id: v.id.clone(),
                arg_name: v.arg_name.clone(),
                passed: ok,
                reason: if ok {
                    format!("matched regex '{raw}'")
                } else {
                    format!("did not match regex '{raw}'")
                },
            }
        }
        CompiledValidatorKind::SqlReadonly => {
            let (ok, msg) = check_sql_readonly(raw_str);
            ValidatorOutcome {
                validator_id: v.id.clone(),
                arg_name: v.arg_name.clone(),
                passed: ok,
                reason: msg,
            }
        }
        CompiledValidatorKind::RepoAllowlist { repos_lower } => {
            let normalized = raw_str.trim().to_ascii_lowercase();
            let ok = repos_lower.contains(&normalized);
            ValidatorOutcome {
                validator_id: v.id.clone(),
                arg_name: v.arg_name.clone(),
                passed: ok,
                reason: if ok {
                    format!("repo '{raw_str}' is in allowlist")
                } else {
                    format!("repo '{raw_str}' is outside permitted scope")
                },
            }
        }
    }
}

/// Pure lexical path normalization (resolves `.` and `..`, normalizes separators)
/// without touching the host filesystem so offline replay is 100% deterministic.
pub fn lexical_normalize_path(input: &str) -> String {
    let unified = input.replace('\\', "/");
    let is_abs = unified.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    for comp in unified.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                if let Some(last) = stack.last() {
                    if *last != ".." {
                        stack.pop();
                    } else if !is_abs {
                        stack.push("..");
                    }
                } else if !is_abs {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    if is_abs {
        format!("/{}", stack.join("/"))
    } else if stack.is_empty() {
        ".".to_owned()
    } else {
        stack.join("/")
    }
}

/// AST-based read-only SQL check using `sqlparser`.
/// Requires strictly a single statement whose root is `Statement::Query`
/// with zero data-modifying CTEs (`INSERT`/`UPDATE`/`DELETE`/`MERGE`).
pub fn check_sql_readonly(sql: &str) -> (bool, String) {
    let dialect = GenericDialect {};
    let statements = match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) => stmts,
        Err(e) => return (false, format!("SQL parse error (fail-closed): {e}")),
    };
    if statements.len() != 1 {
        return (
            false,
            format!(
                "expected exactly 1 SQL statement, found {}",
                statements.len()
            ),
        );
    }
    let Some(stmt) = statements.first() else {
        return (false, "empty SQL input".to_owned());
    };
    match stmt {
        Statement::Query(query) => {
            if !query_is_strictly_readonly(query) {
                return (
                    false,
                    "SQL query contains data-modifying CTE or non-readonly clause".to_owned(),
                );
            }
            (true, "single read-only SQL query".to_owned())
        }
        other => (
            false,
            format!(
                "non-readonly SQL statement rejected: {:?}",
                std::mem::discriminant(other)
            ),
        ),
    }
}

fn query_is_strictly_readonly(query: &sqlparser::ast::Query) -> bool {
    if !query.locks.is_empty() {
        return false;
    }
    if let Some(with) = &query.with {
        for cte in &with.cte_tables {
            if !query_is_strictly_readonly(&cte.query) {
                return false;
            }
        }
    }
    set_expr_is_readonly(&query.body)
}

fn set_expr_is_readonly(body: &SetExpr) -> bool {
    match body {
        SetExpr::Select(select) => select.into.is_none(),
        SetExpr::Query(sub) => query_is_strictly_readonly(sub),
        SetExpr::SetOperation { left, right, .. } => {
            set_expr_is_readonly(left) && set_expr_is_readonly(right)
        }
        SetExpr::Values(_) | SetExpr::Table(_) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PrincipalConfig, ServerConfig, UpstreamTransport};
    use serde_json::json;
    use std::path::PathBuf;

    fn sample_config() -> GatewayConfig {
        GatewayConfig {
            bind_addr: "127.0.0.1:8080".to_owned(),
            tape_path: PathBuf::from("keelway-tape.jsonl"),
            policy_files: vec![],
            budgets: vec![],
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
                    transport: UpstreamTransport::Stdio {
                        command: "echo".to_owned(),
                        args: vec![],
                        env: BTreeMap::new(),
                    },
                    timeout_ms: 30_000,
                    tools: vec!["read_repository".to_owned(), "delete_repository".to_owned()],
                },
                ServerConfig {
                    alias: "database".to_owned(),
                    transport: UpstreamTransport::Stdio {
                        command: "echo".to_owned(),
                        args: vec![],
                        env: BTreeMap::new(),
                    },
                    timeout_ms: 30_000,
                    tools: vec!["query_readonly".to_owned()],
                },
                ServerConfig {
                    alias: "filesystem".to_owned(),
                    transport: UpstreamTransport::Stdio {
                        command: "echo".to_owned(),
                        args: vec![],
                        env: BTreeMap::new(),
                    },
                    timeout_ms: 30_000,
                    tools: vec!["read_file".to_owned()],
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
                ValidatorBinding {
                    id: "workspace_path".to_owned(),
                    server: "filesystem".to_owned(),
                    tool: "read_file".to_owned(),
                    arg_name: "path".to_owned(),
                    kind: ValidatorKind::PathWithin {
                        root: "/workspace".to_owned(),
                    },
                },
            ],
        }
    }

    const SAMPLE_CEDAR: &str = r#"
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
"#;

    #[test]
    fn cedar_two_stage_enforcement_and_forbid_precedence() -> Result<(), KeelwayError> {
        let cfg = sample_config();
        let engine = PolicyEngine::from_config_and_cedar(&cfg, SAMPLE_CEDAR)?;
        let dev = cfg.principals[0].to_principal();

        // Allowed repo
        let ok = engine.evaluate(
            &dev,
            &ToolCall {
                server: "github".to_owned(),
                tool: "read_repository".to_owned(),
                arguments: json!({ "repo": "sorvex/keelway" }),
            },
        )?;
        assert_eq!(ok.decision, Decision::Allow);

        // Unauthorized repo
        let bad_repo = engine.evaluate(
            &dev,
            &ToolCall {
                server: "github".to_owned(),
                tool: "read_repository".to_owned(),
                arguments: json!({ "repo": "other/secret-repo" }),
            },
        )?;
        assert_eq!(bad_repo.decision, Decision::Deny);
        assert!(bad_repo.explanation.reason.contains("allowed_repo"));

        // Explicit forbid
        let del = engine.evaluate(
            &dev,
            &ToolCall {
                server: "github".to_owned(),
                tool: "delete_repository".to_owned(),
                arguments: json!({ "repo": "sorvex/keelway" }),
            },
        )?;
        assert_eq!(del.decision, Decision::Deny);
        assert!(del.explanation.reason.contains("forbid"));

        // tools/list filtering
        assert!(engine.can_list_tool(&dev, "github", "read_repository"));
        assert!(!engine.can_list_tool(&dev, "github", "delete_repository"));
        Ok(())
    }

    #[test]
    fn sql_readonly_blocks_comments_write_ctes_and_multistatement() {
        assert!(check_sql_readonly("SELECT id, name FROM users WHERE active = true").0);
        assert!(!check_sql_readonly("/* SELECT 1 */ DROP TABLE users").0);
        assert!(!check_sql_readonly("SELECT 1; DROP TABLE users;").0);
        assert!(!check_sql_readonly("WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d").0);
    }

    #[test]
    fn path_within_lexical_blocks_traversal() -> Result<(), KeelwayError> {
        let cfg = sample_config();
        let engine = PolicyEngine::from_config_and_cedar(&cfg, SAMPLE_CEDAR)?;
        let dev = cfg.principals[0].to_principal();

        let good = engine.evaluate(
            &dev,
            &ToolCall {
                server: "filesystem".to_owned(),
                tool: "read_file".to_owned(),
                arguments: json!({ "path": "/workspace/src/../README.md" }),
            },
        )?;
        assert_eq!(good.decision, Decision::Allow);

        let escape = engine.evaluate(
            &dev,
            &ToolCall {
                server: "filesystem".to_owned(),
                tool: "read_file".to_owned(),
                arguments: json!({ "path": "/workspace/../../etc/passwd" }),
            },
        )?;
        assert_eq!(escape.decision, Decision::Deny);
        Ok(())
    }

    #[test]
    fn invalid_cedar_hot_reload_keeps_last_good_snapshot() -> Result<(), KeelwayError> {
        let cfg = sample_config();
        let engine = PolicyEngine::from_config_and_cedar(&cfg, SAMPLE_CEDAR)?;
        let before = engine.current_digest();

        // Unknown validator field must fail Cedar schema validation
        let bad_cedar = r#"
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"github/read_repository"
) when {
    context.arg_checks.nonexistent_validator
};
"#;
        assert!(engine.hot_reload_from_cedar(&cfg, bad_cedar).is_err());
        assert_eq!(engine.current_digest(), before);
        Ok(())
    }
}
