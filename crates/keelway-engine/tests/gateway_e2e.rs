use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use keelway_engine::core::{Decision, GatewayConfig, KeelwayError, PromptConfig, ResourceConfig};
use keelway_engine::{
    ApprovalRule, BudgetRule, ExecutionOutcome, GatewayEngine, PrincipalConfig, Receipt,
    ReceiptState, ReplayVerdict, SecretProvider, ServerConfig, UpstreamTransport, ValidatorBinding,
    ValidatorKind,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::tempdir;
use tokio::net::TcpListener;

struct MapSecrets(HashMap<String, String>);

impl SecretProvider for MapSecrets {
    fn resolve(&self, reference: &str) -> Result<String, KeelwayError> {
        if let Some(val) = self.0.get(reference) {
            return Ok(val.clone());
        }
        Ok(reference.to_owned())
    }
}

async fn spawn_mock_mcp_server(
    expected_secret_header: Option<String>,
    calls: Arc<AtomicUsize>,
) -> Result<String, KeelwayError> {
    let app = Router::new()
        .route(
            "/mcp",
            post(
                move |State((secret, counter)): State<(Option<String>, Arc<AtomicUsize>)>,
                      headers: HeaderMap,
                      Json(body): Json<Value>| async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let got_header = headers
                        .get("x-api-key")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let leaked_text = if let Some(ref s) = secret {
                        format!("ok header_matched={} leaked={s}", got_header == *s)
                    } else {
                        "ok".to_owned()
                    };
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": body.get("id").cloned().unwrap_or(Value::Null),
                        "result": {
                            "content": [{ "type": "text", "text": leaked_text }]
                        }
                    }))
                },
            ),
        )
        .with_state((expected_secret_header, calls));

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(format!("http://{addr}/mcp"))
}

const CEDAR_V1: &str = r#"
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
"#;

#[tokio::test]
async fn end_to_end_three_server_federation_secret_isolation_and_replay() -> Result<(), KeelwayError>
{
    let github_secret = "ghp_e2e_super_secret_token_99999"; // gitleaks:allow
    let github_calls = Arc::new(AtomicUsize::new(0));
    let db_calls = Arc::new(AtomicUsize::new(0));
    let fs_calls = Arc::new(AtomicUsize::new(0));

    let github_url =
        spawn_mock_mcp_server(Some(github_secret.to_owned()), github_calls.clone()).await?;
    let db_url = spawn_mock_mcp_server(None, db_calls.clone()).await?;
    let fs_url = spawn_mock_mcp_server(None, fs_calls.clone()).await?;

    let mut gh_headers = BTreeMap::new();
    gh_headers.insert("x-api-key".to_owned(), "secret://env/GH_TOKEN".to_owned());

    let dir = tempdir()?;
    let tape_path = dir.path().join("keelway-tape.jsonl");

    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: tape_path.clone(),
        policy_files: vec![],
        budgets: vec![],
        approval_required: vec![],
        principals: vec![
            PrincipalConfig {
                org_id: "acme".to_owned(),
                agent_id: "coding-agent".to_owned(),
                roles: vec!["developer".to_owned()],
                token_ref: Some("tok-coding".to_owned()),
            },
            PrincipalConfig {
                org_id: "acme".to_owned(),
                agent_id: "research-agent".to_owned(),
                roles: vec!["researcher".to_owned()],
                token_ref: Some("tok-research".to_owned()),
            },
        ],
        servers: vec![
            ServerConfig {
                alias: "github".to_owned(),
                timeout_ms: 5_000,
                tools: vec!["read_repository".to_owned(), "delete_repository".to_owned()],
                resources: vec![],
                prompts: vec![],
                transport: UpstreamTransport::StreamableHttp {
                    url: github_url,
                    headers: gh_headers,
                },
            },
            ServerConfig {
                alias: "database".to_owned(),
                timeout_ms: 5_000,
                tools: vec!["query_readonly".to_owned()],
                resources: vec![],
                prompts: vec![],
                transport: UpstreamTransport::StreamableHttp {
                    url: db_url,
                    headers: BTreeMap::new(),
                },
            },
            ServerConfig {
                alias: "filesystem".to_owned(),
                timeout_ms: 5_000,
                tools: vec!["read_file".to_owned()],
                resources: vec![],
                prompts: vec![],
                transport: UpstreamTransport::StreamableHttp {
                    url: fs_url,
                    headers: BTreeMap::new(),
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
        ..Default::default()
    };

    let mut secret_map = HashMap::new();
    secret_map.insert("secret://env/GH_TOKEN".to_owned(), github_secret.to_owned());
    let provider = MapSecrets(secret_map);

    let engine = GatewayEngine::from_in_memory(cfg.clone(), CEDAR_V1)?;
    let router = engine.build_test_http_router(tape_path.clone(), &provider)?;

    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let client = reqwest::Client::new();
    let gw_url = format!("http://{gw_addr}/mcp");

    // 1. Unauthenticated request -> HTTP 401 fail-closed
    let unauth = client
        .post(&gw_url)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(unauth.status(), reqwest::StatusCode::UNAUTHORIZED);

    // 2. Filtered tools/list for coding-agent (sees github__read_repository, NOT delete_repository)
    let list_resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-coding")
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    let tool_names: Vec<&str> = list_resp["result"]["tools"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|t| t["name"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(tool_names, vec!["github__read_repository"]);

    // 3. Allowed call -> upstream receives real secret header, but response is scrubbed
    let allow_resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-coding")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "github__read_repository", "arguments": { "repo": "sorvex/keelway" } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    let text = allow_resp["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(text.contains("header_matched=true"));
    assert!(!text.contains(github_secret));
    assert!(text.contains("[REDACTED]"));
    assert_eq!(github_calls.load(Ordering::SeqCst), 1);

    // 4. Prompt-injection destructive call -> BLOCKED at gateway, upstream NEVER invoked
    let deny_resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-coding")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "github__delete_repository", "arguments": { "repo": "sorvex/keelway" } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(deny_resp["error"]["code"], -32000);
    assert_eq!(github_calls.load(Ordering::SeqCst), 1);

    // 5. Call where agent unexpectedly puts secret inside validated argument -> recorded in redacted_fields
    let _ = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-coding")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": { "name": "github__read_repository", "arguments": { "repo": github_secret } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;

    // 6. Verify tape SHA-256 chain + zero secret bytes in tape file
    let raw_tape = std::fs::read_to_string(&tape_path)?;
    assert!(!raw_tape.contains(github_secret));
    let verified = GatewayEngine::verify_tape(&tape_path)?;
    assert!(verified.valid);
    assert_eq!(verified.count, 4); // unauth + allow + deny + secret-in-arg

    // 7. Offline replay against a tighter Cedar policy (forbidding all github calls)
    let tighter_cedar = r#"
forbid(principal, action == Action::"call_tool", resource);
"#;
    let tighter_engine = GatewayEngine::from_in_memory(
        GatewayConfig {
            tape_path: PathBuf::from("unused.jsonl"),
            ..cfg
        },
        tighter_cedar,
    )?;
    let replayed = tighter_engine.replay_tape(&tape_path)?;
    assert_eq!(replayed.len(), 4);
    // Receipt #2 (original ALLOW for github.read_repository) is now DENY -> changed = true
    assert_eq!(replayed[1].original_decision, Decision::Allow);
    assert_eq!(replayed[1].replayed_verdict, ReplayVerdict::Deny);
    assert!(replayed[1].changed);
    // Receipt #4 (secret in validated `repo` field) -> INDETERMINATE
    assert!(matches!(
        replayed[3].replayed_verdict,
        ReplayVerdict::Indeterminate { .. }
    ));

    Ok(())
}

const CEDAR_STDIO: &str = r#"
permit(
    principal in Role::"developer",
    action == Action::"list_tool",
    resource == Tool::"localstdio/echo_secret"
);
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"localstdio/echo_secret"
);
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"slowstdio/hang_tool"
);
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"crashstdio/crash_tool"
);
"#;

#[tokio::test]
async fn stdio_upstream_federation_injects_env_and_scrubs_stdout_and_stderr()
-> Result<(), KeelwayError> {
    let stdio_secret = "ghp_stdio_child_secret_token_88888"; // gitleaks:allow
    let dir = tempdir()?;
    let tape_path = dir.path().join("keelway-stdio-tape.jsonl");

    let mut stdio_env = BTreeMap::new();
    stdio_env.insert(
        "STDIO_SECRET".to_owned(),
        "secret://env/STDIO_SECRET".to_owned(),
    );

    let script = concat!(
        "read -r _line; ",
        "if [ -n \"$STDIO_SECRET\" ]; then injected=true; else injected=false; fi; ",
        "printf 'stderr_leak=%s\\n' \"$STDIO_SECRET\" >&2; ",
        "printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"stdio_ok env_injected=%s leaked=%s\"}]}}\\n' \"$injected\" \"$STDIO_SECRET\""
    );

    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: tape_path.clone(),
        policy_files: vec![],
        budgets: vec![],
        approval_required: vec![],
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "coding-agent".to_owned(),
            roles: vec!["developer".to_owned()],
            token_ref: Some("tok-stdio".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "localstdio".to_owned(),
            timeout_ms: 5_000,
            tools: vec!["echo_secret".to_owned()],
            resources: vec![],
            prompts: vec![],
            transport: UpstreamTransport::Stdio {
                command: "sh".to_owned(),
                args: vec!["-c".to_owned(), script.to_owned()],
                env: stdio_env,
            },
        }],
        validators: vec![],
        ..Default::default()
    };

    let mut secret_map = HashMap::new();
    secret_map.insert(
        "secret://env/STDIO_SECRET".to_owned(),
        stdio_secret.to_owned(),
    );
    let provider = MapSecrets(secret_map);

    let engine = GatewayEngine::from_in_memory(cfg, CEDAR_STDIO)?;
    let router = engine.build_test_http_router(tape_path.clone(), &provider)?;

    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let client = reqwest::Client::new();
    let gw_url = format!("http://{gw_addr}/mcp");

    let resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-stdio")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "localstdio__echo_secret",
                "arguments": { "ping": "pong" }
            }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;

    let text = resp["result"]["content"][0]["text"].as_str().unwrap_or("");
    assert!(text.contains("env_injected=true"));
    assert!(text.contains("leaked=[REDACTED]"));
    assert!(!text.contains(stdio_secret));

    let raw_tape = std::fs::read_to_string(&tape_path)?;
    assert!(!raw_tape.contains(stdio_secret));
    let mut receipts: Vec<Receipt> = Vec::new();
    let verified = GatewayEngine::inspect_tape(&tape_path, |r| {
        receipts.push(r);
        Ok(())
    })?;
    assert!(verified.valid);
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].decision, Decision::Allow);
    assert_eq!(receipts[0].state, ReceiptState::Sealed);
    assert_eq!(receipts[0].server, "localstdio");
    assert_eq!(receipts[0].tool, "echo_secret");

    Ok(())
}

#[tokio::test]
async fn stdio_upstream_timeout_returns_32002_and_records_timeout_receipt()
-> Result<(), KeelwayError> {
    let dir = tempdir()?;
    let tape_path = dir.path().join("keelway-timeout-tape.jsonl");

    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: tape_path.clone(),
        policy_files: vec![],
        budgets: vec![],
        approval_required: vec![],
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "coding-agent".to_owned(),
            roles: vec!["developer".to_owned()],
            token_ref: Some("tok-timeout".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "slowstdio".to_owned(),
            timeout_ms: 50,
            tools: vec!["hang_tool".to_owned()],
            resources: vec![],
            prompts: vec![],
            transport: UpstreamTransport::Stdio {
                command: "sh".to_owned(),
                args: vec!["-c".to_owned(), "sleep 2".to_owned()],
                env: BTreeMap::new(),
            },
        }],
        validators: vec![],
        ..Default::default()
    };

    let provider = MapSecrets(HashMap::new());
    let engine = GatewayEngine::from_in_memory(cfg, CEDAR_STDIO)?;
    let router = engine.build_test_http_router(tape_path.clone(), &provider)?;

    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let client = reqwest::Client::new();
    let gw_url = format!("http://{gw_addr}/mcp");

    let resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-timeout")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "slowstdio__hang_tool",
                "arguments": {}
            }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;

    assert_eq!(resp["error"]["code"], -32002);
    let err_msg = resp["error"]["message"].as_str().unwrap_or("");
    assert!(err_msg.contains("UpstreamTimeout"));

    let mut receipts: Vec<Receipt> = Vec::new();
    let verified = GatewayEngine::inspect_tape(&tape_path, |r| {
        receipts.push(r);
        Ok(())
    })?;
    assert!(verified.valid);
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].decision, Decision::Allow);
    assert_eq!(receipts[0].outcome, None);
    assert_eq!(receipts[1].decision, Decision::Allow);
    assert_eq!(receipts[1].outcome, Some(ExecutionOutcome::Timeout));

    Ok(())
}

#[tokio::test]
async fn stdio_upstream_crash_returns_32003_and_records_crashed_receipt() -> Result<(), KeelwayError>
{
    let dir = tempdir()?;
    let tape_path = dir.path().join("keelway-crash-tape.jsonl");

    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: tape_path.clone(),
        policy_files: vec![],
        budgets: vec![],
        approval_required: vec![],
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "coding-agent".to_owned(),
            roles: vec!["developer".to_owned()],
            token_ref: Some("tok-crash".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "crashstdio".to_owned(),
            timeout_ms: 5_000,
            tools: vec!["crash_tool".to_owned()],
            resources: vec![],
            prompts: vec![],
            transport: UpstreamTransport::Stdio {
                command: "sh".to_owned(),
                args: vec!["-c".to_owned(), "exit 1".to_owned()],
                env: BTreeMap::new(),
            },
        }],
        validators: vec![],
        ..Default::default()
    };

    let provider = MapSecrets(HashMap::new());
    let engine = GatewayEngine::from_in_memory(cfg, CEDAR_STDIO)?;
    let router = engine.build_test_http_router(tape_path.clone(), &provider)?;

    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let client = reqwest::Client::new();
    let gw_url = format!("http://{gw_addr}/mcp");

    let resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-crash")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "crashstdio__crash_tool",
                "arguments": {}
            }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;

    assert_eq!(resp["error"]["code"], -32003);
    let err_msg = resp["error"]["message"].as_str().unwrap_or("");
    assert!(err_msg.contains("UpstreamUnavailable"));

    let mut receipts: Vec<Receipt> = Vec::new();
    let verified = GatewayEngine::inspect_tape(&tape_path, |r| {
        receipts.push(r);
        Ok(())
    })?;
    assert!(verified.valid);
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].decision, Decision::Allow);
    assert_eq!(receipts[0].outcome, None);
    assert_eq!(receipts[1].decision, Decision::Allow);
    assert_eq!(receipts[1].outcome, Some(ExecutionOutcome::Crashed));

    Ok(())
}

#[tokio::test]
async fn live_http_gateway_hot_reloads_policy_without_downtime() -> Result<(), KeelwayError> {
    let calls = Arc::new(AtomicUsize::new(0));
    let mock_url = spawn_mock_mcp_server(None, calls.clone()).await?;

    let dir = tempdir()?;
    let policies_dir = dir.path().join("policies");
    std::fs::create_dir_all(&policies_dir)?;
    let policy_path = policies_dir.join("default.cedar");
    let config_path = dir.path().join("keelway.yaml");
    let tape_path = dir.path().join("keelway-hot-reload-tape.jsonl");

    let initial_cedar = r#"
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"github/read_repository"
);
"#;
    std::fs::write(&policy_path, initial_cedar)?;

    let yaml = format!(
        r#"bind_addr: "127.0.0.1:0"
tape_path: "{}"
policy_files:
  - "policies/default.cedar"
principals:
  - org_id: "acme"
    agent_id: "coding-agent"
    roles:
      - "developer"
    token_ref: "tok-hot-reload"
servers:
  - alias: "github"
    timeout_ms: 5000
    tools:
      - "read_repository"
    transport:
      type: "streamable_http"
      url: "{}"
"#,
        tape_path.display(),
        mock_url
    );
    std::fs::write(&config_path, yaml)?;

    let engine = GatewayEngine::from_config_file(&config_path)?;
    let provider = MapSecrets(HashMap::new());
    let router = engine.build_test_http_router(tape_path.clone(), &provider)?;

    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let client = reqwest::Client::new();
    let gw_url = format!("http://{gw_addr}/mcp");

    // 1. Initial policy -> ALLOW
    let allow_resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-hot-reload")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "github__read_repository", "arguments": { "repo": "sorvex/keelway" } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(allow_resp["result"]["content"][0]["text"], "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // 2. Invalid Cedar syntax -> hot_reload() returns Err, last-good snapshot stays live
    std::fs::write(&policy_path, "this is not valid cedar {{{;")?;
    assert!(engine.hot_reload().is_err());

    let still_allow_resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-hot-reload")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "github__read_repository", "arguments": { "repo": "sorvex/keelway" } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(still_allow_resp["result"]["content"][0]["text"], "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // 3. Valid tighter policy (forbid github/read_repository) -> hot_reload() succeeds and blocks immediately
    let tighter_cedar = r#"
forbid(
    principal,
    action == Action::"call_tool",
    resource == Tool::"github/read_repository"
);
"#;
    std::fs::write(&policy_path, tighter_cedar)?;
    assert!(engine.hot_reload().is_ok());

    let blocked_resp: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-hot-reload")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "github__read_repository", "arguments": { "repo": "sorvex/keelway" } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(blocked_resp["error"]["code"], -32000);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    Ok(())
}

#[tokio::test]
async fn execution_budget_blocks_excess_calls_with_32004_and_records_deny_receipt()
-> Result<(), KeelwayError> {
    let calls = Arc::new(AtomicUsize::new(0));
    let db_url = spawn_mock_mcp_server(None, calls.clone()).await?;
    let dir = tempdir()?;
    let tape_path = dir.path().join("keelway-tape.jsonl");

    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: tape_path.clone(),
        policy_files: vec![],
        approval_required: vec![],
        budgets: vec![BudgetRule {
            org_id: "acme".to_owned(),
            agent_id: "research-agent".to_owned(),
            server: "database".to_owned(),
            max_calls_per_minute: Some(2),
            max_concurrent_calls: None,
        }],
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "research-agent".to_owned(),
            roles: vec!["researcher".to_owned()],
            token_ref: Some("tok-budget".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "database".to_owned(),
            timeout_ms: 5_000,
            tools: vec!["query_readonly".to_owned()],
            resources: vec![],
            prompts: vec![],
            transport: UpstreamTransport::StreamableHttp {
                url: db_url,
                headers: BTreeMap::new(),
            },
        }],
        validators: vec![ValidatorBinding {
            id: "readonly_sql".to_owned(),
            server: "database".to_owned(),
            tool: "query_readonly".to_owned(),
            arg_name: "sql".to_owned(),
            kind: ValidatorKind::SqlReadonly,
        }],
        ..Default::default()
    };

    let budget_cedar = r#"
permit(
    principal in Role::"researcher",
    action == Action::"call_tool",
    resource == Tool::"database/query_readonly"
) when {
    context.arg_checks.readonly_sql
};
"#;
    let engine = GatewayEngine::from_in_memory(cfg, budget_cedar)?;
    let router = engine.build_test_http_router(tape_path.clone(), &MapSecrets(HashMap::new()))?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let client = reqwest::Client::new();
    let gw_url = format!("http://{gw_addr}/mcp");

    for id in 1..=2 {
        let resp: Value = client
            .post(&gw_url)
            .header("authorization", "Bearer tok-budget")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": "database__query_readonly", "arguments": { "sql": "SELECT 1" } }
            }))
            .send()
            .await
            .map_err(|e| KeelwayError::Mcp(e.to_string()))?
            .json()
            .await
            .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
        assert!(resp.get("result").is_some());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // 3rd call within 60s exceeds max_calls_per_minute=2 -> -32004 BudgetExceeded
    let limited: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-budget")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "database__query_readonly", "arguments": { "sql": "SELECT 1" } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(limited["error"]["code"], -32004);
    assert_eq!(limited["error"]["message"], "BudgetExceeded");
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    let verified = GatewayEngine::verify_tape(&tape_path)?;
    assert!(verified.valid);
    // 2 ALLOW receipts + 1 pre-budget ALLOW + 1 BudgetExceeded DENY receipt
    assert!(verified.count >= 3);
    Ok(())
}

#[tokio::test]
async fn stdio_child_env_clear_isolates_inherited_host_secrets() -> Result<(), KeelwayError> {
    let dir = tempdir()?;
    let tape_path = dir.path().join("keelway-tape.jsonl");

    // Child prints CARGO_PKG_NAME (always set in `cargo test` parent, must be empty after env_clear)
    // and EXPLICIT_VAR (must be present).
    let script = r#"IFS= read -r line; printf '{"jsonrpc":"2.0","id":1,"result":{"host_leak":"%s","explicit":"%s"}}\n' "${CARGO_PKG_NAME:-}" "${EXPLICIT_VAR:-}" "#;
    let mut env = BTreeMap::new();
    env.insert("EXPLICIT_VAR".to_owned(), "allowed_val".to_owned());

    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: tape_path.clone(),
        policy_files: vec![],
        budgets: vec![],
        approval_required: vec![],
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "coding-agent".to_owned(),
            roles: vec!["developer".to_owned()],
            token_ref: Some("tok-env".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "envstdio".to_owned(),
            timeout_ms: 5_000,
            tools: vec!["check_env".to_owned()],
            resources: vec![],
            prompts: vec![],
            transport: UpstreamTransport::Stdio {
                command: "sh".to_owned(),
                args: vec!["-c".to_owned(), script.to_owned()],
                env,
            },
        }],
        validators: vec![],
        ..Default::default()
    };

    let cedar = r#"
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"envstdio/check_env"
);
"#;

    let engine = GatewayEngine::from_in_memory(cfg, cedar)?;
    let router = engine.build_test_http_router(tape_path, &MapSecrets(HashMap::new()))?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    // Note: in Rust 2024 edition `std::env::set_var` is unsafe, so we check PATH (inherited safe baseline)
    // and ensure arbitrary parent vars like CARGO_PKG_NAME (always set by cargo test!) are NOT leaked.
    let client = reqwest::Client::new();
    let resp: Value = client
        .post(format!("http://{gw_addr}/mcp"))
        .header("authorization", "Bearer tok-env")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "envstdio__check_env", "arguments": {} }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;

    assert_eq!(resp["result"]["host_leak"], "");
    assert_eq!(resp["result"]["explicit"], "allowed_val");
    Ok(())
}

#[tokio::test]
async fn p10_human_gate_and_observability_endpoints_work_end_to_end() -> Result<(), KeelwayError> {
    let calls = Arc::new(AtomicUsize::new(0));
    let db_url = spawn_mock_mcp_server(None, calls.clone()).await?;
    let dir = tempdir()?;
    let tape_path = dir.path().join("keelway-tape.jsonl");

    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: tape_path.clone(),
        policy_files: vec![],
        budgets: vec![],
        approval_required: vec![ApprovalRule {
            org_id: "acme".to_owned(),
            agent_id: "research-agent".to_owned(),
            server: "database".to_owned(),
            tool: "query_readonly".to_owned(),
            timeout_ms: 5_000,
        }],
        principals: vec![
            PrincipalConfig {
                org_id: "acme".to_owned(),
                agent_id: "research-agent".to_owned(),
                roles: vec!["researcher".to_owned()],
                token_ref: Some("tok-p10".to_owned()),
            },
            PrincipalConfig {
                org_id: "acme".to_owned(),
                agent_id: "approver-human".to_owned(),
                roles: vec!["p10-approver".to_owned()],
                token_ref: Some("tok-approver".to_owned()),
            },
            PrincipalConfig {
                org_id: "other".to_owned(),
                agent_id: "other-approver".to_owned(),
                roles: vec!["p10-approver".to_owned()],
                token_ref: Some("tok-other-org".to_owned()),
            },
        ],
        servers: vec![ServerConfig {
            alias: "database".to_owned(),
            timeout_ms: 5_000,
            tools: vec!["query_readonly".to_owned()],
            resources: vec![],
            prompts: vec![],
            transport: UpstreamTransport::StreamableHttp {
                url: db_url,
                headers: BTreeMap::new(),
            },
        }],
        validators: vec![ValidatorBinding {
            id: "readonly_sql".to_owned(),
            server: "database".to_owned(),
            tool: "query_readonly".to_owned(),
            arg_name: "sql".to_owned(),
            kind: ValidatorKind::SqlReadonly,
        }],
        ..Default::default()
    };

    let p10_cedar = r#"
permit(
    principal in Role::"researcher",
    action == Action::"call_tool",
    resource == Tool::"database/query_readonly"
) when {
    context.arg_checks.readonly_sql
};
"#;
    let engine = GatewayEngine::from_in_memory(cfg, p10_cedar)?;
    let router = engine.build_test_http_router(tape_path.clone(), &MapSecrets(HashMap::new()))?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let client = reqwest::Client::new();
    let base = format!("http://{gw_addr}");

    // 1. /healthz returns 200 ok
    let hz = client
        .get(format!("{base}/healthz"))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(hz.status(), reqwest::StatusCode::OK);

    // 2. Launch a tool call that hits the P-10 gate; approve it asynchronously
    let client_call = client.clone();
    let mcp_url = format!("{base}/mcp");
    let call_task = tokio::spawn(async move {
        client_call
            .post(&mcp_url)
            .header("authorization", "Bearer tok-p10")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "database__query_readonly", "arguments": { "sql": "SELECT 42" } }
            }))
            .send()
            .await
    });

    // Non-approver agent cannot list /p10/pending (403 Forbidden)
    let forbidden_pend = client
        .get(format!("{base}/p10/pending"))
        .header("authorization", "Bearer tok-p10")
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(forbidden_pend.status(), reqwest::StatusCode::FORBIDDEN);

    // Poll /p10/pending as p10-approver until the gate appears
    let mut approval_id = None;
    for _ in 0..40 {
        let pend: Value = client
            .get(format!("{base}/p10/pending"))
            .header("authorization", "Bearer tok-approver")
            .send()
            .await
            .map_err(|e| KeelwayError::Mcp(e.to_string()))?
            .json()
            .await
            .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
        if let Some(first) = pend["pending"].as_array().and_then(|a| a.first()) {
            approval_id = first["approval_id"].as_str().map(str::to_owned);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let gate_id =
        approval_id.ok_or_else(|| KeelwayError::Mcp("P-10 gate never appeared".to_owned()))?;

    // Self-approval (no p10-approver role) and cross-tenant approval both fail with 403 Forbidden
    let self_resolve = client
        .post(format!("{base}/p10/resolve"))
        .header("authorization", "Bearer tok-p10")
        .json(&json!({ "approval_id": gate_id, "approved": true }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(self_resolve.status(), reqwest::StatusCode::FORBIDDEN);

    let cross_org_resolve = client
        .post(format!("{base}/p10/resolve"))
        .header("authorization", "Bearer tok-other-org")
        .json(&json!({ "approval_id": gate_id, "approved": true }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(cross_org_resolve.status(), reqwest::StatusCode::FORBIDDEN);

    let resolve_resp = client
        .post(format!("{base}/p10/resolve"))
        .header("authorization", "Bearer tok-approver")
        .json(&json!({ "approval_id": gate_id, "approved": true }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(resolve_resp.status(), reqwest::StatusCode::OK);

    let call_res: Value = call_task
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(call_res["result"]["content"][0]["text"], "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // 3. /metrics reflects p10_approved=1 and calls_allowed=1
    let metrics_text = client
        .get(format!("{base}/metrics"))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .text()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert!(metrics_text.contains("keelway_calls_total{outcome=\"p10_approved\"} 1"));

    // 4. Verify tape recorded AWAITING + SEALED receipts cleanly
    let verified = GatewayEngine::verify_tape(&tape_path)?;
    assert!(verified.valid);
    assert_eq!(verified.count, 2);
    Ok(())
}

#[tokio::test]
async fn payload_size_guardrails_block_oversized_requests_and_responses() -> Result<(), KeelwayError>
{
    let calls = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/mcp",
            post(
                move |State(counter): State<Arc<AtomicUsize>>, Json(body): Json<Value>| async move {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let mode = body["params"]["arguments"]["mode"]
                        .as_str()
                        .unwrap_or("small");
                    let text = if mode == "large" {
                        "x".repeat(256)
                    } else {
                        "ok".to_owned()
                    };
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": body.get("id").cloned().unwrap_or(Value::Null),
                        "result": {
                            "content": [{ "type": "text", "text": text }]
                        }
                    }))
                },
            ),
        )
        .with_state(calls.clone());

    let upstream_listener = TcpListener::bind("127.0.0.1:0").await?;
    let upstream_addr = upstream_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(upstream_listener, app).await;
    });
    let upstream_url = format!("http://{upstream_addr}/mcp");

    let dir = tempdir()?;
    let tape_path = dir.path().join("keelway-tape.jsonl");

    let cfg = GatewayConfig {
        bind_addr: "127.0.0.1:0".to_owned(),
        tape_path: tape_path.clone(),
        max_request_bytes: 64,
        max_response_bytes: 128,
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "coding-agent".to_owned(),
            roles: vec!["developer".to_owned()],
            token_ref: Some("tok-size".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "echo".to_owned(),
            transport: UpstreamTransport::StreamableHttp {
                url: upstream_url,
                headers: BTreeMap::new(),
            },
            timeout_ms: 5_000,
            tools: vec!["ping".to_owned()],
            resources: vec![],
            prompts: vec![],
        }],
        ..Default::default()
    };

    let cedar = r#"
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"echo/ping"
);
"#;
    let engine = GatewayEngine::from_in_memory(cfg, cedar)?;
    let router = engine.build_test_http_router(tape_path.clone(), &MapSecrets(HashMap::new()))?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let client = reqwest::Client::new();
    let gw_url = format!("http://{gw_addr}/mcp");

    // 1. Oversized request arguments (> 64 bytes) rejected with -32006 before reaching upstream
    let oversized_arg = "a".repeat(128);
    let req_too_large: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-size")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "echo__ping", "arguments": { "payload": oversized_arg } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(req_too_large["error"]["code"], -32006);
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // 2. Small request + small response succeeds
    let small_ok: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-size")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "echo__ping", "arguments": { "mode": "small" } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(small_ok["result"]["content"][0]["text"], "ok");
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    // 3. Small request + oversized upstream response (> 128 bytes) rejected with -32006
    let resp_too_large: Value = client
        .post(&gw_url)
        .header("authorization", "Bearer tok-size")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "echo__ping", "arguments": { "mode": "large" } }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(resp_too_large["error"]["code"], -32006);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    Ok(())
}

#[tokio::test]
async fn ed25519_signed_tape_and_traceparent_provenance_work_end_to_end() -> Result<(), KeelwayError>
{
    use keelway_engine::provenance::TapeSigner;

    let tmp = tempfile::tempdir()?;
    let tape_path = tmp.path().join("signed-e2e-tape.jsonl");
    let seed_hex = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff";
    let signer = TapeSigner::from_seed_str(seed_hex)?;
    let vk_hex = signer.verifying_key_hex();

    let seen_traceparent = Arc::new(tokio::sync::Mutex::new(None::<String>));
    let seen_clone = Arc::clone(&seen_traceparent);
    let upstream = Router::new().route(
        "/mcp",
        post(
            move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                let seen = Arc::clone(&seen_clone);
                async move {
                    let tp = headers
                        .get("traceparent")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned);
                    *seen.lock().await = tp;
                    let id = body.get("id").cloned().unwrap_or(Value::Null);
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "content": [{ "type": "text", "text": "signed-ok" }] }
                    }))
                }
            },
        ),
    );
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(up_listener, upstream).await;
    });

    let cfg = GatewayConfig {
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "signed-agent".to_owned(),
            roles: vec!["developer".to_owned()],
            token_ref: Some("tok-signed".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "echo".to_owned(),
            transport: UpstreamTransport::StreamableHttp {
                url: format!("http://{up_addr}/mcp"),
                headers: BTreeMap::new(),
            },
            timeout_ms: 5_000,
            tools: vec!["ping".to_owned()],
            resources: vec![],
            prompts: vec![],
        }],
        signing_key_ref: Some("secret://signing_seed".to_owned()),
        ..Default::default()
    };

    let cedar = r#"
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"echo/ping"
);
"#;
    let mut secrets = HashMap::new();
    secrets.insert("secret://signing_seed".to_owned(), seed_hex.to_owned());

    let engine = GatewayEngine::from_in_memory(cfg, cedar)?;
    let router = engine.build_test_http_router(tape_path.clone(), &MapSecrets(secrets))?;
    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
    let resp: Value = reqwest::Client::new()
        .post(format!("http://{gw_addr}/mcp"))
        .header("authorization", "Bearer tok-signed")
        .header("traceparent", format!("00-{trace_id}-00f067aa0ba902b7-01"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "echo__ping", "arguments": {} }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(resp["result"]["content"][0]["text"], "signed-ok");

    let forwarded_tp = seen_traceparent.lock().await.clone().unwrap_or_default();
    assert!(
        forwarded_tp.starts_with(&format!("00-{trace_id}-")),
        "expected forwarded traceparent with trace_id {trace_id}, got {forwarded_tp}"
    );

    let verified = GatewayEngine::verify_tape_with_key(&tape_path, Some(&vk_hex))?;
    assert_eq!(verified.count, 1);
    let mut recorded_trace_id = None;
    GatewayEngine::inspect_tape(&tape_path, |r| {
        recorded_trace_id = r
            .provenance
            .as_ref()
            .and_then(|p| p.get("trace_id"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        Ok(())
    })?;
    assert_eq!(recorded_trace_id.as_deref(), Some(trace_id));

    let wrong_vk = "aa".repeat(32);
    assert!(GatewayEngine::verify_tape_with_key(&tape_path, Some(&wrong_vk)).is_err());

    Ok(())
}

#[tokio::test]
async fn operator_console_ui_serves_html_with_security_headers() -> Result<(), KeelwayError> {
    let tmp = tempfile::tempdir()?;
    let tape_path = tmp.path().join("ui-tape.jsonl");
    let cfg = GatewayConfig::default();
    let engine = GatewayEngine::from_in_memory(cfg, "")?;
    let router = engine.build_test_http_router(tape_path, &MapSecrets(HashMap::new()))?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/ui"))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let headers = resp.headers().clone();
    assert_eq!(
        headers.get("x-frame-options").and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert!(
        headers
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.contains("default-src 'self'"))
    );
    let body = resp
        .text()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert!(body.contains("Keelway"));
    assert!(body.contains("/p10/pending"));

    Ok(())
}

#[tokio::test]
async fn mcp_lifecycle_and_resource_prompt_governance_work_end_to_end() -> Result<(), KeelwayError>
{
    let upstream_app = Router::new().route(
        "/mcp",
        post(|Json(body): Json<Value>| async move {
            let id = body.get("id").cloned().unwrap_or(Value::Null);
            let method = body.get("method").and_then(Value::as_str).unwrap_or("");
            match method {
                "resources/read" => {
                    let uri = body["params"]["uri"].as_str().unwrap_or("");
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "contents": [{
                                "uri": uri,
                                "mimeType": "text/plain",
                                "text": "doc-ok leak=sk-super-secret-resource"
                            }]
                        }
                    }))
                }
                "prompts/get" => {
                    let name = body["params"]["name"].as_str().unwrap_or("");
                    Json(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "description": format!("prompt {name}"),
                            "messages": [{
                                "role": "user",
                                "content": {
                                    "type": "text",
                                    "text": "hello secret=sk-super-secret-resource"
                                }
                            }]
                        }
                    }))
                }
                _ => Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": "unknown method" }
                })),
            }
        }),
    );

    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(up_listener, upstream_app).await;
    });

    let tmp = tempdir()?;
    let tape_path = tmp.path().join("lifecycle-tape.jsonl");
    let cfg = GatewayConfig {
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "agent-1".to_owned(),
            roles: vec!["developer".to_owned()],
            token_ref: Some("secret://agent_tok".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "docs".to_owned(),
            transport: UpstreamTransport::StreamableHttp {
                url: format!("http://{up_addr}/mcp"),
                headers: BTreeMap::from([(
                    "x-api-key".to_owned(),
                    "secret://upstream_secret".to_owned(),
                )]),
            },
            tools: vec!["ping".to_owned()],
            resources: vec![
                ResourceConfig {
                    uri: "docs://allowed.md".to_owned(),
                    name: Some("Allowed Doc".to_owned()),
                    description: Some("Permitted markdown document".to_owned()),
                    mime_type: Some("text/markdown".to_owned()),
                },
                ResourceConfig {
                    uri: "file:///shared/guide.md".to_owned(),
                    name: Some("Shared Guide".to_owned()),
                    description: Some("Permitted file URI document".to_owned()),
                    mime_type: Some("text/markdown".to_owned()),
                },
                ResourceConfig {
                    uri: "docs://forbidden.md".to_owned(),
                    name: Some("Forbidden Doc".to_owned()),
                    description: None,
                    mime_type: None,
                },
            ],
            prompts: vec![
                PromptConfig {
                    name: "summarize".to_owned(),
                    description: Some("Summarize a document".to_owned()),
                },
                PromptConfig {
                    name: "admin_reset".to_owned(),
                    description: Some("Restricted admin prompt".to_owned()),
                },
            ],
            timeout_ms: 5000,
        }],
        ..GatewayConfig::default()
    };

    let cedar = r#"
permit (
    principal in Role::"developer",
    action == Action::"read_resource",
    resource == Tool::"docs/docs://allowed.md"
);
permit (
    principal in Role::"developer",
    action == Action::"read_resource",
    resource == Tool::"docs/file:///shared/guide.md"
);
permit (
    principal in Role::"developer",
    action == Action::"get_prompt",
    resource == Tool::"docs/summarize"
);
"#;

    let mut secrets = HashMap::new();
    secrets.insert("secret://agent_tok".to_owned(), "tok-lifecycle".to_owned());
    secrets.insert(
        "secret://upstream_secret".to_owned(),
        "sk-super-secret-resource".to_owned(),
    );

    let engine = GatewayEngine::from_in_memory(cfg, cedar)?;
    let router = engine.build_test_http_router(tape_path.clone(), &MapSecrets(secrets))?;
    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let client = reqwest::Client::new();
    let url = format!("http://{gw_addr}/mcp");
    let trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";

    // 1. initialize advertises tools, resources, prompts capabilities
    let init_resp: Value = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert!(init_resp["result"]["capabilities"]["tools"].is_object());
    assert!(init_resp["result"]["capabilities"]["resources"].is_object());
    assert!(init_resp["result"]["capabilities"]["prompts"].is_object());

    // 2. ping returns {} and notifications/initialized (without id) returns 202 Accepted
    let ping_resp: Value = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(ping_resp["result"], json!({}));

    let notif_resp = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .json(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(notif_resp.status(), reqwest::StatusCode::ACCEPTED);
    assert!(
        notif_resp
            .text()
            .await
            .map_err(|e| KeelwayError::Mcp(e.to_string()))?
            .is_empty()
    );

    // 3. resources/list and prompts/list return only Cedar-permitted items
    let res_list: Value = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .json(&json!({ "jsonrpc": "2.0", "id": 4, "method": "resources/list" }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(
        res_list["result"]["resources"],
        json!([
            {
                "uri": "docs://allowed.md",
                "name": "Allowed Doc",
                "description": "Permitted markdown document",
                "mimeType": "text/markdown"
            },
            {
                "uri": "file:///shared/guide.md",
                "name": "Shared Guide",
                "description": "Permitted file URI document",
                "mimeType": "text/markdown"
            }
        ])
    );

    let prompt_list: Value = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .json(&json!({ "jsonrpc": "2.0", "id": 5, "method": "prompts/list" }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(
        prompt_list["result"]["prompts"],
        json!([{
            "name": "summarize",
            "description": "Summarize a document"
        }])
    );

    // 4. Default-deny on unpermitted resources/read
    let denied_read: Value = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .header("traceparent", format!("00-{trace_id}-00f067aa0ba902b7-01"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "resources/read",
            "params": { "uri": "docs://forbidden.md" }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(denied_read["error"]["code"], -32000);

    // 5. Permitted resources/read (via <server>://<path> URI) scrubs secrets
    let allowed_read: Value = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .header("traceparent", format!("00-{trace_id}-00f067aa0ba902b7-01"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/read",
            "params": { "uri": "docs://allowed.md" }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    let read_text = allowed_read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(read_text.contains("doc-ok"));
    assert!(!read_text.contains("sk-super-secret-resource"));
    assert!(read_text.contains("[REDACTED]"));

    // 5b. Discovered non-<server>:// resource URI routes unambiguously without params.server
    let discovered_uri = res_list["result"]["resources"][1]["uri"]
        .as_str()
        .ok_or_else(|| KeelwayError::Mcp("missing discovered resource uri".to_owned()))?;
    let discovered_read: Value = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .header("traceparent", format!("00-{trace_id}-00f067aa0ba902b7-01"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 70,
            "method": "resources/read",
            "params": { "uri": discovered_uri }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    let discovered_read_text = discovered_read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or("");
    assert!(discovered_read_text.contains("doc-ok"));
    assert!(!discovered_read_text.contains("sk-super-secret-resource"));
    assert!(discovered_read_text.contains("[REDACTED]"));

    // 6. Permitted prompts/get (discovered prompt name without params.server) scrubs secrets
    let discovered_prompt_name = prompt_list["result"]["prompts"][0]["name"]
        .as_str()
        .ok_or_else(|| KeelwayError::Mcp("missing discovered prompt name".to_owned()))?;
    let allowed_prompt: Value = client
        .post(&url)
        .header("authorization", "Bearer tok-lifecycle")
        .header("traceparent", format!("00-{trace_id}-00f067aa0ba902b7-01"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "prompts/get",
            "params": { "name": discovered_prompt_name }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    let prompt_text = allowed_prompt["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap_or("");
    assert!(prompt_text.contains("hello"));
    assert!(!prompt_text.contains("sk-super-secret-resource"));
    assert!(prompt_text.contains("[REDACTED]"));

    // 7. Verify audit tape receipts & trace_id provenance
    let verified = GatewayEngine::verify_tape_with_key(&tape_path, None)?;
    assert_eq!(verified.count, 4);
    let mut receipts = Vec::new();
    GatewayEngine::inspect_tape(&tape_path, |r| {
        receipts.push((
            r.server.clone(),
            r.tool.clone(),
            r.decision,
            r.state,
            r.provenance
                .as_ref()
                .and_then(|p| p.get("trace_id"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            r.provenance
                .as_ref()
                .and_then(|p| p.get("mcp_action"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        ));
        Ok(())
    })?;
    assert_eq!(
        receipts,
        vec![
            (
                "docs".to_owned(),
                "docs://forbidden.md".to_owned(),
                Decision::Deny,
                ReceiptState::Blocked,
                Some(trace_id.to_owned()),
                Some("read_resource".to_owned())
            ),
            (
                "docs".to_owned(),
                "docs://allowed.md".to_owned(),
                Decision::Allow,
                ReceiptState::Sealed,
                Some(trace_id.to_owned()),
                Some("read_resource".to_owned())
            ),
            (
                "docs".to_owned(),
                "file:///shared/guide.md".to_owned(),
                Decision::Allow,
                ReceiptState::Sealed,
                Some(trace_id.to_owned()),
                Some("read_resource".to_owned())
            ),
            (
                "docs".to_owned(),
                "summarize".to_owned(),
                Decision::Allow,
                ReceiptState::Sealed,
                Some(trace_id.to_owned()),
                Some("get_prompt".to_owned())
            ),
        ]
    );

    Ok(())
}

#[tokio::test]
async fn jwt_bearer_authentication_governs_mcp_requests_end_to_end() -> Result<(), KeelwayError> {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use keelway_engine::auth::JwtConfig;

    let tmp = tempfile::tempdir()?;
    let tape_path = tmp.path().join("jwt-e2e-tape.jsonl");
    let hs256_secret = "super-secret-hs256-signing-key-at-least-32-bytes";

    let upstream = Router::new().route(
        "/mcp",
        post(|Json(body): Json<Value>| async move {
            let id = body.get("id").cloned().unwrap_or(Value::Null);
            Json(json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "content": [{ "type": "text", "text": "jwt-ok" }] }
            }))
        }),
    );
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(up_listener, upstream).await;
    });

    let cfg = GatewayConfig {
        servers: vec![ServerConfig {
            alias: "echo".to_owned(),
            transport: UpstreamTransport::StreamableHttp {
                url: format!("http://{up_addr}/mcp"),
                headers: BTreeMap::new(),
            },
            timeout_ms: 5_000,
            tools: vec!["ping".to_owned()],
            resources: vec![],
            prompts: vec![],
        }],
        jwt_auth: Some(JwtConfig {
            issuer: "https://idp.example.com".to_owned(),
            audience: "keelway-gw".to_owned(),
            hs256_secret: Some("secret://jwt_hs256".to_owned()),
            ed25519_public_key_hex: None,
            jwks_url: None,
            org_claim: "org_id".to_owned(),
            agent_claim: "agent_id".to_owned(),
            roles_claim: "roles".to_owned(),
        }),
        ..Default::default()
    };

    let cedar = r#"
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"echo/ping"
);
"#;
    let mut secrets = HashMap::new();
    secrets.insert("secret://jwt_hs256".to_owned(), hs256_secret.to_owned());

    let engine = GatewayEngine::from_in_memory(cfg, cedar)?;
    let router = engine.build_test_http_router(tape_path.clone(), &MapSecrets(secrets))?;
    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let now = chrono::Utc::now().timestamp() as usize;
    let valid_token = encode(
        &Header::default(),
        &json!({
            "iss": "https://idp.example.com",
            "aud": "keelway-gw",
            "exp": now + 300,
            "org_id": "acme",
            "agent_id": "jwt-agent",
            "roles": ["developer"]
        }),
        &EncodingKey::from_secret(hs256_secret.as_bytes()),
    )
    .map_err(|e| KeelwayError::Auth(e.to_string()))?;

    let client = reqwest::Client::new();
    let gw_url = format!("http://{gw_addr}/mcp");

    let ok_resp: Value = client
        .post(&gw_url)
        .header("authorization", format!("Bearer {valid_token}"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "echo__ping", "arguments": {} }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(ok_resp["result"]["content"][0]["text"], "jwt-ok");

    let bad_resp = client
        .post(&gw_url)
        .header("authorization", "Bearer invalid.jwt.token")
        .json(&json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(bad_resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    Ok(())
}

#[tokio::test]
async fn circuit_breaker_trips_on_repeated_upstream_failures_and_updates_readyz()
-> Result<(), KeelwayError> {
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_ref = calls.clone();
    let upstream = Router::new().route(
        "/mcp",
        post(move || {
            let calls_ref = calls_ref.clone();
            async move {
                calls_ref.fetch_add(1, Ordering::SeqCst);
                (axum::http::StatusCode::SERVICE_UNAVAILABLE, "upstream down")
            }
        }),
    );
    let up_listener = TcpListener::bind("127.0.0.1:0").await?;
    let up_addr = up_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(up_listener, upstream).await;
    });

    let dir = tempdir()?;
    let tape_path = dir.path().join("cb-e2e-tape.jsonl");
    let cfg = GatewayConfig {
        tape_path: tape_path.clone(),
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "coding-agent".to_owned(),
            roles: vec!["developer".to_owned()],
            token_ref: Some("tok-cb".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "flaky".to_owned(),
            timeout_ms: 5_000,
            tools: vec!["ping".to_owned()],
            resources: vec![],
            prompts: vec![],
            transport: UpstreamTransport::StreamableHttp {
                url: format!("http://{up_addr}/mcp"),
                headers: BTreeMap::new(),
            },
        }],
        ..Default::default()
    };

    let cedar = r#"
permit(
    principal in Role::"developer",
    action == Action::"call_tool",
    resource == Tool::"flaky/ping"
);
"#;

    let engine = GatewayEngine::from_in_memory(cfg, cedar)?;
    let router = engine.build_test_http_router(tape_path, &MapSecrets(HashMap::new()))?;
    let gw_listener = TcpListener::bind("127.0.0.1:0").await?;
    let gw_addr = gw_listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(gw_listener, router).await;
    });

    let client = reqwest::Client::new();
    let readyz_url = format!("http://{gw_addr}/readyz");
    let mcp_url = format!("http://{gw_addr}/mcp");

    let init_readyz = client
        .get(&readyz_url)
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(init_readyz.status(), reqwest::StatusCode::OK);
    let init_readyz_body: Value = init_readyz
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(init_readyz_body["ready"], true);

    for id in 1..=5 {
        let resp: Value = client
            .post(&mcp_url)
            .header("authorization", "Bearer tok-cb")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": "flaky__ping", "arguments": {} }
            }))
            .send()
            .await
            .map_err(|e| KeelwayError::Mcp(e.to_string()))?
            .json()
            .await
            .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
        assert_eq!(resp["error"]["code"], -32003);
    }
    assert_eq!(calls.load(Ordering::SeqCst), 5);

    // 6th call fails fast with circuit breaker open without hitting upstream.
    let tripped: Value = client
        .post(&mcp_url)
        .header("authorization", "Bearer tok-cb")
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": { "name": "flaky__ping", "arguments": {} }
        }))
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(tripped["error"]["code"], -32003);
    assert!(
        tripped["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("circuit breaker open")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 5);

    let open_readyz = client
        .get(&readyz_url)
        .send()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(
        open_readyz.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );
    let open_readyz_body: Value = open_readyz
        .json()
        .await
        .map_err(|e| KeelwayError::Mcp(e.to_string()))?;
    assert_eq!(open_readyz_body["ready"], false);

    Ok(())
}
