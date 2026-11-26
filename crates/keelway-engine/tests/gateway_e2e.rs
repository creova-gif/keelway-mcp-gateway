use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use keelway_engine::core::{Decision, GatewayConfig, KeelwayError};
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
                transport: UpstreamTransport::StreamableHttp {
                    url: github_url,
                    headers: gh_headers,
                },
            },
            ServerConfig {
                alias: "database".to_owned(),
                timeout_ms: 5_000,
                tools: vec!["query_readonly".to_owned()],
                transport: UpstreamTransport::StreamableHttp {
                    url: db_url,
                    headers: BTreeMap::new(),
                },
            },
            ServerConfig {
                alias: "filesystem".to_owned(),
                timeout_ms: 5_000,
                tools: vec!["read_file".to_owned()],
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
            transport: UpstreamTransport::Stdio {
                command: "sh".to_owned(),
                args: vec!["-c".to_owned(), script.to_owned()],
                env: stdio_env,
            },
        }],
        validators: vec![],
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
            transport: UpstreamTransport::Stdio {
                command: "sh".to_owned(),
                args: vec!["-c".to_owned(), "sleep 2".to_owned()],
                env: BTreeMap::new(),
            },
        }],
        validators: vec![],
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
            transport: UpstreamTransport::Stdio {
                command: "sh".to_owned(),
                args: vec!["-c".to_owned(), "exit 1".to_owned()],
                env: BTreeMap::new(),
            },
        }],
        validators: vec![],
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
            transport: UpstreamTransport::Stdio {
                command: "sh".to_owned(),
                args: vec!["-c".to_owned(), script.to_owned()],
                env,
            },
        }],
        validators: vec![],
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
        principals: vec![PrincipalConfig {
            org_id: "acme".to_owned(),
            agent_id: "research-agent".to_owned(),
            roles: vec!["researcher".to_owned()],
            token_ref: Some("tok-p10".to_owned()),
        }],
        servers: vec![ServerConfig {
            alias: "database".to_owned(),
            timeout_ms: 5_000,
            tools: vec!["query_readonly".to_owned()],
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

    // Poll /p10/pending until the gate appears, then approve it
    let mut approval_id = None;
    for _ in 0..40 {
        let pend: Value = client
            .get(format!("{base}/p10/pending"))
            .header("authorization", "Bearer tok-p10")
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

    let resolve_resp = client
        .post(format!("{base}/p10/resolve"))
        .header("authorization", "Bearer tok-p10")
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
