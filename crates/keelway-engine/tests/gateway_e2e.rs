use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use keelway_engine::core::{Decision, GatewayConfig, KeelwayError};
use keelway_engine::{
    GatewayEngine, PrincipalConfig, ReplayVerdict, SecretProvider, ServerConfig, UpstreamTransport,
    ValidatorBinding, ValidatorKind,
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
    let github_secret = "ghp_e2e_super_secret_token_99999";
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
