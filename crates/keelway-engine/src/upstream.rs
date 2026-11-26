use crate::core::{KeelwayError, ServerConfig, UpstreamTransport};
use crate::secrets::{SecretProvider, SecretScrubber};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

/// Live stdio child process handle with bounded exponential-backoff restart.
pub(crate) struct StdioProcess {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

pub(crate) enum UpstreamDriver {
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
    pub(crate) fn from_server_config(
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

    pub(crate) async fn call_tool(
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

    pub(crate) async fn call_method(
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
                    if let Some(err) = parsed.get("error").filter(|v| !v.is_null()) {
                        return Err(KeelwayError::Mcp(format!("upstream JSON-RPC error: {err}")));
                    }
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
                let mut req = client
                    .post(url)
                    .header("accept", "application/json, text/event-stream")
                    .header("mcp-protocol-version", "2025-03-26")
                    .json(&rpc_body);
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

                let is_sse = resp
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/event-stream"));

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

                let parsed: Value = if is_sse {
                    extract_sse_json_payload(&assembled).unwrap_or_else(
                        || json!({ "content": [{ "type": "text", "text": assembled }] }),
                    )
                } else {
                    match serde_json::from_str::<Value>(&assembled) {
                        Ok(val) => val,
                        Err(_)
                            if assembled
                                .lines()
                                .any(|l| l.trim_start().starts_with("data:")) =>
                        {
                            extract_sse_json_payload(&assembled).unwrap_or_else(
                                || json!({ "content": [{ "type": "text", "text": assembled }] }),
                            )
                        }
                        Err(_) => json!({ "content": [{ "type": "text", "text": assembled }] }),
                    }
                };
                if let Some(err) = parsed.get("error").filter(|v| !v.is_null()) {
                    return Err(KeelwayError::Mcp(format!("upstream JSON-RPC error: {err}")));
                }
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
        .stderr(Stdio::piped())
        .kill_on_drop(true);

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

fn extract_sse_json_payload(raw: &str) -> Option<Value> {
    let mut last_valid: Option<Value> = None;
    let mut data_lines: Vec<&str> = Vec::new();

    let flush_event = |lines: &mut Vec<&str>, last: &mut Option<Value>| {
        if lines.is_empty() {
            return;
        }
        let joined = lines.join("\n");
        lines.clear();
        let trimmed = joined.trim();
        if trimmed.is_empty() || trimmed == "[DONE]" {
            return;
        }
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            *last = Some(val);
        }
    };

    for line in raw.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            flush_event(&mut data_lines, &mut last_valid);
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            let payload = rest.strip_prefix(' ').unwrap_or(rest);
            data_lines.push(payload);
        }
    }
    flush_event(&mut data_lines, &mut last_valid);

    last_valid
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_sse_json_payload_handles_multi_event_done_and_multiline_data() {
        let multi_event = "\
event: message\n\
data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{\"progress\":50}}\n\
\n\
data:\n\
\n\
event: message\n\
data: {\n\
data:   \"jsonrpc\": \"2.0\",\n\
data:   \"id\": 7,\n\
data:   \"result\": {\"content\": [{\"type\": \"text\", \"text\": \"hello\"}]}\n\
data: }\n\
\n\
data: [DONE]\n\n";

        let parsed = extract_sse_json_payload(multi_event);
        assert_eq!(parsed.as_ref().and_then(|v| v["id"].as_i64()), Some(7));
        assert_eq!(
            parsed
                .as_ref()
                .and_then(|v| v["result"]["content"][0]["text"].as_str()),
            Some("hello")
        );

        assert!(extract_sse_json_payload("data: [DONE]\n\ndata:\n\n").is_none());
    }
}
