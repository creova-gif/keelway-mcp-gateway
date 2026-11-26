use crate::circuit::CircuitState;
use crate::core::{Decision, Explanation, KeelwayError, Principal, ReceiptState, UnsealedReceipt};
use crate::mcp::GatewayRuntime;
use crate::provenance::extract_or_generate_trace_id;
use axum::extract::{Request, State};
use axum::http::header::{CACHE_CONTROL, HeaderValue, X_CONTENT_TYPE_OPTIONS};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;

const CONSOLE_HTML: &str = include_str!("ui/console.html");

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
        .layer(axum::middleware::from_fn(security_headers_middleware))
        .with_state(runtime)
}

async fn security_headers_middleware(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    if !headers.contains_key(X_CONTENT_TYPE_OPTIONS) {
        headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    }
    if !headers.contains_key(CACHE_CONTROL) {
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    resp
}

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

async fn healthz_handler(State(runtime): State<Arc<GatewayRuntime>>) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "uptime_seconds": runtime.metrics.uptime_seconds(),
        })),
    )
        .into_response()
}

async fn readyz_handler(State(runtime): State<Arc<GatewayRuntime>>) -> Response {
    let snapshot = runtime.circuit_breaker.snapshot();
    let open_count = snapshot
        .iter()
        .filter(|(_, state)| *state == CircuitState::Open)
        .count();
    let any_open = open_count > 0;
    let status = if any_open {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    };
    (
        status,
        Json(json!({
            "ready": !any_open,
            "open_circuits": open_count,
        })),
    )
        .into_response()
}

async fn metrics_handler(State(runtime): State<Arc<GatewayRuntime>>) -> Response {
    runtime
        .metrics
        .set_p10_pending(runtime.p10.pending_count() as u64);
    let open_count = runtime
        .circuit_breaker
        .snapshot()
        .iter()
        .filter(|(_, state)| *state == CircuitState::Open)
        .count();
    runtime.metrics.set_circuits_open(open_count as u64);
    runtime
        .metrics
        .set_active_inflight(runtime.budgets.active_in_flight());
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
    let shutdown_rx = runtime.shutdown_tx.subscribe();
    let sse_stream = futures_util::stream::unfold(
        (rx_owned, shutdown_rx, org_id, exp),
        |(mut rx, mut shutdown_rx, org_id, exp)| async move {
            loop {
                if *shutdown_rx.borrow() {
                    return None;
                }
                if let Some(exp_ts) = exp {
                    let now = Utc::now().timestamp().max(0) as u64;
                    if now >= exp_ts {
                        return None;
                    }
                    let remaining = std::time::Duration::from_secs(exp_ts - now);
                    tokio::select! {
                        _ = shutdown_rx.changed() => return None,
                        res = tokio::time::timeout(remaining, rx.recv()) => {
                            match res {
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
                                        (rx, shutdown_rx, org_id, exp),
                                    ));
                                }
                                Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => continue,
                                Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => return None,
                                Err(_) => return None,
                            }
                        }
                    }
                } else {
                    tokio::select! {
                        _ = shutdown_rx.changed() => return None,
                        res = rx.recv() => {
                            match res {
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
                                        (rx, shutdown_rx, org_id, exp),
                                    ));
                                }
                                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                            }
                        }
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
    let trace_id =
        extract_or_generate_trace_id(headers.get("traceparent").and_then(|v| v.to_str().ok()));
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
                provenance: Some(json!({ "trace_id": trace_id })),
            })
            .await;
        return (
            StatusCode::UNAUTHORIZED,
            [("x-trace-id", trace_id)],
            Json(json!({ "error": "unauthenticated" })),
        )
            .into_response();
    };

    let is_notification = body.get("id").is_none();
    let resp = runtime
        .handle_rpc_request_with_trace(&principal, body, Some(&trace_id))
        .await;
    if is_notification {
        return (StatusCode::ACCEPTED, [("x-trace-id", trace_id)]).into_response();
    }
    (StatusCode::OK, [("x-trace-id", trace_id)], Json(resp)).into_response()
}
