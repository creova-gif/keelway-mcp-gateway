use crate::core::{Decision, ReceiptState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::sync::broadcast;

const CONSOLE_BROADCAST_CAPACITY: usize = 256;

/// Explicit outcome classification for a mediated tool call event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventOutcome {
    Allowed,
    DeniedPolicy,
    DeniedAuth,
    DeniedBudget,
    P10Awaiting,
    P10Approved,
    P10Denied,
}

/// Real-time event emitted for each mediated tool call and streamed to SSE console subscribers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiveConsoleEvent {
    pub timestamp: DateTime<Utc>,
    pub org_id: String,
    pub agent_id: String,
    pub server: String,
    pub tool: String,
    pub decision: Decision,
    pub state: ReceiptState,
    pub outcome: EventOutcome,
    pub reason: String,
}

/// Lock-free gateway metrics and live console event broadcaster.
pub struct GatewayMetrics {
    pub calls_allowed: AtomicU64,
    pub calls_denied_policy: AtomicU64,
    pub calls_denied_auth: AtomicU64,
    pub calls_denied_budget: AtomicU64,
    pub calls_p10_approved: AtomicU64,
    pub calls_p10_denied: AtomicU64,
    pub upstream_timeouts: AtomicU64,
    pub upstream_errors: AtomicU64,
    pub p10_pending: AtomicU64,
    pub circuits_open: AtomicU64,
    pub active_inflight: AtomicU64,
    started_at: Instant,
    console_tx: broadcast::Sender<LiveConsoleEvent>,
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl GatewayMetrics {
    /// Creates a new `GatewayMetrics` instance with zeroed counters and a 256-slot broadcast channel.
    pub fn new() -> Self {
        let (console_tx, _) = broadcast::channel(CONSOLE_BROADCAST_CAPACITY);
        Self {
            calls_allowed: AtomicU64::new(0),
            calls_denied_policy: AtomicU64::new(0),
            calls_denied_auth: AtomicU64::new(0),
            calls_denied_budget: AtomicU64::new(0),
            calls_p10_approved: AtomicU64::new(0),
            calls_p10_denied: AtomicU64::new(0),
            upstream_timeouts: AtomicU64::new(0),
            upstream_errors: AtomicU64::new(0),
            p10_pending: AtomicU64::new(0),
            circuits_open: AtomicU64::new(0),
            active_inflight: AtomicU64::new(0),
            started_at: Instant::now(),
            console_tx,
        }
    }

    /// Subscribes to the live console event broadcast stream.
    pub fn subscribe(&self) -> broadcast::Receiver<LiveConsoleEvent> {
        self.console_tx.subscribe()
    }

    /// Records a tool call event, updating relevant counters and broadcasting to SSE subscribers.
    /// Zero-receiver broadcast errors are ignored.
    pub fn record_event(&self, event: LiveConsoleEvent) {
        self.update_counters_for_event(&event);
        let _ = self.console_tx.send(event);
    }

    /// Increments `calls_allowed`.
    pub fn inc_calls_allowed(&self) {
        self.calls_allowed.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `calls_denied_policy`.
    pub fn inc_calls_denied_policy(&self) {
        self.calls_denied_policy.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `calls_denied_auth`.
    pub fn inc_calls_denied_auth(&self) {
        self.calls_denied_auth.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `calls_denied_budget`.
    pub fn inc_calls_denied_budget(&self) {
        self.calls_denied_budget.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `calls_p10_approved`.
    pub fn inc_calls_p10_approved(&self) {
        self.calls_p10_approved.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `calls_p10_denied`.
    pub fn inc_calls_p10_denied(&self) {
        self.calls_p10_denied.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `upstream_timeouts`.
    pub fn inc_upstream_timeout(&self) {
        self.upstream_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `upstream_errors`.
    pub fn inc_upstream_error(&self) {
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increments `p10_pending`.
    pub fn inc_p10_pending(&self) {
        self.p10_pending.fetch_add(1, Ordering::Relaxed);
    }

    /// Sets `p10_pending` to an exact count.
    pub fn set_p10_pending(&self, count: u64) {
        self.p10_pending.store(count, Ordering::Relaxed);
    }

    /// Sets `circuits_open` to an exact count.
    pub fn set_circuits_open(&self, count: u64) {
        self.circuits_open.store(count, Ordering::Relaxed);
    }

    /// Sets `active_inflight` to an exact count.
    pub fn set_active_inflight(&self, count: u64) {
        self.active_inflight.store(count, Ordering::Relaxed);
    }

    /// Returns the number of whole seconds elapsed since `GatewayMetrics::new()`.
    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Renders all metrics in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let allowed = self.calls_allowed.load(Ordering::Relaxed);
        let denied_policy = self.calls_denied_policy.load(Ordering::Relaxed);
        let denied_auth = self.calls_denied_auth.load(Ordering::Relaxed);
        let denied_budget = self.calls_denied_budget.load(Ordering::Relaxed);
        let p10_approved = self.calls_p10_approved.load(Ordering::Relaxed);
        let p10_denied = self.calls_p10_denied.load(Ordering::Relaxed);
        let timeouts = self.upstream_timeouts.load(Ordering::Relaxed);
        let errors = self.upstream_errors.load(Ordering::Relaxed);
        let pending = self.p10_pending.load(Ordering::Relaxed);
        let circuits_open = self.circuits_open.load(Ordering::Relaxed);
        let active_inflight = self.active_inflight.load(Ordering::Relaxed);
        let uptime_seconds = self.uptime_seconds();

        let mut out = String::with_capacity(800);
        let _ = writeln!(
            out,
            "# HELP keelway_calls_total Total number of MCP tool calls processed by outcome."
        );
        let _ = writeln!(out, "# TYPE keelway_calls_total counter");
        let _ = writeln!(out, "keelway_calls_total{{outcome=\"allowed\"}} {allowed}");
        let _ = writeln!(
            out,
            "keelway_calls_total{{outcome=\"denied_policy\"}} {denied_policy}"
        );
        let _ = writeln!(
            out,
            "keelway_calls_total{{outcome=\"denied_auth\"}} {denied_auth}"
        );
        let _ = writeln!(
            out,
            "keelway_calls_total{{outcome=\"denied_budget\"}} {denied_budget}"
        );
        let _ = writeln!(
            out,
            "keelway_calls_total{{outcome=\"p10_approved\"}} {p10_approved}"
        );
        let _ = writeln!(
            out,
            "keelway_calls_total{{outcome=\"p10_denied\"}} {p10_denied}"
        );

        let _ = writeln!(
            out,
            "# HELP keelway_upstream_errors_total Total number of upstream MCP server errors by kind."
        );
        let _ = writeln!(out, "# TYPE keelway_upstream_errors_total counter");
        let _ = writeln!(
            out,
            "keelway_upstream_errors_total{{kind=\"timeout\"}} {timeouts}"
        );
        let _ = writeln!(
            out,
            "keelway_upstream_errors_total{{kind=\"error\"}} {errors}"
        );

        let _ = writeln!(
            out,
            "# HELP keelway_p10_pending Number of tool calls currently awaiting P10 human approval."
        );
        let _ = writeln!(out, "# TYPE keelway_p10_pending gauge");
        let _ = writeln!(out, "keelway_p10_pending {pending}");

        let _ = writeln!(
            out,
            "# HELP keelway_circuits_open Number of upstream circuit breakers currently in open state."
        );
        let _ = writeln!(out, "# TYPE keelway_circuits_open gauge");
        let _ = writeln!(out, "keelway_circuits_open {circuits_open}");

        let _ = writeln!(
            out,
            "# HELP keelway_active_upstream_inflight Number of upstream MCP tool calls currently in flight."
        );
        let _ = writeln!(out, "# TYPE keelway_active_upstream_inflight gauge");
        let _ = writeln!(out, "keelway_active_upstream_inflight {active_inflight}");

        let _ = writeln!(
            out,
            "# HELP keelway_gateway_uptime_seconds Elapsed seconds since gateway metrics initialization."
        );
        let _ = writeln!(out, "# TYPE keelway_gateway_uptime_seconds gauge");
        let _ = writeln!(out, "keelway_gateway_uptime_seconds {uptime_seconds}");
        out
    }

    fn update_counters_for_event(&self, event: &LiveConsoleEvent) {
        match event.outcome {
            EventOutcome::Allowed => self.inc_calls_allowed(),
            EventOutcome::DeniedPolicy => self.inc_calls_denied_policy(),
            EventOutcome::DeniedAuth => self.inc_calls_denied_auth(),
            EventOutcome::DeniedBudget => self.inc_calls_denied_budget(),
            EventOutcome::P10Awaiting => self.inc_p10_pending(),
            EventOutcome::P10Approved => self.inc_calls_p10_approved(),
            EventOutcome::P10Denied => self.inc_calls_p10_denied(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(
        decision: Decision,
        state: ReceiptState,
        outcome: EventOutcome,
        reason: &str,
    ) -> LiveConsoleEvent {
        LiveConsoleEvent {
            timestamp: Utc::now(),
            org_id: "org-1".to_owned(),
            agent_id: "agent-1".to_owned(),
            server: "github".to_owned(),
            tool: "create_issue".to_owned(),
            decision,
            state,
            outcome,
            reason: reason.to_owned(),
        }
    }

    #[test]
    fn record_event_increments_counters_by_outcome() {
        let metrics = GatewayMetrics::new();

        metrics.record_event(sample_event(
            Decision::Allow,
            ReceiptState::Sealed,
            EventOutcome::Allowed,
            "allowed by policy",
        ));
        metrics.record_event(sample_event(
            Decision::Deny,
            ReceiptState::Blocked,
            EventOutcome::DeniedPolicy,
            "forbidden by cedar policy",
        ));
        metrics.record_event(sample_event(
            Decision::Deny,
            ReceiptState::Blocked,
            EventOutcome::DeniedAuth,
            "authentication failed: unknown principal",
        ));
        metrics.record_event(sample_event(
            Decision::Deny,
            ReceiptState::Blocked,
            EventOutcome::DeniedBudget,
            "execution budget exceeded",
        ));
        metrics.record_event(sample_event(
            Decision::Allow,
            ReceiptState::Sealed,
            EventOutcome::P10Approved,
            "p10 human approval granted",
        ));
        metrics.record_event(sample_event(
            Decision::Deny,
            ReceiptState::Blocked,
            EventOutcome::P10Denied,
            "p10 approval rejected",
        ));
        metrics.record_event(sample_event(
            Decision::Allow,
            ReceiptState::Awaiting,
            EventOutcome::P10Awaiting,
            "awaiting p10 approval",
        ));
        metrics.inc_upstream_timeout();
        metrics.inc_upstream_error();

        assert_eq!(metrics.calls_allowed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.calls_denied_policy.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.calls_denied_auth.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.calls_denied_budget.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.calls_p10_approved.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.calls_p10_denied.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.p10_pending.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.upstream_timeouts.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.upstream_errors.load(Ordering::Relaxed), 1);

        metrics.set_p10_pending(3);
        assert_eq!(metrics.p10_pending.load(Ordering::Relaxed), 3);
        metrics.set_p10_pending(0);
        assert_eq!(metrics.p10_pending.load(Ordering::Relaxed), 0);

        metrics.set_circuits_open(2);
        assert_eq!(metrics.circuits_open.load(Ordering::Relaxed), 2);
        metrics.set_circuits_open(0);
        assert_eq!(metrics.circuits_open.load(Ordering::Relaxed), 0);

        metrics.set_active_inflight(4);
        assert_eq!(metrics.active_inflight.load(Ordering::Relaxed), 4);
        metrics.set_active_inflight(0);
        assert_eq!(metrics.active_inflight.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn render_prometheus_emits_expected_exposition_format() {
        let metrics = GatewayMetrics::new();
        metrics.inc_calls_allowed();
        metrics.inc_calls_allowed();
        metrics.inc_calls_denied_policy();
        metrics.inc_calls_denied_auth();
        metrics.inc_calls_denied_budget();
        metrics.inc_calls_p10_approved();
        metrics.inc_calls_p10_denied();
        metrics.inc_upstream_timeout();
        metrics.inc_upstream_error();
        metrics.inc_upstream_error();
        metrics.inc_p10_pending();
        metrics.set_circuits_open(1);
        metrics.set_active_inflight(3);

        let rendered = metrics.render_prometheus();

        let expected_prefix = "\
# HELP keelway_calls_total Total number of MCP tool calls processed by outcome.
# TYPE keelway_calls_total counter
keelway_calls_total{outcome=\"allowed\"} 2
keelway_calls_total{outcome=\"denied_policy\"} 1
keelway_calls_total{outcome=\"denied_auth\"} 1
keelway_calls_total{outcome=\"denied_budget\"} 1
keelway_calls_total{outcome=\"p10_approved\"} 1
keelway_calls_total{outcome=\"p10_denied\"} 1
# HELP keelway_upstream_errors_total Total number of upstream MCP server errors by kind.
# TYPE keelway_upstream_errors_total counter
keelway_upstream_errors_total{kind=\"timeout\"} 1
keelway_upstream_errors_total{kind=\"error\"} 2
# HELP keelway_p10_pending Number of tool calls currently awaiting P10 human approval.
# TYPE keelway_p10_pending gauge
keelway_p10_pending 1
# HELP keelway_circuits_open Number of upstream circuit breakers currently in open state.
# TYPE keelway_circuits_open gauge
keelway_circuits_open 1
# HELP keelway_active_upstream_inflight Number of upstream MCP tool calls currently in flight.
# TYPE keelway_active_upstream_inflight gauge
keelway_active_upstream_inflight 3
# HELP keelway_gateway_uptime_seconds Elapsed seconds since gateway metrics initialization.
# TYPE keelway_gateway_uptime_seconds gauge
keelway_gateway_uptime_seconds ";
        assert!(rendered.starts_with(expected_prefix));
        let uptime_line = rendered
            .strip_prefix(expected_prefix)
            .and_then(|rest| rest.strip_suffix('\n'));
        assert!(uptime_line.is_some_and(|v| v.parse::<u64>().is_ok()));
    }

    #[tokio::test]
    async fn broadcast_delivers_events_to_subscribers_and_handles_zero_receivers() {
        let metrics = GatewayMetrics::new();

        // Recording with zero subscribers must not error or panic.
        metrics.record_event(sample_event(
            Decision::Allow,
            ReceiptState::Sealed,
            EventOutcome::Allowed,
            "no subscribers yet",
        ));

        let mut rx1 = metrics.subscribe();
        let mut rx2 = metrics.subscribe();

        let event = sample_event(
            Decision::Deny,
            ReceiptState::Blocked,
            EventOutcome::DeniedPolicy,
            "policy deny",
        );
        metrics.record_event(event.clone());

        let recv1 = rx1.recv().await;
        let recv2 = rx2.recv().await;

        assert_eq!(recv1, Ok(event.clone()));
        assert_eq!(recv2, Ok(event));
    }
}
