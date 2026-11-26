use crate::core::{ApprovalRule, KeelwayError, Principal};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;
use uuid::Uuid;

/// Public snapshot of an active P-10 human-in-the-loop approval gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingGateInfo {
    pub approval_id: String,
    pub org_id: String,
    pub agent_id: String,
    pub server: String,
    pub tool: String,
    pub redacted_args: Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
struct PendingEntry {
    info: PendingGateInfo,
    sender: oneshot::Sender<bool>,
}

/// RAII guard that cancels a pending P-10 approval gate if dropped before being disarmed.
#[derive(Debug)]
pub struct PendingGateGuard {
    manager: P10GateManager,
    approval_id: Option<String>,
}

impl PendingGateGuard {
    /// Disarms the guard so dropping it will not cancel the pending gate.
    pub fn disarm(&mut self) {
        self.approval_id = None;
    }
}

impl Drop for PendingGateGuard {
    fn drop(&mut self) {
        if let Some(id) = self.approval_id.take() {
            self.manager.cancel(&id);
        }
    }
}

/// Manages P-10 human-in-the-loop approval gates for sensitive tool invocations.
#[derive(Debug, Clone, Default)]
pub struct P10GateManager {
    rules: Vec<ApprovalRule>,
    pending: Arc<Mutex<HashMap<String, PendingEntry>>>,
}

impl P10GateManager {
    /// Creates a new `P10GateManager` from configured approval rules.
    pub fn new(rules: Vec<ApprovalRule>) -> Self {
        Self {
            rules,
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns `Some(timeout_ms)` if any configured [`ApprovalRule`] matches
    /// `(principal.org_id, principal.agent_id | "*", server, tool)`.
    pub fn requires_approval(
        &self,
        principal: &Principal,
        server: &str,
        tool: &str,
    ) -> Option<u64> {
        if self.rules.is_empty() {
            return None;
        }
        let org = principal.org_id.as_str();
        let agent = principal.agent_id.as_str();
        for agent_candidate in [agent, "*"] {
            if let Some(rule) = self.rules.iter().find(|r| {
                r.org_id == org
                    && r.agent_id == agent_candidate
                    && r.server == server
                    && r.tool == tool
            }) {
                return Some(rule.timeout_ms);
            }
        }
        None
    }

    /// Registers a new pending approval gate and returns `(approval_id, receiver)`.
    pub fn create_gate(
        &self,
        principal: &Principal,
        server: &str,
        tool: &str,
        redacted_args: Value,
    ) -> (String, oneshot::Receiver<bool>) {
        let approval_id = Uuid::new_v4().to_string();
        let (sender, receiver) = oneshot::channel();
        let info = PendingGateInfo {
            approval_id: approval_id.clone(),
            org_id: principal.org_id.clone(),
            agent_id: principal.agent_id.clone(),
            server: server.to_owned(),
            tool: tool.to_owned(),
            redacted_args,
            created_at: Utc::now(),
        };

        let mut guard = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(approval_id.clone(), PendingEntry { info, sender });

        (approval_id, receiver)
    }

    /// Returns the number of currently pending approval gates.
    pub fn pending_count(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    /// Returns all currently active pending approval gates.
    pub fn list_pending(&self) -> Vec<PendingGateInfo> {
        let guard = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut items: Vec<PendingGateInfo> =
            guard.values().map(|entry| entry.info.clone()).collect();
        items.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.approval_id.cmp(&b.approval_id))
        });
        items
    }

    /// Returns an RAII guard that cancels `approval_id` on drop unless disarmed.
    pub fn guard(&self, approval_id: &str) -> PendingGateGuard {
        PendingGateGuard {
            manager: self.clone(),
            approval_id: Some(approval_id.to_owned()),
        }
    }

    /// Resolves a pending gate by `approval_id` for `approver_org` and `approver_agent`,
    /// removing it and sending `approved` on the associated `oneshot` channel.
    pub fn resolve(
        &self,
        approval_id: &str,
        approver_org: &str,
        approver_agent: &str,
        approved: bool,
    ) -> Result<(), KeelwayError> {
        let mut guard = self
            .pending
            .lock()
            .map_err(|_| KeelwayError::Mcp("approval gate lock poisoned".to_owned()))?;
        let Some(entry) = guard.get(approval_id) else {
            return Err(KeelwayError::Mcp(
                "unknown or expired approval_id".to_owned(),
            ));
        };
        if entry.info.org_id != approver_org {
            return Err(KeelwayError::Auth(format!(
                "cross-tenant P-10 resolution forbidden for org '{approver_org}'"
            )));
        }
        if entry.info.agent_id == approver_agent {
            return Err(KeelwayError::Auth(format!(
                "self-approval forbidden for agent '{approver_agent}'"
            )));
        }
        let entry = guard
            .remove(approval_id)
            .ok_or_else(|| KeelwayError::Mcp("unknown or expired approval_id".to_owned()))?;
        drop(guard);
        entry.sender.send(approved).map_err(|_| {
            KeelwayError::Mcp(format!("approval waiter disconnected for '{approval_id}'"))
        })
    }

    /// Removes a pending gate without resolving it (e.g. on timeout or drop).
    pub fn cancel(&self, approval_id: &str) {
        let mut guard = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(approval_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn principal(org_id: &str, agent_id: &str) -> Principal {
        Principal {
            org_id: org_id.to_owned(),
            agent_id: agent_id.to_owned(),
            roles: Vec::new(),
        }
    }

    fn rule(
        org_id: &str,
        agent_id: &str,
        server: &str,
        tool: &str,
        timeout_ms: u64,
    ) -> ApprovalRule {
        ApprovalRule {
            org_id: org_id.to_owned(),
            agent_id: agent_id.to_owned(),
            server: server.to_owned(),
            tool: tool.to_owned(),
            timeout_ms,
        }
    }

    #[test]
    fn requires_approval_matches_exact_and_wildcard_agent() {
        let mgr = P10GateManager::new(vec![
            rule("org-a", "*", "github", "delete_repo", 60_000),
            rule("org-a", "agent-2", "github", "delete_repo", 15_000),
            rule("org-b", "agent-1", "slack", "post_message", 30_000),
        ]);

        assert_eq!(
            mgr.requires_approval(&principal("org-a", "agent-1"), "github", "delete_repo"),
            Some(60_000)
        );
        assert_eq!(
            mgr.requires_approval(&principal("org-a", "agent-2"), "github", "delete_repo"),
            Some(15_000)
        );
        assert_eq!(
            mgr.requires_approval(&principal("org-a", "agent-1"), "github", "list_repos"),
            None
        );
        assert_eq!(
            mgr.requires_approval(&principal("org-b", "agent-2"), "slack", "post_message"),
            None
        );
        assert_eq!(
            mgr.requires_approval(&principal("org-b", "agent-1"), "slack", "post_message"),
            Some(30_000)
        );
    }

    #[tokio::test]
    async fn resolve_approve_sends_true_and_clears_pending()
    -> Result<(), Box<dyn std::error::Error>> {
        let mgr = P10GateManager::new(Vec::new());
        let (id, rx) = mgr.create_gate(
            &principal("org-a", "agent-1"),
            "github",
            "delete_repo",
            json!({"repo": "keelway", "token": "[REDACTED]"}),
        );

        assert!(Uuid::parse_str(&id).is_ok());
        let pending = mgr.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].approval_id, id);
        assert_eq!(pending[0].org_id, "org-a");
        assert_eq!(pending[0].agent_id, "agent-1");
        assert_eq!(pending[0].server, "github");
        assert_eq!(pending[0].tool, "delete_repo");
        assert_eq!(
            pending[0].redacted_args,
            json!({"repo": "keelway", "token": "[REDACTED]"})
        );

        mgr.resolve(&id, "org-a", "approver-1", true)?;
        assert!(mgr.list_pending().is_empty());
        assert!(rx.await?);
        Ok(())
    }

    #[tokio::test]
    async fn resolve_deny_sends_false_and_clears_pending() -> Result<(), Box<dyn std::error::Error>>
    {
        let mgr = P10GateManager::new(Vec::new());
        let (id, rx) = mgr.create_gate(
            &principal("org-a", "agent-1"),
            "github",
            "delete_repo",
            json!({}),
        );

        mgr.resolve(&id, "org-a", "approver-1", false)?;
        assert!(mgr.list_pending().is_empty());
        assert!(!rx.await?);
        Ok(())
    }

    #[tokio::test]
    async fn cancel_removes_pending_and_closes_channel() {
        let mgr = P10GateManager::new(Vec::new());
        let (id, rx) = mgr.create_gate(
            &principal("org-a", "agent-1"),
            "github",
            "delete_repo",
            json!({}),
        );

        assert_eq!(mgr.list_pending().len(), 1);
        mgr.cancel(&id);
        assert!(mgr.list_pending().is_empty());
        assert!(rx.await.is_err());
    }

    #[test]
    fn resolve_unknown_id_returns_err() {
        let mgr = P10GateManager::new(Vec::new());
        let err = mgr.resolve("nonexistent-id", "org-a", "approver-1", true);
        assert!(matches!(err, Err(KeelwayError::Mcp(_))));
    }

    #[tokio::test]
    async fn resolve_cross_tenant_and_self_approval_rejected_without_removing_gate()
    -> Result<(), Box<dyn std::error::Error>> {
        let mgr = P10GateManager::new(Vec::new());
        let (id, rx) = mgr.create_gate(
            &principal("org-a", "agent-1"),
            "github",
            "delete_repo",
            json!({}),
        );

        let cross_err = mgr.resolve(&id, "org-b", "approver-1", true);
        assert!(matches!(cross_err, Err(KeelwayError::Auth(_))));
        assert_eq!(mgr.pending_count(), 1);

        let self_err = mgr.resolve(&id, "org-a", "agent-1", true);
        assert!(matches!(self_err, Err(KeelwayError::Auth(_))));
        assert_eq!(mgr.pending_count(), 1);

        mgr.resolve(&id, "org-a", "approver-1", true)?;
        assert!(rx.await?);
        Ok(())
    }

    #[test]
    fn resolve_disconnected_waiter_returns_err() {
        let mgr = P10GateManager::new(Vec::new());
        let (id, rx) = mgr.create_gate(
            &principal("org-a", "agent-1"),
            "github",
            "delete_repo",
            json!({}),
        );
        drop(rx);

        let err = mgr.resolve(&id, "org-a", "approver-1", true);
        assert!(matches!(err, Err(KeelwayError::Mcp(_))));
        assert_eq!(mgr.pending_count(), 0);
    }

    #[tokio::test]
    async fn pending_gate_guard_cancels_on_drop_unless_disarmed() {
        let mgr = P10GateManager::new(Vec::new());

        let (id1, rx1) = mgr.create_gate(
            &principal("org-a", "agent-1"),
            "github",
            "delete_repo",
            json!({}),
        );
        {
            let _guard = mgr.guard(&id1);
            assert_eq!(mgr.pending_count(), 1);
        }
        assert_eq!(mgr.pending_count(), 0);
        assert!(rx1.await.is_err());

        let (id2, _rx2) = mgr.create_gate(
            &principal("org-a", "agent-1"),
            "github",
            "delete_repo",
            json!({}),
        );
        {
            let mut guard = mgr.guard(&id2);
            guard.disarm();
        }
        assert_eq!(mgr.pending_count(), 1);
    }
}
