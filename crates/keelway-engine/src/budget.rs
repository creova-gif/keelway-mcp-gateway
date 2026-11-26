use crate::core::{BudgetRule, KeelwayError, Principal};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Default)]
struct BucketState {
    timestamps: VecDeque<Instant>,
    in_flight: u32,
}

type BucketKey = (String, String, String);
type SharedBuckets = Arc<Mutex<HashMap<BucketKey, BucketState>>>;

/// Enforces per-principal, per-server rate and concurrency execution budgets.
#[derive(Debug, Default)]
pub struct BudgetTracker {
    rules: Vec<BudgetRule>,
    state: SharedBuckets,
}

impl BudgetTracker {
    /// Creates a new `BudgetTracker` from configured budget rules.
    pub fn new(rules: Vec<BudgetRule>) -> Self {
        Self {
            rules,
            state: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Acquires an execution budget lease for `(principal, server)`, checking the most specific
    /// matching [`BudgetRule`] in precedence order:
    /// `(org, agent, server)` -> `(org, agent, "*")` -> `(org, "*", server)` -> `(org, "*", "*")`.
    pub fn acquire(
        &self,
        principal: &Principal,
        server: &str,
    ) -> Result<BudgetLease, KeelwayError> {
        self.acquire_at(principal, server, Instant::now())
    }

    fn acquire_at(
        &self,
        principal: &Principal,
        server: &str,
        now: Instant,
    ) -> Result<BudgetLease, KeelwayError> {
        let Some(rule) = self.find_rule(principal, server) else {
            return Ok(BudgetLease::noop());
        };

        let key = (
            rule.org_id.clone(),
            rule.agent_id.clone(),
            rule.server.clone(),
        );

        let mut guard = self
            .state
            .lock()
            .map_err(|_| KeelwayError::BudgetExceeded("budget tracker lock poisoned".to_owned()))?;
        let bucket = guard.entry(key.clone()).or_default();

        while let Some(&oldest) = bucket.timestamps.front() {
            if now.saturating_duration_since(oldest) >= RATE_LIMIT_WINDOW {
                bucket.timestamps.pop_front();
            } else {
                break;
            }
        }

        if let Some(max_concurrent) = rule.max_concurrent_calls {
            if bucket.in_flight >= max_concurrent {
                return Err(KeelwayError::BudgetExceeded(format!(
                    "max_concurrent_calls ({max_concurrent}) exceeded for {}/{} on server '{server}'",
                    principal.org_id, principal.agent_id
                )));
            }
        }

        if let Some(max_per_min) = rule.max_calls_per_minute {
            if bucket.timestamps.len() >= max_per_min as usize {
                return Err(KeelwayError::BudgetExceeded(format!(
                    "max_calls_per_minute ({max_per_min}) exceeded for {}/{} on server '{server}'",
                    principal.org_id, principal.agent_id
                )));
            }
        }

        if rule.max_calls_per_minute.is_some() {
            bucket.timestamps.push_back(now);
        }
        bucket.in_flight = bucket.in_flight.saturating_add(1);

        Ok(BudgetLease {
            state: Some(Arc::clone(&self.state)),
            key: Some(key),
        })
    }

    fn find_rule(&self, principal: &Principal, server: &str) -> Option<&BudgetRule> {
        if self.rules.is_empty() {
            return None;
        }
        let org = principal.org_id.as_str();
        let agent = principal.agent_id.as_str();
        let candidates = [
            (org, agent, server),
            (org, agent, "*"),
            (org, "*", server),
            (org, "*", "*"),
        ];
        for (o, a, s) in candidates {
            if let Some(rule) = self
                .rules
                .iter()
                .find(|r| r.org_id == o && r.agent_id == a && r.server == s)
            {
                return Some(rule);
            }
        }
        None
    }
}

/// RAII lease representing an active in-flight execution slot.
/// Automatically decrements `in_flight` on drop.
#[derive(Debug)]
pub struct BudgetLease {
    state: Option<SharedBuckets>,
    key: Option<BucketKey>,
}

impl BudgetLease {
    fn noop() -> Self {
        Self {
            state: None,
            key: None,
        }
    }
}

impl Drop for BudgetLease {
    fn drop(&mut self) {
        if let (Some(state), Some(key)) = (self.state.as_ref(), self.key.take()) {
            if let Ok(mut guard) = state.lock() {
                if let Some(bucket) = guard.get_mut(&key) {
                    bucket.in_flight = bucket.in_flight.saturating_sub(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(org: &str, agent: &str) -> Principal {
        Principal {
            org_id: org.to_owned(),
            agent_id: agent.to_owned(),
            roles: Vec::new(),
        }
    }

    #[test]
    fn per_minute_rate_limit_enforced_and_slides() {
        let tracker = BudgetTracker::new(vec![BudgetRule {
            org_id: "acme".to_owned(),
            agent_id: "bot-1".to_owned(),
            server: "github".to_owned(),
            max_calls_per_minute: Some(3),
            max_concurrent_calls: None,
        }]);
        let p = principal("acme", "bot-1");
        let t0 = Instant::now();

        for _ in 0..3 {
            let lease = tracker.acquire_at(&p, "github", t0);
            assert!(lease.is_ok(), "first N calls within limit should succeed");
            drop(lease);
        }

        let err = tracker.acquire_at(&p, "github", t0 + Duration::from_secs(10));
        assert!(
            matches!(err, Err(KeelwayError::BudgetExceeded(_))),
            "N+1 call within 60s window must fail with BudgetExceeded"
        );

        let after_window = tracker.acquire_at(&p, "github", t0 + Duration::from_secs(61));
        assert!(
            after_window.is_ok(),
            "call after 60s sliding window expires should succeed"
        );
    }

    #[test]
    fn concurrent_limit_enforced_and_released_on_drop() {
        let tracker = BudgetTracker::new(vec![BudgetRule {
            org_id: "acme".to_owned(),
            agent_id: "bot-1".to_owned(),
            server: "postgres".to_owned(),
            max_calls_per_minute: Some(10),
            max_concurrent_calls: Some(2),
        }]);
        let p = principal("acme", "bot-1");

        let lease1 = tracker.acquire(&p, "postgres");
        assert!(lease1.is_ok());
        let lease2 = tracker.acquire(&p, "postgres");
        assert!(lease2.is_ok());

        let rejected = tracker.acquire(&p, "postgres");
        assert!(
            matches!(rejected, Err(KeelwayError::BudgetExceeded(_))),
            "3rd concurrent call must fail with BudgetExceeded"
        );

        drop(lease1);

        let lease3 = tracker.acquire(&p, "postgres");
        assert!(
            lease3.is_ok(),
            "dropping a BudgetLease must release its concurrent slot"
        );
    }

    #[test]
    fn specificity_precedence_overrides_wildcard() {
        let tracker = BudgetTracker::new(vec![
            BudgetRule {
                org_id: "acme".to_owned(),
                agent_id: "*".to_owned(),
                server: "*".to_owned(),
                max_calls_per_minute: Some(1),
                max_concurrent_calls: Some(1),
            },
            BudgetRule {
                org_id: "acme".to_owned(),
                agent_id: "vip-bot".to_owned(),
                server: "github".to_owned(),
                max_calls_per_minute: Some(3),
                max_concurrent_calls: Some(3),
            },
        ]);

        let vip = principal("acme", "vip-bot");
        let other = principal("acme", "regular-bot");

        let v1 = tracker.acquire(&vip, "github");
        let v2 = tracker.acquire(&vip, "github");
        let v3 = tracker.acquire(&vip, "github");
        assert!(v1.is_ok() && v2.is_ok() && v3.is_ok());
        assert!(matches!(
            tracker.acquire(&vip, "github"),
            Err(KeelwayError::BudgetExceeded(_))
        ));

        let o1 = tracker.acquire(&other, "github");
        assert!(o1.is_ok());
        assert!(matches!(
            tracker.acquire(&other, "github"),
            Err(KeelwayError::BudgetExceeded(_))
        ));
    }

    #[test]
    fn unconfigured_principal_or_server_has_no_limit() {
        let tracker = BudgetTracker::new(vec![BudgetRule {
            org_id: "acme".to_owned(),
            agent_id: "*".to_owned(),
            server: "*".to_owned(),
            max_calls_per_minute: Some(1),
            max_concurrent_calls: Some(1),
        }]);
        let other_org = principal("other-org", "bot-1");
        assert!(tracker.acquire(&other_org, "github").is_ok());
        assert!(tracker.acquire(&other_org, "github").is_ok());
    }
}
