use crate::core::KeelwayError;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

const DEFAULT_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(15);

/// Observable state of a per-server circuit breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Copy)]
enum InternalState {
    Closed { failures: u32 },
    Open { opened_at: Instant },
    HalfOpen { probe_in_flight: bool },
}

impl InternalState {
    fn as_public(&self) -> CircuitState {
        match self {
            Self::Closed { .. } => CircuitState::Closed,
            Self::Open { .. } => CircuitState::Open,
            Self::HalfOpen { .. } => CircuitState::HalfOpen,
        }
    }
}

/// Per-server bounded circuit breaker protecting gateway capacity when upstreams degrade.
#[derive(Debug)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown: Duration,
    servers: Mutex<BTreeMap<String, InternalState>>,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(DEFAULT_FAILURE_THRESHOLD, DEFAULT_COOLDOWN)
    }
}

impl CircuitBreaker {
    /// Creates a new circuit breaker with the given consecutive failure threshold and open cooldown.
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cooldown,
            servers: Mutex::new(BTreeMap::new()),
        }
    }

    fn lock_servers(&self) -> MutexGuard<'_, BTreeMap<String, InternalState>> {
        // Recover from lock poisoning rather than panicking in production paths.
        self.servers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Checks whether a call to `server` may proceed, transitioning `Open` -> `HalfOpen` after cooldown.
    pub fn before_call(&self, server: &str) -> Result<(), KeelwayError> {
        let mut servers = self.lock_servers();
        let Some(state) = servers.get_mut(server) else {
            return Ok(());
        };

        match state {
            InternalState::Closed { .. } => Ok(()),
            InternalState::Open { opened_at } => {
                if opened_at.elapsed() >= self.cooldown {
                    *state = InternalState::HalfOpen {
                        probe_in_flight: true,
                    };
                    Ok(())
                } else {
                    Err(KeelwayError::UpstreamUnavailable(format!(
                        "circuit breaker open for server '{server}'"
                    )))
                }
            }
            InternalState::HalfOpen { probe_in_flight } => {
                if *probe_in_flight {
                    Err(KeelwayError::UpstreamUnavailable(format!(
                        "circuit breaker half-open probe in flight for '{server}'"
                    )))
                } else {
                    *probe_in_flight = true;
                    Ok(())
                }
            }
        }
    }

    /// Records a successful call to `server`, resetting its circuit to `Closed`.
    pub fn record_success(&self, server: &str) {
        let mut servers = self.lock_servers();
        servers.insert(server.to_owned(), InternalState::Closed { failures: 0 });
    }

    /// Records a failed call to `server`, tripping to `Open` when threshold is reached or a probe fails.
    pub fn record_failure(&self, server: &str) {
        let mut servers = self.lock_servers();
        match servers.get_mut(server) {
            Some(InternalState::Closed { failures }) => {
                *failures = failures.saturating_add(1);
                if *failures >= self.failure_threshold {
                    servers.insert(
                        server.to_owned(),
                        InternalState::Open {
                            opened_at: Instant::now(),
                        },
                    );
                }
            }
            Some(InternalState::HalfOpen { .. }) | Some(InternalState::Open { .. }) => {
                servers.insert(
                    server.to_owned(),
                    InternalState::Open {
                        opened_at: Instant::now(),
                    },
                );
            }
            None => {
                let next = if self.failure_threshold <= 1 {
                    InternalState::Open {
                        opened_at: Instant::now(),
                    }
                } else {
                    InternalState::Closed { failures: 1 }
                };
                servers.insert(server.to_owned(), next);
            }
        }
    }

    /// Returns a snapshot of `(server_alias, CircuitState)` sorted by server alias.
    pub fn snapshot(&self) -> Vec<(String, CircuitState)> {
        let servers = self.lock_servers();
        servers
            .iter()
            .map(|(alias, state)| (alias.clone(), state.as_public()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_after_threshold_and_fails_fast() {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(30));

        assert!(breaker.before_call("alpha").is_ok());
        breaker.record_failure("alpha");
        assert!(breaker.before_call("alpha").is_ok());
        breaker.record_failure("alpha");
        assert!(breaker.before_call("alpha").is_ok());
        breaker.record_failure("alpha");

        let err = breaker.before_call("alpha");
        assert!(matches!(err, Err(KeelwayError::UpstreamUnavailable(_))));
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Open)]
        );

        // Other servers remain unaffected.
        assert!(breaker.before_call("beta").is_ok());
    }

    #[test]
    fn transitions_to_half_open_after_cooldown_and_recovers_on_success() {
        let breaker = CircuitBreaker::new(2, Duration::from_millis(20));

        breaker.record_failure("alpha");
        breaker.record_failure("alpha");
        assert!(matches!(
            breaker.before_call("alpha"),
            Err(KeelwayError::UpstreamUnavailable(_))
        ));

        std::thread::sleep(Duration::from_millis(30));

        // First call after cooldown enters HalfOpen and acquires the single probe slot.
        assert!(breaker.before_call("alpha").is_ok());
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::HalfOpen)]
        );

        // Concurrent calls while probe is in flight fail fast.
        assert!(matches!(
            breaker.before_call("alpha"),
            Err(KeelwayError::UpstreamUnavailable(_))
        ));

        // Probe succeeds -> circuit closes.
        breaker.record_success("alpha");
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Closed)]
        );
        assert!(breaker.before_call("alpha").is_ok());
    }

    #[test]
    fn reopens_on_half_open_probe_failure() {
        let breaker = CircuitBreaker::new(1, Duration::from_millis(15));

        breaker.record_failure("alpha");
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Open)]
        );

        std::thread::sleep(Duration::from_millis(25));

        assert!(breaker.before_call("alpha").is_ok());
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::HalfOpen)]
        );

        breaker.record_failure("alpha");
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Open)]
        );
        assert!(matches!(
            breaker.before_call("alpha"),
            Err(KeelwayError::UpstreamUnavailable(_))
        ));
    }
}
