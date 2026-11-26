use crate::core::KeelwayError;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
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

#[derive(Debug, Clone, Copy)]
struct ServerCircuit {
    state: InternalState,
    generation: u64,
}

#[derive(Debug)]
struct CircuitBreakerInner {
    failure_threshold: u32,
    cooldown: Duration,
    servers: Mutex<BTreeMap<String, ServerCircuit>>,
}

/// Per-server bounded circuit breaker protecting gateway capacity when upstreams degrade.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    inner: Arc<CircuitBreakerInner>,
}

/// RAII permit for an in-flight upstream call governed by [`CircuitBreaker`].
///
/// Captures the circuit `generation` at dispatch time so stale pre-trip completions cannot
/// corrupt a newly opened circuit, and releases an active `HalfOpen` probe slot on drop.
#[derive(Debug)]
pub struct CircuitPermit {
    breaker: CircuitBreaker,
    server: String,
    generation: u64,
    active: bool,
}

impl CircuitPermit {
    /// Records a successful call for the captured generation, closing the circuit if applicable.
    pub fn record_success(mut self) {
        self.active = false;
        self.breaker
            .record_success_gen(&self.server, self.generation);
    }

    /// Records a failed call for the captured generation, tripping the circuit when threshold is reached.
    pub fn record_failure(mut self) {
        self.active = false;
        self.breaker
            .record_failure_gen(&self.server, self.generation);
    }

    /// Releases the permit without recording a success or failure (e.g. non-trip errors).
    pub fn release(mut self) {
        self.active = false;
        self.breaker.release_probe(&self.server, self.generation);
    }
}

impl Drop for CircuitPermit {
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            self.breaker.release_probe(&self.server, self.generation);
        }
    }
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
            inner: Arc::new(CircuitBreakerInner {
                failure_threshold: failure_threshold.max(1),
                cooldown,
                servers: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    fn lock_servers(&self) -> MutexGuard<'_, BTreeMap<String, ServerCircuit>> {
        // Recover from lock poisoning rather than panicking in production paths.
        self.inner
            .servers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Checks whether a call to `server` may proceed, transitioning `Open` -> `HalfOpen` after cooldown.
    pub fn before_call(&self, server: &str) -> Result<CircuitPermit, KeelwayError> {
        let mut servers = self.lock_servers();
        let generation = match servers.get_mut(server) {
            None => 0,
            Some(entry) => match &mut entry.state {
                InternalState::Closed { .. } => entry.generation,
                InternalState::Open { opened_at } => {
                    if opened_at.elapsed() >= self.inner.cooldown {
                        entry.state = InternalState::HalfOpen {
                            probe_in_flight: true,
                        };
                        entry.generation = entry.generation.wrapping_add(1);
                        entry.generation
                    } else {
                        return Err(KeelwayError::UpstreamUnavailable(format!(
                            "circuit breaker open for server '{server}'"
                        )));
                    }
                }
                InternalState::HalfOpen { probe_in_flight } => {
                    if *probe_in_flight {
                        return Err(KeelwayError::UpstreamUnavailable(format!(
                            "circuit breaker half-open probe in flight for '{server}'"
                        )));
                    } else {
                        *probe_in_flight = true;
                        entry.generation
                    }
                }
            },
        };

        Ok(CircuitPermit {
            breaker: self.clone(),
            server: server.to_owned(),
            generation,
            active: true,
        })
    }

    /// Records a successful call to `server`, resetting its circuit to `Closed`.
    pub fn record_success(&self, server: &str) {
        let mut servers = self.lock_servers();
        let generation = servers.get(server).map(|e| e.generation).unwrap_or(0);
        servers.insert(
            server.to_owned(),
            ServerCircuit {
                state: InternalState::Closed { failures: 0 },
                generation,
            },
        );
    }

    /// Records a successful call to `server` only if `generation` matches the current circuit generation.
    pub fn record_success_gen(&self, server: &str, generation: u64) {
        let mut servers = self.lock_servers();
        let Some(entry) = servers.get_mut(server) else {
            return;
        };
        if entry.generation != generation {
            return;
        }
        entry.state = InternalState::Closed { failures: 0 };
    }

    /// Records a failed call to `server`, tripping to `Open` when threshold is reached or a probe fails.
    pub fn record_failure(&self, server: &str) {
        let mut servers = self.lock_servers();
        let generation = servers.get(server).map(|e| e.generation).unwrap_or(0);
        self.record_failure_locked(&mut servers, server, generation);
    }

    /// Records a failed call to `server` only if `generation` matches the current circuit generation.
    pub fn record_failure_gen(&self, server: &str, generation: u64) {
        let mut servers = self.lock_servers();
        self.record_failure_locked(&mut servers, server, generation);
    }

    fn record_failure_locked(
        &self,
        servers: &mut BTreeMap<String, ServerCircuit>,
        server: &str,
        generation: u64,
    ) {
        match servers.get_mut(server) {
            Some(entry) => {
                if entry.generation != generation {
                    return;
                }
                match &mut entry.state {
                    InternalState::Closed { failures } => {
                        *failures = failures.saturating_add(1);
                        if *failures >= self.inner.failure_threshold {
                            entry.state = InternalState::Open {
                                opened_at: Instant::now(),
                            };
                            entry.generation = entry.generation.wrapping_add(1);
                        }
                    }
                    InternalState::HalfOpen { .. } | InternalState::Open { .. } => {
                        entry.state = InternalState::Open {
                            opened_at: Instant::now(),
                        };
                        entry.generation = entry.generation.wrapping_add(1);
                    }
                }
            }
            None => {
                if generation != 0 {
                    return;
                }
                let entry = if self.inner.failure_threshold <= 1 {
                    ServerCircuit {
                        state: InternalState::Open {
                            opened_at: Instant::now(),
                        },
                        generation: 1,
                    }
                } else {
                    ServerCircuit {
                        state: InternalState::Closed { failures: 1 },
                        generation: 0,
                    }
                };
                servers.insert(server.to_owned(), entry);
            }
        }
    }

    fn release_probe(&self, server: &str, generation: u64) {
        let mut servers = self.lock_servers();
        let Some(entry) = servers.get_mut(server) else {
            return;
        };
        if entry.generation != generation {
            return;
        }
        if let InternalState::HalfOpen { probe_in_flight } = &mut entry.state {
            *probe_in_flight = false;
        }
    }

    /// Returns a snapshot of `(server_alias, CircuitState)` sorted by server alias.
    pub fn snapshot(&self) -> Vec<(String, CircuitState)> {
        let servers = self.lock_servers();
        servers
            .iter()
            .map(|(alias, entry)| {
                let public_state = match entry.state {
                    InternalState::Open { opened_at }
                        if opened_at.elapsed() >= self.inner.cooldown =>
                    {
                        CircuitState::HalfOpen
                    }
                    other => other.as_public(),
                };
                (alias.clone(), public_state)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trips_after_threshold_and_fails_fast() -> Result<(), KeelwayError> {
        let breaker = CircuitBreaker::new(3, Duration::from_secs(30));

        breaker.before_call("alpha")?.record_failure();
        breaker.before_call("alpha")?.record_failure();
        breaker.before_call("alpha")?.record_failure();

        let err = breaker.before_call("alpha");
        assert!(matches!(err, Err(KeelwayError::UpstreamUnavailable(_))));
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Open)]
        );

        // Other servers remain unaffected.
        assert!(breaker.before_call("beta").is_ok());
        Ok(())
    }

    #[test]
    fn transitions_to_half_open_after_cooldown_and_recovers_on_success() -> Result<(), KeelwayError>
    {
        let breaker = CircuitBreaker::new(2, Duration::from_millis(20));

        breaker.before_call("alpha")?.record_failure();
        breaker.before_call("alpha")?.record_failure();
        assert!(matches!(
            breaker.before_call("alpha"),
            Err(KeelwayError::UpstreamUnavailable(_))
        ));

        std::thread::sleep(Duration::from_millis(30));

        // Snapshot reports HalfOpen after cooldown even before a probe is dispatched.
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::HalfOpen)]
        );

        // First call after cooldown enters HalfOpen and acquires the single probe slot.
        let probe = breaker.before_call("alpha")?;
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
        probe.record_success();
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Closed)]
        );
        assert!(breaker.before_call("alpha").is_ok());
        Ok(())
    }

    #[test]
    fn reopens_on_half_open_probe_failure() -> Result<(), KeelwayError> {
        let breaker = CircuitBreaker::new(1, Duration::from_millis(15));

        breaker.before_call("alpha")?.record_failure();
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Open)]
        );

        std::thread::sleep(Duration::from_millis(25));

        let probe = breaker.before_call("alpha")?;
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::HalfOpen)]
        );

        probe.record_failure();
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Open)]
        );
        assert!(matches!(
            breaker.before_call("alpha"),
            Err(KeelwayError::UpstreamUnavailable(_))
        ));
        Ok(())
    }

    #[test]
    fn stale_generation_success_does_not_reset_open_circuit() -> Result<(), KeelwayError> {
        let breaker = CircuitBreaker::new(2, Duration::from_secs(30));

        let stale_permit = breaker.before_call("alpha")?;
        breaker.before_call("alpha")?.record_failure();
        breaker.before_call("alpha")?.record_failure();

        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Open)]
        );

        // Stale pre-trip request completing with success must be ignored.
        stale_permit.record_success();
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Open)]
        );
        assert!(matches!(
            breaker.before_call("alpha"),
            Err(KeelwayError::UpstreamUnavailable(_))
        ));
        Ok(())
    }

    #[test]
    fn dropped_half_open_probe_releases_probe_in_flight() -> Result<(), KeelwayError> {
        let breaker = CircuitBreaker::new(1, Duration::from_millis(15));

        breaker.before_call("alpha")?.record_failure();
        std::thread::sleep(Duration::from_millis(25));

        let probe = breaker.before_call("alpha")?;
        assert!(matches!(
            breaker.before_call("alpha"),
            Err(KeelwayError::UpstreamUnavailable(_))
        ));

        // Dropping the probe (e.g. cancelled future) frees the HalfOpen slot.
        drop(probe);

        let next_probe = breaker.before_call("alpha")?;
        next_probe.record_success();
        assert_eq!(
            breaker.snapshot(),
            vec![("alpha".to_owned(), CircuitState::Closed)]
        );
        Ok(())
    }
}
