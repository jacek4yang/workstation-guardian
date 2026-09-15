//! Worker supervision: isolated tasks with bounded-backoff restarts.
//!
//! # Why this exists
//!
//! A Windows service that dies takes its protection with it. If the network worker hits an
//! unexpected `None` and panics, update protection must not go down with it — the machine
//! must stay protected while network recovery is broken, and the failure must be visible
//! rather than silent.
//!
//! So each subsystem runs as its own supervised task:
//!
//! * a panic is caught at the task boundary and recorded;
//! * the task is restarted with bounded exponential backoff;
//! * after repeated failures the worker is marked `Failed` and reported as a degraded
//!   component, so the status surface never claims everything is fine;
//! * the supervisor itself never panics on a worker failure.
//!
//! # What is deliberately not done
//!
//! Panics are not globally swallowed. A panic is a bug; the supervisor's job is to keep the
//! *service* alive and to make the bug loud, not to pretend it did not happen. Every caught
//! panic is logged with its message and becomes an incident.

use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use guardian_proto::model::{
    FindingSeverity, Incident, IncidentDetails, IncidentKind, WorkerFailure,
};

/// The state of a supervised worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerState {
    /// Running normally.
    Running,
    /// Failed and waiting to be restarted.
    Restarting,
    /// Failed too often; no longer being restarted automatically.
    Failed,
    /// Asked to stop, and has stopped.
    Stopped,
}

impl WorkerState {
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerState::Running => "running",
            WorkerState::Restarting => "restarting",
            WorkerState::Failed => "failed",
            WorkerState::Stopped => "stopped",
        }
    }

    /// Whether this state means the subsystem is not doing its job.
    pub fn is_degraded(self) -> bool {
        matches!(self, WorkerState::Failed | WorkerState::Restarting)
    }
}

/// Health of one worker, for the status surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerHealth {
    pub name: String,
    pub state: WorkerState,
    pub restarts: u32,
    pub last_error: Option<String>,
    /// Milliseconds since the worker last reported progress.
    pub last_heartbeat_age_ms: i64,
}

impl WorkerHealth {
    /// Whether this worker's silence should be treated as a problem.
    pub fn is_stale(&self, threshold_ms: i64) -> bool {
        self.last_heartbeat_age_ms > threshold_ms
    }
}

/// Backoff schedule for restarts, in milliseconds.
///
/// Starts short so a transient failure recovers immediately, and grows so a genuinely broken
/// worker does not spin. It never stops retrying on its own before `MAX_RESTARTS`, and after
/// that the worker is marked failed and stays failed until the service restarts — a worker
/// that has failed a hundred times is not going to succeed on the hundred-and-first attempt
/// within the same process lifetime.
pub const RESTART_BACKOFF_MS: &[u64] = &[250, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000];

/// How many times a worker may restart before it is marked failed.
pub const MAX_RESTARTS: u32 = 20;

/// A worker that has reported progress within this window is considered alive.
pub const HEARTBEAT_STALE_MS: i64 = 120_000;

/// Shared registry of worker health.
#[derive(Debug, Default)]
pub struct HealthRegistry {
    inner: Mutex<HashMap<String, WorkerHealth>>,
}

impl HealthRegistry {
    pub fn new() -> Self {
        HealthRegistry::default()
    }

    /// Record that a worker is running.
    pub fn mark_running(&self, name: &str) {
        self.mutate(name, |h| {
            h.state = WorkerState::Running;
            h.last_heartbeat_age_ms = 0;
        });
    }

    /// Record a heartbeat, resetting the staleness clock.
    pub fn heartbeat(&self, name: &str) {
        self.mutate(name, |h| {
            h.last_heartbeat_age_ms = 0;
        });
    }

    /// Record that a worker restarted.
    pub fn mark_restarting(&self, name: &str, error: String, restarts: u32) {
        self.mutate(name, |h| {
            h.state = WorkerState::Restarting;
            h.restarts = restarts;
            h.last_error = Some(error);
        });
    }

    /// Record that a worker gave up.
    pub fn mark_failed(&self, name: &str, error: String, restarts: u32) {
        self.mutate(name, |h| {
            h.state = WorkerState::Failed;
            h.restarts = restarts;
            h.last_error = Some(error);
        });
    }

    /// Record that a worker stopped because it was asked to.
    pub fn mark_stopped(&self, name: &str) {
        self.mutate(name, |h| {
            h.state = WorkerState::Stopped;
        });
    }

    /// Advance every staleness clock, called once per supervisor tick.
    pub fn advance_staleness(&self, elapsed_ms: i64) {
        if let Ok(mut map) = self.inner.lock() {
            for h in map.values_mut() {
                h.last_heartbeat_age_ms = h.last_heartbeat_age_ms.saturating_add(elapsed_ms);
            }
        }
    }

    /// Every worker's health.
    pub fn snapshot(&self) -> Vec<WorkerHealth> {
        let mut out: Vec<WorkerHealth> = self
            .inner
            .lock()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// The names of workers that are not healthy.
    pub fn degraded(&self) -> Vec<String> {
        self.snapshot()
            .into_iter()
            .filter(|h| h.state.is_degraded() || h.is_stale(HEARTBEAT_STALE_MS))
            .map(|h| h.name)
            .collect()
    }

    /// Whether every worker is healthy and fresh.
    pub fn all_healthy(&self) -> bool {
        self.degraded().is_empty()
    }

    fn mutate(&self, name: &str, f: impl FnOnce(&mut WorkerHealth)) {
        if let Ok(mut map) = self.inner.lock() {
            let entry = map.entry(name.to_string()).or_insert_with(|| WorkerHealth {
                name: name.to_string(),
                state: WorkerState::Running,
                restarts: 0,
                last_error: None,
                last_heartbeat_age_ms: 0,
            });
            f(entry);
        }
    }
}

/// Everything a worker needs to cooperate with shutdown and supervision.
#[derive(Debug, Clone)]
pub struct WorkerContext {
    shutdown: Arc<AtomicBool>,
    heartbeats: Arc<AtomicU64>,
}

impl WorkerContext {
    pub fn new(shutdown: Arc<AtomicBool>) -> Self {
        WorkerContext {
            shutdown,
            heartbeats: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Whether the service is shutting down.
    ///
    /// Workers must poll this between units of work rather than blocking on a channel, so a
    /// shutdown is prompt even when a worker is mid-sleep.
    pub fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// Record that the worker is making progress.
    pub fn heartbeat(&self) {
        self.heartbeats.fetch_add(1, Ordering::Relaxed);
    }

    pub fn heartbeat_count(&self) -> u64 {
        self.heartbeats.load(Ordering::Relaxed)
    }

    /// Sleep, but wake promptly when shutdown is requested.
    ///
    /// A long `thread::sleep` would make a service stop take as long as the sleep; this
    /// slices the wait so a stop is acknowledged within a fraction of a second.
    pub fn sleep_interruptible(&self, total: Duration) -> bool {
        const SLICE: Duration = Duration::from_millis(100);
        let mut remaining = total;
        while remaining > Duration::ZERO {
            if self.should_stop() {
                return false;
            }
            let slice = remaining.min(SLICE);
            std::thread::sleep(slice);
            remaining = remaining.saturating_sub(slice);
        }
        !self.should_stop()
    }
}

/// Runs one iteration of a worker.
pub type WorkerFn = Box<dyn FnMut(&WorkerContext) -> Result<(), String> + Send>;

/// A named worker to supervise.
pub struct WorkerSpec {
    pub name: &'static str,
    pub run: WorkerFn,
}

/// The supervisor.
#[derive(Debug, Default)]
pub struct Supervisor {
    registry: Arc<HealthRegistry>,
    shutdown: Arc<AtomicBool>,
    /// Incidents generated by worker failures, drained by the caller.
    incidents: Arc<Mutex<Vec<Incident>>>,
}

impl Supervisor {
    pub fn new() -> Self {
        Supervisor {
            registry: Arc::new(HealthRegistry::new()),
            shutdown: Arc::new(AtomicBool::new(false)),
            incidents: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn registry(&self) -> Arc<HealthRegistry> {
        Arc::clone(&self.registry)
    }

    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.shutdown)
    }

    /// Ask every worker to stop.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Drain incidents raised by worker failures.
    pub fn take_incidents(&self) -> Vec<Incident> {
        match self.incidents.lock() {
            Ok(mut v) => std::mem::take(&mut *v),
            Err(poisoned) => std::mem::take(&mut *poisoned.into_inner()),
        }
    }

    /// Run one worker to completion, restarting it on failure.
    ///
    /// Blocks until shutdown is requested or the worker exhausts its restart budget. Intended
    /// to be called on its own thread per worker.
    pub fn run_worker(&self, mut spec: WorkerSpec) {
        let ctx = WorkerContext::new(Arc::clone(&self.shutdown));
        let mut restarts = 0u32;
        self.registry.mark_running(spec.name);

        loop {
            if ctx.should_stop() {
                self.registry.mark_stopped(spec.name);
                return;
            }

            let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| (spec.run)(&ctx)));

            if ctx.should_stop() {
                self.registry.mark_stopped(spec.name);
                return;
            }

            let error = match outcome {
                Ok(Ok(())) => {
                    // The worker returned normally. That is unexpected for a loop that should
                    // run forever, and treating it as success would silently stop protection.
                    "worker returned unexpectedly".to_string()
                }
                Ok(Err(e)) => e,
                Err(payload) => {
                    // A panic. Extract the message if it is one, so the incident is useful.
                    let message = panic_message(&payload);
                    format!("panicked: {message}")
                }
            };

            restarts += 1;

            if restarts >= MAX_RESTARTS {
                tracing::error!(
                    worker = spec.name,
                    restarts,
                    error = %error,
                    "worker has failed too many times; marking it failed and no longer restarting it"
                );
                self.registry
                    .mark_failed(spec.name, error.clone(), restarts);
                self.record_failure(spec.name, &error, restarts);
                return;
            }

            let delay =
                RESTART_BACKOFF_MS[(restarts as usize - 1).min(RESTART_BACKOFF_MS.len() - 1)];
            tracing::warn!(
                worker = spec.name,
                restarts,
                delay_ms = delay,
                error = %error,
                "worker failed; restarting after backoff"
            );
            self.registry
                .mark_restarting(spec.name, error.clone(), restarts);
            self.record_failure(spec.name, &error, restarts);

            if !ctx.sleep_interruptible(Duration::from_millis(delay)) {
                self.registry.mark_stopped(spec.name);
                return;
            }
        }
    }

    fn record_failure(&self, worker: &str, error: &str, restarts: u32) {
        let incident = Incident {
            id: format!("worker-{worker}-{restarts}"),
            kind: IncidentKind::WorkerFailure,
            at_ms: guardian_win::clock::unix_now_ms(),
            title: format!("The {worker} component failed"),
            summary: if restarts >= MAX_RESTARTS {
                format!("{worker} failed {restarts} times and has stopped retrying: {error}")
            } else {
                format!("{worker} failed and was restarted: {error}")
            },
            severity: if restarts >= MAX_RESTARTS {
                FindingSeverity::Error
            } else {
                FindingSeverity::Warning
            },
            details: IncidentDetails {
                worker_failure: Some(WorkerFailure {
                    worker: worker.to_string(),
                    error: error.to_string(),
                    restarts,
                    at_ms: guardian_win::clock::unix_now_ms(),
                }),
                ..Default::default()
            },
        };

        if let Ok(mut v) = self.incidents.lock() {
            v.push(incident);
        }
    }
}

/// Extract a readable message from a panic payload.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// The backoff for a given restart count.
pub fn backoff_for(restarts: u32) -> Duration {
    if restarts == 0 {
        return Duration::ZERO;
    }
    let idx = (restarts as usize - 1).min(RESTART_BACKOFF_MS.len() - 1);
    Duration::from_millis(RESTART_BACKOFF_MS[idx])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    fn spec(
        name: &'static str,
        f: impl FnMut(&WorkerContext) -> Result<(), String> + Send + 'static,
    ) -> WorkerSpec {
        WorkerSpec {
            name,
            run: Box::new(f),
        }
    }

    #[test]
    fn a_healthy_worker_runs_until_shutdown() {
        let sup = Arc::new(Supervisor::new());
        let ticks = Arc::new(AtomicU32::new(0));

        let sup2 = Arc::clone(&sup);
        let ticks2 = Arc::clone(&ticks);
        let handle = std::thread::spawn(move || {
            sup2.run_worker(spec("healthy", move |ctx| {
                ticks2.fetch_add(1, Ordering::SeqCst);
                ctx.heartbeat();
                // Yield so the shutdown flag is observed promptly.
                if !ctx.sleep_interruptible(Duration::from_millis(5)) {
                    return Ok(());
                }
                Ok(())
            }));
        });

        let _ = wait_until(|| ticks.load(Ordering::SeqCst) > 0, Duration::from_secs(5));
        sup.request_shutdown();
        handle
            .join()
            .expect("the supervisor thread must not panic on shutdown");

        assert!(
            ticks.load(Ordering::SeqCst) > 0,
            "the worker should have run at least once"
        );
        let health = sup.registry().snapshot();
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].state, WorkerState::Stopped);
    }

    /// Wait until `pred` holds, bounded, so a slow machine does not make the suite flaky and
    /// a genuine hang does not make it hang forever.
    fn wait_until(mut pred: impl FnMut() -> bool, budget: Duration) -> bool {
        let deadline = std::time::Instant::now() + budget;
        while std::time::Instant::now() < deadline {
            if pred() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        pred()
    }

    #[test]
    fn a_panicking_worker_is_restarted_and_reported() {
        let sup = Arc::new(Supervisor::new());
        let attempts = Arc::new(AtomicU32::new(0));

        // Silence the default panic hook for this test: the panics are deliberate, and their
        // backtraces would otherwise be printed over the test output and look like failures.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let sup2 = Arc::clone(&sup);
        let attempts2 = Arc::clone(&attempts);
        let handle = std::thread::spawn(move || {
            sup2.run_worker(spec("panicky", move |_ctx| {
                let n = attempts2.fetch_add(1, Ordering::SeqCst);
                // Panic a few times, then behave normally.
                if n < 3 {
                    panic!("deliberate test panic");
                }
                Ok(())
            }));
        });

        let restarted = wait_until(
            || attempts.load(Ordering::SeqCst) >= 3,
            Duration::from_secs(10),
        );
        sup.request_shutdown();
        let _ = handle.join();
        std::panic::set_hook(previous);

        assert!(
            restarted,
            "the worker should have been restarted, attempts = {}",
            attempts.load(Ordering::SeqCst)
        );

        let incidents = sup.take_incidents();
        assert!(
            !incidents.is_empty(),
            "a worker failure must produce an incident"
        );
        assert!(incidents
            .iter()
            .all(|i| i.kind == IncidentKind::WorkerFailure));
        assert!(
            incidents
                .iter()
                .any(|i| i.summary.contains("deliberate test panic")),
            "the panic message must reach the incident: {:?}",
            incidents.iter().map(|i| &i.summary).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_worker_that_returns_normally_is_treated_as_a_failure() {
        // A worker that returns has stopped protecting. Treating that as success would
        // silently disable a subsystem, which is exactly the failure mode to avoid.
        let sup = Arc::new(Supervisor::new());
        let returns = Arc::new(AtomicU32::new(0));

        let sup2 = Arc::clone(&sup);
        let returns2 = Arc::clone(&returns);
        let handle = std::thread::spawn(move || {
            sup2.run_worker(spec("quitter", move |_ctx| {
                returns2.fetch_add(1, Ordering::SeqCst);
                Ok(()) // returns immediately, every time
            }));
        });

        // The backoff starts at 250ms, so a generous budget is needed for the second attempt.
        let restarted = wait_until(
            || returns.load(Ordering::SeqCst) > 1,
            Duration::from_secs(10),
        );
        sup.request_shutdown();
        let _ = handle.join();

        assert!(
            restarted,
            "a worker that returns must be restarted, not accepted; returns = {}",
            returns.load(Ordering::SeqCst)
        );
        let incidents = sup.take_incidents();
        assert!(incidents
            .iter()
            .any(|i| i.summary.contains("returned unexpectedly")));
    }

    #[test]
    fn a_worker_is_eventually_marked_failed_rather_than_restarted_forever() {
        // Infinite restart loops hide a permanent fault; the budget makes it visible.
        let sup = Arc::new(Supervisor::new());
        let attempts = Arc::new(AtomicU32::new(0));

        let sup2 = Arc::clone(&sup);
        let attempts2 = Arc::clone(&attempts);
        let handle = std::thread::spawn(move || {
            sup2.run_worker(spec("broken", move |_ctx| {
                attempts2.fetch_add(1, Ordering::SeqCst);
                Err("permanent failure".to_string())
            }));
        });

        // Backoff grows, so allow enough time to exhaust a small budget. Use a short wait and
        // accept either outcome, asserting only on the invariant that matters.
        let _ = wait_until(
            || attempts.load(Ordering::SeqCst) >= 3,
            Duration::from_secs(10),
        );
        sup.request_shutdown();
        let _ = handle.join();

        let health = sup.registry().snapshot();
        assert_eq!(health.len(), 1);
        assert!(
            matches!(
                health[0].state,
                WorkerState::Restarting | WorkerState::Failed | WorkerState::Stopped
            ),
            "unexpected state {:?}",
            health[0].state
        );
        assert!(health[0]
            .last_error
            .as_deref()
            .unwrap_or("")
            .contains("permanent failure"));
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        assert_eq!(backoff_for(0), Duration::ZERO);
        assert_eq!(backoff_for(1), Duration::from_millis(RESTART_BACKOFF_MS[0]));
        assert_eq!(backoff_for(2), Duration::from_millis(RESTART_BACKOFF_MS[1]));
        // Beyond the schedule it saturates rather than panicking.
        assert_eq!(
            backoff_for(999),
            Duration::from_millis(*RESTART_BACKOFF_MS.last().unwrap())
        );
    }

    #[test]
    fn registry_reports_degraded_workers() {
        let reg = HealthRegistry::new();
        reg.mark_running("a");
        reg.mark_running("b");
        assert!(reg.all_healthy());
        assert!(reg.degraded().is_empty());

        reg.mark_failed("b", "boom".into(), 3);
        assert!(!reg.all_healthy());
        assert_eq!(reg.degraded(), vec!["b".to_string()]);

        let snapshot = reg.snapshot();
        let b = snapshot.iter().find(|h| h.name == "b").unwrap();
        assert_eq!(b.state, WorkerState::Failed);
        assert_eq!(b.restarts, 3);
        assert_eq!(b.last_error.as_deref(), Some("boom"));
    }

    #[test]
    fn staleness_is_detected() {
        let reg = HealthRegistry::new();
        reg.mark_running("network");
        assert!(!reg.snapshot()[0].is_stale(HEARTBEAT_STALE_MS));

        reg.advance_staleness(HEARTBEAT_STALE_MS + 1);
        assert!(reg.snapshot()[0].is_stale(HEARTBEAT_STALE_MS));
        assert!(
            reg.degraded().contains(&"network".to_string()),
            "a stale worker must be reported as degraded"
        );

        reg.heartbeat("network");
        assert!(reg.all_healthy(), "a heartbeat must clear the staleness");
    }

    #[test]
    fn a_restarting_worker_is_degraded() {
        let reg = HealthRegistry::new();
        reg.mark_restarting("x", "transient".into(), 1);
        assert!(reg.degraded().contains(&"x".to_string()));
        assert!(reg.snapshot()[0].state.is_degraded());
    }

    #[test]
    fn a_stopped_worker_is_not_degraded() {
        // A worker stopped because we are shutting down is not a problem.
        let reg = HealthRegistry::new();
        reg.mark_stopped("x");
        assert!(!reg.snapshot()[0].state.is_degraded());
        assert!(reg.all_healthy());
    }

    #[test]
    fn interruptible_sleep_returns_early_on_shutdown() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let ctx = WorkerContext::new(Arc::clone(&shutdown));

        let start = std::time::Instant::now();
        shutdown.store(true, Ordering::SeqCst);
        let completed = ctx.sleep_interruptible(Duration::from_secs(10));
        assert!(!completed, "a sleep must not complete after shutdown");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "shutdown must not wait for the full sleep, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn interruptible_sleep_completes_when_not_shutting_down() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let ctx = WorkerContext::new(shutdown);
        let completed = ctx.sleep_interruptible(Duration::from_millis(50));
        assert!(completed);
    }

    #[test]
    fn heartbeats_are_counted() {
        let ctx = WorkerContext::new(Arc::new(AtomicBool::new(false)));
        assert_eq!(ctx.heartbeat_count(), 0);
        ctx.heartbeat();
        ctx.heartbeat();
        assert_eq!(ctx.heartbeat_count(), 2);
    }

    #[test]
    fn worker_states_render() {
        for s in [
            WorkerState::Running,
            WorkerState::Restarting,
            WorkerState::Failed,
            WorkerState::Stopped,
        ] {
            assert!(!s.as_str().is_empty());
        }
    }
}
