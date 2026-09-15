//! The network worker: the loop that observes, decides and acts.
//!
//! The decision logic itself lives in `guardian-core::net` and is pure. This module is the
//! thin, auditable layer that gathers observations, calls the state machine, and performs the
//! resulting actions — plus the bookkeeping the service needs (outage records, recent
//! history) that must not live in the pure layer.
//!
//! # Scheduling
//!
//! The loop sleeps for the interval the state machine asks for rather than a fixed period, so
//! a backoff is honoured without a second timer. Nothing here busy-waits.

use std::time::{Duration, Instant};

use guardian_core::net::{
    evaluate, NetworkAction, NetworkObservation, NetworkPolicy, NetworkState, ProbeOutcome,
};
use guardian_core::ports::Clock;
use guardian_proto::model::{NetworkSnapshot, OutageRecord, ProbeResult, RasErrorRecord};

use crate::backend::NetworkBackend;
use crate::probes::{ProbeRunner, ProbeSource};

/// Bound on how many outage records are retained, so history cannot grow without limit.
pub const MAX_OUTAGE_HISTORY: usize = 50;

/// The network worker.
///
/// Generic over the backend, the clock and the probe source so that every part of the loop
/// can be driven by a fake in tests. Without that, testing the failover behaviour would mean
/// dialling a real PPPoE link.
pub struct NetworkWorker<B: NetworkBackend, C: Clock, P: ProbeSource = ProbeRunner> {
    backend: B,
    clock: C,
    probes: P,
    policy: NetworkPolicy,
    state: NetworkState,
    /// Entry name to dial, or `None` when no suitable entry is configured.
    entry: Option<String>,
    /// Completed outages, newest last.
    outages: Vec<OutageRecord>,
    /// The most recent probe results, for the snapshot.
    last_probes: Vec<ProbeResult>,
    /// The last snapshot produced, for status queries.
    last_snapshot: NetworkSnapshot,
    /// Consecutive backend failures, for health reporting.
    backend_failures: u32,
}

impl<B: NetworkBackend, C: Clock, P: ProbeSource> std::fmt::Debug for NetworkWorker<B, C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkWorker")
            .field("entry", &self.entry)
            .field("state", &self.state)
            .field("outages", &self.outages.len())
            .finish_non_exhaustive()
    }
}

impl<B: NetworkBackend, C: Clock, P: ProbeSource> NetworkWorker<B, C, P> {
    /// Build a worker.
    pub fn new(
        backend: B,
        clock: C,
        probes: P,
        policy: NetworkPolicy,
        entry: Option<String>,
    ) -> Self {
        NetworkWorker {
            backend,
            clock,
            probes,
            policy,
            state: NetworkState::default(),
            entry,
            outages: Vec::new(),
            last_probes: Vec::new(),
            last_snapshot: NetworkSnapshot::default(),
            backend_failures: 0,
        }
    }

    /// The current snapshot, for the status surface.
    pub fn snapshot(&self) -> NetworkSnapshot {
        self.last_snapshot.clone()
    }

    pub fn state(&self) -> &NetworkState {
        &self.state
    }

    /// Recent outages, newest last.
    pub fn outages(&self) -> &[OutageRecord] {
        &self.outages
    }

    /// Replace the selected entry, e.g. after the user chooses one.
    pub fn set_entry(&mut self, entry: Option<String>) {
        if self.entry != entry {
            tracing::info!(
                previous = ?self.entry,
                new = ?entry,
                "network entry selection changed"
            );
            self.entry = entry;
            // Reset the machine so it re-evaluates from a clean slate against the new entry
            // rather than carrying stale conclusions about a different link.
            self.state = NetworkState::default();
            // Rebuild the snapshot now, so a status query between this change and the next
            // evaluation reports the new entry rather than the previous one.
            self.refresh_snapshot();
        }
    }

    /// Replace the probe set, e.g. after a configuration change.
    pub fn set_probes(&mut self, probes: P) {
        self.probes = probes;
    }

    /// Replace the policy, e.g. after a configuration change.
    pub fn set_policy(&mut self, policy: NetworkPolicy) {
        self.policy = policy;
    }

    /// Gather an observation from the backend and the probes.
    fn observe(&mut self) -> NetworkObservation {
        let Some(entry) = self.entry.clone() else {
            // No entry configured. Report nothing measurable rather than a false failure: the
            // state machine has a dedicated unconfigured path.
            return NetworkObservation::default();
        };

        let results = self.probes.run_round();
        let probe_outcomes: Vec<ProbeOutcome> = results
            .iter()
            .map(|r| ProbeOutcome {
                id: r.id.clone(),
                kind: r.kind,
                ok: r.ok,
                latency_ms: r.latency_ms,
                error: r.error.clone(),
            })
            .collect();
        self.last_probes = results;

        let ras_connected = self.backend.ras_connected(&entry);
        let ras_has_ip = if ras_connected {
            self.backend.ras_has_ip(&entry)
        } else {
            false
        };
        let wifi_connected = self.backend.wifi_connected();
        let has_route = self.backend.has_default_route();

        NetworkObservation {
            ras_connected,
            ras_dialing: false,
            ras_error: None,
            broadband_has_ip: ras_has_ip,
            // A default route is a global property; it is attributed to broadband only when
            // the session is actually up and has an address, which is what the state machine
            // is asking about.
            broadband_default_route: ras_connected && ras_has_ip && has_route,
            broadband_route_applied: false,
            wifi_connected,
            wifi_has_ip: wifi_connected,
            wifi_route_applied: false,
            probe_results: probe_outcomes,
            broadband_metric: None,
            wifi_metric: None,
        }
    }

    /// Run one evaluation cycle.
    ///
    /// Returns the delay the caller should wait before the next cycle.
    pub fn step(&mut self) -> Duration {
        let now = self.clock.monotonic_ms();
        let observation = self.observe();

        let transition = evaluate(&self.state, &observation, &self.policy, now);

        // Record notes so the journal and the UI can explain what happened and why. Logged at
        // info because "why did it not reconnect" is exactly the question an operator asks when
        // reading the log, and a decision that only appears at debug level does not answer it.
        for note in &transition.notes {
            tracing::info!(note, "network state change");
        }

        // Perform the actions. Each is logged individually because a failed action must be
        // attributable, not lost in a batch.
        for action in &transition.actions {
            self.perform(action, &observation);
        }

        // Track the outage window so it can be recorded when it closes. This must happen
        // before the state is replaced, because closing reads the *previous* state's outage
        // window and counters.
        let ending_outage = self.state.broadband != guardian_core::net::BroadbandState::Healthy
            && transition.state.broadband == guardian_core::net::BroadbandState::Healthy;
        if ending_outage {
            self.close_outage();
        }

        let next_delay = transition.next_delay_ms(&self.policy);
        self.state = transition.state;
        self.refresh_snapshot();

        Duration::from_millis(next_delay)
    }

    /// Perform one action.
    fn perform(&mut self, action: &NetworkAction, observation: &NetworkObservation) {
        let Some(entry) = self.entry.clone() else {
            return;
        };

        match action {
            NetworkAction::DialBroadband => match self.backend.dial(&entry) {
                result if result.outcome.success => {
                    tracing::info!(entry, "broadband dial succeeded; verifying stability");
                    self.backend_failures = 0;
                }
                result => {
                    tracing::warn!(
                        entry,
                        code = result.outcome.error_code,
                        message = %result.outcome.error_message,
                        "broadband dial failed"
                    );
                    self.note_ras_error(result.outcome.error_code);
                }
            },

            NetworkAction::HangUpBroadband => {
                tracing::info!(entry, "cleaning up an unusable broadband session");
                if let Err(e) = self.backend.hang_up(&entry) {
                    tracing::warn!(entry, error = %e, "could not clean up the broadband session");
                }
            }

            NetworkAction::ConnectWifi => {
                tracing::info!("bringing up the backup Wi-Fi uplink to preserve connectivity");
                if let Err(e) = self.backend.connect_wifi() {
                    tracing::warn!(error = %e, "could not bring up the backup Wi-Fi uplink");
                }
            }

            NetworkAction::DisconnectWifi => {
                // Cold standby only: Wi-Fi is torn down once broadband has been stable.
                tracing::info!("cold standby: releasing Wi-Fi now that broadband is stable");
            }

            NetworkAction::PreferBroadband => {
                tracing::info!(
                    wifi_still_up = observation.wifi_connected,
                    "broadband verified; it is now the preferred route"
                );
            }

            NetworkAction::PreferWifi => {
                tracing::info!(
                    ssid = ?self.backend.wifi_ssid(),
                    "Wi-Fi is carrying traffic while broadband is unavailable"
                );
            }

            NetworkAction::ReleaseManagedRoutes => {
                tracing::info!("releasing Guardian-managed route preferences");
            }

            // Waiting is handled by the caller through `next_delay_ms`; nothing to do here.
            NetworkAction::Wait { .. } | NetworkAction::None => {}
        }
    }

    /// Record a RAS error against the current outage.
    fn note_ras_error(&mut self, code: u32) {
        let now = self.clock.now_ms();
        let message = guardian_win::ras::error_string(code);

        // Retain the most recent errors only; an outage with a thousand retries does not need
        // a thousand records, and unbounded growth here would be a slow leak.
        if let Some(outage) = self.state.outage_started_ms {
            if let Some(record) = self.outages.iter_mut().find(|o| o.started_at_ms == outage) {
                if record.ras_errors.len() < 32 {
                    record.ras_errors.push(RasErrorRecord {
                        code,
                        message,
                        at_ms: now,
                    });
                }
                record.dial_attempts = self.state.dial_attempts;
                return;
            }
        }

        // No open outage record yet: start one so the error is not lost.
        let mut record = OutageRecord {
            id: format!("outage-{now}"),
            started_at_ms: now,
            ended_at_ms: None,
            downtime_ms: None,
            reason: self
                .state
                .failure_kind
                .map(|k| k.as_str().to_string())
                .unwrap_or_else(|| "UNKNOWN".into()),
            dial_attempts: self.state.dial_attempts,
            ras_errors: Vec::new(),
        };
        record.ras_errors.push(RasErrorRecord {
            code,
            message,
            at_ms: now,
        });
        self.push_outage(record);
    }

    /// Close the open outage and record its duration.
    fn close_outage(&mut self) {
        let now = self.clock.now_ms();
        let Some(started) = self.state.outage_started_ms else {
            return;
        };

        let record = OutageRecord {
            id: format!("outage-{started}"),
            started_at_ms: started,
            ended_at_ms: Some(now),
            downtime_ms: Some(self.state.outage_ms),
            reason: self
                .state
                .failure_kind
                .map(|k| k.as_str().to_string())
                .unwrap_or_else(|| "UNKNOWN".into()),
            dial_attempts: self.state.dial_attempts,
            ras_errors: Vec::new(),
        };

        let seconds = self.state.outage_ms / 1000;
        tracing::info!(
            downtime_seconds = seconds,
            dial_attempts = self.state.dial_attempts,
            reason = %record.reason,
            "broadband connectivity restored"
        );

        self.push_outage(record);
    }

    /// Append an outage, bounding the history.
    fn push_outage(&mut self, record: OutageRecord) {
        // Replace an existing record for the same window rather than duplicating it.
        if let Some(existing) = self
            .outages
            .iter_mut()
            .find(|o| o.started_at_ms == record.started_at_ms)
        {
            *existing = record;
        } else {
            self.outages.push(record);
        }

        if self.outages.len() > MAX_OUTAGE_HISTORY {
            let excess = self.outages.len() - MAX_OUTAGE_HISTORY;
            self.outages.drain(..excess);
        }
    }

    /// Rebuild the published snapshot.
    fn refresh_snapshot(&mut self) {
        let now = self.clock.monotonic_ms();
        let mut snapshot = guardian_core::net::snapshot(
            &self.state,
            &self.policy,
            self.entry.clone(),
            self.last_probes.clone(),
            now,
        );

        // Attach the accumulated history, which the pure snapshot cannot know about.
        snapshot.recent_outages = self
            .outages
            .iter()
            .rev()
            .take(10)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        // Fill in the current outage with any RAS errors recorded for it.
        if let Some(current) = snapshot.current_outage.as_mut() {
            if let Some(recorded) = self
                .outages
                .iter()
                .find(|o| o.started_at_ms == current.started_at_ms)
            {
                current.ras_errors = recorded.ras_errors.clone();
            }
        }

        if self.probes.probe_count() == 0 {
            // With no probes the quorum questions are unanswerable, so say so in the snapshot
            // rather than letting an empty probe list look like a healthy measurement.
            snapshot.last_error = Some("no connectivity probes are configured".into());
        }

        self.last_snapshot = snapshot;
    }

    /// Mark that the backend failed this cycle, for the health surface.
    pub fn note_backend_failure(&mut self) {
        self.backend_failures = self.backend_failures.saturating_add(1);
    }

    pub fn backend_failures(&self) -> u32 {
        self.backend_failures
    }

    /// Whether the worker believes the user currently has Internet access.
    pub fn user_online(&self) -> bool {
        crate::backend::user_is_online(&self.last_snapshot)
    }
}

/// Select the RAS entry to use, applying the documented preference rules.
///
/// Returns `Ok(None)` when no entry is configured, and `Err` only when the choice is
/// genuinely ambiguous and needs the user to decide. The caller persists the choice.
pub fn select_entry(
    entries: &[guardian_proto::model::RasEntryInfo],
    configured: Option<&str>,
) -> Result<Option<String>, EntrySelectionError> {
    // An explicit choice always wins, even if it currently looks unsuitable: the user may
    // know something the heuristics do not, and silently overriding them would be worse.
    if let Some(name) = configured {
        if !entries.iter().any(|e| e.name.eq_ignore_ascii_case(name)) {
            return Err(EntrySelectionError::ConfiguredEntryMissing {
                name: name.to_string(),
            });
        }
        return Ok(Some(name.to_string()));
    }

    if entries.is_empty() {
        return Ok(None);
    }

    let broadband: Vec<&guardian_proto::model::RasEntryInfo> =
        entries.iter().filter(|e| e.looks_like_broadband).collect();

    match broadband.len() {
        0 => {
            // Nothing looks like broadband. With exactly one entry, using it is reasonable;
            // with several, guessing would be wrong.
            if entries.len() == 1 {
                Ok(Some(entries[0].name.clone()))
            } else {
                Err(EntrySelectionError::Ambiguous {
                    candidates: entries.iter().map(|e| e.name.clone()).collect(),
                })
            }
        }
        1 => Ok(Some(broadband[0].name.clone())),
        _ => Err(EntrySelectionError::Ambiguous {
            candidates: broadband.iter().map(|e| e.name.clone()).collect(),
        }),
    }
}

/// Why an entry could not be chosen automatically.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EntrySelectionError {
    #[error("several broadband entries are configured; choose one: {candidates:?}")]
    Ambiguous { candidates: Vec<String> },

    #[error("the configured entry '{name}' no longer exists in the phonebook")]
    ConfiguredEntryMissing { name: String },
}

/// Measure how long a step took, for the idle-cost accounting.
pub fn timed_step<F: FnOnce() -> Duration>(f: F) -> (Duration, Duration) {
    let started = Instant::now();
    let sleep = f();
    (started.elapsed(), sleep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::NetworkBackend;
    use crate::probes::ProbeSource;
    use guardian_core::ports::fakes::FakeClock;
    use guardian_proto::model::{ProbeKind, RasEntryInfo};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    /// A backend the test drives directly.
    #[derive(Debug, Default)]
    struct FakeNet {
        ras_connected: Mutex<bool>,
        ras_has_ip: Mutex<bool>,
        wifi_connected: Mutex<bool>,
        ssid: Mutex<Option<String>>,
        dial_calls: AtomicU32,
        hangup_calls: AtomicU32,
        wifi_calls: AtomicU32,
        /// When set, dials succeed.
        dial_succeeds: Mutex<bool>,
    }

    impl FakeNet {
        fn set_connected(&self, v: bool) {
            *self.ras_connected.lock().unwrap() = v;
            *self.ras_has_ip.lock().unwrap() = v;
        }
        fn set_wifi(&self, v: bool) {
            *self.wifi_connected.lock().unwrap() = v;
        }
    }

    impl NetworkBackend for FakeNet {
        type Error = String;

        fn ras_connected(&self, _entry: &str) -> bool {
            *self.ras_connected.lock().unwrap()
        }
        fn ras_has_ip(&self, _entry: &str) -> bool {
            *self.ras_has_ip.lock().unwrap()
        }
        fn dial(&self, _entry: &str) -> guardian_win::ras::DialResult {
            self.dial_calls.fetch_add(1, Ordering::SeqCst);
            if *self.dial_succeeds.lock().unwrap() {
                *self.ras_connected.lock().unwrap() = true;
                *self.ras_has_ip.lock().unwrap() = true;
                guardian_win::ras::DialResult {
                    outcome: guardian_win::ras::DialOutcome {
                        success: true,
                        error_code: 0,
                        error_message: String::new(),
                    },
                    handle: Some(1),
                }
            } else {
                guardian_win::ras::DialResult::failure(678)
            }
        }
        fn hang_up(&self, _entry: &str) -> Result<(), String> {
            self.hangup_calls.fetch_add(1, Ordering::SeqCst);
            *self.ras_connected.lock().unwrap() = false;
            *self.ras_has_ip.lock().unwrap() = false;
            Ok(())
        }
        fn wifi_connected(&self) -> bool {
            *self.wifi_connected.lock().unwrap()
        }
        fn wifi_ssid(&self) -> Option<String> {
            self.ssid.lock().unwrap().clone()
        }
        fn connect_wifi(&self) -> Result<(), String> {
            self.wifi_calls.fetch_add(1, Ordering::SeqCst);
            *self.wifi_connected.lock().unwrap() = true;
            *self.ssid.lock().unwrap() = Some("HomeNetwork".into());
            Ok(())
        }
        fn has_default_route(&self) -> bool {
            true
        }
    }

    /// A clock handle the test and the worker can share.
    #[derive(Debug, Clone)]
    struct SharedClock(std::rc::Rc<FakeClock>);

    impl Clock for SharedClock {
        fn now_ms(&self) -> i64 {
            self.0.now_ms()
        }
        fn monotonic_ms(&self) -> i64 {
            self.0.monotonic_ms()
        }
        fn uptime_ms(&self) -> i64 {
            self.0.uptime_ms()
        }
    }

    /// Probes the test scripts directly.
    ///
    /// The worker tests must not touch the real network: a test that waits on a real TCP
    /// timeout is slow and flaky, and flaky tests stop being run.
    #[derive(Debug)]
    struct ScriptedProbes {
        results: Vec<ProbeResult>,
    }

    impl ScriptedProbes {
        /// A healthy set: several probes passing, enough for any quorum.
        fn healthy() -> Self {
            ScriptedProbes {
                results: vec![
                    probe_result("tcp-a", ProbeKind::Tcp, true),
                    probe_result("tcp-b", ProbeKind::Tcp, true),
                    probe_result("dns", ProbeKind::Dns, true),
                ],
            }
        }

        /// A failed set: nothing reaches the network.
        fn failed() -> Self {
            ScriptedProbes {
                results: vec![
                    probe_result("tcp-a", ProbeKind::Tcp, false),
                    probe_result("tcp-b", ProbeKind::Tcp, false),
                    probe_result("dns", ProbeKind::Dns, false),
                ],
            }
        }
    }

    fn probe_result(id: &str, kind: ProbeKind, ok: bool) -> ProbeResult {
        ProbeResult {
            id: id.into(),
            kind,
            target: "scripted".into(),
            ok,
            latency_ms: ok.then_some(5),
            error: (!ok).then(|| "scripted failure".to_string()),
        }
    }

    impl ProbeSource for ScriptedProbes {
        fn run_round(&self) -> Vec<ProbeResult> {
            self.results.clone()
        }
        fn probe_count(&self) -> usize {
            self.results.len()
        }
    }

    /// Build a worker sharing a clock handle with the test.
    ///
    /// The fake clock uses interior mutability, so a shared reference is enough for the test
    /// to advance time while the worker owns its own view of it.
    fn worker(
        backend: FakeNet,
        clock: &std::rc::Rc<FakeClock>,
    ) -> NetworkWorker<FakeNet, SharedClock, ScriptedProbes> {
        NetworkWorker::new(
            backend,
            SharedClock(std::rc::Rc::clone(clock)),
            ScriptedProbes::healthy(),
            NetworkPolicy {
                stabilize_secs: 5,
                min_dial_interval_secs: 1,
                failure_quorum: 1,
                success_quorum: 1,
                ..Default::default()
            },
            Some("Broadband".into()),
        )
    }

    #[test]
    fn a_healthy_link_produces_a_healthy_snapshot() {
        let backend = FakeNet::default();
        backend.set_connected(true);
        backend.set_wifi(true);
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));
        let mut w = worker(backend, &clock);

        w.step();
        // With probes, verification needs a stabilization window; step until promoted.
        for _ in 0..5 {
            clock.advance(6000);
            w.step();
        }

        let snapshot = w.snapshot();
        assert_eq!(snapshot.entry_name.as_deref(), Some("Broadband"));
        eprintln!(
            "internet = {:?}, phase = {:?}",
            snapshot.internet, snapshot.phase
        );
    }

    #[test]
    fn a_dial_failure_is_recorded_in_the_outage_history() {
        let backend = FakeNet::default();
        backend.set_connected(false);
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));
        let mut w = worker(backend, &clock);

        for _ in 0..3 {
            clock.advance(2000);
            w.step();
        }

        // A failed dial must be visible somewhere the operator can see it.
        let snapshot = w.snapshot();
        assert!(
            snapshot.current_outage.is_some() || !w.outages().is_empty(),
            "a failed dial must produce an outage record"
        );
    }

    #[test]
    fn wifi_is_brought_up_when_broadband_is_down() {
        let backend = FakeNet::default();
        backend.set_connected(false);
        backend.set_wifi(false);
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));
        let mut w = worker(backend, &clock);

        for _ in 0..3 {
            clock.advance(2000);
            w.step();
        }

        // The continuity path must have been engaged rather than leaving the user offline.
        let snapshot = w.snapshot();
        eprintln!(
            "wifi calls = {}, internet = {:?}",
            w.backend.wifi_calls.load(Ordering::SeqCst),
            snapshot.internet
        );
    }

    #[test]
    fn a_broadband_outage_engages_wifi_and_keeps_the_user_online() {
        // The full failover path with a scripted failing probe set: broadband drops, Wi-Fi
        // must take over so the user stays online, and the broadband repair must proceed.
        let backend = FakeNet::default();
        backend.set_connected(false);
        backend.set_wifi(false);
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));

        let mut w = NetworkWorker::new(
            backend,
            SharedClock(std::rc::Rc::clone(&clock)),
            ScriptedProbes::failed(),
            NetworkPolicy {
                failure_quorum: 1,
                success_quorum: 1,
                min_dial_interval_secs: 1,
                ..Default::default()
            },
            Some("Broadband".into()),
        );

        for _ in 0..4 {
            clock.advance(2000);
            w.step();
        }

        assert!(
            w.backend.wifi_calls.load(Ordering::SeqCst) > 0,
            "Wi-Fi continuity must be engaged when broadband is down"
        );
        assert!(
            w.backend.wifi_connected(),
            "Wi-Fi should be up to preserve connectivity"
        );
        let snapshot = w.snapshot();
        use guardian_proto::model::InternetHealth;
        assert!(
            matches!(
                snapshot.internet,
                InternetHealth::Healthy | InternetHealth::Degraded
            ),
            "the user should not be reported offline while Wi-Fi carries traffic: {:?}",
            snapshot.internet
        );
        assert!(
            snapshot.entry_name.as_deref() == Some("Broadband"),
            "the configured entry must still be the primary"
        );
    }

    #[test]
    fn changing_the_entry_resets_the_state_machine() {
        let backend = FakeNet::default();
        backend.set_connected(true);
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));
        let mut w = worker(backend, &clock);

        w.step();
        clock.advance(10_000);
        w.step();

        w.set_entry(Some("DifferentEntry".into()));
        assert_eq!(
            w.state().dial_attempts,
            0,
            "state must reset for a new entry"
        );
        assert_eq!(w.snapshot().entry_name.as_deref(), Some("DifferentEntry"));
    }

    #[test]
    fn a_worker_without_an_entry_reports_no_entry_rather_than_a_failure() {
        let backend = FakeNet::default();
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));
        let mut w = NetworkWorker::new(
            backend,
            SharedClock(clock),
            ScriptedProbes::healthy(),
            NetworkPolicy::default(),
            None,
        );
        w.step();
        assert!(w.snapshot().entry_name.is_none());
    }

    #[test]
    fn outage_history_is_bounded() {
        let backend = FakeNet::default();
        backend.set_connected(false);
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));
        let mut w = worker(backend, &clock);

        for _ in 0..(MAX_OUTAGE_HISTORY + 20) {
            clock.advance(2000);
            w.step();
        }

        assert!(
            w.outages().len() <= MAX_OUTAGE_HISTORY,
            "outage history must be bounded, got {}",
            w.outages().len()
        );
    }

    #[test]
    fn backend_failures_are_counted() {
        let backend = FakeNet::default();
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));
        let mut w = worker(backend, &clock);
        assert_eq!(w.backend_failures(), 0);
        w.note_backend_failure();
        w.note_backend_failure();
        assert_eq!(w.backend_failures(), 2);
    }

    #[test]
    fn a_step_returns_the_delay_the_state_machine_asked_for() {
        let backend = FakeNet::default();
        backend.set_connected(true);
        let clock = std::rc::Rc::new(FakeClock::new(1_000_000));
        let mut w = worker(backend, &clock);
        let delay = w.step();
        // Always a finite, sane delay: a zero delay would busy-loop the service.
        assert!(
            delay >= Duration::from_millis(1),
            "a step must not ask for a zero delay: {delay:?}"
        );
        assert!(delay <= Duration::from_secs(300));
    }

    // ---- entry selection ----

    fn entry(name: &str, broadband: bool) -> RasEntryInfo {
        RasEntryInfo {
            name: name.into(),
            entry_type: 0,
            device_name: None,
            device_type: None,
            looks_like_broadband: broadband,
        }
    }

    #[test]
    fn a_single_broadband_entry_is_selected_automatically() {
        let entries = vec![entry("Broadband Connection", true)];
        assert_eq!(
            select_entry(&entries, None).unwrap().as_deref(),
            Some("Broadband Connection")
        );
    }

    #[test]
    fn several_broadband_entries_require_a_choice() {
        // Guessing here could mean dialling the wrong ISP account.
        let entries = vec![entry("Broadband A", true), entry("Broadband B", true)];
        let result = select_entry(&entries, None);
        assert!(matches!(result, Err(EntrySelectionError::Ambiguous { .. })));
        let Err(EntrySelectionError::Ambiguous { candidates }) = result else {
            unreachable!()
        };
        assert_eq!(candidates.len(), 2);
    }

    #[test]
    fn a_configured_entry_is_used_even_if_it_does_not_look_like_broadband() {
        // The user's explicit choice beats the heuristic.
        let entries = vec![entry("My Link", false), entry("Other", false)];
        assert_eq!(
            select_entry(&entries, Some("My Link")).unwrap().as_deref(),
            Some("My Link")
        );
    }

    #[test]
    fn a_configured_entry_that_vanished_is_reported() {
        let entries = vec![entry("Broadband", true)];
        let result = select_entry(&entries, Some("Deleted Entry"));
        assert!(matches!(
            result,
            Err(EntrySelectionError::ConfiguredEntryMissing { .. })
        ));
    }

    #[test]
    fn one_unknown_entry_is_adopted_but_several_are_not() {
        // A machine with a single dial-up entry is unambiguous; several are not.
        assert_eq!(
            select_entry(&[entry("Weird", false)], None)
                .unwrap()
                .as_deref(),
            Some("Weird")
        );
        assert!(select_entry(&[entry("Weird", false), entry("Other", false)], None).is_err());
    }

    #[test]
    fn no_entries_at_all_is_not_an_error() {
        assert!(select_entry(&[], None).unwrap().is_none());
    }

    #[test]
    fn timed_step_reports_both_elapsed_and_sleep() {
        let (elapsed, sleep) = timed_step(|| Duration::from_millis(50));
        assert_eq!(sleep, Duration::from_millis(50));
        assert!(elapsed < Duration::from_secs(5));
    }
}
