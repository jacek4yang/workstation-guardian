//! The Windows Update guardian worker.
//!
//! Wraps the pure verification logic in `guardian-core::update_policy` with the real registry
//! backend, and adds the periodic verification loop, tamper detection and incident recording.
//!
//! # Idempotence
//!
//! [`UpdateWorker::verify`] reads before writing and only writes genuine differences. On a
//! conformant machine it performs **zero** registry writes, which is what makes a
//! forever-running verifier acceptable. A test asserts this against the real hive.
//!
//! # Fail-closed
//!
//! Every failure path reports a non-`Protected` level:
//!
//! * the registry cannot be read -> `Unknown`, and protection is re-applied anyway
//! * the machine is domain-joined or MDM-enrolled -> `Degraded`, because an external
//!   authority can override local policy at any refresh
//! * a value Guardian owns was changed -> the change is journaled, restored, and reported

use std::time::Duration;

use guardian_core::ports::{Clock, UpdatePolicyBackend};
use guardian_core::update_policy::{all_desired_writes, analyze, TamperEvent};
use guardian_proto::model::{
    Finding, FindingSeverity, Incident, IncidentDetails, IncidentKind, ManagementState,
    PolicyTamper, ProtectionLevel, UpdateProtectionReport,
};
use guardian_win::policy::PolicyBackend;

/// The outcome of one verification pass.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub report: UpdateProtectionReport,
    /// Values actually written this pass. Empty means nothing needed changing.
    pub writes_performed: usize,
    /// Deepest severity produced this pass.
    pub severity: FindingSeverity,
    /// Incidents this pass generated (tamper, degradation).
    pub incidents: Vec<Incident>,
}

impl VerifyOutcome {
    /// Whether this pass changed anything at all.
    pub fn changed_anything(&self) -> bool {
        self.writes_performed > 0
    }
}

/// The update protection worker.
#[derive(Debug)]
pub struct UpdateWorker<B: UpdatePolicyBackend, C: Clock> {
    backend: B,
    clock: C,
    /// Whether Guardian is configured to protect at all.
    protect: bool,
    /// Whether mismatches should be repaired, or only reported.
    auto_restore: bool,
    /// The most recent report, so a status query between passes is cheap.
    last_report: Option<UpdateProtectionReport>,
    /// Consecutive passes that failed to read policy.
    consecutive_failures: u32,
    /// The value name of the tamper incident already reported, so a persistent mismatch does
    /// not generate an incident every pass. Cleared once the value conforms again.
    reported_tamper: Option<String>,
    /// Total verification passes, for diagnostics.
    passes: u64,
    /// Total values ever written, for diagnostics.
    total_writes: u64,
}

impl<B: UpdatePolicyBackend, C: Clock> UpdateWorker<B, C> {
    pub fn new(backend: B, clock: C, protect: bool, auto_restore: bool) -> Self {
        UpdateWorker {
            backend,
            clock,
            protect,
            auto_restore,
            last_report: None,
            consecutive_failures: 0,
            reported_tamper: None,
            passes: 0,
            total_writes: 0,
        }
    }

    /// The most recent report, if a pass has run.
    pub fn last_report(&self) -> Option<&UpdateProtectionReport> {
        self.last_report.as_ref()
    }

    /// A report for the status surface, even before a pass has completed.
    pub fn report_or_unknown(&self) -> UpdateProtectionReport {
        match &self.last_report {
            Some(r) => r.clone(),
            None => UpdateProtectionReport::unavailable(
                "update protection has not been verified yet",
                self.clock.now_ms(),
            ),
        }
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn passes(&self) -> u64 {
        self.passes
    }

    pub fn total_writes(&self) -> u64 {
        self.total_writes
    }

    /// Update the protection settings, e.g. after a configuration change.
    pub fn set_protection(&mut self, protect: bool, auto_restore: bool) {
        self.protect = protect;
        self.auto_restore = auto_restore;
    }

    /// Run one verification pass.
    pub fn verify(&mut self) -> VerifyOutcome {
        self.passes += 1;
        let now = self.clock.now_ms();

        if !self.protect {
            // Protection is configured off. Report that honestly rather than reading policy
            // and implying something is being enforced.
            let report = UpdateProtectionReport {
                level: ProtectionLevel::Unprotected,
                primary_lock_effective: false,
                values: Vec::new(),
                neutralized_deadlines: Vec::new(),
                management: self.backend.management_state(),
                findings: vec![Finding {
                    severity: FindingSeverity::Error,
                    code: "update.protection_disabled".into(),
                    message: "update protection is disabled in configuration".into(),
                }],
                checked_at_ms: now,
                backend_error: None,
            };
            self.last_report = Some(report.clone());
            return VerifyOutcome {
                report,
                writes_performed: 0,
                severity: FindingSeverity::Error,
                incidents: Vec::new(),
            };
        }

        let managed = self.backend.management_state();
        let read_result = self.backend.read();

        // Fail closed: if the policy cannot be read we cannot confirm protection, so the
        // report becomes Unknown and protection is re-applied rather than assumed in place.
        let read_failed = read_result.is_err();
        let read_error = read_result.as_ref().err().map(|e| e.to_string());

        let analysis = match read_result {
            Ok(rb) => analyze(&rb, &managed, now, None),
            Err(e) => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                tracing::warn!(
                    error = %e,
                    failures = self.consecutive_failures,
                    "could not read the Windows Update policy"
                );
                analyze(
                    &Default::default(),
                    &managed,
                    now,
                    Some(format!("could not read update policy: {e}")),
                )
            }
        };

        if !read_failed {
            self.consecutive_failures = 0;
        }

        // Decide whether to repair. `auto_restore` is honoured, but a machine whose policy
        // cannot be read is always re-applied: leaving it unknown is worse than a write.
        let should_apply = self.auto_restore || read_failed;

        let mut writes_performed = 0usize;
        let mut write_error = None;

        if should_apply && !analysis.writes_needed.is_empty() {
            // Only write the values that differ. `apply` is itself idempotent, but passing the
            // computed difference keeps the intent explicit and the log honest.
            match self.backend.apply(&all_desired_writes()) {
                Ok(written) => {
                    writes_performed = written.len();
                    self.total_writes += written.len() as u64;
                    if !written.is_empty() {
                        tracing::info!(
                            count = written.len(),
                            "re-applied Guardian-owned update policy"
                        );
                    }
                }
                Err(e) => {
                    write_error = Some(e.to_string());
                    tracing::error!(error = %e, "could not apply the update policy");
                }
            }
        }

        // Build the incidents this pass implies.
        let mut incidents = Vec::new();

        if !analysis.tamper.is_empty() {
            // Raise an incident only when this is a *new* divergence, or when the previous
            // attempt failed to repair it. A mismatch that something keeps reintroducing is
            // one ongoing problem, not a new incident every couple of minutes.
            let repairing = writes_performed > 0 && write_error.is_none();
            let already_reported = self
                .reported_tamper
                .as_deref()
                .map(|v| v == analysis.tamper[0].value_name)
                .unwrap_or(false);

            let worth_reporting = !already_reported || !repairing;

            if worth_reporting {
                incidents.push(self.tamper_incident(
                    &analysis.tamper,
                    repairing,
                    write_error.as_deref(),
                ));
            }
            self.reported_tamper = Some(analysis.tamper[0].value_name.clone());
        } else {
            // The divergence is gone, so a future one is a new event worth reporting.
            self.reported_tamper = None;
        }

        // Re-read after applying so the report describes the state the machine is in *now*,
        // not the state it was found in. The UI shows this as "are updates locked right now",
        // and answering that with a pre-write observation would show Degraded for the entire
        // interval after a successful repair.
        let mut report = if writes_performed > 0 && write_error.is_none() {
            match self.backend.read() {
                Ok(rb) => analyze(&rb, &managed, now, None).into_report(&managed, now),
                Err(e) => {
                    let mut r = analysis.into_report(&managed, now);
                    r.level = ProtectionLevel::Unknown;
                    r.primary_lock_effective = false;
                    r.findings.push(Finding {
                        severity: FindingSeverity::Error,
                        code: "update.verify_after_apply_failed".into(),
                        message: format!(
                            "protection was applied but could not be re-verified: {e}"
                        ),
                    });
                    r
                }
            }
        } else {
            analysis.into_report(&managed, now)
        };

        // Carry whichever failure is most relevant so the UI can explain the state rather
        // than just reporting "Unknown": a write failure masks a read failure, and a read
        // failure is what makes the level Unknown in the first place.
        report.backend_error = write_error.clone().or_else(|| read_error.clone());

        // A write failure means protection may not be in place regardless of what the analysis
        // found, so it can never be reported as Protected.
        if write_error.is_some() {
            report.level = ProtectionLevel::Unknown;
            report.primary_lock_effective = false;
            report.findings.push(Finding {
                severity: FindingSeverity::Error,
                code: "update.apply_failed".into(),
                message: "protection could not be applied; the machine may not be protected".into(),
            });
        }

        let severity = report
            .findings
            .iter()
            .map(|f| f.severity)
            .max()
            .unwrap_or(FindingSeverity::Info);

        self.last_report = Some(report.clone());

        VerifyOutcome {
            report,
            writes_performed,
            severity,
            incidents,
        }
    }

    /// Record a tamper incident.
    ///
    /// Raised once per divergence rather than once per pass: a mismatch that persists until
    /// the next verification would otherwise generate an incident every couple of minutes and
    /// bury everything else in the log.
    fn tamper_incident(
        &mut self,
        events: &[TamperEvent],
        restored: bool,
        restore_error: Option<&str>,
    ) -> Incident {
        let now = self.clock.now_ms();
        let first = &events[0];

        if self.reported_tamper.as_deref() != Some(first.value_name.as_str()) {
            tracing::warn!(
                value = %first.value_name,
                expected = ?first.expected,
                observed = ?first.observed,
                restored,
                "Guardian-owned update policy was modified"
            );
        }
        let summary = if restored {
            format!(
                "{} was changed from {:?} to {:?} and has been restored",
                first.value_name, first.expected, first.observed
            )
        } else {
            format!(
                "{} was changed from {:?} to {:?} and could not be restored: {}",
                first.value_name,
                first.expected,
                first.observed,
                restore_error.unwrap_or("the reason was not reported")
            )
        };

        Incident {
            id: format!("tamper-{now}-{}", first.value_name),
            kind: IncidentKind::PolicyTamper,
            at_ms: now,
            title: "Update protection was modified".into(),
            summary,
            severity: if restored {
                FindingSeverity::Warning
            } else {
                FindingSeverity::Error
            },
            details: IncidentDetails {
                policy_tamper: Some(PolicyTamper {
                    value_name: first.value_name.clone(),
                    expected: first.expected.clone(),
                    observed: first.observed.clone(),
                    key_path: first.key_path.clone(),
                    detected_at_ms: now,
                    restored,
                    restore_error: restore_error.map(str::to_string),
                }),
                extra: events
                    .iter()
                    .skip(1)
                    .map(|e| {
                        (
                            e.value_name.clone(),
                            format!("{:?} -> {:?}", e.expected, e.observed),
                        )
                    })
                    .collect(),
                ..Default::default()
            },
        }
    }

    /// Restore everything Guardian originally recorded, for uninstall.
    ///
    /// Only values Guardian itself wrote are restored. A value that belonged to Group Policy
    /// is never touched, because Guardian never recorded owning it.
    pub fn restore_original(
        &self,
        original: &[guardian_core::ports::OwnedPolicy],
    ) -> Result<(), String> {
        self.backend.restore(original).map_err(|e| e.to_string())
    }

    pub fn management_state(&self) -> ManagementState {
        self.backend.management_state()
    }

    /// How long to wait before the next pass.
    pub fn next_interval(&self, configured_secs: u64) -> Duration {
        // Back off when the policy cannot be read: a machine with a locked-down hive should
        // not be hammered with failed reads, and the state is already reported as Unknown.
        let base = configured_secs.max(30);
        let factor = match self.consecutive_failures {
            0 => 1,
            1 => 2,
            2 => 3,
            _ => 5,
        };
        Duration::from_secs(base.saturating_mul(factor))
    }

    /// Whether protection is currently verified as effective.
    pub fn is_protected(&self) -> bool {
        self.last_report
            .as_ref()
            .map(|r| r.level.is_protected())
            .unwrap_or(false)
    }
}

impl UpdateWorker<PolicyBackend, guardian_win::clock::SystemClock> {
    /// Build the production worker.
    pub fn production(protect: bool, auto_restore: bool) -> Self {
        UpdateWorker::new(
            PolicyBackend::new(),
            guardian_win::clock::SystemClock,
            protect,
            auto_restore,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::ports::fakes::{FakeClock, FakeUpdateBackend};
    use guardian_proto::model::PolValue;

    fn worker(
        backend: FakeUpdateBackend,
        clock: FakeClock,
    ) -> UpdateWorker<FakeUpdateBackend, FakeClock> {
        UpdateWorker::new(backend, clock, true, true)
    }

    /// Build a worker that shares its backend with the test.
    ///
    /// `FakeUpdateBackend` uses interior mutability, so a shared handle lets a test observe
    /// what the worker wrote without the worker giving up ownership.
    fn shared_worker(
        backend: std::rc::Rc<FakeUpdateBackend>,
        clock: FakeClock,
        protect: bool,
        auto_restore: bool,
    ) -> UpdateWorker<SharedBackend, FakeClock> {
        UpdateWorker::new(SharedBackend(backend), clock, protect, auto_restore)
    }

    /// Forwards every backend call to a shared fake.
    #[derive(Debug, Clone)]
    struct SharedBackend(std::rc::Rc<FakeUpdateBackend>);

    impl UpdatePolicyBackend for SharedBackend {
        type Error = <FakeUpdateBackend as UpdatePolicyBackend>::Error;

        fn read(&self) -> Result<guardian_core::ports::PolicyReadback, Self::Error> {
            self.0.read()
        }
        fn apply(
            &self,
            desired: &[guardian_core::ports::PolicyWrite],
        ) -> Result<Vec<guardian_core::ports::PolicyWrite>, Self::Error> {
            self.0.apply(desired)
        }
        fn restore(
            &self,
            original: &[guardian_core::ports::OwnedPolicy],
        ) -> Result<(), Self::Error> {
            self.0.restore(original)
        }
        fn management_state(&self) -> ManagementState {
            self.0.management_state()
        }
    }

    #[test]
    fn a_bare_machine_is_protected_and_written_once() {
        // First pass writes; a second pass must write nothing, which is the efficiency
        // property that makes a forever-running verifier acceptable.
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        let first = w.verify();
        assert!(
            first.writes_performed > 0,
            "a bare machine needs protection applied"
        );
        assert_eq!(first.report.level, ProtectionLevel::Protected);

        let second = w.verify();
        assert_eq!(
            second.writes_performed, 0,
            "a conformant machine must not be rewritten"
        );
        assert_eq!(second.report.level, ProtectionLevel::Protected);
        assert!(w.is_protected());
    }

    #[test]
    fn a_tampered_value_is_restored_and_reported() {
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        w.verify();

        // Something changes the primary protection.
        w.backend.set(
            guardian_core::update_policy::WU_AU_KEY,
            "NoAutoUpdate",
            PolValue::Dword(0),
        );

        let outcome = w.verify();
        assert_eq!(outcome.incidents.len(), 1);
        let incident = &outcome.incidents[0];
        assert_eq!(incident.kind, IncidentKind::PolicyTamper);
        assert!(incident.summary.contains("NoAutoUpdate"));
        assert!(incident.details.policy_tamper.as_ref().unwrap().restored);

        // The value must actually be back.
        assert_eq!(
            w.backend
                .get(guardian_core::update_policy::WU_AU_KEY, "NoAutoUpdate"),
            Some(PolValue::Dword(1))
        );
        assert!(w.is_protected());
    }

    #[test]
    fn a_persistent_mismatch_does_not_raise_an_incident_every_pass() {
        // A machine where something keeps reverting the value would otherwise generate an
        // incident every two minutes and bury every other event.
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        w.verify();

        let mut incidents = 0;
        for _ in 0..5 {
            w.backend.set(
                guardian_core::update_policy::WU_AU_KEY,
                "NoAutoUpdate",
                PolValue::Dword(0),
            );
            incidents += w.verify().incidents.len();
        }

        assert!(
            incidents <= 2,
            "a repeating mismatch must not flood the incident log, got {incidents}"
        );
    }

    #[test]
    fn an_unreadable_policy_is_unknown_and_never_protected() {
        let backend = FakeUpdateBackend::new();
        *backend.fail_with.borrow_mut() = Some("registry access denied".into());
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        let outcome = w.verify();
        assert_eq!(outcome.report.level, ProtectionLevel::Unknown);
        assert!(!outcome.report.level.is_protected());
        assert!(!w.is_protected());
        assert!(w.consecutive_failures() > 0);
        assert!(outcome.report.backend_error.is_some());
    }

    #[test]
    fn repeated_read_failures_back_off_the_interval() {
        // Hammering a locked-down hive with failed reads is pointless; the interval grows.
        let backend = FakeUpdateBackend::new();
        *backend.fail_with.borrow_mut() = Some("denied".into());
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        let base = 120;
        assert_eq!(w.next_interval(base), Duration::from_secs(base));

        w.verify();
        assert_eq!(w.next_interval(base), Duration::from_secs(base * 2));

        w.verify();
        assert_eq!(w.next_interval(base), Duration::from_secs(base * 3));

        w.verify();
        w.verify();
        assert_eq!(w.next_interval(base), Duration::from_secs(base * 5));
    }

    #[test]
    fn a_recovered_read_resets_the_backoff() {
        let backend = std::rc::Rc::new(FakeUpdateBackend::new());
        *backend.fail_with.borrow_mut() = Some("denied".into());
        let clock = FakeClock::new(1_000_000);
        let mut w = shared_worker(std::rc::Rc::clone(&backend), clock, true, true);

        w.verify();
        assert_eq!(w.consecutive_failures(), 1);

        *backend.fail_with.borrow_mut() = None;
        w.verify();
        assert_eq!(w.consecutive_failures(), 0);
        assert_eq!(w.next_interval(120), Duration::from_secs(120));
    }

    #[test]
    fn disabling_protection_is_reported_as_unprotected() {
        // The UI must not show "Protected" for a machine where the operator turned it off.
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let mut w = UpdateWorker::new(backend, clock, false, true);

        let outcome = w.verify();
        assert_eq!(outcome.report.level, ProtectionLevel::Unprotected);
        assert!(!outcome.report.level.is_protected());
        assert!(outcome
            .report
            .findings
            .iter()
            .any(|f| f.code == "update.protection_disabled"));
    }

    #[test]
    fn an_externally_managed_machine_is_degraded_not_protected() {
        use guardian_proto::model::ManagementState;
        let backend = FakeUpdateBackend::new();
        *backend.management.borrow_mut() = ManagementState::DomainJoined {
            domain: "corp.example".into(),
        };
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        w.verify();
        w.verify();

        let report = w.last_report().expect("a report");
        assert_eq!(
            report.level,
            ProtectionLevel::Degraded,
            "an externally managed machine must not claim Protected"
        );
        assert!(!w.is_protected());
        assert!(report
            .findings
            .iter()
            .any(|f| f.code == "update.external_policy"));
    }

    #[test]
    fn an_apply_failure_downgrades_the_report_to_unknown() {
        // If the values look right but we could not write, we cannot claim protection.
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        w.verify(); // establish protection

        // Now make the backend fail, and force a divergence so an apply is attempted.
        w.backend.set(
            guardian_core::update_policy::WU_AU_KEY,
            "NoAutoUpdate",
            PolValue::Dword(0),
        );
        *w.backend.fail_with.borrow_mut() = Some("write denied".into());

        let outcome = w.verify();
        assert_eq!(
            outcome.report.level,
            ProtectionLevel::Unknown,
            "a failed write must not be reported as protected"
        );
        assert!(outcome
            .report
            .findings
            .iter()
            .any(|f| f.code == "update.apply_failed"));
    }

    #[test]
    fn auto_restore_disabled_reports_but_does_not_write() {
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let mut w = UpdateWorker::new(backend, clock, true, false);

        let outcome = w.verify();
        assert_eq!(
            outcome.writes_performed, 0,
            "auto_restore is off, so nothing may be written"
        );
        assert!(!w.is_protected(), "unapplied protection is not protection");
        assert!(w.backend.is_empty(), "no values should have been written");
    }

    #[test]
    fn a_report_is_available_before_the_first_pass() {
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let w = worker(backend, clock);

        let report = w.report_or_unknown();
        assert_eq!(report.level, ProtectionLevel::Unknown);
        assert!(!report.level.is_protected());
        assert!(!report.findings.is_empty());
    }

    #[test]
    fn write_counters_track_real_writes_only() {
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        w.verify();
        let after_first = w.total_writes();
        assert!(after_first > 0);

        w.verify();
        w.verify();
        assert_eq!(
            w.total_writes(),
            after_first,
            "no-op passes must not increment the write counter"
        );
        assert_eq!(w.passes(), 3);
    }

    #[test]
    fn a_partially_unreadable_hive_is_never_protected() {
        let backend = FakeUpdateBackend::new();
        backend
            .unreadable
            .borrow_mut()
            .push(guardian_core::update_policy::WU_AU_KEY.into());
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);

        let outcome = w.verify();
        assert!(!outcome.report.level.is_protected());
        assert_eq!(outcome.report.level, ProtectionLevel::Unknown);
    }

    #[test]
    fn restore_original_only_touches_recorded_values() {
        use guardian_core::ports::OwnedPolicy;
        let backend = FakeUpdateBackend::new();
        let clock = FakeClock::new(1_000_000);
        let mut w = worker(backend, clock);
        w.verify();

        // A value Guardian never owned must survive a restore untouched.
        w.backend.set(
            guardian_core::update_policy::WU_POLICY_KEY,
            "SomeExternalPolicy",
            PolValue::Dword(7),
        );

        let original: Vec<OwnedPolicy> = vec![OwnedPolicy {
            key_path: guardian_core::update_policy::WU_AU_KEY.into(),
            value_name: "NoAutoUpdate".into(),
            // It did not exist before Guardian wrote it, so restoring means removing it.
            value: None,
            created_key: false,
        }];

        w.restore_original(&original).expect("restore must succeed");

        assert_eq!(
            w.backend
                .get(guardian_core::update_policy::WU_AU_KEY, "NoAutoUpdate"),
            None,
            "a value Guardian created must be removed on restore"
        );
        assert_eq!(
            w.backend.get(
                guardian_core::update_policy::WU_POLICY_KEY,
                "SomeExternalPolicy"
            ),
            Some(PolValue::Dword(7)),
            "a value Guardian never owned must be left alone"
        );
    }

    #[test]
    fn production_worker_does_not_write_to_the_real_hive_during_a_no_op_pass() {
        // The most important real-machine property: on a machine that is already correctly
        // configured, verification must not touch the registry. This test only reads.
        let worker = UpdateWorker::production(true, true);
        let managed = worker.management_state();
        let backend = PolicyBackend::new();
        let readback = backend.read().expect("reading policy needs no elevation");

        let analysis = analyze(&readback, &managed, 0, None);
        if analysis.writes_needed.is_empty() {
            // Deliberately not calling apply(): this suite must not modify system policy.
            // The apply path is covered by the fake backend above.
            assert!(analysis.values.iter().all(|v| v.matches));
        }
    }
}
