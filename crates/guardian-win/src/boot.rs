//! Pending-reboot detection and boot-session bookkeeping.
//!
//! Every probe here is read-only. Nothing in this module changes system state, so it is safe
//! to call from diagnostics, from the service, and from a test.

use guardian_core::ports::PendingRebootSource;
use guardian_core::reboot::{classify_signals, SIGNAL_SPECS};
use guardian_proto::model::{PendingRebootReport, RebootSignal, RebootSignalWeight};

use crate::clock::unix_now_ms;
use crate::registry::{RegKey, RegPath};
use crate::WinError;

/// A read-only probe over the established pending-reboot indicators.
#[derive(Debug, Default, Clone, Copy)]
pub struct RebootProbe;

impl RebootProbe {
    pub fn new() -> Self {
        RebootProbe
    }

    /// Collect every signal, recording failures rather than aborting.
    ///
    /// A probe that cannot be read is reported as `read_failed`, which makes the aggregate
    /// verdict degrade to `Unknown` instead of a confident `NotPending`.
    pub fn collect_signals(&self) -> Vec<RebootSignal> {
        let mut signals = Vec::with_capacity(SIGNAL_SPECS.len());

        for spec in SIGNAL_SPECS {
            let signal = match probe_one(spec.id) {
                ProbeResult::Present(present) => RebootSignal {
                    id: spec.id.to_string(),
                    source: spec.source,
                    present,
                    weight: spec.weight,
                    detail: spec.detail.to_string(),
                    read_failed: false,
                },
                ProbeResult::Failed(detail) => RebootSignal {
                    id: spec.id.to_string(),
                    source: spec.source,
                    present: false,
                    weight: spec.weight,
                    detail,
                    read_failed: true,
                },
            };
            signals.push(signal);
        }

        signals
    }

    /// Classify the machine's pending-reboot state.
    pub fn classify(&self) -> PendingRebootReport {
        let now = unix_now_ms();
        let signals = self.collect_signals();
        classify_signals(signals, now)
    }
}

impl PendingRebootSource for RebootProbe {
    type Error = WinError;

    fn collect(&self) -> Result<Vec<RebootSignal>, Self::Error> {
        Ok(self.collect_signals())
    }
}

enum ProbeResult {
    Present(bool),
    Failed(String),
}

/// Probe a single signal by id.
///
/// Each arm names the exact registry location it reads, so `guardianctl doctor` output and
/// the incident report can say precisely which indicator fired.
fn probe_one(id: &str) -> ProbeResult {
    match id {
        // Component Based Servicing sets this key (with no values) when a servicing
        // operation needs a restart. The key's *existence* is the indicator.
        "cbs.reboot_pending" => key_exists(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        ),

        // The Update Orchestrator's explicit reboot-required marker.
        "wu.reboot_required" => key_exists(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        ),

        // Set when an update has been staged and is waiting for a restart window.
        "wu.auto_update_reboot_required" => key_exists(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\PostRebootReporting",
        ),

        // A file rename is queued for the next boot. The value's presence matters, not its
        // contents.
        "sm.pending_file_rename" => value_present(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "PendingFileRenameOperations",
        ),

        // The related rename-ops value written by some installers.
        "sm.pending_file_rename_operations" => value_present(
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "PendingFileRenameOperations2",
        ),

        // Weak signals: written by the update UX and the update engine respectively. Both
        // can be present on a healthy machine, which is why they only corroborate.
        "wu.ux_schedule_reboot" => value_present(
            r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings",
            "ScheduleRebootTime",
        ),

        "wu.update_exe_reboot_required" => value_present(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
            "RebootRequired",
        ),

        other => ProbeResult::Failed(format!("unknown reboot signal id '{other}'")),
    }
}

/// Whether a key exists, treating access denial as a failed read rather than absence.
fn key_exists(path: &str) -> ProbeResult {
    let p = RegPath::local_machine(path);
    match RegKey::open_read(&p) {
        Ok(_) => ProbeResult::Present(true),
        Err(e) if e.is_not_found() => ProbeResult::Present(false),
        Err(e) => ProbeResult::Failed(format!("could not read {path}: {e}")),
    }
}

/// Whether a value exists in a key.
fn value_present(path: &str, name: &str) -> ProbeResult {
    let p = RegPath::local_machine(path);
    let key = match RegKey::open_read(&p) {
        Ok(k) => k,
        Err(e) if e.is_not_found() => return ProbeResult::Present(false),
        Err(e) => return ProbeResult::Failed(format!("could not read {path}: {e}")),
    };
    match key.get_value(name) {
        Ok(Some(_)) => ProbeResult::Present(true),
        Ok(None) => ProbeResult::Present(false),
        Err(e) if e.is_access_denied() => {
            ProbeResult::Failed(format!("access denied reading {path}\\{name}"))
        }
        Err(e) => ProbeResult::Failed(format!("could not read {path}\\{name}: {e}")),
    }
}

/// Whether a reboot is present with at least `Strong` confidence.
pub fn is_reboot_strongly_pending() -> bool {
    let report = RebootProbe::new().classify();
    matches!(
        report.verdict,
        guardian_proto::model::PendingRebootVerdict::Pending
            | guardian_proto::model::PendingRebootVerdict::ProbablyPending
    )
}

/// The confidence weight a signal id carries, for diagnostics formatting.
pub fn weight_of(id: &str) -> Option<RebootSignalWeight> {
    SIGNAL_SPECS.iter().find(|s| s.id == id).map(|s| s.weight)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_proto::model::{PendingRebootVerdict, RebootSignalWeight};

    #[test]
    fn classification_always_produces_a_verdict() {
        // Whatever this machine's state, the probe must return a definite verdict and must
        // not panic or error.
        let report = RebootProbe::new().classify();
        assert!(!report.signals.is_empty(), "every signal must be reported");
        assert!(report.checked_at_ms > 0);
        match report.verdict {
            PendingRebootVerdict::NotPending
            | PendingRebootVerdict::ProbablyPending
            | PendingRebootVerdict::Pending
            | PendingRebootVerdict::Unknown => {}
        }
    }

    #[test]
    fn every_documented_signal_is_probed() {
        let signals = RebootProbe::new().collect_signals();
        assert_eq!(
            signals.len(),
            SIGNAL_SPECS.len(),
            "each spec must produce exactly one observation"
        );
        for spec in SIGNAL_SPECS {
            assert!(
                signals.iter().any(|s| s.id == spec.id),
                "signal {} was not probed",
                spec.id
            );
        }
    }

    #[test]
    fn no_signal_is_reported_as_failed_on_a_normal_machine() {
        // Reading these keys needs no elevation. A failure here would mean the probe is
        // wrong, not that the machine is unusual.
        let signals = RebootProbe::new().collect_signals();
        for s in &signals {
            assert!(
                !s.read_failed,
                "signal {} failed to read: {}",
                s.id, s.detail
            );
        }
    }

    #[test]
    fn present_signals_carry_a_useful_explanation() {
        let report = RebootProbe::new().classify();
        for reason in report.reasons() {
            assert!(!reason.is_empty());
            assert!(!reason.contains('\n'), "reasons must be single-line");
        }
    }

    #[test]
    fn weight_lookup_matches_the_spec_table() {
        assert_eq!(
            weight_of("cbs.reboot_pending"),
            Some(RebootSignalWeight::Conclusive)
        );
        assert_eq!(
            weight_of("sm.pending_file_rename"),
            Some(RebootSignalWeight::Strong)
        );
        assert_eq!(
            weight_of("wu.ux_schedule_reboot"),
            Some(RebootSignalWeight::Weak)
        );
        assert_eq!(weight_of("nonexistent"), None);
    }

    #[test]
    fn unknown_signal_ids_are_reported_as_failed_not_present() {
        match probe_one("totally-made-up") {
            ProbeResult::Failed(msg) => assert!(msg.contains("unknown")),
            ProbeResult::Present(_) => panic!("an unknown id must not claim a state"),
        }
    }

    #[test]
    fn a_key_that_does_not_exist_reads_as_not_present() {
        match key_exists(r"SOFTWARE\WorkstationGuardianTest\no-such-key-8f3a2b") {
            ProbeResult::Present(false) => {}
            ProbeResult::Present(true) => panic!("an absent key must not read as present"),
            ProbeResult::Failed(e) => panic!("an absent key is not a probe failure: {e}"),
        }
    }

    #[test]
    fn a_value_that_does_not_exist_reads_as_not_present() {
        match value_present(
            r"SOFTWARE\Microsoft\Windows\CurrentVersion",
            "NoSuchValue8f3a2b",
        ) {
            ProbeResult::Present(false) => {}
            ProbeResult::Present(true) => panic!("an absent value must not read as present"),
            ProbeResult::Failed(e) => panic!("an absent value is not a probe failure: {e}"),
        }
    }

    #[test]
    fn the_source_trait_agrees_with_the_inherent_method() {
        use guardian_core::ports::PendingRebootSource;
        let probe = RebootProbe::new();
        let via_trait = probe.collect().expect("collect must succeed");
        let via_inherent = probe.collect_signals();
        assert_eq!(via_trait.len(), via_inherent.len());
        for (a, b) in via_trait.iter().zip(via_inherent.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.present, b.present);
        }
    }

    #[test]
    fn strong_pending_check_agrees_with_the_classifier() {
        let report = RebootProbe::new().classify();
        let expected = matches!(
            report.verdict,
            PendingRebootVerdict::Pending | PendingRebootVerdict::ProbablyPending
        );
        assert_eq!(is_reboot_strongly_pending(), expected);
    }

    #[test]
    fn repeated_probes_are_stable() {
        // The probe is read-only, so two calls in a row must agree. A difference would mean
        // a probe is mutating state, which none of them may do.
        let a = RebootProbe::new().collect_signals();
        let b = RebootProbe::new().collect_signals();
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.id, y.id);
            assert_eq!(
                x.present, y.present,
                "signal {} changed between read-only probes",
                x.id
            );
        }
    }
}
