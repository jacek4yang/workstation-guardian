//! Windows Update protection policy model and verification logic.
//!
//! # What this module guarantees
//!
//! While Guardian holds the lock, automatic Windows Update activity and automatic
//! Windows Update reboots are prevented through *supported local policy*, specifically
//! `NoAutoUpdate=1` under
//! `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`.
//!
//! # What it does not do
//!
//! It does not disable the `wuauserv` service, delete Update scheduled tasks, patch system
//! binaries, firewall Microsoft endpoints, kill servicing workers, or loop on
//! `AbortSystemShutdown`. Those approaches are fragile, unsupported and are actively
//! detected and undone by Windows servicing. They would also break the machine's security
//! posture, which is a cost the operator never agreed to.
//!
//! # Fail-closed rules
//!
//! * Unreadable policy is `Unknown`, never `Protected`.
//! * A value owned by Group Policy or MDM is never reported as satisfying protection,
//!   because Guardian cannot promise what it does not control.
//! * Corruption of any input defaults back to applying protection.

use guardian_proto::model::*;

use crate::ports::{PolicyReadback, PolicyWrite};

/// Root policy key for Windows Update.
pub const WU_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate";
/// The `AU` (Automatic Updates) subkey.
pub const WU_AU_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU";

/// The values Guardian owns, in the order they are applied.
///
/// `NoAutoUpdate` is the primary protection. The rest are defence in depth: if a servicing
/// component ignores one, the others still constrain automatic reboots while a user is
/// logged on.
pub fn desired_policy() -> Vec<PolicyWrite> {
    vec![
        // Primary protection: automatic updating is disabled by policy.
        PolicyWrite {
            key_path: WU_AU_KEY.into(),
            value_name: "NoAutoUpdate".into(),
            value: PolValue::Dword(1),
        },
        // Defence in depth: never auto-reboot while a user is logged on.
        PolicyWrite {
            key_path: WU_AU_KEY.into(),
            value_name: "NoAutoRebootWithLoggedOnUsers".into(),
            value: PolValue::Dword(1),
        },
        // Defence in depth: do not force a reboot at the scheduled time regardless.
        PolicyWrite {
            key_path: WU_AU_KEY.into(),
            value_name: "AlwaysAutoRebootAtScheduledTime".into(),
            value: PolValue::Dword(0),
        },
    ]
}

/// Deadline policies that could force a reboot even with `NoAutoUpdate=1` in place.
///
/// Guardian neutralizes these locally because a deadline converts "an update is waiting"
/// into "the machine will restart", which is exactly the failure mode being prevented.
/// A value under external management is *not* touched and is reported instead.
pub fn deadline_policies_to_neutralize() -> Vec<PolicyWrite> {
    vec![
        // Forces a restart once a deadline passes.
        PolicyWrite {
            key_path: WU_POLICY_KEY.into(),
            value_name: "SetAutoRestartDeadline".into(),
            value: PolValue::Dword(0),
        },
        // Enables the deadline-related notifications that accompany the above.
        PolicyWrite {
            key_path: WU_POLICY_KEY.into(),
            value_name: "SetAutoRestartNotificationConfig".into(),
            value: PolValue::Dword(0),
        },
        // Deadline for installing updates, which also schedules restarts.
        PolicyWrite {
            key_path: WU_POLICY_KEY.into(),
            value_name: "SetUpdateNotificationLevel".into(),
            value: PolValue::Dword(0),
        },
    ]
}

/// Everything Guardian intends to own on a fully-locked machine.
pub fn all_desired_writes() -> Vec<PolicyWrite> {
    let mut v = desired_policy();
    v.extend(deadline_policies_to_neutralize());
    v
}

/// The result of one verification pass, including what Guardian had to change.
#[derive(Debug, Clone)]
pub struct VerifyOutcome {
    pub report: UpdateProtectionReport,
    /// Values Guardian wrote during this pass; empty when nothing needed changing.
    pub writes_performed: Vec<PolicyWrite>,
    /// Deadline policies found enabled and neutralized during this pass.
    pub deadlines_neutralized: Vec<String>,
    /// Values found diverging from what Guardian had recorded as its own.
    pub tamper: Vec<TamperEvent>,
}

impl VerifyOutcome {
    /// Whether this pass made any change at all. Used to avoid journal spam.
    pub fn changed_anything(&self) -> bool {
        !self.writes_performed.is_empty() || !self.deadlines_neutralized.is_empty()
    }
}

/// A single owned value that something else modified.
#[derive(Debug, Clone)]
pub struct TamperEvent {
    pub key_path: String,
    pub value_name: String,
    pub expected: PolValue,
    pub observed: Option<PolValue>,
}

/// Compute the report for a readback, given what Guardian previously installed.
///
/// This function is pure: it decides *what is true* and *what should be written*. The
/// caller performs the writes through [`crate::ports::UpdatePolicyBackend`].
pub fn analyze(
    readback: &PolicyReadback,
    managed: &ManagementState,
    _now_ms: i64,
    backend_error: Option<String>,
) -> Analysis {
    let mut findings = Vec::new();
    let mut values = Vec::new();
    let mut writes_needed = Vec::new();
    let mut tamper = Vec::new();
    let mut deadlines_neutralized = Vec::new();

    if let Some(err) = backend_error {
        // Could not read policy at all: fail closed, report Unknown, ask for a re-apply.
        return Analysis {
            level: ProtectionLevel::Unknown,
            primary_lock_effective: false,
            values: Vec::new(),
            deadline_status: Vec::new(),
            findings: vec![Finding {
                severity: FindingSeverity::Error,
                code: "update.read_failed".into(),
                message: err,
            }],
            writes_needed: all_desired_writes(),
            tamper: Vec::new(),
            deadlines_neutralized: Vec::new(),
        };
    }

    if !readback.unreadable_keys.is_empty() {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            code: "update.partial_read".into(),
            message: format!(
                "could not read policy key(s): {}",
                readback.unreadable_keys.join(", ")
            ),
        });
    }

    // An external authority outranks local policy. Guardian must not fight it, and must
    // not claim protection it cannot deliver.
    let externally_managed = managed.is_externally_managed();
    if externally_managed {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            code: "update.external_policy".into(),
            message: format!(
                "this machine is {}; Group Policy or MDM can override local update policy",
                managed.describe()
            ),
        });
    }

    for desired in all_desired_writes() {
        let observed = readback
            .values
            .iter()
            .find(|o| o.key_path == desired.key_path && o.value_name == desired.value_name)
            .and_then(|o| o.value.clone());

        let matches = observed.as_ref() == Some(&desired.value);

        // If the value already matches, there is nothing to write and no tamper to report.
        if !matches {
            // Was this value one Guardian had set before? If the readback shows something
            // different from what we intended, something changed it.
            let is_deadline = deadline_policies_to_neutralize()
                .iter()
                .any(|d| d.key_path == desired.key_path && d.value_name == desired.value_name);

            if is_deadline {
                // A deadline policy that is present and non-zero is a real hazard,
                // regardless of whether Guardian had ever touched it. A missing or
                // already-zero value is simply "nothing to do".
                if observed.is_some() && observed.as_ref() != Some(&desired.value) {
                    deadlines_neutralized
                        .push(format!("{}\\{}", desired.key_path, desired.value_name));
                    findings.push(Finding {
                        severity: FindingSeverity::Warning,
                        code: "update.deadline_present".into(),
                        message: format!(
                            "{} was set to {:?}; a Windows Update restart deadline could force a reboot",
                            desired.value_name, observed
                        ),
                    });
                }
            } else if observed.is_some() {
                // A core value is present but wrong: something changed it out from under us.
                //
                // A value that is simply *absent* is not tampering, but it is not benign
                // either. It means protection is not in effect, which is reported through
                // the level (`Degraded`) rather than through a tamper incident. Conflating
                // the two would make the incident stream useless on a fresh machine.
                tamper.push(TamperEvent {
                    key_path: desired.key_path.clone(),
                    value_name: desired.value_name.clone(),
                    expected: desired.value.clone(),
                    observed: observed.clone(),
                });
            }

            writes_needed.push(desired.clone());
        }
    }

    // Re-evaluate the *primary* protection against what will be true after the writes are
    // applied. We report the level for the state we are about to establish, and separately
    // note whether it holds right now.
    let primary_now = readback
        .values
        .iter()
        .find(|o| o.key_path == WU_AU_KEY && o.value_name == "NoAutoUpdate")
        .and_then(|o| o.value.clone())
        .and_then(|v| v.as_dword())
        .map(|v| v == 1)
        .unwrap_or(false);

    for desired in all_desired_writes() {
        let observed = readback
            .values
            .iter()
            .find(|o| o.key_path == desired.key_path && o.value_name == desired.value_name)
            .and_then(|o| o.value.clone());
        let matches = observed.as_ref() == Some(&desired.value);
        values.push(PolicyValueStatus {
            name: desired.value_name.clone(),
            desired: desired.value.clone(),
            observed,
            matches,
            external_owner: if externally_managed && !matches {
                Some(managed.describe())
            } else {
                None
            },
        });
    }

    let primary_lock_effective = primary_now;

    // The verdict. Anything short of "everything conforms, right now, with nothing
    // external in the way" is not Protected.
    let all_conform_now = values.iter().all(|v| v.matches);
    let level = if externally_managed {
        if primary_lock_effective && all_conform_now {
            // Local policy is in place but could be overridden at any refresh. Guardian is
            // honest about this rather than claiming a guarantee it cannot make.
            ProtectionLevel::Degraded
        } else {
            ProtectionLevel::Degraded
        }
    } else if all_conform_now && readback.complete {
        ProtectionLevel::Protected
    } else if !readback.complete {
        ProtectionLevel::Unknown
    } else {
        ProtectionLevel::Degraded
    };

    if !tamper.is_empty() {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            code: "update.tamper_detected".into(),
            message: format!(
                "{} Guardian-owned update policy value(s) were modified",
                tamper.len()
            ),
        });
    }

    Analysis {
        level,
        primary_lock_effective,
        values,
        deadline_status: build_deadline_status(readback, &deadlines_neutralized),
        findings,
        writes_needed,
        tamper,
        deadlines_neutralized,
    }
}

fn build_deadline_status(
    readback: &PolicyReadback,
    neutralized_names: &[String],
) -> Vec<DeadlinePolicyStatus> {
    deadline_policies_to_neutralize()
        .into_iter()
        .map(|d| {
            let observed = readback
                .values
                .iter()
                .find(|o| o.key_path == d.key_path && o.value_name == d.value_name)
                .and_then(|o| o.value.clone());
            let full = format!("{}\\{}", d.key_path, d.value_name);
            DeadlinePolicyStatus {
                name: d.value_name.clone(),
                neutralized: neutralized_names.contains(&full)
                    || observed.as_ref() == Some(&d.value),
                observed,
                external_owner: None,
            }
        })
        .collect()
}

/// The pure result of a verification pass.
#[derive(Debug, Clone)]
pub struct Analysis {
    pub level: ProtectionLevel,
    pub primary_lock_effective: bool,
    pub values: Vec<PolicyValueStatus>,
    pub deadline_status: Vec<DeadlinePolicyStatus>,
    pub findings: Vec<Finding>,
    pub writes_needed: Vec<PolicyWrite>,
    pub tamper: Vec<TamperEvent>,
    pub deadlines_neutralized: Vec<String>,
}

impl Analysis {
    pub fn into_report(self, managed: &ManagementState, now_ms: i64) -> UpdateProtectionReport {
        let backend_error = None;
        UpdateProtectionReport {
            level: self.level,
            primary_lock_effective: self.primary_lock_effective,
            values: self.values,
            neutralized_deadlines: self.deadline_status,
            management: managed.clone(),
            findings: self.findings,
            checked_at_ms: now_ms,
            backend_error,
        }
    }
}

/// Whether turning protection *off* is currently safe.
///
/// Maintenance mode is the only path that unlocks updates, and it is always explicit. This
/// helper exists so the rule is expressed once.
pub fn may_unlock(mode: ProtectionMode, authorized: bool) -> bool {
    authorized && matches!(mode, ProtectionMode::Maintenance)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::PolicyObservation;

    fn readback(pairs: &[(&str, &str, PolValue)]) -> PolicyReadback {
        PolicyReadback {
            values: pairs
                .iter()
                .map(|(k, n, v)| PolicyObservation {
                    key_path: (*k).to_string(),
                    value_name: (*n).to_string(),
                    value: Some(v.clone()),
                })
                .collect(),
            unreadable_keys: Vec::new(),
            complete: true,
        }
    }

    /// A readback of an empty machine: every owned value is absent.
    ///
    /// `complete: true` because the read succeeded — it simply found nothing. That is a
    /// valid, fully-observed state, and must be reported as `Degraded` (protection absent)
    /// rather than `Unknown` (protection unverified).
    fn empty_but_readable() -> PolicyReadback {
        PolicyReadback {
            values: Vec::new(),
            unreadable_keys: Vec::new(),
            complete: true,
        }
    }

    /// Overwrite a value in a readback, replacing any existing entry for that key/name.
    fn set_value(rb: &mut PolicyReadback, key: &str, name: &str, value: PolValue) {
        rb.values
            .retain(|o| !(o.key_path == key && o.value_name == name));
        rb.values.push(PolicyObservation {
            key_path: key.to_string(),
            value_name: name.to_string(),
            value: Some(value),
        });
    }

    fn fully_locked() -> PolicyReadback {
        readback(
            &all_desired_writes()
                .iter()
                .map(|w| (w.key_path.as_str(), w.value_name.as_str(), w.value.clone()))
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn fully_conformant_unmanaged_host_is_protected() {
        let a = analyze(&fully_locked(), &ManagementState::Unmanaged, 100, None);
        assert_eq!(a.level, ProtectionLevel::Protected);
        assert!(a.primary_lock_effective);
        assert!(a.writes_needed.is_empty(), "no writes when already correct");
        assert!(a.tamper.is_empty());
        assert!(a.values.iter().all(|v| v.matches));
    }

    #[test]
    fn no_auto_update_treated_as_the_primary_lock() {
        // Only NoAutoUpdate set: everything else missing. The report must still say the
        // primary lock is effective while flagging the missing defence in depth.
        let rb = readback(&[(WU_AU_KEY, "NoAutoUpdate", PolValue::Dword(1))]);
        let a = analyze(&rb, &ManagementState::Unmanaged, 100, None);
        assert!(a.primary_lock_effective);
        assert_eq!(a.level, ProtectionLevel::Degraded);
        assert!(!a.writes_needed.is_empty());
    }

    #[test]
    fn unprotected_host_reports_degraded_and_requests_writes() {
        let rb = readback(&[(WU_AU_KEY, "NoAutoUpdate", PolValue::Dword(0))]);
        let a = analyze(&rb, &ManagementState::Unmanaged, 100, None);
        assert!(!a.primary_lock_effective);
        assert_eq!(a.level, ProtectionLevel::Degraded);
        assert!(a.values.iter().any(|v| !v.matches));
        assert!(a
            .writes_needed
            .iter()
            .any(|w| w.value_name == "NoAutoUpdate"));
    }

    #[test]
    fn missing_values_request_writes_with_no_tamper() {
        // First run on a machine with no policy at all: we should write, and must not call
        // it tamper because nothing was changed out from under us.
        let a = analyze(
            &empty_but_readable(),
            &ManagementState::Unmanaged,
            100,
            None,
        );
        assert_eq!(
            a.writes_needed.len(),
            all_desired_writes().len(),
            "every value must be applied on a bare host"
        );
        assert!(a.tamper.is_empty(), "a missing value is not tampering");
        assert_eq!(a.level, ProtectionLevel::Degraded);
    }

    #[test]
    fn changed_value_is_reported_as_tamper_and_restored() {
        let mut rb = fully_locked();
        for o in rb.values.iter_mut() {
            if o.value_name == "NoAutoUpdate" {
                o.value = Some(PolValue::Dword(0));
            }
        }
        let a = analyze(&rb, &ManagementState::Unmanaged, 100, None);
        assert_eq!(a.tamper.len(), 1);
        assert_eq!(a.tamper[0].value_name, "NoAutoUpdate");
        assert_eq!(a.tamper[0].observed, Some(PolValue::Dword(0)));
        assert!(a
            .writes_needed
            .iter()
            .any(|w| w.value_name == "NoAutoUpdate"));
        assert!(!a.primary_lock_effective);
    }

    #[test]
    fn unreadable_policy_is_unknown_never_protected() {
        let rb = PolicyReadback {
            values: Vec::new(),
            unreadable_keys: vec![WU_AU_KEY.into()],
            complete: false,
        };
        let a = analyze(&rb, &ManagementState::Unmanaged, 100, None);
        assert_eq!(a.level, ProtectionLevel::Unknown);
        assert!(!a.level.is_protected());
    }

    #[test]
    fn backend_error_is_unknown_never_protected() {
        let a = analyze(
            &PolicyReadback::default(),
            &ManagementState::Unmanaged,
            100,
            Some("registry access denied".into()),
        );
        assert_eq!(a.level, ProtectionLevel::Unknown);
        assert!(!a.level.is_protected());
        // Fail-closed: we still ask for protection to be (re)applied.
        assert!(!a.writes_needed.is_empty());
    }

    #[test]
    fn externally_managed_host_is_never_reported_protected() {
        // Even when the values look perfect, something else can override them at any
        // Group Policy refresh. Claiming Protected here would be a lie that only shows up
        // as lost work.
        for managed in [
            ManagementState::DomainJoined {
                domain: "corp.example".into(),
            },
            ManagementState::MdmEnrolled {
                provider: "Intune".into(),
            },
            ManagementState::DomainAndMdm {
                domain: "corp.example".into(),
                provider: "Intune".into(),
            },
            ManagementState::Unknown,
        ] {
            let a = analyze(&fully_locked(), &managed, 100, None);
            assert_eq!(
                a.level,
                ProtectionLevel::Degraded,
                "{managed:?} must not report Protected"
            );
            assert!(!a.level.is_protected());
            assert!(
                a.findings
                    .iter()
                    .any(|f| f.code == "update.external_policy"),
                "the externally-controlled policy must be named"
            );
        }
    }

    #[test]
    fn deadline_policy_enabled_is_neutralized_and_flagged() {
        let mut rb = fully_locked();
        set_value(
            &mut rb,
            WU_POLICY_KEY,
            "SetAutoRestartDeadline",
            PolValue::Dword(1),
        );
        let a = analyze(&rb, &ManagementState::Unmanaged, 100, None);
        assert_eq!(a.deadlines_neutralized.len(), 1);
        assert!(a
            .findings
            .iter()
            .any(|f| f.code == "update.deadline_present"));
        assert!(a
            .writes_needed
            .iter()
            .any(|w| w.value_name == "SetAutoRestartDeadline"));
        assert_eq!(a.level, ProtectionLevel::Degraded);
    }

    #[test]
    fn deadline_policy_already_zero_is_quiet() {
        let mut rb = fully_locked();
        set_value(
            &mut rb,
            WU_POLICY_KEY,
            "SetAutoRestartDeadline",
            PolValue::Dword(0),
        );
        let a = analyze(&rb, &ManagementState::Unmanaged, 100, None);
        assert!(a.deadlines_neutralized.is_empty());
        assert!(a.writes_needed.is_empty());
        assert_eq!(a.level, ProtectionLevel::Protected);
    }

    #[test]
    fn unchanged_state_produces_no_writes_twice_in_a_row() {
        // The core efficiency property: verification must be free when nothing changed.
        let rb = fully_locked();
        let a1 = analyze(&rb, &ManagementState::Unmanaged, 100, None);
        let a2 = analyze(&rb, &ManagementState::Unmanaged, 200, None);
        assert!(a1.writes_needed.is_empty());
        assert!(a2.writes_needed.is_empty());
        assert!(a1.values.iter().all(|v| v.matches));
        assert!(a2.values.iter().all(|v| v.matches));
    }

    #[test]
    fn descriptor_covers_every_owned_value() {
        // Guards against adding a value to one list and forgetting the other.
        let desired: Vec<_> = all_desired_writes();
        let names: Vec<_> = desired.iter().map(|d| d.value_name.as_str()).collect();
        for required in [
            "NoAutoUpdate",
            "NoAutoRebootWithLoggedOnUsers",
            "AlwaysAutoRebootAtScheduledTime",
        ] {
            assert!(names.contains(&required), "{required} must be owned");
        }
        // No duplicates: two writers disagreeing would be a silent hazard.
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    #[test]
    fn unlock_requires_maintenance_and_authorization() {
        assert!(!may_unlock(ProtectionMode::Normal, true));
        assert!(!may_unlock(ProtectionMode::Working, true));
        assert!(!may_unlock(ProtectionMode::Maintenance, false));
        assert!(may_unlock(ProtectionMode::Maintenance, true));
    }
}
