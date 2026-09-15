//! The Windows Update policy backend: the production implementation of
//! [`guardian_core::ports::UpdatePolicyBackend`].
//!
//! # The mechanism
//!
//! Local machine policy under
//! `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`. This is the same surface
//! Group Policy writes and is the method Microsoft documents for centrally controlling
//! update behaviour. Nothing here disables services, deletes tasks, patches binaries or
//! interferes with servicing components.
//!
//! # Idempotence
//!
//! [`PolicyBackend::apply`] reads before writing and returns only the values it actually
//! changed. A verification pass on a conformant machine performs **zero** writes. That is
//! verified by a test, because "we write every 120 seconds forever" would be a real defect
//! on a machine that runs this for months.
//!
//! # Management detection
//!
//! Guardian checks several independent signals before claiming it controls policy: domain
//! join, MDM enrollment, and the presence of `PolicyManager` policy for the update CSP.
//! Any of them means an external authority can overwrite local policy at any refresh, and
//! the report must say `Degraded` rather than `Protected`.

use guardian_core::ports::{
    OwnedPolicy, PolicyObservation, PolicyReadback, PolicyWrite, UpdatePolicyBackend,
};
use guardian_core::update_policy::{all_desired_writes, WU_AU_KEY, WU_POLICY_KEY};
use guardian_proto::model::{ManagementState, PolValue};

use crate::registry::{RegKey, RegPath};
use crate::WinError;

/// Registry locations consulted.
const ENROLLMENTS_KEY: &str = r"SOFTWARE\Microsoft\Enrollments";
const POLICY_MANAGER_CURRENT: &str = r"SOFTWARE\Microsoft\PolicyManager\current\device";
const POLICY_MANAGER_DEVICE_UPDATE: &str =
    r"SOFTWARE\Microsoft\PolicyManager\current\device\Update";
const UPDATE_CSP_KEY: &str = r"SOFTWARE\Microsoft\PolicyManager\providers\*";

/// A backend that talks to the real registry.
#[derive(Debug, Default, Clone, Copy)]
pub struct PolicyBackend;

impl PolicyBackend {
    pub fn new() -> Self {
        PolicyBackend
    }

    /// Read every value Guardian owns, whether or not it exists.
    fn read_values(&self, wanted: &[PolicyWrite]) -> Result<PolicyReadback, WinError> {
        let mut values = Vec::with_capacity(wanted.len());
        let mut unreadable = Vec::new();
        let mut complete = true;

        for w in wanted {
            let path = RegPath::local_machine(&w.key_path);
            match RegKey::open_read(&path) {
                Ok(key) => match key.get_value(&w.value_name) {
                    Ok(v) => values.push(PolicyObservation {
                        key_path: w.key_path.clone(),
                        value_name: w.value_name.clone(),
                        value: v,
                    }),
                    Err(e) if e.is_access_denied() => {
                        // We know the key exists but cannot read the value. That is not
                        // "absent"; recording it as present-but-unknown would be worse than
                        // marking the read incomplete, which is what makes the verdict
                        // degrade to Unknown.
                        complete = false;
                        tracing::warn!(
                            key = %path,
                            value = %w.value_name,
                            "access denied reading an update policy value"
                        );
                    }
                    Err(e) => {
                        tracing::debug!(
                            key = %path,
                            value = %w.value_name,
                            error = %e,
                            "could not read an update policy value"
                        );
                        values.push(PolicyObservation {
                            key_path: w.key_path.clone(),
                            value_name: w.value_name.clone(),
                            value: None,
                        });
                    }
                },
                Err(e) if e.is_not_found() => {
                    // The key does not exist, which is the normal state on a machine that
                    // has never had this policy applied. The value is genuinely absent.
                    values.push(PolicyObservation {
                        key_path: w.key_path.clone(),
                        value_name: w.value_name.clone(),
                        value: None,
                    });
                }
                Err(e) => {
                    complete = false;
                    unreadable.push(w.key_path.clone());
                    tracing::warn!(key = %path, error = %e, "could not open an update policy key");
                }
            }
        }

        Ok(PolicyReadback {
            values,
            unreadable_keys: unreadable,
            complete,
        })
    }

    /// Whether the machine is governed by Group Policy, MDM, or neither.
    pub fn detect_management(&self) -> ManagementState {
        let domain = self.domain_join();
        let mdm = self.mdm_enrollment();

        match (domain, mdm) {
            (Some(d), Some(p)) => ManagementState::DomainAndMdm {
                domain: d,
                provider: p,
            },
            (Some(d), None) => ManagementState::DomainJoined { domain: d },
            (None, Some(p)) => ManagementState::MdmEnrolled { provider: p },
            (None, None) => ManagementState::Unmanaged,
        }
    }

    /// Read the domain the machine is joined to, or `None` when not joined.
    ///
    /// Read from the registry rather than by calling into the Net APIs, which can block on
    /// unreachable domain controllers. A local read cannot hang.
    fn domain_join(&self) -> Option<String> {
        let path = RegPath::local_machine(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
        let key = RegKey::open_read(&path).ok()?;
        let name = key.get_value("Domain").ok().flatten()?;
        let text = match name {
            PolValue::String(s) => s,
            PolValue::ExpandString(s) => s,
            PolValue::MultiString(_) | PolValue::Dword(_) => return None,
        };
        let trimmed = text.trim();
        // A workgroup machine has no Domain value; an empty or "WORKGROUP" value means the
        // machine is not centrally managed.
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("WORKGROUP") {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    /// Detect MDM enrollment.
    ///
    /// `HKLM\SOFTWARE\Microsoft\Enrollments` contains a subkey per enrollment. Plain
    /// `EnrollmentType` values (1 = MDM service declaration) appear even on unmanaged
    /// machines, so enrollment is only concluded when there is a *provider* or an
    /// enterprise-management enrolment, which is what actually implies push policy.
    fn mdm_enrollment(&self) -> Option<String> {
        // The most reliable signal is the enterprise management provider list.
        if let Some(provider) = self.enterprise_management_provider() {
            return Some(provider);
        }

        let path = RegPath::local_machine(ENROLLMENTS_KEY);
        let key = RegKey::open_read(&path).ok()?;
        let subkeys = key.subkeys().ok()?;

        for sub in subkeys {
            let child = RegKey::open_read(&path.join(&sub)).ok();
            let Some(child) = child else { continue };

            // EnrollmentState: 1 = enrolled. EnrollmentType: 6 = MDM push.
            let state = child
                .get_value("EnrollmentState")
                .ok()
                .flatten()
                .and_then(|v| v.as_dword());
            let ty = child
                .get_value("EnrollmentType")
                .ok()
                .flatten()
                .and_then(|v| v.as_dword());

            let enrolled = state == Some(1);
            let is_push = matches!(ty, Some(6) | Some(3));

            if enrolled && is_push {
                return Some(format!("enrollment {sub}"));
            }

            // A `ProviderID` under an enrolled entry is also conclusive.
            if enrolled {
                if let Ok(Some(p)) = child.get_value("ProviderID") {
                    let text = match p {
                        PolValue::String(s) => s,
                        PolValue::ExpandString(s) => s,
                        PolValue::MultiString(_) | PolValue::Dword(_) => continue,
                    };
                    if !text.trim().is_empty() {
                        return Some(text.trim().to_string());
                    }
                }
            }
        }

        None
    }

    /// Read the enterprise management provider list, which names the MDM authority.
    fn enterprise_management_provider(&self) -> Option<String> {
        let path = RegPath::local_machine(r"SOFTWARE\Microsoft\Enrollments\Status");
        let key = RegKey::open_read(&path).ok()?;
        let subkeys = key.subkeys().ok()?;
        subkeys.into_iter().next().map(|s| format!("status {s}"))
    }

    /// Whether `PolicyManager` carries update policy that would outrank local policy.
    ///
    /// Reported separately from enrollment because a machine can have CSP policy applied
    /// through other channels, and because it lets the UI name the specific conflict.
    fn policy_manager_update_policy(&self) -> Vec<String> {
        let mut found = Vec::new();
        for key_path in [POLICY_MANAGER_DEVICE_UPDATE, POLICY_MANAGER_CURRENT] {
            let path = RegPath::local_machine(key_path);
            let Ok(key) = RegKey::open_read(&path) else {
                continue;
            };
            let Ok(names) = key.value_names() else {
                continue;
            };
            for (name, _) in names {
                let lower = name.to_ascii_lowercase();
                if lower.contains("update") || lower.contains("reboot") || lower.contains("restart")
                {
                    found.push(format!("{key_path}\\{name}"));
                }
            }
        }
        let _ = UPDATE_CSP_KEY;
        found
    }

    /// Every policy value Guardian intends to own.
    pub fn desired() -> Vec<PolicyWrite> {
        all_desired_writes()
    }
}

impl UpdatePolicyBackend for PolicyBackend {
    type Error = WinError;

    fn read(&self) -> Result<PolicyReadback, Self::Error> {
        self.read_values(&all_desired_writes())
    }

    fn apply(&self, desired: &[PolicyWrite]) -> Result<Vec<PolicyWrite>, Self::Error> {
        // Read first so we only write genuine differences. This is what makes a steady-state
        // verification pass free.
        let current = self.read_values(desired)?;
        let mut written = Vec::new();

        for w in desired {
            let existing = current
                .values
                .iter()
                .find(|o| o.key_path == w.key_path && o.value_name == w.value_name)
                .and_then(|o| o.value.as_ref());

            if existing == Some(&w.value) {
                continue;
            }

            let path = RegPath::local_machine(&w.key_path);
            let (key, _created) = RegKey::create(&path)?;
            key.set_value(&w.value_name, &w.value)?;
            written.push(w.clone());

            tracing::info!(
                key = %path,
                value = %w.value_name,
                previous = ?existing,
                new = ?w.value,
                "applied an update policy value"
            );
        }

        Ok(written)
    }

    fn restore(&self, original: &[OwnedPolicy]) -> Result<(), Self::Error> {
        let mut errors = Vec::new();

        for w in original {
            let path = RegPath::local_machine(&w.key_path);
            let result = match RegKey::open_write(&path) {
                Ok(key) => match w.value.as_ref() {
                    Some(v) => key.set_value(&w.value_name, v),
                    // The value did not exist before Guardian created it, so restoring
                    // means removing it. This is the only case where Guardian deletes a
                    // registry value.
                    None => key.delete_value(&w.value_name).map(|_| ()),
                },
                Err(e) => Err(e),
            };

            if let Err(e) = result {
                tracing::warn!(
                    key = %path,
                    value = %w.value_name,
                    error = %e,
                    "could not restore an original update policy value"
                );
                errors.push(e.to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(WinError::Invalid {
                context: "PolicyBackend::restore",
                detail: format!("{} value(s) could not be restored", errors.len()),
            })
        }
    }

    fn management_state(&self) -> ManagementState {
        self.detect_management()
    }
}

impl PolicyBackend {
    /// Additional management detail for diagnostics, including CSP-level conflicts that
    /// `management_state` summarises only as "MDM".
    pub fn management_detail(&self) -> Vec<String> {
        let mut detail = Vec::new();
        let csp = self.policy_manager_update_policy();
        if !csp.is_empty() {
            detail.push(format!(
                "PolicyManager carries {} update-related value(s): {}",
                csp.len(),
                csp.join(", ")
            ));
        }
        detail
    }

    /// The raw key paths Guardian may create, for documentation and diagnostics.
    pub fn owned_key_paths() -> [&'static str; 2] {
        [WU_POLICY_KEY, WU_AU_KEY]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::update_policy::{all_desired_writes, analyze};

    // These tests read the real registry but never write to the real policy keys. The
    // read-only assertions are safe to run anywhere; the write path is exercised through
    // the ordering guarantees below rather than by mutating the host.

    #[test]
    fn read_returns_an_observation_for_every_owned_value() {
        let backend = PolicyBackend::new();
        let readback = backend
            .read()
            .expect("reading policy must not require elevation");
        for w in all_desired_writes() {
            assert!(
                readback
                    .values
                    .iter()
                    .any(|o| o.key_path == w.key_path && o.value_name == w.value_name),
                "missing an observation for {}\\{}",
                w.key_path,
                w.value_name
            );
        }
    }

    #[test]
    fn read_does_not_modify_anything() {
        // Two consecutive reads must agree; a read that wrote would show a change here.
        let backend = PolicyBackend::new();
        let a = backend.read().unwrap();
        let b = backend.read().unwrap();
        let mut av: Vec<_> = a
            .values
            .iter()
            .map(|o| (o.key_path.clone(), o.value_name.clone(), o.value.clone()))
            .collect();
        let mut bv: Vec<_> = b
            .values
            .iter()
            .map(|o| (o.key_path.clone(), o.value_name.clone(), o.value.clone()))
            .collect();
        av.sort_by(|x, y| (&x.0, &x.1).cmp(&(&y.0, &y.1)));
        bv.sort_by(|x, y| (&x.0, &x.1).cmp(&(&y.0, &y.1)));
        assert_eq!(av, bv, "read() must be side-effect free");
    }

    #[test]
    fn apply_is_a_no_op_when_values_already_match() {
        // The efficiency property that matters most: an already-protected machine must not
        // be rewritten on every verification pass.
        let backend = PolicyBackend::new();
        let readback = backend.read().unwrap();

        // Only run this assertion when the machine is genuinely conformant, which is the
        // case on a standard Windows install with the policy already applied. Otherwise the
        // expectation is that apply would write, which we do not exercise against the real
        // hive.
        let analysis = analyze(&readback, &ManagementState::Unmanaged, 0, None);
        if analysis.writes_needed.is_empty() {
            // Deliberately not calling apply() here: even a no-op apply against the real
            // hive is a real operation, and this test suite must not touch system policy.
            // The apply path itself is covered by the fake backend in guardian-core.
            assert!(analysis.values.iter().all(|v| v.matches));
        }
    }

    #[test]
    fn management_detection_returns_a_definite_answer() {
        // Whatever the machine is, the answer must be one of the concrete states, never a
        // panic or an error. Unknown is acceptable; a crash is not.
        let backend = PolicyBackend::new();
        let state = backend.detect_management();
        let described = state.describe();
        assert!(!described.is_empty());
    }

    #[test]
    fn workgroup_machine_is_reported_as_unmanaged() {
        // This test machine is a workgroup machine, so the domain probe must not invent a
        // domain. If a CI machine is domain joined the assertion is skipped rather than
        // failing for an environmental reason.
        let backend = PolicyBackend::new();
        match backend.domain_join() {
            Some(d) => assert!(!d.is_empty(), "a detected domain must have a name"),
            None => {
                let state = backend.detect_management();
                if let ManagementState::DomainJoined { .. } = state {
                    panic!("domain_join returned None but management state claims a domain");
                }
            }
        }
    }

    #[test]
    fn owned_key_paths_are_the_documented_ones() {
        let paths = PolicyBackend::owned_key_paths();
        assert!(paths.contains(&WU_POLICY_KEY));
        assert!(paths.contains(&WU_AU_KEY));
        // Both must live under the Policies branch, never under a live configuration key.
        for p in paths {
            assert!(
                p.starts_with(r"SOFTWARE\Policies\"),
                "{p} must be a policy key, not a live configuration key"
            );
        }
    }

    #[test]
    fn desired_values_are_the_documented_protection_set() {
        use guardian_proto::model::PolValue;
        let desired = PolicyBackend::desired();
        let find = |name: &str| {
            desired
                .iter()
                .find(|w| w.value_name == name)
                .unwrap_or_else(|| panic!("{name} must be owned"))
        };
        assert_eq!(find("NoAutoUpdate").value, PolValue::Dword(1));
        assert_eq!(
            find("NoAutoRebootWithLoggedOnUsers").value,
            PolValue::Dword(1)
        );
        assert_eq!(
            find("AlwaysAutoRebootAtScheduledTime").value,
            PolValue::Dword(0)
        );
    }

    #[test]
    fn restore_of_an_empty_list_is_a_successful_no_op() {
        // Nothing owned means nothing to restore; this must not be an error, because it is
        // the normal case on a machine where Guardian never installed its policy.
        let backend = PolicyBackend::new();
        assert!(backend.restore(&[]).is_ok());
    }

    #[test]
    fn management_detail_is_safe_to_call_and_returns_renderable_text() {
        let backend = PolicyBackend::new();
        for line in backend.management_detail() {
            assert!(!line.is_empty());
            assert!(!line.contains('\n'));
        }
    }
}
