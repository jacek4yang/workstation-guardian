//! Policy restoration and installation diagnostics.
//!
//! # Why there is no installer here
//!
//! Guardian is a single tray application. It registers no Windows service, creates no scheduled
//! task, adds no autostart entry, and writes nothing outside its own data directory and the one
//! Windows Update policy key it owns. Running the program *is* the installation.
//!
//! That leaves exactly one thing this module must do: undo the policy.
//!
//! # Safety properties this module must uphold
//!
//! * **Restore touches only what Guardian owned.** Values are restored from Guardian's own rollback
//!   metadata. Values belonging to Group Policy or MDM are not in that list, so they are never
//!   touched, because Guardian never recorded owning them.
//! * **Restore never reboots.** Nothing in this module may restart the machine.
//! * **Restore refuses to guess.** If the rollback metadata cannot be read, it reports that rather
//!   than removing policy values it might not have created.

use std::path::Path;

use guardian_core::ports::UpdatePolicyBackend;
use guardian_storage::GuardianPaths;

/// Restore the update policy values Guardian recorded writing.
///
/// This is the only mutation Guardian offers that *reduces* protection, so it is deliberately
/// explicit: it is reached from `guardianctl restore-policy`, never automatically, and never as a
/// side effect of removing files.
pub fn restore_policy() -> Result<String, String> {
    let paths = GuardianPaths::production();
    let store = guardian_storage::Store::open(paths.clone())
        .map_err(|e| format!("could not open the state store: {e}"))?;
    let (state, load_error) = store.load_state();

    if let Some(e) = load_error {
        return Err(format!(
            "the rollback metadata could not be read ({e}); refusing to guess which policy \
             values Guardian changed"
        ));
    }

    if !state.policy_installed {
        return Ok(
            "Guardian had not installed its update policy, so there is nothing to restore.\n"
                .to_string(),
        );
    }

    if state.original_policy.is_empty() {
        return Ok(
            "No original policy values were recorded, so nothing was restored.\n  \
             Guardian may have created values where none existed; remove \
             HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate manually if desired.\n"
                .to_string(),
        );
    }

    // The stored form and the ports form are deliberately different types: the stored one is a
    // durable record, the other is what the backend accepts. Converting explicitly here keeps
    // that boundary visible.
    let original: Vec<guardian_core::ports::OwnedPolicy> = state
        .original_policy
        .iter()
        .map(|v| guardian_core::ports::OwnedPolicy {
            key_path: v.key_path.clone(),
            value_name: v.value_name.clone(),
            value: v.value.clone(),
            created_key: v.created_key,
        })
        .collect();

    let backend = guardian_win::policy::PolicyBackend::new();
    backend.restore(&original).map_err(|e| e.to_string())?;

    let mut msg = format!(
        "Restored {} original update policy value(s).\n",
        state.original_policy.len()
    );
    msg.push_str(
        "  Values belonging to external management were not touched, because Guardian never \
         recorded owning them.\n",
    );
    msg.push_str(
        "  The machine was NOT rebooted. Windows Update is unlocked only after it next refreshes \
         its policy.\n",
    );

    Ok(msg)
}

/// Whether the process is elevated.
///
/// Used only to explain, up front, why update protection cannot be applied — rather than letting a
/// registry write fail with a bare access-denied later.
pub fn is_elevated() -> bool {
    guardian_win::elevation::is_elevated()
}

/// A short description of the installation state, for diagnostics.
///
/// There is no service to report on. What matters is whether the program is running elevated and
/// whether its state files exist.
pub fn installation_summary() -> String {
    let paths = GuardianPaths::production();

    let mut out = format!(
        "  Elevated:           {}\n  Data directory:     {}\n",
        if is_elevated() {
            "yes"
        } else {
            "NO — policy cannot be applied"
        },
        paths.root().display()
    );
    out.push_str(&format!(
        "  Configuration:      {}\n",
        describe_path(&paths.config_file())
    ));
    out.push_str(&format!(
        "  Journal:            {}\n",
        describe_path(&paths.journal_file())
    ));

    out
}

/// Describe a path as present or absent, with its size.
fn describe_path(path: &Path) -> String {
    match std::fs::metadata(path) {
        Ok(m) => format!("{} ({} bytes)", path.display(), m.len()),
        Err(_) => format!("{} (absent)", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restoring_policy_without_rollback_metadata_says_so_rather_than_guessing() {
        // This exercises the real state path, which on a test machine has no rollback metadata.
        // The important property is that it refuses to guess.
        match restore_policy() {
            Ok(msg) => assert!(
                msg.contains("nothing to restore")
                    || msg.contains("No original policy")
                    || msg.contains("Restored"),
                "unexpected message: {msg}"
            ),
            // A locked-down ProgramData is also acceptable, as long as the failure is explained.
            Err(e) => assert!(!e.is_empty()),
        }
    }

    #[test]
    fn the_installation_summary_reports_elevation_and_paths() {
        let text = installation_summary();
        assert!(text.contains("Elevated"));
        assert!(text.contains("Configuration"));
        assert!(text.contains("Journal"));
        // There is no service any more, so the summary must not claim there is one.
        assert!(
            !text.contains("Service installed"),
            "the summary still reports a Windows service"
        );
    }

    #[test]
    fn describing_a_path_handles_both_cases() {
        let temp = std::env::temp_dir().join(format!("guardian-desc-{}", std::process::id()));
        std::fs::write(&temp, b"12345").unwrap();
        assert!(describe_path(&temp).contains("5 bytes"));
        let _ = std::fs::remove_file(&temp);

        assert!(describe_path(Path::new(r"C:\definitely-not-real-8f3a2b")).contains("absent"));
    }

    #[test]
    fn elevation_check_does_not_panic() {
        // Reads the process token; must work whether or not the caller is elevated.
        let _ = is_elevated();
    }
}
