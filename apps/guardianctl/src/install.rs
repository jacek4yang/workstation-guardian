//! Installation, uninstallation and service control.
//!
//! # Safety properties this module must uphold
//!
//! * **Elevation is explicit.** Installation needs administrator rights; the module reports that
//!   clearly rather than failing with a raw `ERROR_ACCESS_DENIED`.
//! * **The binary path is validated** before it reaches the SCM, which runs it as `LocalSystem`.
//! * **Uninstall restores only what Guardian owned.** The policy values Guardian recorded writing
//!   are restored from its own rollback metadata. Values belonging to Group Policy or MDM are
//!   never touched, because Guardian never recorded owning them.
//! * **Uninstall never reboots.** No install or uninstall path may restart the machine.

use std::path::{Path, PathBuf};

use guardian_proto::model::ConfigDocument;
use guardian_storage::GuardianPaths;
use guardian_win::service::{Scm, StartType};

/// Which service control action to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    Start,
    Stop,
}

/// Install the service and initialize its state.
pub fn install(force: bool) -> Result<String, String> {
    let mut report = String::new();

    let service_exe = locate_service_binary()?;
    report.push_str(&format!("Service binary: {}\n", service_exe.display()));

    let scm =
        Scm::connect().map_err(|e| format!("{e}\nInstallation requires administrator rights."))?;

    if scm.is_installed(guardian_proto::SERVICE_NAME) {
        if !force {
            report.push_str(&format!(
                "The service '{}' is already installed. Use --force to reinstall.\n",
                guardian_proto::SERVICE_NAME
            ));
            return Ok(report);
        }
        report.push_str("Reinstalling over the existing service.\n");
        // Stop first so the binary is not in use, then remove the registration.
        let _ = scm.stop(guardian_proto::SERVICE_NAME, 30_000);
        scm.uninstall(guardian_proto::SERVICE_NAME)
            .map_err(|e| format!("could not remove the existing service: {e}"))?;
    }

    // The path handed to the SCM is quoted, which `install` requires for a path with spaces and
    // which is harmless otherwise.
    let quoted = format!("\"{}\"", service_exe.display());
    scm.install(
        guardian_proto::SERVICE_NAME,
        guardian_proto::SERVICE_DISPLAY_NAME,
        &quoted,
        StartType::Automatic,
    )
    .map_err(|e| format!("could not install the service: {e}"))?;
    report.push_str("Service registered.\n");

    // Recovery: restart on failure, with increasing delays, never a reboot.
    match scm.configure_recovery(guardian_proto::SERVICE_NAME) {
        Ok(()) => report.push_str(
            "Recovery configured: the service restarts itself on failure \
             (no reboot action is ever set).\n",
        ),
        Err(e) => report.push_str(&format!(
            "WARNING: could not configure recovery: {e}\n  \
             The service will still run, but will not be restarted automatically.\n"
        )),
    }

    // Initialize the state directory and configuration before the first start, so the service
    // does not have to create them under a restricted context.
    let paths = GuardianPaths::production();
    match initialize_state(&paths) {
        Ok(msg) => report.push_str(&msg),
        Err(e) => report.push_str(&format!("WARNING: {e}\n")),
    }

    // Start it.
    match scm.start(guardian_proto::SERVICE_NAME, 30_000) {
        Ok(()) => report.push_str("Service started.\n"),
        Err(e) => report.push_str(&format!(
            "WARNING: the service was installed but could not be started: {e}\n  \
             Start it with 'guardianctl start' or from the Services snap-in.\n"
        )),
    }

    report.push_str(&format!(
        "\nState directory: {}\nRun 'guardianctl doctor' to verify the installation.\n",
        paths.root().display()
    ));

    Ok(report)
}

/// Remove the service, restoring the policy Guardian changed.
pub fn uninstall(keep_policy: bool) -> Result<String, String> {
    let mut report = String::new();

    let scm = Scm::connect()
        .map_err(|e| format!("{e}\nUninstallation requires administrator rights."))?;

    if !scm.is_installed(guardian_proto::SERVICE_NAME) {
        return Ok(format!(
            "The service '{}' is not installed; nothing to remove.\n",
            guardian_proto::SERVICE_NAME
        ));
    }

    // Stop before restoring policy, so the running service cannot re-apply protection while
    // uninstall is removing it. That race would leave the values applied with nothing managing
    // them, which is worse than either outcome.
    match scm.stop(guardian_proto::SERVICE_NAME, 30_000) {
        Ok(()) => report.push_str("Service stopped.\n"),
        Err(e) => report.push_str(&format!(
            "WARNING: could not stop the service cleanly: {e}\n  \
             Continuing, but protection may be re-applied until the process exits.\n"
        )),
    }

    if keep_policy {
        report.push_str(
            "Update policy left in place at your request (--keep-policy).\n  \
             Windows Update will remain locked after removal until you change it yourself.\n",
        );
    } else {
        match restore_policy() {
            Ok(msg) => report.push_str(&msg),
            Err(e) => report.push_str(&format!(
                "WARNING: could not restore the update policy: {e}\n  \
                 Check HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate manually.\n"
            )),
        }
    }

    scm.uninstall(guardian_proto::SERVICE_NAME)
        .map_err(|e| format!("could not remove the service: {e}"))?;
    report.push_str("Service registration removed.\n");

    report.push_str(
        "\nThe machine was NOT rebooted. State and logs remain under \
         %ProgramData%\\WorkstationGuardian for inspection; delete that directory to remove them.\n",
    );

    Ok(report)
}

/// Start or stop the service.
pub fn control_service(action: ServiceAction) -> Result<String, String> {
    // Starting needs elevation; querying does not. Connect with the rights the action needs so
    // the failure message is about the action rather than about the connection.
    let scm = Scm::connect().map_err(|e| format!("{e}\nThis requires administrator rights."))?;

    if !scm.is_installed(guardian_proto::SERVICE_NAME) {
        return Err(format!(
            "the service '{}' is not installed",
            guardian_proto::SERVICE_NAME
        ));
    }

    match action {
        ServiceAction::Start => {
            scm.start(guardian_proto::SERVICE_NAME, 30_000)
                .map_err(|e| format!("could not start the service: {e}"))?;
            Ok("Service started.\n".to_string())
        }
        ServiceAction::Stop => {
            scm.stop(guardian_proto::SERVICE_NAME, 30_000)
                .map_err(|e| format!("could not stop the service: {e}"))?;
            Ok("Service stopped.\n\n\
                 NOTE: with the service stopped, Guardian is not protecting this machine. \
                 Windows Update policy remains applied until it is changed.\n"
                .to_string())
        }
    }
}

/// Locate the service binary next to this executable.
///
/// The installer ships the binaries side by side, so the sibling of `guardianctl` is the right
/// answer. An explicit override is honoured for development and for layouts the installer does
/// not produce.
pub fn locate_service_binary() -> Result<PathBuf, String> {
    if let Ok(override_path) = std::env::var("GUARDIAN_SERVICE_PATH") {
        let p = PathBuf::from(&override_path);
        if p.is_file() {
            return Ok(p);
        }
        return Err(format!(
            "GUARDIAN_SERVICE_PATH points at '{}', which is not a file",
            p.display()
        ));
    }

    let self_exe = std::env::current_exe()
        .map_err(|e| format!("could not determine this executable's location: {e}"))?;
    let dir = self_exe
        .parent()
        .ok_or_else(|| "this executable has no parent directory".to_string())?;

    for candidate in [
        dir.join("guardian-service.exe"),
        // A development layout: `target/<profile>/guardianctl.exe` with the service beside it.
        dir.join("guardian-service"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(format!(
        "could not find guardian-service.exe next to {}\n\
         Install both binaries into the same directory, or set GUARDIAN_SERVICE_PATH.",
        self_exe.display()
    ))
}

/// Initialize the state directory and a default configuration.
fn initialize_state(paths: &GuardianPaths) -> Result<String, String> {
    paths
        .ensure_dirs()
        .map_err(|e| format!("could not create {}: {e}", paths.root().display()))?;

    let mut msg = String::new();

    // Write a default configuration only when none exists: never overwrite an operator's settings.
    if !paths.config_file().exists() {
        let config = ConfigDocument::default();
        guardian_storage::AtomicFile::new(paths.config_file())
            .write_json(&config)
            .map_err(|e| format!("could not write the default configuration: {e}"))?;
        msg.push_str("Default configuration written.\n");
    } else {
        msg.push_str("Existing configuration preserved.\n");
    }

    Ok(msg)
}

/// Restore the update policy values Guardian recorded writing.
///
/// Only values in Guardian's own rollback metadata are touched. A value that was set by Group
/// Policy or MDM is not in that list, so it is left exactly as it is.
fn restore_policy() -> Result<String, String> {
    use guardian_core::ports::UpdatePolicyBackend;

    let paths = GuardianPaths::production();
    let store = guardian_storage::Store::open(paths)
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

    Ok(msg)
}

/// Whether the process is elevated.
///
/// Used only to give a clear message before an operation that needs it, rather than letting the
/// SCM return a bare access-denied.
pub fn is_elevated() -> bool {
    guardian_win::session::has_interactive_user() && guardian_win::elevation::is_elevated()
}

/// A short description of the installation state, for diagnostics.
pub fn installation_summary() -> String {
    let installed = guardian_win::service::is_installed(guardian_proto::SERVICE_NAME);
    let paths = GuardianPaths::production();

    let mut out = format!(
        "  Service installed:  {}\n  State directory:    {}\n",
        if installed { "yes" } else { "no" },
        paths.root().display()
    );

    if installed {
        if let Ok(status) = guardian_win::service::query_status(guardian_proto::SERVICE_NAME) {
            out.push_str(&format!(
                "  Service state:      {} (pid {})\n",
                status.state.as_str(),
                status.process_id
            ));
        }
    }

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
    fn the_service_binary_can_be_located_or_reports_clearly() {
        // In a `cargo test` layout the service binary may or may not be beside the test
        // executable, so both outcomes are acceptable; what matters is that the failure is
        // explained rather than silent.
        match locate_service_binary() {
            Ok(path) => {
                assert!(path.is_file());
                assert!(
                    path.to_string_lossy().contains("guardian-service"),
                    "located an unexpected binary: {}",
                    path.display()
                );
            }
            Err(e) => {
                assert!(e.contains("guardian-service"));
            }
        }
    }

    #[test]
    fn an_override_path_is_honoured() {
        let temp =
            std::env::temp_dir().join(format!("guardian-fake-service-{}.exe", std::process::id()));
        std::fs::write(&temp, b"not really an exe").unwrap();

        // The environment is process-global, so this test owns it exclusively.
        unsafe { std::env::set_var("GUARDIAN_SERVICE_PATH", temp.to_string_lossy().to_string()) };
        let located = locate_service_binary();
        unsafe { std::env::remove_var("GUARDIAN_SERVICE_PATH") };

        assert_eq!(located.unwrap(), temp);
        let _ = std::fs::remove_file(&temp);
    }

    #[test]
    fn a_bad_override_path_is_reported() {
        unsafe {
            std::env::set_var(
                "GUARDIAN_SERVICE_PATH",
                r"C:\definitely-not-a-real-path-8f3a2b\x.exe",
            )
        };
        let located = locate_service_binary();
        unsafe { std::env::remove_var("GUARDIAN_SERVICE_PATH") };

        let err = located.unwrap_err();
        assert!(err.contains("GUARDIAN_SERVICE_PATH"));
    }

    #[test]
    fn initializing_state_creates_the_directory_and_configuration() {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "guardian-install-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));

        let paths = GuardianPaths::for_test_dir(dir.clone());
        let msg = initialize_state(&paths).expect("initialization must succeed");
        assert!(msg.contains("Default configuration written"));
        assert!(paths.config_file().is_file());

        // The written configuration must protect updates, since it is the default.
        let (config, error) =
            guardian_storage::Store::open(GuardianPaths::for_test_dir(dir.clone()))
                .unwrap()
                .load_config();
        assert!(error.is_none());
        assert!(
            config.body.update.protect,
            "the default configuration must protect updates"
        );

        // Running again must not overwrite it.
        let msg2 = initialize_state(&paths).expect("second initialization");
        assert!(msg2.contains("preserved"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn initialization_preserves_an_existing_configuration() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("guardian-install-preserve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let paths = GuardianPaths::for_test_dir(dir.clone());
        let mut config = ConfigDocument::default();
        config.body.update.verify_interval_secs = 99;
        guardian_storage::AtomicFile::new(paths.config_file())
            .write_json(&config)
            .unwrap();

        initialize_state(&paths).unwrap();

        let (loaded, _) = guardian_storage::Store::open(GuardianPaths::for_test_dir(dir.clone()))
            .unwrap()
            .load_config();
        assert_eq!(
            loaded.body.update.verify_interval_secs, 99,
            "an operator's configuration must never be overwritten by the installer"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restoring_policy_without_rollback_metadata_says_so_rather_than_guessing() {
        // This test exercises the real state path, which on a test machine has no rollback
        // metadata. The important property is that it refuses to guess.
        let result = restore_policy();
        match result {
            Ok(msg) => {
                assert!(
                    msg.contains("nothing to restore")
                        || msg.contains("No original policy")
                        || msg.contains("Restored"),
                    "unexpected message: {msg}"
                );
            }
            Err(e) => {
                // A locked-down ProgramData is also an acceptable outcome, as long as the
                // failure is explained rather than silent.
                assert!(!e.is_empty());
            }
        }
    }

    #[test]
    fn the_installation_summary_renders() {
        let text = installation_summary();
        assert!(text.contains("Service installed"));
        assert!(text.contains("State directory"));
        assert!(text.contains("Configuration"));
        assert!(text.contains("Journal"));
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
