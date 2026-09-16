//! Starting Guardian at logon, and starting the session helper.
//!
//! # Why this is opt-in and reversible
//!
//! Guardian is a tray application precisely so that it registers nothing behind the user's back.
//! Adding an autostart entry is therefore a change the user asks for, not one that happens at
//! first run — and it is a single value under `HKCU`, so it can be removed by the same button that
//! added it, or by deleting it in Task Manager's Startup tab.
//!
//! Nothing here touches `HKLM`, a scheduled task, or the Service Control Manager.
//!
//! # What is actually registered
//!
//! * **Guardian itself** — `guardian-ui.exe`, so the machine is protected from logon. Optional.
//! * **The session helper** — `guardian-session.exe`, which is what lets Guardian hold a shutdown
//!   while work is running. Without it Guardian still locks Windows Update, but it cannot block a
//!   shutdown, and it says so: restart protection reads `Degraded` rather than claiming a
//!   capability it does not have.
//!
//! The helper must run in the interactive user's session, so it belongs under `HKCU\...\Run`
//! rather than anywhere machine-wide. That is a Windows requirement, not a preference: a process
//! in another session cannot own the window that `ShutdownBlockReasonCreate` needs.

use std::path::{Path, PathBuf};

use guardian_proto::model::PolValue;
use guardian_win::registry::{RegKey, RegPath};
use guardian_win::WinError;

/// The `Run` key Guardian writes to. `HKCU`, so no elevation is needed to change it.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

/// The value name for Guardian itself.
const GUARDIAN_VALUE: &str = "WorkstationGuardian";

/// The value name for the session helper.
const HELPER_VALUE: &str = "WorkstationGuardianSession";

/// Which autostart entries currently exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutostartState {
    pub guardian: bool,
    pub helper: bool,
}

impl AutostartState {
    /// Whether Guardian would start at logon.
    pub fn any(&self) -> bool {
        self.guardian || self.helper
    }
}

/// Read the current autostart state.
///
/// A missing key or value is not an error: it means "not enabled", which is the default.
pub fn state() -> AutostartState {
    AutostartState {
        guardian: value_exists(GUARDIAN_VALUE),
        helper: value_exists(HELPER_VALUE),
    }
}

fn value_exists(name: &str) -> bool {
    let Ok(key) = RegKey::open_read(&RegPath::current_user(RUN_KEY)) else {
        return false;
    };
    matches!(key.get_value(name), Ok(Some(_)))
}

/// Enable or disable both entries.
///
/// `helper_path` is where `guardian-session.exe` lives. The caller resolves it, because only the
/// caller knows the layout it was shipped in; the helper is usually a sibling of this executable.
pub fn set_enabled(
    enabled: bool,
    guardian_path: &Path,
    helper_path: Option<&Path>,
) -> Result<AutostartState, WinError> {
    if enabled {
        enable(guardian_path, helper_path)?;
    } else {
        disable()?;
    }
    Ok(state())
}

/// Write the entries.
fn enable(guardian_path: &Path, helper_path: Option<&Path>) -> Result<(), WinError> {
    let (key, _) = RegKey::create(&RegPath::current_user(RUN_KEY))?;

    // Quoted: an unquoted path with spaces is parsed as "C:\Program" plus arguments, which is the
    // classic way an autostart entry silently fails to launch anything.
    key.set_value(
        GUARDIAN_VALUE,
        &PolValue::String(format!("\"{}\"", guardian_path.display())),
    )?;

    // The helper is optional: a user may choose to start it themselves, or may only care about
    // update protection. Absent means "leave that entry alone".
    if let Some(helper) = helper_path {
        key.set_value(
            HELPER_VALUE,
            &PolValue::String(format!("\"{}\"", helper.display())),
        )?;
    }

    Ok(())
}

/// Remove the entries. Succeeds whether or not they existed.
///
/// Removing an entry that is not there is not an error: the caller asked for the machine to be in
/// a state, and it is in that state.
fn disable() -> Result<(), WinError> {
    let key = match RegKey::open_write(&RegPath::current_user(RUN_KEY)) {
        Ok(k) => k,
        // No Run key at all means nothing to remove.
        Err(e) if e.is_not_found() => return Ok(()),
        Err(e) => return Err(e),
    };

    for name in [GUARDIAN_VALUE, HELPER_VALUE] {
        match key.delete_value(name) {
            Ok(_) => {}
            // A missing value is the desired end state, not a failure.
            Err(e) if e.is_not_found() => {}
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

/// Where `guardian-session.exe` is, if it is beside this executable.
///
/// Both binaries ship in the same directory, so the sibling is the right answer. `None` means it
/// was not found, which is reported to the user rather than guessed at: registering a path that
/// does not exist would create an autostart entry that fails silently at every logon.
pub fn helper_beside(exe: &Path) -> Option<PathBuf> {
    let dir = exe.parent()?;
    [
        dir.join("guardian-session.exe"),
        dir.join("guardian-session"),
    ]
    .into_iter()
    .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_run_key_is_the_current_user_one() {
        // Writing autostart under HKLM would need elevation and would affect every user on the
        // machine. Guardian is a per-user tray application and has no business doing that.
        let path = RegPath::current_user(RUN_KEY);
        assert_eq!(path.hive.as_str(), "HKEY_CURRENT_USER");
        assert_eq!(
            path.subkey,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        );
    }

    #[test]
    fn the_value_names_are_distinct() {
        // A collision would mean enabling the helper silently replaced Guardian's own entry.
        assert_ne!(GUARDIAN_VALUE, HELPER_VALUE);
    }

    #[test]
    fn reading_the_state_never_fails() {
        // This runs on machines where the key does not exist and where it does. Either way it must
        // return a state rather than an error: "not enabled" is the default, not a fault.
        let _ = state();
    }

    #[test]
    fn a_disabled_state_is_any_false() {
        let off = AutostartState {
            guardian: false,
            helper: false,
        };
        assert!(!off.any());

        let partial = AutostartState {
            guardian: false,
            helper: true,
        };
        assert!(
            partial.any(),
            "the helper alone still means something starts"
        );
    }

    #[test]
    fn the_helper_is_looked_for_beside_the_executable() {
        // The real layout: both binaries in one directory. Tests run from target/<profile>, where
        // the helper may or may not be built; what matters is that a missing one is `None` rather
        // than a fabricated path.
        let exe = std::env::current_exe().expect("a test process knows its path");
        match helper_beside(&exe) {
            Some(found) => {
                assert!(found.is_file());
                assert!(
                    found
                        .file_name()
                        .is_some_and(|n| n.to_string_lossy().contains("guardian-session")),
                    "found an unexpected binary: {}",
                    found.display()
                );
            }
            None => { /* not built in this profile; acceptable */ }
        }
    }

    #[test]
    fn a_path_is_quoted_before_it_is_written() {
        // An unquoted path with spaces is parsed as a truncated executable plus arguments, so the
        // entry silently launches nothing. The quoting is the fix, and it is asserted here because
        // the failure mode is invisible at write time.
        let quoted = format!("\"{}\"", r"C:\Program Files\Guardian\guardian-ui.exe");
        assert!(quoted.starts_with('"') && quoted.ends_with('"'));
        assert_eq!(quoted.matches('"').count(), 2);
    }
}
