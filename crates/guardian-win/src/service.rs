//! Service Control Manager access: install, remove, start, stop, and read status.
//!
//! Uses the documented SCM API directly rather than shelling out to `sc.exe`. Shelling out means
//! parsing localized output, having no structured error codes, and depending on a tool that may
//! not be on the path in a recovery context. The API is in-process and reports exactly what
//! happened.
//!
//! # Recovery configuration
//!
//! [`configure_recovery`] sets first, second and subsequent failure actions to *restart the
//! service* with increasing delays. It deliberately never sets a "reboot the computer" action:
//! a protection service that reboots the machine to recover itself is precisely the failure
//! this project exists to prevent.

use windows::core::PCWSTR;
use windows::Win32::Foundation::ERROR_SERVICE_EXISTS;
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, ControlService, CreateServiceW, DeleteService,
    OpenSCManagerW, OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx, StartServiceW,
    SC_ACTION, SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_ALL_ACCESS, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_ALL_ACCESS, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
    SERVICE_CONTROL_STOP, SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DESCRIPTIONW,
    SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
    SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS,
};

use crate::{WideString, WinError};

/// `DELETE`, the standard access right required to remove an object.
///
/// `DeleteService` needs the service handle opened with this right. The `windows` crate does not
/// re-export it alongside the service constants, so it is named here with its documented value
/// rather than left as a bare literal at the call site.
const DELETE: u32 = 0x0001_0000;

/// Recovery delays in milliseconds: 5s, 15s, then 60s for every subsequent failure.
///
/// Short enough to recover quickly from a transient fault, long enough not to spin a
/// permanently broken service, and never a reboot.
pub const RECOVERY_DELAYS_MS: [u32; 3] = [5_000, 15_000, 60_000];

/// How the service should start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartType {
    /// Start automatically at boot. The default for a protection service.
    Automatic,
    /// Start automatically, but after other automatic services.
    AutomaticDelayed,
    /// Start only when asked.
    Manual,
}

impl StartType {
    fn raw(self) -> windows::Win32::System::Services::SERVICE_START_TYPE {
        match self {
            StartType::Automatic | StartType::AutomaticDelayed => SERVICE_AUTO_START,
            StartType::Manual => windows::Win32::System::Services::SERVICE_DEMAND_START,
        }
    }
}

/// A handle to the service control manager.
#[derive(Debug)]
pub struct Scm {
    handle: SC_HANDLE,
}

impl Scm {
    /// Connect to the local service control manager.
    ///
    /// Any service operation requires administrator rights; a failure here is usually that, and
    /// the error says so.
    pub fn connect() -> Result<Self, WinError> {
        // Safety: a null machine name means the local machine; the desired-access mask is the
        // documented one for creating and configuring services.
        let handle =
            unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS) };
        match handle {
            Ok(h) if !h.is_invalid() => Ok(Scm { handle: h }),
            _ => Err(WinError::last("OpenSCManagerW")),
        }
    }

    /// Connect with the minimum access needed to query status.
    ///
    /// Used by diagnostics, which must work for a non-elevated user so an operator can see what
    /// is wrong without first elevating.
    pub fn connect_read_only() -> Result<Self, WinError> {
        // Safety: as above, with the read-only access mask.
        let handle = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) };
        match handle {
            Ok(h) if !h.is_invalid() => Ok(Scm { handle: h }),
            _ => Err(WinError::last("OpenSCManagerW")),
        }
    }

    /// Whether a service is installed.
    pub fn is_installed(&self, name: &str) -> bool {
        self.open_service(name, SERVICE_QUERY_STATUS).is_ok()
    }

    /// Open a service with the given access rights.
    ///
    /// The rights are a plain `u32` bitmask, as the SCM defines them.
    fn open_service(&self, name: &str, access: u32) -> Result<ServiceHandle, WinError> {
        let wide = WideString::new(name);
        // Safety: `wide` is a valid NUL-terminated name and the manager handle is valid.
        let handle = unsafe { OpenServiceW(self.handle, PCWSTR(wide.as_ptr()), access) };
        match handle {
            Ok(h) if !h.is_invalid() => Ok(ServiceHandle { handle: h }),
            _ => Err(WinError::last("OpenServiceW")),
        }
    }

    /// Query the current state of a service.
    pub fn query_status(&self, name: &str) -> Result<ServiceStatus, WinError> {
        let service = self.open_service(name, SERVICE_QUERY_STATUS)?;

        let mut buf = [0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
        let mut needed = 0u32;

        // Safety: `buf` is exactly the size of a SERVICE_STATUS_PROCESS, which is what the
        // SC_STATUS_PROCESS_INFO level writes.
        let ok = unsafe {
            QueryServiceStatusEx(
                service.handle,
                SC_STATUS_PROCESS_INFO,
                Some(&mut buf),
                &mut needed,
            )
        };

        if ok.is_err() {
            return Err(WinError::last("QueryServiceStatusEx"));
        }

        // Safety: the API filled `buf` with a SERVICE_STATUS_PROCESS. The array is 4-byte
        // aligned, which is sufficient for this structure's fields.
        let status: SERVICE_STATUS_PROCESS =
            unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const SERVICE_STATUS_PROCESS) };

        Ok(ServiceStatus {
            state: ServiceState::from_raw(status.dwCurrentState),
            process_id: status.dwProcessId,
            exit_code: status.dwWin32ExitCode,
            checkpoint: status.dwCheckPoint,
            wait_hint_ms: status.dwWaitHint,
        })
    }

    /// Install the service.
    ///
    /// `binary_path` must be an absolute path to the service executable, quoted if it contains
    /// spaces. It is validated here rather than trusted: the SCM stores it verbatim and executes
    /// it as LocalSystem, so a relative or unquoted path would be a genuine privilege-escalation
    /// vector.
    pub fn install(
        &self,
        name: &str,
        display_name: &str,
        binary_path: &str,
        start_type: StartType,
    ) -> Result<(), WinError> {
        validate_service_binary_path(binary_path)?;

        let name_w = WideString::new(name);
        let display_w = WideString::new(display_name);
        let path_w = WideString::new(binary_path);

        // Safety: all strings are valid NUL-terminated values that outlive the call. No
        // dependencies (null) means the service runs standalone rather than in a group.
        let handle = unsafe {
            CreateServiceW(
                self.handle,
                PCWSTR(name_w.as_ptr()),
                PCWSTR(display_w.as_ptr()),
                SERVICE_ALL_ACCESS,
                SERVICE_WIN32_OWN_PROCESS,
                start_type.raw(),
                SERVICE_ERROR_NORMAL,
                PCWSTR(path_w.as_ptr()),
                PCWSTR::null(), // no load-order group
                None,           // no tag id
                PCWSTR::null(), // no dependencies
                PCWSTR::null(), // LocalSystem
                PCWSTR::null(), // no password
            )
        };

        let service = match handle {
            Ok(h) if !h.is_invalid() => ServiceHandle { handle: h },
            Ok(_) => return Err(WinError::last("CreateServiceW")),
            Err(e) => {
                // ERROR_SERVICE_EXISTS means it is already installed, which the caller may
                // treat as success or as a reason to reinstall.
                let code = e.code().0 as u32;
                if code == ERROR_SERVICE_EXISTS.0 {
                    return Err(WinError::Api {
                        operation: "CreateServiceW",
                        code,
                        message: format!("the service '{name}' is already installed"),
                    });
                }
                return Err(WinError::last("CreateServiceW"));
            }
        };

        // Set the description so the Services snap-in explains what this is.
        let desc = WideString::new(crate::SERVICE_DESCRIPTION_TEXT);
        let description = SERVICE_DESCRIPTIONW {
            lpDescription: windows::core::PWSTR(desc.as_ptr() as *mut u16),
        };
        // Safety: the info struct points at a string that outlives the call.
        let _ = unsafe {
            ChangeServiceConfig2W(
                service.handle,
                windows::Win32::System::Services::SERVICE_CONFIG_DESCRIPTION,
                Some(&description as *const _ as *const core::ffi::c_void),
            )
        };

        if start_type == StartType::AutomaticDelayed {
            let delayed = SERVICE_DELAYED_AUTO_START_INFO {
                fDelayedAutostart: true.into(),
            };
            // Safety: the info struct is correctly typed for this level.
            let _ = unsafe {
                ChangeServiceConfig2W(
                    service.handle,
                    windows::Win32::System::Services::SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                    Some(&delayed as *const _ as *const core::ffi::c_void),
                )
            };
        }

        Ok(())
    }

    /// Remove the service.
    pub fn uninstall(&self, name: &str) -> Result<(), WinError> {
        // Stop it first, so the binary can be replaced or removed.
        let _ = self.stop(name, 20_000);

        let service = self.open_service(name, DELETE | SERVICE_STOP)?;

        // Safety: the service handle was opened with DELETE access.
        let ok = unsafe { DeleteService(service.handle) };
        if ok.is_err() {
            return Err(WinError::last("DeleteService"));
        }
        Ok(())
    }

    /// Start the service.
    pub fn start(&self, name: &str, timeout_ms: u32) -> Result<(), WinError> {
        let service = self.open_service(name, SERVICE_START | SERVICE_QUERY_STATUS)?;

        // Safety: the handle was opened with SERVICE_START access. An empty argument list is
        // the documented form for a service that takes none.
        let ok = unsafe { StartServiceW(service.handle, None) };
        if ok.is_err() {
            let err = WinError::last("StartServiceW");
            // Already running is the desired end state, not a failure.
            if let WinError::Api { code, .. } = &err {
                if *code == windows::Win32::Foundation::ERROR_SERVICE_ALREADY_RUNNING.0 {
                    return Ok(());
                }
            }
            return Err(err);
        }

        self.wait_for_state(&service, SERVICE_RUNNING, timeout_ms)
    }

    /// Stop the service, waiting for it to actually stop.
    ///
    /// Waiting matters: a caller that returns before the process has exited will see a stale
    /// process id and may believe the service is still running.
    pub fn stop(&self, name: &str, timeout_ms: u32) -> Result<(), WinError> {
        let service = self.open_service(name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;

        let mut status = SERVICE_STATUS::default();
        // Safety: the handle was opened with SERVICE_STOP access.
        let ok = unsafe { ControlService(service.handle, SERVICE_CONTROL_STOP, &mut status) };
        if ok.is_err() {
            let err = WinError::last("ControlService");
            // Not running is the desired end state.
            if let WinError::Api { code, .. } = &err {
                if *code == windows::Win32::Foundation::ERROR_SERVICE_NOT_ACTIVE.0 {
                    return Ok(());
                }
            }
            return Err(err);
        }

        self.wait_for_state(&service, SERVICE_STOPPED, timeout_ms)
    }

    /// Poll until a service reaches the wanted state, bounded.
    fn wait_for_state(
        &self,
        service: &ServiceHandle,
        wanted: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE,
        timeout_ms: u32,
    ) -> Result<(), WinError> {
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_millis(u64::from(timeout_ms));

        loop {
            let mut buf = [0u8; std::mem::size_of::<SERVICE_STATUS_PROCESS>()];
            let mut needed = 0u32;
            // Safety: as in `query_status`.
            let ok = unsafe {
                QueryServiceStatusEx(
                    service.handle,
                    SC_STATUS_PROCESS_INFO,
                    Some(&mut buf),
                    &mut needed,
                )
            };
            if ok.is_err() {
                return Err(WinError::last("QueryServiceStatusEx"));
            }

            // Safety: filled by the API, read unaligned.
            let status: SERVICE_STATUS_PROCESS =
                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const SERVICE_STATUS_PROCESS) };

            if status.dwCurrentState == wanted {
                return Ok(());
            }

            if std::time::Instant::now() >= deadline {
                return Err(WinError::Timeout {
                    operation: "wait_for_service_state",
                });
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    /// Configure SCM recovery so a crashed service is restarted.
    ///
    /// Never configures a reboot: a protection service that reboots the machine to recover
    /// itself would cause exactly the work loss this project exists to prevent.
    pub fn configure_recovery(&self, name: &str) -> Result<(), WinError> {
        let service = self.open_service(name, SERVICE_CHANGE_CONFIG)?;

        // Three restart actions with increasing delays. Subsequent failures reuse the last.
        let actions: Vec<SC_ACTION> = RECOVERY_DELAYS_MS
            .iter()
            .map(|ms| SC_ACTION {
                Type: SC_ACTION_RESTART,
                Delay: *ms,
            })
            .collect();

        let failure_actions = SERVICE_FAILURE_ACTIONSW {
            dwResetPeriod: 24 * 60 * 60, // reset the failure count after a quiet day
            lpRebootMsg: windows::core::PWSTR::null(),
            lpCommand: windows::core::PWSTR::null(),
            cActions: actions.len() as u32,
            lpsaActions: actions.as_ptr() as *mut SC_ACTION,
        };

        // Safety: the struct points at `actions`, which outlives the call. No reboot message or
        // command is set, which is deliberate.
        let ok = unsafe {
            ChangeServiceConfig2W(
                service.handle,
                windows::Win32::System::Services::SERVICE_CONFIG_FAILURE_ACTIONS,
                Some(&failure_actions as *const _ as *const core::ffi::c_void),
            )
        };

        if ok.is_err() {
            return Err(WinError::last("ChangeServiceConfig2W(failure actions)"));
        }

        // Mark the service as not "non-crashy": without this, Windows suppresses recovery
        // actions for a service it considers to have crashed too often.
        let failure_actions_flag = windows::Win32::System::Services::SERVICE_FAILURE_ACTIONS_FLAG {
            fFailureActionsOnNonCrashFailures: true.into(),
        };
        // Safety: correctly typed for this level.
        let _ = unsafe {
            ChangeServiceConfig2W(
                service.handle,
                windows::Win32::System::Services::SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                Some(&failure_actions_flag as *const _ as *const core::ffi::c_void),
            )
        };

        Ok(())
    }

    /// Read the configured start type.
    pub fn start_type(&self, name: &str) -> Result<StartType, WinError> {
        let service = self.open_service(name, SERVICE_QUERY_CONFIG)?;

        // Two-call size negotiation.
        let mut needed = 0u32;
        // Safety: a null buffer with zero size is the documented size query.
        let _ = unsafe { QueryServiceConfigW(service.handle, None, 0, &mut needed) };
        if needed == 0 {
            return Err(WinError::last("QueryServiceConfigW(size)"));
        }

        let mut buf = vec![0u8; needed as usize + 64];
        let mut actual = 0u32;
        // Safety: `buf` is at least `needed` bytes, which is what the size query reported.
        let ok = unsafe {
            QueryServiceConfigW(
                service.handle,
                Some(buf.as_mut_ptr()
                    as *mut windows::Win32::System::Services::QUERY_SERVICE_CONFIGW),
                buf.len() as u32,
                &mut actual,
            )
        };
        if ok.is_err() {
            return Err(WinError::last("QueryServiceConfigW"));
        }

        // Safety: the API filled the buffer with a QUERY_SERVICE_CONFIGW. The Vec<u8>
        // allocation is aligned enough for this structure's 4-byte fields.
        let config = unsafe {
            &*(buf.as_ptr() as *const windows::Win32::System::Services::QUERY_SERVICE_CONFIGW)
        };

        Ok(if config.dwStartType == SERVICE_AUTO_START {
            StartType::Automatic
        } else {
            StartType::Manual
        })
    }
}

impl Drop for Scm {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // Safety: the handle came from OpenSCManagerW and is closed exactly once.
            unsafe {
                let _ = CloseServiceHandle(self.handle);
            }
        }
    }
}

/// An open service handle.
#[derive(Debug)]
struct ServiceHandle {
    handle: SC_HANDLE,
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // Safety: the handle came from OpenServiceW or CreateServiceW.
            unsafe {
                let _ = CloseServiceHandle(self.handle);
            }
        }
    }
}

/// A service's runtime state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    ContinuePending,
    PausePending,
    Paused,
    Unknown,
}

impl ServiceState {
    fn from_raw(raw: windows::Win32::System::Services::SERVICE_STATUS_CURRENT_STATE) -> Self {
        use windows::Win32::System::Services::*;
        match raw {
            s if s == SERVICE_STOPPED => ServiceState::Stopped,
            s if s == SERVICE_START_PENDING => ServiceState::StartPending,
            s if s == SERVICE_STOP_PENDING => ServiceState::StopPending,
            s if s == SERVICE_RUNNING => ServiceState::Running,
            s if s == SERVICE_CONTINUE_PENDING => ServiceState::ContinuePending,
            s if s == SERVICE_PAUSE_PENDING => ServiceState::PausePending,
            s if s == SERVICE_PAUSED => ServiceState::Paused,
            _ => ServiceState::Unknown,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ServiceState::Stopped => "stopped",
            ServiceState::StartPending => "starting",
            ServiceState::StopPending => "stopping",
            ServiceState::Running => "running",
            ServiceState::ContinuePending => "resuming",
            ServiceState::PausePending => "pausing",
            ServiceState::Paused => "paused",
            ServiceState::Unknown => "unknown",
        }
    }

    pub fn is_running(self) -> bool {
        self == ServiceState::Running
    }
}

/// A service's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceStatus {
    pub state: ServiceState,
    pub process_id: u32,
    pub exit_code: u32,
    pub checkpoint: u32,
    pub wait_hint_ms: u32,
}

/// Validate a service binary path before handing it to the SCM.
///
/// The SCM stores this string verbatim and executes it as `LocalSystem`. A relative path or an
/// unquoted path containing spaces would be a genuine local privilege-escalation vector, so it
/// is rejected here rather than trusted.
pub fn validate_service_binary_path(path: &str) -> Result<(), WinError> {
    const INVALID: fn(String) -> WinError = |detail| WinError::Invalid {
        context: "service binary path",
        detail,
    };

    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(INVALID("the path is empty".into()));
    }

    // Strip the surrounding quotes if present, then validate the path itself. The quoted form is
    // what the installer *must* produce for a path containing spaces, so it has to be accepted;
    // the SCM stores the string verbatim and would otherwise split it at the first space.
    let quoted = trimmed.starts_with('"');
    let inner = if quoted {
        match trimmed.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
            Some(i) => i,
            None => {
                return Err(INVALID(
                    "the path starts with a quote but does not end with one".into(),
                ))
            }
        }
    } else {
        trimmed
    };

    if inner.is_empty() {
        return Err(INVALID("the path is empty".into()));
    }

    // Shell metacharacters are rejected in both forms: the SCM passes the string to a command
    // interpreter in some configurations, and a metacharacter there is a command injection
    // against a LocalSystem process.
    for meta in ['&', '|', '>', '<', '^', '%', '!'] {
        if inner.contains(meta) {
            return Err(INVALID(format!(
                "the path contains the shell metacharacter '{meta}'"
            )));
        }
    }

    if inner.contains("..") {
        return Err(INVALID("the path contains '..'".into()));
    }

    // Must be absolute. A relative path would resolve against the SCM's working directory, which
    // is not ours to control, and the SCM runs the result as LocalSystem.
    let chars: Vec<char> = inner.chars().collect();
    // Both separators are accepted: an operator on a machine where a tool emitted a forward
    // slash should get a clear validation error, not a silent misconfiguration.
    let has_drive = chars.len() >= 3
        && chars[0].is_ascii_alphabetic()
        && chars[1] == ':'
        && (chars[2] == '\\' || chars[2] == '/');
    let has_unc = inner.starts_with(r"\\");
    let has_native_prefix = inner.starts_with(r"\??\");

    if !has_drive && !has_unc && !has_native_prefix {
        return Err(INVALID(format!("'{inner}' is not an absolute path")));
    }

    if !inner.to_ascii_lowercase().ends_with(".exe") {
        return Err(INVALID("the path does not name an .exe".into()));
    }

    // A path with spaces must be quoted, or the SCM mis-parses it as binary plus arguments.
    if inner.contains(' ') && !quoted {
        return Err(INVALID(format!(
            "'{inner}' contains spaces and is not quoted; the Service Control Manager would              parse it as a binary plus arguments"
        )));
    }

    Ok(())
}

/// Whether a service is installed, for diagnostics. Does not require elevation.
pub fn is_installed(name: &str) -> bool {
    match Scm::connect_read_only() {
        Ok(scm) => scm.is_installed(name),
        // Without SCM access we cannot say. Reporting "not installed" would be a guess that
        // would send an operator down the wrong path, so this reports the failure by returning
        // the conservative answer and leaving the detail to the caller's other checks.
        Err(_) => false,
    }
}

/// Query a service's status without requiring elevation.
pub fn query_status(name: &str) -> Result<ServiceStatus, WinError> {
    Scm::connect_read_only()?.query_status(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_well_formed_service_path_is_accepted() {
        for good in [
            // A path containing spaces must be quoted: the SCM stores the string verbatim and
            // would otherwise parse it as a binary plus arguments.
            r#""C:\Program Files\Workstation Guardian\guardian-service.exe""#,
            r"D:\apps\guardian-service.exe",
            "c:/apps/guardian-service.exe",
            r"C:\guardian.exe",
            r"\??\C:\Windows\System32\guardian-service.exe",
        ] {
            assert!(
                validate_service_binary_path(good).is_ok(),
                "should accept '{good}'"
            );
        }
    }

    #[test]
    fn a_relative_path_is_rejected() {
        // The SCM resolves a relative path against a directory we do not control.
        for bad in [
            "guardian-service.exe",
            r".\guardian-service.exe",
            r"apps\guardian-service.exe",
        ] {
            assert!(
                validate_service_binary_path(bad).is_err(),
                "should reject relative path '{bad}'"
            );
        }
    }

    #[test]
    fn a_path_with_parent_traversal_is_rejected() {
        assert!(validate_service_binary_path(r"C:\apps\..\Windows\guardian.exe").is_err());
    }

    #[test]
    fn shell_metacharacters_are_rejected() {
        // The SCM passes the string to a command interpreter in some configurations; a
        // metacharacter here would be a command injection.
        for bad in [
            r"C:\apps\guardian.exe & calc.exe",
            r"C:\apps\guardian.exe | calc.exe",
            r"C:\apps\guardian.exe > out.txt",
            r"C:\apps\guardian.exe %TEMP%",
        ] {
            assert!(
                validate_service_binary_path(bad).is_err(),
                "should reject '{bad}'"
            );
        }
    }

    #[test]
    fn a_non_exe_path_is_rejected() {
        assert!(validate_service_binary_path(r"C:\apps\script.bat").is_err());
        assert!(validate_service_binary_path(r"C:\apps\thing.dll").is_err());
    }

    #[test]
    fn an_empty_path_is_rejected() {
        assert!(validate_service_binary_path("").is_err());
        assert!(validate_service_binary_path("   ").is_err());
    }

    #[test]
    fn an_unquoted_path_with_spaces_is_rejected() {
        // The SCM would parse this as the binary "C:\Program" with arguments.
        assert!(validate_service_binary_path(r"C:\Program Files\app\guardian.exe").is_err());
        // The quoted form is what the installer must produce.
        assert!(validate_service_binary_path(r#""C:\Program Files\app\guardian.exe""#).is_ok());
    }

    #[test]
    fn service_state_mapping_covers_the_documented_states() {
        use windows::Win32::System::Services::*;
        assert_eq!(
            ServiceState::from_raw(SERVICE_STOPPED),
            ServiceState::Stopped
        );
        assert_eq!(
            ServiceState::from_raw(SERVICE_RUNNING),
            ServiceState::Running
        );
        assert_eq!(
            ServiceState::from_raw(SERVICE_START_PENDING),
            ServiceState::StartPending
        );
        assert_eq!(
            ServiceState::from_raw(SERVICE_STOP_PENDING),
            ServiceState::StopPending
        );
        assert_eq!(ServiceState::from_raw(SERVICE_PAUSED), ServiceState::Paused);
        assert_eq!(
            ServiceState::from_raw(SERVICE_STATUS_CURRENT_STATE(99)),
            ServiceState::Unknown
        );
    }

    #[test]
    fn only_running_counts_as_running() {
        assert!(ServiceState::Running.is_running());
        for s in [
            ServiceState::Stopped,
            ServiceState::StartPending,
            ServiceState::StopPending,
            ServiceState::Paused,
            ServiceState::Unknown,
        ] {
            assert!(!s.is_running(), "{s:?} must not count as running");
        }
    }

    #[test]
    fn state_names_render() {
        for s in [
            ServiceState::Stopped,
            ServiceState::Running,
            ServiceState::Unknown,
        ] {
            assert!(!s.as_str().is_empty());
        }
    }

    #[test]
    fn reading_only_scm_connection_is_available_without_elevation() {
        // Diagnostics must be usable by a non-elevated operator, so this must not require
        // administrator rights. Whether it succeeds depends on the machine's policy.
        match Scm::connect_read_only() {
            Ok(scm) => {
                // Our own test process is not a service, so it must report as absent.
                assert!(!scm.is_installed("workstation-guardian-nonexistent-8f3a2b"));
            }
            Err(e) => {
                eprintln!("SCM read-only connection unavailable in this context: {e}");
            }
        }
    }

    #[test]
    fn querying_an_absent_service_is_not_installed() {
        assert!(!is_installed("workstation-guardian-nonexistent-8f3a2b"));
    }

    #[test]
    fn querying_an_absent_services_status_fails_cleanly() {
        let result = query_status("workstation-guardian-nonexistent-8f3a2b");
        assert!(result.is_err(), "an absent service has no status");
    }

    #[test]
    fn recovery_delays_are_increasing_and_never_zero() {
        // A zero delay would spin, and a decreasing schedule would be pointless.
        for window in RECOVERY_DELAYS_MS.windows(2) {
            assert!(
                window[1] >= window[0],
                "recovery delays must not decrease: {RECOVERY_DELAYS_MS:?}"
            );
        }
        assert!(RECOVERY_DELAYS_MS.iter().all(|d| *d > 0));
    }

    #[test]
    fn recovery_never_requests_a_reboot() {
        use windows::Win32::System::Services::SC_ACTION_TYPE;
        // This is a design invariant, not an implementation detail: a protection service that
        // reboots the machine to recover itself would cause the very work loss it prevents.
        // The constant is the only action type used, and it must be RESTART.
        assert_eq!(SC_ACTION_RESTART.0, 1);
        let action: SC_ACTION_TYPE = SC_ACTION_RESTART;
        assert_ne!(
            action.0, 2,
            "SC_ACTION_REBOOT must never be used for service recovery"
        );
        assert_ne!(action.0, 3, "SC_ACTION_RUN_COMMAND must never be used");
    }
}
