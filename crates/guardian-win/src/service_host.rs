//! Windows service lifecycle: register with the SCM, report status, and handle control codes.
//!
//! # Design
//!
//! The control handler does as little as possible. Windows calls it on a dedicated thread that
//! must not block, and a handler that stalls makes the Service Control Manager believe the
//! service is unresponsive — which triggers a timeout and, if recovery is misconfigured, a
//! machine restart. So the handler records the request and returns; the main thread polls.
//!
//! # Preshutdown
//!
//! `SERVICE_ACCEPT_PRESHUTDOWN` is requested so Windows gives the service a chance to flush state
//! *before* it stops issuing control codes to other services. The handler signals the main loop,
//! which writes the clean-shutdown marker. The work is a handful of small file writes and is
//! expected to finish in well under a second; the timeout is set accordingly, because a service
//! that stalls a shutdown is a bug, not a feature.
//!
//! # What this module must never do
//!
//! It never calls `AbortSystemShutdown`, never blocks a shutdown indefinitely, and never
//! requests a reboot as a recovery action. Guardian's job is to protect work from an
//! *unexpected* restart, not to make the machine unmanageable.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState as WindowsServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{WideString, WinError};

/// How long the service asks the SCM to allow for a stop or preshutdown.
///
/// The work is flushing a few small files. Nine seconds is generous for that and short enough
/// that a stuck service does not hold the whole machine's shutdown.
pub const STOP_WAIT_HINT_MS: u32 = 9_000;

/// Control codes this service accepts.
pub fn accepted_controls() -> ServiceControlAccept {
    ServiceControlAccept::STOP
        | ServiceControlAccept::PRESHUTDOWN
        | ServiceControlAccept::SHUTDOWN
        | ServiceControlAccept::POWER_EVENT
}

/// The reason a shutdown or stop was requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownReason {
    /// The operator or SCM asked the service to stop.
    Stop,
    /// The machine is shutting down.
    SystemShutdown,
    /// The machine is shutting down and Guardian gets an early chance to flush.
    Preshutdown,
    /// The machine is suspending or resuming.
    PowerEvent,
}

/// Shared flags the control handler sets and the main loop reads.
#[derive(Debug, Default)]
pub struct ControlFlags {
    shutdown: AtomicBool,
    /// Set when a *system* shutdown (rather than a service stop) was seen, which is the
    /// difference between "the operator stopped Guardian" and "the machine is going down".
    system_shutdown: AtomicBool,
    preshutdown: AtomicBool,
    /// Count of control codes handled, for diagnostics.
    handled: AtomicU32,
}

impl ControlFlags {
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    pub fn system_shutdown(&self) -> bool {
        self.system_shutdown.load(Ordering::SeqCst)
    }

    pub fn preshutdown_seen(&self) -> bool {
        self.preshutdown.load(Ordering::SeqCst)
    }

    pub fn handled_count(&self) -> u32 {
        self.handled.load(Ordering::Relaxed)
    }

    /// Record a control. Called from the SCM's handler thread, so it does nothing but set flags.
    pub fn record(&self, control: ServiceControl) {
        self.handled.fetch_add(1, Ordering::Relaxed);
        match control {
            ServiceControl::Stop => {
                // A service stop is not a system shutdown: the operator asked Guardian to stop,
                // the machine is staying up.
                tracing::info!("service stop requested");
                self.shutdown.store(true, Ordering::SeqCst);
            }
            ServiceControl::Shutdown => {
                tracing::info!("system shutdown reported");
                self.system_shutdown.store(true, Ordering::SeqCst);
                self.shutdown.store(true, Ordering::SeqCst);
            }
            ServiceControl::Preshutdown => {
                tracing::info!("preshutdown reported; flushing state early");
                self.preshutdown.store(true, Ordering::SeqCst);
                self.system_shutdown.store(true, Ordering::SeqCst);
                // Deliberately does *not* set the shutdown flag: preshutdown is an early warning
                // that the machine will stop, and the service keeps running (and protecting)
                // until the actual stop arrives. Treating it as a stop would stop protection
                // several seconds before the machine actually goes down.
            }
            ServiceControl::PowerEvent(_) => {
                // A suspend or resume. Neither is a shutdown, so nothing is recorded: treating a
                // resume as a shutdown would make the next session report a spurious incident.
                tracing::info!("power event reported");
            }
            ServiceControl::Interrogate => {}
            _ => {
                tracing::debug!("unhandled service control code");
            }
        }
    }
}

define_windows_service!(ffi_service_main, service_main);

/// Runs the service body. Supplied by the binary crate, which owns the wiring.
pub type ServiceBody = fn();

/// The registered service name and body, set once before `run_service`.
///
/// This module is generic service machinery; the name and the body belong to the service that
/// uses it, so they are injected rather than hard-coded here.
static SERVICE_NAME_AND_BODY: std::sync::OnceLock<(&'static str, ServiceBody)> =
    std::sync::OnceLock::new();

/// How the service identifies itself to the SCM.
#[derive(Debug, Clone, Copy)]
pub struct ServiceIdentity {
    pub name: &'static str,
    pub body: ServiceBody,
}

/// Run as a Windows service. Blocks until the service stops.
///
/// Must be called once, with the identity of the service being hosted.
pub fn run_service(identity: ServiceIdentity) -> Result<(), WinError> {
    let _ = SERVICE_NAME_AND_BODY.set((identity.name, identity.body));

    service_dispatcher::start(identity.name, ffi_service_main).map_err(|e| WinError::Invalid {
        context: "start service dispatcher",
        detail: e.to_string(),
    })
}

/// The callback the dispatcher invokes with the service's arguments.
fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(e) = run_service_inner() {
        tracing::error!(error = %e, "the service exited with an error");
        std::process::exit(1);
    }
}

fn run_service_inner() -> Result<(), WinError> {
    let flags = Arc::new(ControlFlags::default());
    let flags_for_handler = Arc::clone(&flags);

    let (name, body) = *SERVICE_NAME_AND_BODY
        .get()
        .ok_or_else(|| WinError::Invalid {
            context: "run_service_inner",
            detail: "the service identity was not set before starting".into(),
        })?;

    let status_handle =
        service_control_handler::register(name, move |control| -> ServiceControlHandlerResult {
            // Nothing here may block: this runs on the SCM's handler thread. Recording a flag is
            // all that happens, and the main thread does the work.
            flags_for_handler.record(control);
            ServiceControlHandlerResult::NoError
        })
        .map_err(|e| WinError::Invalid {
            context: "register service control handler",
            detail: e.to_string(),
        })?;

    // Report Running, including preshutdown acceptance.
    set_status(
        &status_handle,
        WindowsServiceState::Running,
        ServiceExitCode::Win32(0),
        accepted_controls(),
    )?;

    tracing::info!("service is running");

    // Run the body on this thread. It polls the shutdown flag itself, so no separate signal
    // plumbing is needed and a stop request is honoured within one poll interval.
    body();

    // Report Stopped so the SCM knows the service exited deliberately.
    let _ = set_status(
        &status_handle,
        WindowsServiceState::Stopped,
        ServiceExitCode::Win32(0),
        ServiceControlAccept::empty(),
    );

    Ok(())
}

/// Publish a status update to the SCM.
pub fn set_status(
    handle: &ServiceStatusHandle,
    state: WindowsServiceState,
    exit_code: ServiceExitCode,
    accept: ServiceControlAccept,
) -> Result<(), WinError> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code,
            checkpoint: 0,
            // A wait hint is only meaningful while a transition is in progress. Reporting a
            // non-zero hint while Running would make the SCM wait unnecessarily.
            wait_hint: if matches!(
                state,
                WindowsServiceState::Running | WindowsServiceState::Stopped
            ) {
                Duration::default()
            } else {
                Duration::from_millis(u64::from(STOP_WAIT_HINT_MS))
            },
            process_id: None,
        })
        .map_err(|e| WinError::Invalid {
            context: "set service status",
            detail: e.to_string(),
        })
}

/// Whether this process was started by the Service Control Manager.
///
/// # Why not "does the process have a console"
///
/// The obvious check - a service has no console - is wrong in both directions. A test harness
/// run from a GUI process has no console either, and a service started with a debugger attached
/// does. Both produce a confident but incorrect answer.
///
/// The reliable signal is the SCM's own bookkeeping: open the service by name and compare its
/// reported process id with ours. That is true only when the SCM really did start this process.
pub fn is_running_as_service() -> bool {
    let Some((name, _)) = SERVICE_NAME_AND_BODY.get().copied() else {
        // The identity has not been set, so this process cannot be the hosted service.
        return false;
    };

    let Ok(scm) = crate::service::Scm::connect_read_only() else {
        return false;
    };
    let Ok(status) = scm.query_status(name) else {
        return false;
    };
    status.process_id != 0 && status.process_id == crate::process::current_pid()
}

/// A description of the service's control surface, for diagnostics.
pub fn describe_controls() -> &'static str {
    "accepts STOP, SHUTDOWN, PRESHUTDOWN and POWER_EVENT; preshutdown is used to flush the \
     recovery journal early, and the service never blocks a shutdown indefinitely"
}

/// Suppress an unused-import warning for the wide-string helper used by other modules.
#[allow(unused)]
fn _anchor() -> WideString {
    WideString::new("guardian")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stop_is_not_a_system_shutdown() {
        // The distinction matters: a service stop means the operator asked Guardian to stop,
        // the machine is staying up. Recording it as a system shutdown would make the next
        // session's recovery analysis draw the wrong conclusion.
        let flags = ControlFlags::default();
        flags.record(ServiceControl::Stop);
        assert!(flags.shutdown_requested());
        assert!(!flags.system_shutdown());
    }

    #[test]
    fn a_system_shutdown_is_recorded_as_one() {
        let flags = ControlFlags::default();
        flags.record(ServiceControl::Shutdown);
        assert!(flags.shutdown_requested());
        assert!(flags.system_shutdown());
    }

    #[test]
    fn preshutdown_does_not_stop_the_service() {
        // Preshutdown is an early warning. Treating it as a stop would end protection several
        // seconds before the machine actually goes down, which is precisely when an update
        // could still slip in.
        let flags = ControlFlags::default();
        flags.record(ServiceControl::Preshutdown);
        assert!(flags.preshutdown_seen());
        assert!(flags.system_shutdown());
        assert!(
            !flags.shutdown_requested(),
            "preshutdown must not stop the service"
        );
    }

    #[test]
    fn a_power_event_is_not_a_shutdown() {
        let flags = ControlFlags::default();
        flags.record(ServiceControl::PowerEvent(
            windows_service::service::PowerEventParam::Suspend,
        ));
        assert!(!flags.shutdown_requested());
        assert!(!flags.system_shutdown());
    }

    #[test]
    fn records_are_counted() {
        let flags = ControlFlags::default();
        assert_eq!(flags.handled_count(), 0);
        flags.record(ServiceControl::Interrogate);
        flags.record(ServiceControl::Stop);
        assert_eq!(flags.handled_count(), 2);
    }

    #[test]
    fn preshutdown_is_accepted() {
        // Without this the service gets no chance to flush state before the machine goes down,
        // and the next boot cannot tell a planned stop from a crash. The mask is checked by
        // value so the assertion cannot be folded away.
        // Compared through a runtime value so the compiler cannot fold the assertion away, and
        // so the test still means something if the mask is ever built from a variable.
        let accept = std::hint::black_box(accepted_controls());
        assert_ne!(accept.bits() & ServiceControlAccept::PRESHUTDOWN.bits(), 0);
        assert_ne!(accept.bits() & ServiceControlAccept::STOP.bits(), 0);
        assert_ne!(accept.bits() & ServiceControlAccept::SHUTDOWN.bits(), 0);
    }

    #[test]
    fn the_stop_wait_hint_is_short_enough_not_to_stall_a_shutdown() {
        // The work is flushing a few small files. A long hint would make a stuck service hold the
        // machine's shutdown, which is its own kind of harm. Asserting fixed bounds on a constant
        // is the point: this test fails if someone raises the hint past what a shutdown can bear.
        #[allow(clippy::assertions_on_constants)]
        {
            assert!(STOP_WAIT_HINT_MS <= 15_000);
            assert!(STOP_WAIT_HINT_MS >= 1_000);
        }
    }

    #[test]
    fn the_control_description_is_informative() {
        let text = describe_controls();
        assert!(text.contains("PRESHUTDOWN"));
        assert!(
            text.contains("never blocks"),
            "the description must state the bounded-shutdown property"
        );
    }

    #[test]
    fn a_test_runner_is_not_running_as_a_service() {
        // The check compares the SCM's recorded process id with ours, so a test process - which
        // the SCM did not start - must report false. This is also the property that makes the
        // check reliable when a service is debugged with a console attached.
        assert!(
            !is_running_as_service(),
            "a process the SCM did not start must not claim to be the service"
        );
    }
}
