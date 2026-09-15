//! `guardian-session` — the per-user shutdown blocker.
//!
//! # Why a separate process exists at all
//!
//! `ShutdownBlockReasonCreate` requires a window owned by a process in the *interactive* user's
//! session. The service runs in session 0 with no window station, so it cannot register a block
//! on a user's behalf. This helper is the minimum needed to bridge that: it runs in the user's
//! session, holds a hidden message window, and creates or destroys the block reason as the
//! service tells it to.
//!
//! It is deliberately tiny. It makes no decisions: the service decides when work is at risk, and
//! this process only carries that decision out. If the helper is missing or has crashed, the
//! service reports restart protection as degraded and keeps protecting updates regardless.
//!
//! # Resource footprint
//!
//! It blocks on a pipe read for as long as the service has nothing to say, so its idle cost is a
//! blocked thread and one window. It does not poll.

#![deny(unsafe_op_in_unsafe_fn)]
#![windows_subsystem = "windows"]

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use guardian_proto::{Request, Response, SubscriberKind};
use guardian_win::session::{MessageWindow, ShutdownBlocker};

/// The reason shown to the user when a shutdown is held.
///
/// Short, specific and truthful about what is happening and why.
const BLOCK_REASON: &str = "Workstation Guardian: active development tasks are still running.";

/// How long to wait between reconnection attempts while the service is unavailable.
const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

fn main() {
    // A message window is required for both the shutdown block and for receiving
    // WM_QUERYENDSESSION. It is never shown.
    let window = match MessageWindow::create("WorkstationGuardianSession", "Workstation Guardian") {
        Ok(w) => w,
        Err(e) => {
            // Without a window there is nothing useful this process can do. Exit quietly rather
            // than retrying forever: the service reports the degraded state either way.
            eprintln!("guardian-session: could not create the message window: {e}");
            std::process::exit(1);
        }
    };

    let mut blocker = ShutdownBlocker::new(window.hwnd());
    let running = Arc::new(AtomicBool::new(true));

    // Survive a reconnection by never treating a lost service as fatal: this process must still
    // be alive to block a shutdown once the service comes back.
    loop {
        match run_session(&mut blocker, Arc::clone(&running)) {
            Ok(()) => {
                // The service closed the subscription cleanly, which happens on service stop.
                // Reconnect: the service may be restarting.
                tracing::debug!("subscription ended; reconnecting");
            }
            Err(e) => {
                tracing::debug!(error = %e, "connection to the service was lost");
            }
        }

        // Whatever happened, release the block while we are disconnected. Holding a block with
        // no service to tell us when to release it would be exactly the "software that will not
        // let you shut down" behaviour this project must not exhibit.
        blocker.unblock();

        std::thread::sleep(RECONNECT_DELAY);
    }
}

/// Connect and consume protection-state pushes until the connection ends.
fn run_session(blocker: &mut ShutdownBlocker, _running: Arc<AtomicBool>) -> Result<(), String> {
    let mut client = guardian_service::ipc::IpcClient::connect(10_000)
        .map_err(|e| format!("could not connect to the service: {e}"))?;

    // Identify ourselves, then subscribe. The service keeps the connection open and streams
    // state changes; there is no polling on either side.
    client
        .call_expect(&Request::Hello {
            protocol: guardian_proto::PROTOCOL_VERSION,
        })
        .map_err(|e| format!("version handshake failed: {e}"))?;

    // The subscription replies with the current state, then streams changes. The first push is
    // therefore applied immediately, so a helper that starts while work is already running blocks
    // straight away rather than waiting for the next change.
    client
        .subscribe(
            &Request::Subscribe {
                client: SubscriberKind::SessionHelper,
            },
            |response| match response {
                Response::Status(snapshot) => {
                    apply_state(blocker, snapshot.mode);
                    true
                }
                Response::Ok { .. } => true,
                // An unrecognised message is ignored rather than fatal, so a newer service can
                // send something this build does not understand without breaking shutdown
                // blocking.
                other => {
                    tracing::debug!(?other, "ignoring an unexpected message from the service");
                    true
                }
            },
        )
        .map_err(|e| format!("subscription failed: {e}"))?;

    Ok(())
}

/// Create or destroy the shutdown block to match the protection mode.
///
/// Idempotent: `ShutdownBlocker` tracks its own state, so this is safe to call on every push
/// without checking first.
fn apply_state(blocker: &mut ShutdownBlocker, mode: guardian_proto::model::ProtectionMode) {
    use guardian_proto::model::ProtectionMode;

    match mode {
        ProtectionMode::Working => {
            if let Err(e) = blocker.block(BLOCK_REASON) {
                // A failure to register the block is worth knowing about, but it is not fatal:
                // the service still protects updates, and the operator can see the degraded
                // state in the UI.
                eprintln!("guardian-session: could not enable shutdown blocking: {e}");
            }
        }
        ProtectionMode::Normal | ProtectionMode::Maintenance => {
            // In MAINTENANCE the user has explicitly asked to do update work, so holding a
            // shutdown block would be fighting the decision they just made.
            blocker.unblock();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_proto::model::ProtectionMode;

    #[test]
    fn the_block_reason_is_short_and_specific() {
        // The API caps this at 512 characters, and the shutdown UI shows it to a user who is
        // trying to leave. It must name the tool and say what is happening.
        assert!(BLOCK_REASON.len() < 512);
        assert!(BLOCK_REASON.contains("Workstation Guardian"));
        assert!(BLOCK_REASON.contains("running"));
        assert!(!BLOCK_REASON.contains('\n'));
    }

    #[test]
    fn working_mode_requests_a_block_when_a_window_is_available() {
        let Ok(window) = MessageWindow::create("GuardianSessionTest1", "test") else {
            // A restricted context; the behaviour itself is covered by guardian-win's tests.
            return;
        };
        let mut blocker = ShutdownBlocker::new(window.hwnd());
        assert!(!blocker.is_active());

        apply_state(&mut blocker, ProtectionMode::Working);
        assert!(blocker.is_active(), "WORKING must block shutdown");

        apply_state(&mut blocker, ProtectionMode::Normal);
        assert!(!blocker.is_active(), "NORMAL must release the block");
    }

    #[test]
    fn maintenance_mode_does_not_block() {
        // The user explicitly asked to do update work; blocking their shutdown would fight that.
        let Ok(window) = MessageWindow::create("GuardianSessionTest2", "test") else {
            return;
        };
        let mut blocker = ShutdownBlocker::new(window.hwnd());

        apply_state(&mut blocker, ProtectionMode::Working);
        assert!(blocker.is_active());

        apply_state(&mut blocker, ProtectionMode::Maintenance);
        assert!(
            !blocker.is_active(),
            "MAINTENANCE must not hold a shutdown block"
        );
    }

    #[test]
    fn applying_the_same_state_twice_is_harmless() {
        let Ok(window) = MessageWindow::create("GuardianSessionTest3", "test") else {
            return;
        };
        let mut blocker = ShutdownBlocker::new(window.hwnd());

        apply_state(&mut blocker, ProtectionMode::Working);
        apply_state(&mut blocker, ProtectionMode::Working);
        assert!(blocker.is_active());

        apply_state(&mut blocker, ProtectionMode::Normal);
        apply_state(&mut blocker, ProtectionMode::Normal);
        assert!(!blocker.is_active());
    }

    #[test]
    fn reconnect_delay_is_reasonable() {
        // Long enough not to spin when the service is down, short enough that a helper started
        // before the service becomes useful promptly.
        assert!(RECONNECT_DELAY >= std::time::Duration::from_secs(1));
        assert!(RECONNECT_DELAY <= std::time::Duration::from_secs(30));
    }

    #[test]
    fn connecting_without_a_service_fails_cleanly() {
        // The real service is not running during tests, so this must report rather than hang or
        // panic. The helper treats this as normal and retries.
        let result = guardian_service::ipc::IpcClient::connect(200);
        assert!(
            result.is_err(),
            "there should be no service listening on a test machine"
        );
        assert!(!result.unwrap_err().is_empty());
    }
}
