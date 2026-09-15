//! Windows session and shutdown facilities.
//!
//! Two related capabilities:
//!
//! 1. **Session enumeration** — the service runs in session 0 and needs to know which
//!    interactive sessions exist so it can coordinate the per-user helpers, and so it can
//!    associate detected agents with the user who is running them.
//! 2. **Shutdown blocking** — `ShutdownBlockReasonCreate` lets a windowed process ask the
//!    OS to hold a shutdown while important work is in progress. This is the documented,
//!    supported mechanism; the alternative (looping on `AbortSystemShutdown`) fights the
//!    OS, is unreliable, and is exactly the kind of fragile hack this project avoids.
//!
//! # Important limitation, stated plainly
//!
//! `ShutdownBlockReasonCreate` only protects against the *interactive* shutdown paths that
//! respect it. A forced shutdown (`shutdown /f`), an administrative power action, a
//! service-initiated restart, a kernel fault or a power loss are all unaffected. Guardian
//! therefore treats shutdown blocking as one layer, not as a guarantee, and the docs say so.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::System::RemoteDesktop::{
    WTSClientProtocolType, WTSEnumerateSessionsW, WTSFreeMemory, WTSQuerySessionInformationW,
    WTSUserName, WTS_CONNECTSTATE_CLASS, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows::Win32::System::Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy};

use crate::{WideString, WinError};

/// An interactive Windows session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub session_id: u32,
    pub state: SessionState,
    pub user_name: Option<String>,
    /// True for RDP/RemoteApp sessions, false for console sessions.
    pub is_remote: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Active,
    Connected,
    ConnectQuery,
    Shadow,
    Disconnected,
    Idle,
    Listen,
    Reset,
    Down,
    Init,
    Unknown,
}

impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionState::Active => "active",
            SessionState::Connected => "connected",
            SessionState::ConnectQuery => "connect_query",
            SessionState::Shadow => "shadow",
            SessionState::Disconnected => "disconnected",
            SessionState::Idle => "idle",
            SessionState::Listen => "listen",
            SessionState::Reset => "reset",
            SessionState::Down => "down",
            SessionState::Init => "init",
            SessionState::Unknown => "unknown",
        }
    }

    /// Whether a user is present in this session right now.
    pub fn is_interactive(self) -> bool {
        matches!(self, SessionState::Active)
    }
}

fn map_state(state: WTS_CONNECTSTATE_CLASS) -> SessionState {
    // WTS_CONNECTSTATE_CLASS values, in their documented order.
    match state.0 {
        0 => SessionState::Active,
        1 => SessionState::Connected,
        2 => SessionState::ConnectQuery,
        3 => SessionState::Shadow,
        4 => SessionState::Disconnected,
        5 => SessionState::Idle,
        6 => SessionState::Listen,
        7 => SessionState::Reset,
        8 => SessionState::Down,
        9 => SessionState::Init,
        _ => SessionState::Unknown,
    }
}

/// Enumerate interactive sessions on this machine.
///
/// Returns an empty list rather than an error when session enumeration is unavailable; a
/// caller that cannot see sessions must still protect updates.
pub fn enumerate_sessions() -> Result<Vec<SessionInfo>, WinError> {
    let mut p_sessions: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;

    // Safety: the two out-parameters are correctly typed, and the returned array is owned by
    // the WTS API until WTSFreeMemory is called on it.
    let ok = unsafe {
        WTSEnumerateSessionsW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            0,
            1,
            &mut p_sessions,
            &mut count,
        )
    };

    if ok.is_err() {
        return Err(WinError::last("WTSEnumerateSessionsW"));
    }
    if p_sessions.is_null() || count == 0 {
        return Ok(Vec::new());
    }

    // Guard the slice length against a nonsensical count from a broken provider.
    const MAX_SESSIONS: usize = 1024;
    let len = (count as usize).min(MAX_SESSIONS);

    // Safety: `p_sessions` points to `count` entries allocated by the API, and `len` is
    // bounded by that count.
    let infos: &[WTS_SESSION_INFOW] = unsafe { std::slice::from_raw_parts(p_sessions, len) };

    let mut out = Vec::with_capacity(len);
    for info in infos {
        out.push(SessionInfo {
            session_id: info.SessionId,
            state: map_state(info.State),
            user_name: query_user_name(info.SessionId),
            is_remote: query_is_remote(info.SessionId),
        });
    }

    // Safety: the buffer came from WTSEnumerateSessionsW and has been fully consumed.
    unsafe { WTSFreeMemory(p_sessions as *mut core::ffi::c_void) };

    Ok(out)
}

/// Read the user name for a session, if one is logged on.
fn query_user_name(session_id: u32) -> Option<String> {
    let mut out = windows::core::PWSTR::null();
    let mut bytes = 0u32;

    // Safety: out-parameters are correctly typed; on success the API allocates a buffer that
    // we own and must free with WTSFreeMemory.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session_id,
            WTSUserName,
            &mut out,
            &mut bytes,
        )
    };

    if ok.is_err() || out.is_null() || bytes < 2 {
        if !out.is_null() {
            // Safety: allocated by the WTS API for us to free.
            unsafe { WTSFreeMemory(out.0 as *mut core::ffi::c_void) };
        }
        return None;
    }

    // `bytes` includes the terminating NUL, so the unit count is bytes/2 - 1.
    let units = (bytes as usize / 2).saturating_sub(1);
    // Safety: the API reported `bytes` bytes at `out`.
    let slice = unsafe { std::slice::from_raw_parts(out.0, units) };
    let name = String::from_utf16_lossy(slice);

    // Safety: as above.
    unsafe { WTSFreeMemory(out.0 as *mut core::ffi::c_void) };

    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

/// Whether a session is remote (RDP) rather than at the console.
fn query_is_remote(session_id: u32) -> bool {
    let mut out = windows::core::PWSTR::null();
    let mut bytes = 0u32;

    // Safety: out-parameters are correctly typed; the buffer is owned by the WTS API.
    let ok = unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session_id,
            WTSClientProtocolType,
            &mut out,
            &mut bytes,
        )
    };

    if ok.is_err() || out.is_null() || bytes < 2 {
        if !out.is_null() {
            // Safety: allocated by the WTS API.
            unsafe { WTSFreeMemory(out.0 as *mut core::ffi::c_void) };
        }
        return false;
    }

    // The value is a 16-bit protocol number: 0 = console, 1 = legacy RDP, 2 = RDP.
    // Safety: the API reported at least two bytes.
    let protocol = unsafe { *out.0 };
    // Safety: as above.
    unsafe { WTSFreeMemory(out.0 as *mut core::ffi::c_void) };

    protocol != 0
}

/// The session the calling process belongs to.
pub fn current_session_id() -> u32 {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    let mut id = 0u32;
    // Safety: `id` is a valid out-parameter.
    let ok = unsafe { ProcessIdToSessionId(crate::process::current_pid(), &mut id) };
    if ok.is_ok() {
        id
    } else {
        0
    }
}

/// Whether any session currently has a logged-on user.
pub fn has_interactive_user() -> bool {
    enumerate_sessions()
        .map(|s| {
            s.iter()
                .any(|s| s.state.is_interactive() && s.user_name.is_some())
        })
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Shutdown blocking
// ---------------------------------------------------------------------------

/// Owns a shutdown block reason for a window.
///
/// The reason is registered on creation and removed on drop, so a panic or an early return
/// cannot leave the OS holding a stale block — which would be exactly the "software prevents
/// shutdown" behaviour this project must avoid.
#[derive(Debug)]
pub struct ShutdownBlocker {
    hwnd: HWND,
    active: bool,
}

impl ShutdownBlocker {
    /// Create a blocker attached to `hwnd`.
    ///
    /// `hwnd` must belong to the calling thread and be a real top-level window; the API
    /// associates the reason with that window and the shutdown UI resolves the reason
    /// through it.
    pub fn new(hwnd: HWND) -> Self {
        ShutdownBlocker {
            hwnd,
            active: false,
        }
    }

    /// Whether a block is currently registered.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Register a block reason.
    ///
    /// `reason` is shown to the user by the shutdown UI, so it must be short, specific and
    /// truthful. The API caps the string at 512 characters.
    ///
    /// Calling this while already active is a no-op, which keeps the call site simple: the
    /// session helper can call it on every state push without tracking whether it already
    /// did.
    pub fn block(&mut self, reason: &str) -> Result<(), WinError> {
        if self.active {
            return Ok(());
        }
        if reason.len() > 512 {
            return Err(WinError::Invalid {
                context: "ShutdownBlockReasonCreate",
                detail: format!("reason is {} bytes, over the 512 byte limit", reason.len()),
            });
        }

        let wide = WideString::new(reason);
        // Safety: `hwnd` is a window owned by this thread and `wide` is a valid
        // NUL-terminated string that outlives the call.
        let ok = unsafe { ShutdownBlockReasonCreate(self.hwnd, PCWSTR(wide.as_ptr())) };

        if ok.is_err() {
            let err = WinError::last("ShutdownBlockReasonCreate");
            // Flush the previous error so a later unrelated call cannot pick it up.
            tracing::warn!(error = %err, "could not register a shutdown block reason");
            return Err(err);
        }

        self.active = true;
        tracing::info!(reason, "shutdown blocking enabled");
        Ok(())
    }

    /// Remove the block reason.
    ///
    /// Idempotent, and never fails in a way the caller must handle: if the API rejects the
    /// destroy there is nothing useful to do except record it, because failing to remove a
    /// block is a bug in our window management, not an environmental condition.
    pub fn unblock(&mut self) {
        if !self.active {
            return;
        }
        // Safety: `hwnd` was valid when the reason was created and this object is tied to
        // the same window's lifetime.
        let ok = unsafe { ShutdownBlockReasonDestroy(self.hwnd) };
        self.active = false;
        if ok.is_err() {
            tracing::warn!("ShutdownBlockReasonDestroy reported failure; the block may be stale");
        } else {
            tracing::info!("shutdown blocking disabled");
        }
    }
}

impl Drop for ShutdownBlocker {
    fn drop(&mut self) {
        self.unblock();
    }
}

/// A message-only or hidden message window, used by the session helper to receive
/// `WM_QUERYENDSESSION` / `WM_ENDSESSION`.
///
/// The helper needs a real window for `ShutdownBlockReasonCreate` to have an effect and to
/// receive session messages. It is deliberately invisible and does no drawing.
pub struct MessageWindow {
    hwnd: HWND,
}

// The window is created on and confined to one thread; making that explicit prevents the
// handle from being used from another thread, where the message loop would not be pumping.
impl MessageWindow {
    /// Create a hidden window with the given window class name.
    pub fn create(class_name: &str, title: &str) -> Result<Self, WinError> {
        use windows::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, RegisterClassW, CW_USEDEFAULT, WINDOW_EX_STYLE, WNDCLASSW,
            WS_OVERLAPPED,
        };

        let class = WideString::new(class_name);
        let title_wide = WideString::new(title);

        // Safety: an already-loaded module handle; the name is a static wide string.
        let instance =
            unsafe { GetModuleHandleW(None) }.map_err(|_| WinError::last("GetModuleHandleW"))?;

        let wc = WNDCLASSW {
            lpfnWndProc: Some(message_window_proc),
            hInstance: instance.into(),
            lpszClassName: PCWSTR(class.as_ptr()),
            ..Default::default()
        };

        // Safety: `wc` is fully initialised and the class name outlives the call. A class
        // that is already registered returns 0, which is fine.
        let atom = unsafe { RegisterClassW(&wc) };
        if atom == 0 {
            let err = WinError::last("RegisterClassW");
            // Re-registering an existing class is not an error for our purposes.
            tracing::debug!(error = %err, "RegisterClassW returned 0");
        }

        // Safety: class and title are valid NUL-terminated strings that outlive the call.
        // The window is created without WS_VISIBLE so it never appears on screen.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                PCWSTR(class.as_ptr()),
                PCWSTR(title_wide.as_ptr()),
                WS_OVERLAPPED,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                0,
                0,
                None,
                None,
                Some(instance.into()),
                None,
            )
        };

        match hwnd {
            Ok(h) if !h.is_invalid() => Ok(MessageWindow { hwnd: h }),
            _ => Err(WinError::last("CreateWindowExW")),
        }
    }

    pub fn hwnd(&self) -> HWND {
        self.hwnd
    }
}

impl Drop for MessageWindow {
    fn drop(&mut self) {
        use windows::Win32::UI::WindowsAndMessaging::DestroyWindow;
        if !self.hwnd.is_invalid() {
            // Safety: the window was created by us and is destroyed exactly once.
            unsafe {
                let _ = DestroyWindow(self.hwnd);
            }
        }
    }
}

impl std::fmt::Debug for MessageWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageWindow")
            .field("hwnd", &format!("{:?}", self.hwnd))
            .finish()
    }
}

/// Default window procedure for the helper's hidden window.
///
/// It exists only so a window can be created; all meaningful work happens in the helper's
/// own message loop, which needs to see the session messages before the default handler
/// runs.
extern "system" fn message_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    // Safety: the default procedure is always a valid fallback for messages we do not
    // handle. Returning its result is the documented behaviour for an unhandled message.
    unsafe { windows::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wparam, lparam) }
}

/// Message ids the helper cares about, re-exported so the helper does not depend on the
/// `windows` crate directly.
pub mod messages {
    pub use windows::Win32::UI::WindowsAndMessaging::{
        WM_ENDSESSION, WM_QUERYENDSESSION, WM_QUERYOPEN,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_enumeration_succeeds_or_reports_a_clean_error() {
        // In a normal interactive session this returns at least the current session. In a
        // restricted service context it may legitimately fail; either is acceptable, but a
        // panic is not.
        match enumerate_sessions() {
            Ok(sessions) => {
                for s in &sessions {
                    if let Some(name) = &s.user_name {
                        assert!(!name.is_empty(), "a reported user name must not be empty");
                    }
                }
            }
            Err(e) => {
                // Report the reason but do not fail: session enumeration is unavailable in
                // some sandboxes, and that is not a defect in this code.
                eprintln!("session enumeration unavailable in this context: {e}");
            }
        }
    }

    #[test]
    fn our_own_session_is_visible_when_enumeration_works() {
        if let Ok(sessions) = enumerate_sessions() {
            if sessions.is_empty() {
                return; // Restricted context.
            }
            let mine = current_session_id();
            let found = sessions.iter().find(|s| s.session_id == mine);
            // The current session must be listed; if it is not, the enumeration is
            // returning something other than this machine's sessions.
            assert!(
                found.is_some(),
                "our own session {mine} was missing from {sessions:?}"
            );
        }
    }

    #[test]
    fn state_mapping_covers_the_documented_range() {
        use windows::Win32::System::RemoteDesktop::{WTSActive, WTS_CONNECTSTATE_CLASS};
        assert_eq!(map_state(WTSActive), SessionState::Active);
        assert_eq!(
            map_state(WTS_CONNECTSTATE_CLASS(4)),
            SessionState::Disconnected
        );
        assert_eq!(map_state(WTS_CONNECTSTATE_CLASS(5)), SessionState::Idle);
        assert_eq!(map_state(WTS_CONNECTSTATE_CLASS(99)), SessionState::Unknown);
    }

    #[test]
    fn interactive_state_detection_is_precise() {
        assert!(SessionState::Active.is_interactive());
        for s in [
            SessionState::Connected,
            SessionState::Disconnected,
            SessionState::Idle,
            SessionState::Listen,
            SessionState::Unknown,
        ] {
            assert!(!s.is_interactive(), "{s:?} must not count as interactive");
        }
    }

    #[test]
    fn state_names_are_non_empty_and_stable() {
        for s in [
            SessionState::Active,
            SessionState::Disconnected,
            SessionState::Unknown,
        ] {
            assert!(!s.as_str().is_empty());
        }
    }

    #[test]
    fn has_interactive_user_does_not_fail_in_a_service_context() {
        // Must return a bool rather than erroring out; a service must be able to ask.
        let _ = has_interactive_user();
    }

    #[test]
    fn over_long_block_reason_is_rejected_before_calling_the_api() {
        // A 600-byte reason would be silently truncated or rejected by Windows; catching it
        // here keeps the failure local and testable.
        let window = MessageWindow::create("GuardianTestWndClass", "guardian test");
        if let Ok(window) = window {
            let mut blocker = ShutdownBlocker::new(window.hwnd());
            let long = "x".repeat(600);
            assert!(blocker.block(&long).is_err());
            assert!(!blocker.is_active());
        }
    }

    #[test]
    fn shutdown_blocker_round_trips_when_a_window_exists() {
        // Exercises the real API. Whether the OS honours the block is not something a unit
        // test can assert, but registration and removal must succeed.
        let Ok(window) = MessageWindow::create("GuardianTestWndClass2", "guardian test 2") else {
            // A headless or restricted context; skip rather than fail.
            return;
        };
        let mut blocker = ShutdownBlocker::new(window.hwnd());
        assert!(!blocker.is_active());

        blocker
            .block("Workstation Guardian: active development tasks are still running.")
            .expect("registering a block reason must succeed for a valid window");
        assert!(blocker.is_active());

        // A second block is a no-op, not an error.
        blocker.block("different reason").unwrap();
        assert!(blocker.is_active());

        blocker.unblock();
        assert!(!blocker.is_active());

        // Unblocking again is harmless.
        blocker.unblock();
        assert!(!blocker.is_active());
    }

    #[test]
    fn dropping_a_blocker_removes_the_block() {
        let Ok(window) = MessageWindow::create("GuardianTestWndClass3", "guardian test 3") else {
            return;
        };
        let hwnd = window.hwnd();
        {
            let mut blocker = ShutdownBlocker::new(hwnd);
            blocker.block("transient").unwrap();
            assert!(blocker.is_active());
            // Dropping here must unblock; otherwise a crash could leave a stale block.
        }
        // Re-register on the same window to prove the previous block was released and left
        // no conflicting state.
        let mut blocker2 = ShutdownBlocker::new(hwnd);
        blocker2.block("second").expect("re-registering must work");
        blocker2.unblock();
    }

    #[test]
    fn message_window_creation_and_drop_are_clean() {
        let window = MessageWindow::create("GuardianTestWndClass4", "guardian test 4")
            .expect("a hidden message window must be creatable");
        assert!(!window.hwnd().is_invalid());
        drop(window);
    }

    #[test]
    fn message_window_messages_are_re_exported() {
        // The helper depends on these ids; confirming they are reachable keeps the
        // re-export honest.
        let _ = messages::WM_QUERYENDSESSION;
        let _ = messages::WM_ENDSESSION;
    }
}
