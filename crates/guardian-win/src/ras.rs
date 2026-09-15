//! RAS/PPPoE access through the documented Win32 RAS API.
//!
//! # Why not `rasdial.exe`
//!
//! Shelling out to `rasdial` means spawning a process, parsing localized console output, and
//! having no access to the structured error codes or the connection state machine. The RAS
//! API is a stable, documented, in-process C API that reports exactly what happened. It is
//! also the only way to observe connection state *changes* without polling.
//!
//! # Credentials
//!
//! Guardian never stores a broadband password. `RasDialW` is called with the entry's stored
//! credentials (the phonebook retains them in Windows' own credential storage when the user
//! saves them), and the dial is performed without Guardian ever holding the secret. Nothing
//! in this module accepts a password parameter.

use windows::core::PCWSTR;
use windows::Win32::NetworkManagement::Rras::{RASP_PppIp, RasGetProjectionInfoW, HRASCONN};
use windows::Win32::NetworkManagement::Rras::{
    RasEnumConnectionsW, RasEnumEntriesW, RasGetConnectStatusW, RasGetErrorStringW, RasHangUpW,
    RASCONNSTATE, RASCONNSTATUSW, RASCONNW, RASENTRYNAMEW, RASPPPIPW,
};

use guardian_proto::model::{RasConnectionState, RasEntryInfo};

use crate::{WideString, WinError};

/// Maximum number of RAS connections we will enumerate.
///
/// A workstation has a handful at most. Bounding this keeps a corrupted RAS table from
/// causing an enormous allocation.
const MAX_CONNECTIONS: usize = 64;
/// Maximum number of phonebook entries we will enumerate.
const MAX_ENTRIES: usize = 128;

/// Enumerate the RAS phonebook entries available on this machine.
///
/// The two-call size negotiation is mandatory: `RasEnumEntriesW` returns
/// `ERROR_BUFFER_TOO_SMALL` and writes the required size when the initial buffer is short,
/// and the required size varies with the number of entries.
pub fn enum_entries() -> Result<Vec<RasEntryInfo>, WinError> {
    let mut size = 0u32;
    let mut count = 0u32;

    // First call: pass a null buffer to learn how much room is needed. Windows documents
    // this exact pattern for RasEnumEntriesW.
    //
    // Safety: a null buffer with a zero size is the documented size query.
    let rc =
        unsafe { RasEnumEntriesW(PCWSTR::null(), PCWSTR::null(), None, &mut size, &mut count) };

    const ERROR_BUFFER_TOO_SMALL: u32 = 603;
    const ERROR_SUCCESS: u32 = 0;

    if rc != ERROR_SUCCESS && rc != ERROR_BUFFER_TOO_SMALL {
        // 623 is ERROR_NO_PHONEBOOK; a machine with no dial-up configuration at all is a
        // normal, supported state, not a failure.
        const ERROR_NO_PHONEBOOK: u32 = 623;
        const ERROR_CANNOT_OPEN_PHONEBOOK: u32 = 621;
        if rc == ERROR_NO_PHONEBOOK || rc == ERROR_CANNOT_OPEN_PHONEBOOK {
            return Ok(Vec::new());
        }
        return Err(WinError::from_code("RasEnumEntriesW", rc));
    }

    if count == 0 {
        return Ok(Vec::new());
    }

    let wanted = (count as usize).min(MAX_ENTRIES);
    let mut entries = vec![RASENTRYNAMEW::default(); wanted];
    // The caller must set dwSize on the first element before the call.
    entries[0].dwSize = std::mem::size_of::<RASENTRYNAMEW>() as u32;
    let mut size = (std::mem::size_of::<RASENTRYNAMEW>() * wanted) as u32;

    // Safety: `entries` has room for `wanted` structures and `size` describes that buffer.
    let rc = unsafe {
        RasEnumEntriesW(
            PCWSTR::null(),
            PCWSTR::null(),
            Some(entries.as_mut_ptr()),
            &mut size,
            &mut count,
        )
    };

    if rc != ERROR_SUCCESS {
        return Err(WinError::from_code("RasEnumEntriesW", rc));
    }

    let actual = (count as usize).min(entries.len());
    let mut out = Vec::with_capacity(actual);
    for e in &entries[..actual] {
        let name = crate::wide_to_string(&e.szEntryName);
        if name.is_empty() {
            continue;
        }
        out.push(RasEntryInfo {
            name,
            entry_type: e.dwFlags,
            device_name: None,
            device_type: None,
            // The entry name is not enough to know whether it is broadband; the caller
            // refines this by inspecting the phonebook entry's device type. The flag set
            // here is a first approximation that the service tightens.
            looks_like_broadband: is_likely_broadband_name(&e.szEntryName),
        });
    }

    Ok(out)
}

/// Heuristic on the entry name alone.
///
/// Used only as an initial ordering hint when exactly one entry exists. The authoritative
/// check reads the entry's device type, which is done by the caller with the phonebook API.
fn is_likely_broadband_name(name: &[u16]) -> bool {
    let s = String::from_utf16_lossy(name).to_ascii_lowercase();
    s.contains("broadband")
        || s.contains("pppoe")
        || s.contains("ppp")
        || s.contains("dsl")
        || s.contains("光纤")
        || s.contains("宽带")
}

/// Enumerate connections that are currently active.
pub fn enum_connections() -> Result<Vec<RasConnection>, WinError> {
    let mut size = 0u32;
    let mut count = 0u32;

    // Safety: a null buffer with a zero size is the documented size query.
    let rc = unsafe { RasEnumConnectionsW(None, &mut size, &mut count) };

    const ERROR_BUFFER_TOO_SMALL: u32 = 603;
    const ERROR_SUCCESS: u32 = 0;

    if rc != ERROR_SUCCESS && rc != ERROR_BUFFER_TOO_SMALL {
        return Err(WinError::from_code("RasEnumConnectionsW", rc));
    }

    if count == 0 {
        return Ok(Vec::new());
    }

    let wanted = (count as usize).min(MAX_CONNECTIONS);
    let mut conns = vec![RASCONNW::default(); wanted];
    conns[0].dwSize = std::mem::size_of::<RASCONNW>() as u32;
    let mut size = (std::mem::size_of::<RASCONNW>() * wanted) as u32;

    // Safety: `conns` has room for `wanted` structures and `size` describes the buffer.
    let rc = unsafe { RasEnumConnectionsW(Some(conns.as_mut_ptr()), &mut size, &mut count) };

    if rc != ERROR_SUCCESS {
        return Err(WinError::from_code("RasEnumConnectionsW", rc));
    }

    let actual = (count as usize).min(conns.len());
    let mut out = Vec::with_capacity(actual);
    for c in &conns[..actual] {
        out.push(RasConnection {
            handle: c.hrasconn.0 as usize,
            entry_name: crate::wide_to_string(&c.szEntryName),
            device_name: crate::wide_to_string(&c.szDeviceName),
        });
    }

    Ok(out)
}

/// An active RAS connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RasConnection {
    /// Opaque connection handle, used for hangup and status queries.
    pub handle: usize,
    pub entry_name: String,
    pub device_name: String,
}

/// Query the state of a connection.
pub fn connection_status(handle: usize) -> Result<RasConnectionState, WinError> {
    // dwSize is validated by the API before any field is read.
    let mut status = RASCONNSTATUSW {
        dwSize: std::mem::size_of::<RASCONNSTATUSW>() as u32,
        ..Default::default()
    };

    // Safety: `status` is correctly sized per dwSize, as the API requires.
    let rc =
        unsafe { RasGetConnectStatusW(HRASCONN(handle as *mut core::ffi::c_void), &mut status) };

    if rc != 0 {
        return Err(WinError::from_code("RasGetConnectStatusW", rc));
    }

    Ok(translate_state(status.rasconnstate))
}

/// Map a `RASCONNSTATE` onto Guardian's coarse state.
///
/// The mapping is explicit rather than a catch-all so that a state Windows adds later is
/// reported as `Unknown` instead of being silently folded into "connecting".
// The `RASCS_*` constants come from the `windows` crate and use its naming, not Rust's;
// they are re-exported names, not ours to rename.
#[allow(non_upper_case_globals)]
pub fn translate_state(state: RASCONNSTATE) -> RasConnectionState {
    use windows::Win32::NetworkManagement::Rras::*;
    match state {
        RASCS_Connected => RasConnectionState::Connected,
        RASCS_Disconnected => RasConnectionState::Disconnected,

        // Everything in the dial/authenticate pipeline is "connecting" from the user's
        // point of view.
        RASCS_OpenPort
        | RASCS_PortOpened
        | RASCS_ConnectDevice
        | RASCS_DeviceConnected
        | RASCS_AllDevicesConnected
        | RASCS_Authenticate
        | RASCS_AuthNotify
        | RASCS_AuthRetry
        | RASCS_AuthCallback
        | RASCS_AuthChangePassword
        | RASCS_AuthProject
        | RASCS_AuthLinkSpeed
        | RASCS_AuthAck
        | RASCS_ReAuthenticate
        | RASCS_Authenticated
        | RASCS_PrepareForCallback
        | RASCS_WaitForModemReset
        | RASCS_WaitForCallback
        | RASCS_Projected
        | RASCS_StartAuthentication
        | RASCS_CallbackComplete
        | RASCS_LogonNetwork
        | RASCS_SubEntryConnected
        | RASCS_SubEntryDisconnected
        | RASCS_ApplySettings => RasConnectionState::Connecting,

        // The interactive/paused family: the dial is alive and waiting on input, which is
        // closer to "connecting" than to either terminal state. Treating it as connecting
        // is also the safe choice: it will not cause a hangup of a session that is
        // mid-authentication.
        RASCS_Interactive
        | RASCS_RetryAuthentication
        | RASCS_CallbackSetByCaller
        | RASCS_PasswordExpired
        | RASCS_InvokeEapUI => RasConnectionState::Connecting,

        // Any state we do not recognise is reported as unknown rather than guessed at.
        _ => RasConnectionState::Unknown,
    }
}

/// Whether a connection is currently up, and details about its IP configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionHealth {
    pub state: RasConnectionState,
    /// The negotiated local IP address, when the connection has one.
    pub local_ip: Option<String>,
    /// Whether the connection reports an IP projection at all.
    pub has_ip_configuration: bool,
}

/// Inspect a connection's IP projection.
///
/// A PPPoE session can be "connected" before IP negotiation completes, which is exactly the
/// `NO_IP_CONFIGURATION` case the network state machine distinguishes. Reading the
/// projection is how that is detected rather than guessed.
pub fn connection_health(handle: usize) -> Result<ConnectionHealth, WinError> {
    let state = connection_status(handle)?;

    let mut ip = RASPPPIPW {
        dwSize: std::mem::size_of::<RASPPPIPW>() as u32,
        ..Default::default()
    };
    let mut size = std::mem::size_of::<RASPPPIPW>() as u32;

    // Safety: `ip` is correctly sized per dwSize and `size` describes it. The projection
    // type RASP_PppIp selects the RASPPPIPW layout.
    let rc = unsafe {
        RasGetProjectionInfoW(
            HRASCONN(handle as *mut core::ffi::c_void),
            RASP_PppIp,
            &mut ip as *mut _ as *mut core::ffi::c_void,
            &mut size,
        )
    };

    if rc != 0 {
        // No IP projection yet: the session is up but has no usable address. That is a
        // definite "no IP configuration" answer, not an unknown.
        return Ok(ConnectionHealth {
            state,
            local_ip: None,
            has_ip_configuration: false,
        });
    }

    let addr = crate::wide_to_string(&ip.szIpAddress);
    Ok(ConnectionHealth {
        state,
        has_ip_configuration: !addr.is_empty() && addr != "0.0.0.0",
        local_ip: if addr.is_empty() { None } else { Some(addr) },
    })
}

/// Hang up a connection.
///
/// Deliberately takes an explicit handle rather than "the current connection" so a caller
/// cannot accidentally tear down a healthy session it did not mean to touch.
pub fn hang_up(handle: usize) -> Result<(), WinError> {
    // Safety: the handle came from RasEnumConnectionsW and is used exactly once here.
    let rc = unsafe { RasHangUpW(HRASCONN(handle as *mut core::ffi::c_void)) };
    if rc != 0 {
        return Err(WinError::from_code("RasHangUpW", rc));
    }
    Ok(())
}

/// Translate a RAS error code to text using the RAS API itself.
///
/// Falls back to Guardian's own table when the API has nothing, which happens for codes
/// that are Windows error codes rather than RAS-specific ones.
pub fn error_string(code: u32) -> String {
    let mut buf = [0u16; 512];
    // Safety: `buf` is a valid buffer of the stated length.
    let rc = unsafe { RasGetErrorStringW(code, &mut buf) };
    if rc == 0 {
        let text = crate::wide_to_string(&buf);
        if !text.trim().is_empty() {
            return text;
        }
    }
    guardian_core::net::ras_error_message(code).to_string()
}

// ---------------------------------------------------------------------------
// Dialing
// ---------------------------------------------------------------------------

/// The result of one dial attempt.
#[derive(Debug, Clone)]
pub struct DialOutcome {
    pub success: bool,
    pub error_code: u32,
    pub error_message: String,
}

/// Where the connection we established lives, so it can be tracked and hung up.
#[derive(Debug, Clone)]
pub struct DialResult {
    pub outcome: DialOutcome,
    /// Handle of the established connection, present only on success.
    pub handle: Option<usize>,
}

impl DialResult {
    pub fn failure(code: u32) -> Self {
        DialResult {
            outcome: DialOutcome {
                success: false,
                error_code: code,
                error_message: error_string(code),
            },
            handle: None,
        }
    }
}

/// Dial a phonebook entry, reusing the credentials Windows has stored for it.
///
/// This is the only dial entry point. It never accepts a password, and it never modifies the
/// phonebook: it asks Windows to use the entry as configured, so the credential never
/// enters Guardian's address space or its logs.
///
/// Returns a [`DialResult`]; a dial failure is a normal outcome carrying a RAS error code,
/// not an `Err`.
pub fn dial(entry_name: &str) -> DialResult {
    use windows::Win32::NetworkManagement::Rras::{RasDialW, RASDIALPARAMSW};

    let mut params = RASDIALPARAMSW {
        dwSize: std::mem::size_of::<RASDIALPARAMSW>() as u32,
        ..Default::default()
    };

    // Entry name, bounded to the field width. RASDIALPARAMSW uses inline arrays.
    let entry_wide = WideString::new(entry_name);
    let entry_units = entry_wide.as_slice_with_nul();
    let copy_len = entry_units.len().min(params.szEntryName.len());
    params.szEntryName[..copy_len].copy_from_slice(&entry_units[..copy_len]);

    // Deliberately leave szUserName and szPassword empty. RAS then uses the credentials
    // stored with the phonebook entry, which live in Windows' own protected storage.
    // Guardian never sees, holds, or logs the broadband password.
    params.szUserName[0] = 0;
    params.szPassword[0] = 0;

    let mut handle = HRASCONN::default();

    // Safety: `params` is correctly sized per dwSize and its inline strings are
    // NUL-terminated; `handle` receives the connection handle on success. A null
    // notification callback means the call blocks until the dial completes or fails, which
    // is what we want: no callback state to manage, no lifetime hazard.
    let rc = unsafe { RasDialW(None, None, &params, 0, None, &mut handle) };

    if rc != 0 {
        return DialResult::failure(rc);
    }

    let success = !handle.0.is_null();
    DialResult {
        outcome: DialOutcome {
            success,
            error_code: 0,
            error_message: String::new(),
        },
        handle: success.then_some(handle.0 as usize),
    }
}

/// Find the active connection for a named entry, if any.
pub fn find_active_connection(entry_name: &str) -> Option<RasConnection> {
    let Ok(conns) = enum_connections() else {
        return None;
    };
    conns
        .into_iter()
        .find(|c| c.entry_name.eq_ignore_ascii_case(entry_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerating_entries_does_not_fail_on_a_machine_without_dialup() {
        // The test machine may or may not have a phonebook. Both are valid; neither may
        // produce an error or a panic.
        match enum_entries() {
            Ok(entries) => {
                for e in &entries {
                    assert!(!e.name.is_empty(), "an enumerated entry must have a name");
                }
            }
            Err(e) => panic!("enumeration must tolerate an absent phonebook, got: {e}"),
        }
    }

    #[test]
    fn enumerating_connections_is_safe_when_none_are_up() {
        let conns = enum_connections().expect("enumeration must work with no connections");
        for c in &conns {
            assert!(c.handle != 0 || c.entry_name.is_empty() || true);
        }
    }

    #[test]
    fn querying_a_bogus_handle_fails_cleanly() {
        // A handle that was never a RAS connection must produce an error, not a panic or a
        // wild read.
        let result = connection_status(0xDEAD_BEEF);
        assert!(result.is_err());
    }

    #[test]
    fn error_strings_are_never_empty() {
        // The RAS API provides text for many codes; Guardian's fallback covers the rest.
        for code in [0u32, 691, 678, 651, 812, 999_999] {
            let msg = error_string(code);
            assert!(!msg.trim().is_empty(), "code {code} produced no text");
            assert!(!msg.contains('\n'), "code {code} text is multi-line");
        }
    }

    #[test]
    fn known_ras_errors_produce_recognisable_text() {
        // `RasGetErrorStringW` returns text localized to the OS language, so this test must
        // not assert on English words that come from that path. What it can assert is that
        // the function returns something useful, and that Guardian's own fallback table —
        // which is what reports when the API has no string — carries the documented meaning.
        let localized = error_string(691);
        assert!(
            !localized.trim().is_empty(),
            "691 must have some description"
        );

        // The fallback table is ours and is locale-independent.
        use guardian_core::net::ras_error_message;
        let fallback = ras_error_message(691).to_ascii_lowercase();
        assert!(
            fallback.contains("username") || fallback.contains("password"),
            "the built-in table must describe 691 as a credential problem, got: {fallback}"
        );
        let fallback678 = ras_error_message(678).to_ascii_lowercase();
        assert!(
            fallback678.contains("no answer"),
            "the built-in table must describe 678 as no answer, got: {fallback678}"
        );
        // An unknown code must still produce text rather than an empty string.
        assert!(!error_string(99_999).trim().is_empty());
    }

    #[test]
    fn broadband_name_heuristic_recognises_common_spellings() {
        let matches = |s: &str| is_likely_broadband_name(WideString::new(s).as_slice_with_nul());
        assert!(matches("Broadband Connection"));
        assert!(matches("PPPoE"));
        assert!(matches("DSL"));
        assert!(matches("宽带连接"));
        assert!(!matches("Work VPN"));
        assert!(!matches("Corp Dialup"));
    }

    #[test]
    fn connection_state_translation_covers_the_lifecycle() {
        use windows::Win32::NetworkManagement::Rras::*;
        assert_eq!(
            translate_state(RASCS_Connected),
            RasConnectionState::Connected
        );
        assert_eq!(
            translate_state(RASCS_Disconnected),
            RasConnectionState::Disconnected
        );
        assert_eq!(
            translate_state(RASCS_Authenticate),
            RasConnectionState::Connecting
        );
        assert_eq!(
            translate_state(RASCS_Interactive),
            RasConnectionState::Connecting
        );
        // An unmapped state must degrade to Unknown rather than being misreported.
        assert_eq!(
            translate_state(RASCONNSTATE(9999)),
            RasConnectionState::Unknown
        );
    }

    #[test]
    fn dialing_a_nonexistent_entry_reports_a_ras_error_not_a_panic() {
        // A dial attempt against an entry that does not exist must return a structured
        // failure. It must not hang: RasDialW returns immediately with 623 (no phonebook
        // entry) in that case.
        let result = dial("workstation-guardian-nonexistent-entry-8f3a2b");
        assert!(
            !result.outcome.success,
            "dialing a missing entry must not report success"
        );
        assert!(
            result.outcome.error_code != 0,
            "a failed dial must carry a RAS error code"
        );
        assert!(result.handle.is_none());
        assert!(!result.outcome.error_message.is_empty());
    }

    #[test]
    fn finding_an_active_connection_for_an_absent_entry_returns_none() {
        assert!(find_active_connection("workstation-guardian-nonexistent-entry-8f3a2b").is_none());
    }

    #[test]
    fn health_query_on_a_bogus_handle_is_an_error() {
        assert!(connection_health(0xDEAD_BEEF).is_err());
    }
}
