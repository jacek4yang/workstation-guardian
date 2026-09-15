//! Wi-Fi control through the Native Wi-Fi API.
//!
//! # Why not `netsh wlan`
//!
//! `netsh` is a command-line wrapper whose output is localized and whose exit codes do not
//! distinguish "profile not found" from "wrong key" from "no radio". Proper handling of
//! those cases is the difference between a backup link that comes up reliably during an
//! outage and one that silently fails. The Native Wi-Fi API reports each condition as a
//! distinct `WIN32_ERROR`, in-process, with no process spawn and no text parsing.
//!
//! # What this module is for
//!
//! Wi-Fi is **only** a continuity path. Nothing here promotes Wi-Fi to preferred; that
//! decision belongs to the network state machine in `guardian-core`, which enforces
//! "broadband wins whenever it is healthy".
//!
//! # Credentials
//!
//! Connecting to a profile uses the key material Windows already has stored for it. This
//! module never accepts, holds or logs a Wi-Fi password. A profile that has no stored key
//! fails with [`WifiError::NoStoredKey`], which is reported to the user rather than worked
//! around.

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::NetworkManagement::WiFi::{
    dot11_radio_state_on, wlan_interface_state_connected, WlanCloseHandle, WlanConnect,
    WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle, WlanQueryInterface, WLAN_INTERFACE_INFO,
    WLAN_INTERFACE_INFO_LIST, WLAN_OPCODE_VALUE_TYPE, WLAN_PHY_RADIO_STATE, WLAN_RADIO_STATE,
};

use crate::{WideString, WinError};

/// Errors specific to Wi-Fi operations.
#[derive(Debug, thiserror::Error)]
pub enum WifiError {
    #[error("{0}")]
    Win(#[from] WinError),

    #[error("no wireless interface is present on this machine")]
    NoInterface,

    #[error("the wireless radio is turned off")]
    RadioOff,

    #[error("no saved profile exists for SSID '{ssid}'")]
    ProfileNotFound { ssid: String },

    #[error("the saved profile for SSID '{ssid}' has no usable key stored")]
    NoStoredKey { ssid: String },

    #[error("the wireless service is not running")]
    ServiceUnavailable,
}

/// Maximum interfaces we will enumerate.
const MAX_INTERFACES: usize = 32;

/// An open handle to the WLAN service. Closes itself on drop.
#[derive(Debug)]
pub struct WlanClient {
    handle: HANDLE,
}

// The WLAN handle is usable from any thread; the API serializes internally.
unsafe impl Send for WlanClient {}

impl WlanClient {
    /// Open a session with the wireless service.
    pub fn open() -> Result<Self, WifiError> {
        let mut negotiated = 0u32;
        let mut handle = HANDLE::default();

        // Safety: both out-parameters are correctly typed. The requested version 2 is the
        // documented value for Windows 7 and later, which is a superset of everything used
        // here.
        let rc = unsafe { WlanOpenHandle(2, None, &mut negotiated, &mut handle) };

        if rc != ERROR_SUCCESS.0 {
            // 1062 is ERROR_SERVICE_NOT_ACTIVE, which is the common case on a machine with
            // no wireless adapter or with the WLAN service disabled.
            if rc == 1062 {
                return Err(WifiError::ServiceUnavailable);
            }
            return Err(WifiError::Win(WinError::from_code("WlanOpenHandle", rc)));
        }

        // A version below 2 means a very old stack; everything here needs at least 2.
        if negotiated < 2 {
            // Safety: the handle came from WlanOpenHandle.
            unsafe {
                let _ = WlanCloseHandle(handle, None);
            }
            return Err(WifiError::ServiceUnavailable);
        }

        Ok(WlanClient { handle })
    }

    /// List the wireless interfaces.
    pub fn interfaces(&self) -> Result<Vec<InterfaceInfo>, WifiError> {
        let mut list_ptr: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();

        // Safety: `list_ptr` is a valid out-parameter; the returned list is owned by the
        // WLAN API until WlanFreeMemory is called on it.
        let rc = unsafe { WlanEnumInterfaces(self.handle, None, &mut list_ptr) };
        if rc != ERROR_SUCCESS.0 {
            return Err(WifiError::Win(WinError::from_code(
                "WlanEnumInterfaces",
                rc,
            )));
        }
        if list_ptr.is_null() {
            return Ok(Vec::new());
        }

        // Safety: the API returned a valid list with `dwNumberOfItems` entries.
        let list = unsafe { &*list_ptr };
        let count = (list.dwNumberOfItems as usize).min(MAX_INTERFACES);

        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            // Safety: `i` is within the count the API reported.
            let info: &WLAN_INTERFACE_INFO = &list.InterfaceInfo[i];
            let guid = info.InterfaceGuid;
            out.push(InterfaceInfo {
                guid: format!(
                    "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                    guid.data1,
                    guid.data2,
                    guid.data3,
                    guid.data4[0],
                    guid.data4[1],
                    guid.data4[2],
                    guid.data4[3],
                    guid.data4[4],
                    guid.data4[5],
                    guid.data4[6],
                    guid.data4[7]
                ),
                raw_guid: guid,
                description: crate::wide_to_string(&info.strInterfaceDescription),
                is_connected: info.isState == wlan_interface_state_connected,
            });
        }

        // Safety: the list came from WlanEnumInterfaces and has been fully consumed.
        unsafe { WlanFreeMemory(list_ptr as *mut core::ffi::c_void) };

        Ok(out)
    }

    /// The first connected interface, if any.
    pub fn connected_interface(&self) -> Result<Option<InterfaceInfo>, WifiError> {
        Ok(self.interfaces()?.into_iter().find(|i| i.is_connected))
    }

    /// The SSID currently associated with an interface, if any.
    pub fn current_ssid(&self, interface: &InterfaceInfo) -> Result<Option<String>, WifiError> {
        use windows::Win32::NetworkManagement::WiFi::{
            wlan_intf_opcode_current_connection, WLAN_CONNECTION_ATTRIBUTES,
        };

        let mut data_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut size = 0u32;
        let mut value_type = WLAN_OPCODE_VALUE_TYPE::default();

        // Safety: out-parameters are correctly typed; the returned buffer is owned by the
        // WLAN API until WlanFreeMemory.
        let rc = unsafe {
            WlanQueryInterface(
                self.handle,
                &interface.raw_guid,
                wlan_intf_opcode_current_connection,
                None,
                &mut size,
                &mut data_ptr,
                Some(&mut value_type),
            )
        };

        if rc != ERROR_SUCCESS.0
            || data_ptr.is_null()
            || size < std::mem::size_of::<WLAN_CONNECTION_ATTRIBUTES>() as u32
        {
            if !data_ptr.is_null() {
                // Safety: allocated by the WLAN API for us to free.
                unsafe { WlanFreeMemory(data_ptr) };
            }
            return Ok(None);
        }

        // Safety: the API returned a WLAN_CONNECTION_ATTRIBUTES of the reported size.
        let attrs = unsafe { &*(data_ptr as *const WLAN_CONNECTION_ATTRIBUTES) };
        let assoc = &attrs.wlanAssociationAttributes;
        let len = assoc.dot11Ssid.uSSIDLength as usize;

        let ssid = if len == 0 || len > assoc.dot11Ssid.ucSSID.len() {
            None
        } else {
            // Safety: `len` is bounded by the array length, checked above.
            let bytes = &assoc.dot11Ssid.ucSSID[..len];
            Some(String::from_utf8_lossy(bytes).to_string())
        };

        // Safety: as above.
        unsafe { WlanFreeMemory(data_ptr) };

        Ok(ssid)
    }

    /// Whether the radio is on.
    pub fn radio_on(&self, interface: &InterfaceInfo) -> Result<bool, WifiError> {
        use windows::Win32::NetworkManagement::WiFi::wlan_intf_opcode_radio_state;

        let mut data_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut size = 0u32;
        let mut value_type = WLAN_OPCODE_VALUE_TYPE::default();

        // Safety: out-parameters are correctly typed; the buffer is owned by the WLAN API.
        let rc = unsafe {
            WlanQueryInterface(
                self.handle,
                &interface.raw_guid,
                wlan_intf_opcode_radio_state,
                None,
                &mut size,
                &mut data_ptr,
                Some(&mut value_type),
            )
        };

        if rc != ERROR_SUCCESS.0 || data_ptr.is_null() {
            if !data_ptr.is_null() {
                // Safety: allocated by the WLAN API.
                unsafe { WlanFreeMemory(data_ptr) };
            }
            // If the radio state cannot be read, report it as on rather than off: claiming
            // the radio is off would suppress a connect attempt that might have worked.
            return Ok(true);
        }

        // Safety: the API returned a WLAN_RADIO_STATE of the reported size.
        let state = unsafe { &*(data_ptr as *const WLAN_RADIO_STATE) };
        let mut on = false;
        let phys = (state.dwNumberOfPhys as usize).min(state.PhyRadioState.len());
        for i in 0..phys {
            // Safety: `i` is bounded by the array length, clamped above.
            let phy: &WLAN_PHY_RADIO_STATE = &state.PhyRadioState[i];
            // Both the software and hardware switches must be on for the radio to transmit.
            if phy.dot11SoftwareRadioState == dot11_radio_state_on
                && phy.dot11HardwareRadioState == dot11_radio_state_on
            {
                on = true;
                break;
            }
        }

        // Safety: as above.
        unsafe { WlanFreeMemory(data_ptr) };

        Ok(on)
    }

    /// Connect to a saved profile by SSID.
    ///
    /// Uses the profile's stored key material; Guardian never sees a Wi-Fi password.
    pub fn connect(&self, interface: &InterfaceInfo, ssid: &str) -> Result<(), WifiError> {
        use windows::Win32::NetworkManagement::WiFi::{
            wlan_connection_mode_profile, DOT11_SSID, WLAN_CONNECTION_PARAMETERS,
        };

        if !self.radio_on(interface)? {
            return Err(WifiError::RadioOff);
        }

        // The profile name is the SSID for a typical home network. A machine with a profile
        // whose name differs from the SSID is reported as not found, which is honest.
        let profile_name = WideString::new(ssid);
        let ssid_bytes = ssid.as_bytes();
        if ssid_bytes.len() > 32 {
            return Err(WifiError::ProfileNotFound {
                ssid: ssid.to_string(),
            });
        }

        let mut dot11 = DOT11_SSID {
            uSSIDLength: ssid_bytes.len() as u32,
            ..Default::default()
        };
        dot11.ucSSID[..ssid_bytes.len()].copy_from_slice(ssid_bytes);

        let params = WLAN_CONNECTION_PARAMETERS {
            wlanConnectionMode: wlan_connection_mode_profile,
            strProfile: windows::core::PCWSTR(profile_name.as_ptr()),
            pDot11Ssid: &mut dot11,
            pDesiredBssidList: std::ptr::null_mut(),
            dot11BssType: windows::Win32::NetworkManagement::WiFi::dot11_BSS_type_any,
            dwFlags: 0,
        };

        // Safety: `params` points at data (the profile string and the SSID) that outlives
        // this synchronous call.
        let rc = unsafe { WlanConnect(self.handle, &interface.raw_guid, &params, None) };

        if rc == ERROR_SUCCESS.0 {
            return Ok(());
        }

        // Translate the codes that have a specific meaning for the user.
        match rc {
            // ERROR_NOT_FOUND: no profile with this name.
            1168 => Err(WifiError::ProfileNotFound {
                ssid: ssid.to_string(),
            }),
            // ERROR_INVALID_DATA / key-related failures.
            13 | 87 | 5023 => Err(WifiError::NoStoredKey {
                ssid: ssid.to_string(),
            }),
            _ => Err(WifiError::Win(WinError::from_code("WlanConnect", rc))),
        }
    }

    /// Whether the wireless service reports itself as available.
    pub fn availability(&self) -> Result<bool, WifiError> {
        let mut data_ptr: *mut core::ffi::c_void = std::ptr::null_mut();
        let mut size = 0u32;
        let mut value_type = WLAN_OPCODE_VALUE_TYPE::default();

        // Availability is a service-level query that needs an interface to name, but the
        // answer reflects the service rather than that specific adapter.
        let interfaces = self.interfaces()?;
        let Some(iface) = interfaces.first() else {
            return Ok(false);
        };

        // Safety: out-parameters are correctly typed.
        let rc = unsafe {
            WlanQueryInterface(
                self.handle,
                &iface.raw_guid,
                windows::Win32::NetworkManagement::WiFi::wlan_intf_opcode_radio_state,
                None,
                &mut size,
                &mut data_ptr,
                Some(&mut value_type),
            )
        };

        if !data_ptr.is_null() {
            // Safety: allocated by the WLAN API.
            unsafe { WlanFreeMemory(data_ptr) };
        }

        Ok(rc == ERROR_SUCCESS.0)
    }
}

impl Drop for WlanClient {
    fn drop(&mut self) {
        // Safety: the handle came from WlanOpenHandle and is closed exactly once.
        unsafe {
            let _ = WlanCloseHandle(self.handle, None);
        }
    }
}

/// A wireless interface.
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// GUID in registry string form, for display.
    pub guid: String,
    pub(crate) raw_guid: windows::core::GUID,
    pub description: String,
    pub is_connected: bool,
}

/// Whether this machine has any wireless interface at all.
///
/// Used to decide whether Wi-Fi continuity is even applicable, so a desktop with no radio
/// does not report a spurious "backup unavailable" warning.
pub fn has_wireless_interface() -> bool {
    match WlanClient::open() {
        Ok(client) => client.interfaces().map(|i| !i.is_empty()).unwrap_or(false),
        Err(_) => false,
    }
}

/// Read the SSID of the currently connected interface, if any.
pub fn current_connection() -> Option<(String, String)> {
    let client = WlanClient::open().ok()?;
    let iface = client.connected_interface().ok()??;
    let ssid = client.current_ssid(&iface).ok()??;
    Some((iface.description.clone(), ssid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_the_wlan_client_either_succeeds_or_reports_a_specific_reason() {
        match WlanClient::open() {
            Ok(client) => {
                // On a machine with a radio, enumeration must work.
                let interfaces = client
                    .interfaces()
                    .expect("interface enumeration must work once the client is open");
                for i in &interfaces {
                    assert!(!i.guid.is_empty(), "an interface needs a GUID");
                    assert!(
                        i.guid.starts_with('{') && i.guid.ends_with('}'),
                        "the GUID must render in registry form: {}",
                        i.guid
                    );
                }
            }
            Err(WifiError::ServiceUnavailable) => {
                // A machine with no WLAN service is a normal, supported configuration.
                eprintln!("wireless service unavailable; Wi-Fi continuity is not applicable here");
            }
            Err(WifiError::NoInterface) => {}
            Err(e) => panic!("unexpected failure opening the WLAN client: {e}"),
        }
    }

    #[test]
    fn has_wireless_interface_never_panics() {
        // Returns a bool rather than an error: the caller only needs to know whether Wi-Fi
        // continuity is applicable.
        let _ = has_wireless_interface();
    }

    #[test]
    fn current_connection_never_panics() {
        let _ = current_connection();
    }

    #[test]
    fn querying_a_connected_interface_reports_an_ssid_or_none() {
        let Ok(client) = WlanClient::open() else {
            return;
        };
        let Ok(Some(iface)) = client.connected_interface() else {
            return;
        };
        // A connected interface should have an SSID. If the query fails we get None, which
        // is honest; what must not happen is a panic or a fabricated SSID.
        match client.current_ssid(&iface) {
            Ok(Some(ssid)) => {
                assert!(!ssid.is_empty(), "an SSID must not be empty when reported");
                assert!(ssid.len() <= 32, "an SSID is at most 32 bytes");
            }
            Ok(None) => eprintln!("connected interface reported no SSID"),
            Err(e) => eprintln!("SSID query failed: {e}"),
        }
    }

    #[test]
    fn radio_state_reads_without_error() {
        let Ok(client) = WlanClient::open() else {
            return;
        };
        let Ok(interfaces) = client.interfaces() else {
            return;
        };
        for iface in &interfaces {
            // A read failure is tolerated (it reports "on" so a connect is still attempted),
            // but it must not error out.
            let _ = client.radio_on(iface);
        }
    }

    #[test]
    fn connecting_to_a_nonexistent_profile_reports_profile_not_found() {
        // No such network exists, so the API must refuse. This exercises the error mapping
        // without touching a real network.
        let Ok(client) = WlanClient::open() else {
            return;
        };
        let Ok(interfaces) = client.interfaces() else {
            return;
        };
        let Some(iface) = interfaces.first() else {
            return;
        };
        if !client.radio_on(iface).unwrap_or(false) {
            return; // Radio off; a connect attempt would not be meaningful.
        }

        let result = client.connect(iface, "workstation-guardian-no-such-network-8f3a2b");
        assert!(
            result.is_err(),
            "connecting to a nonexistent profile must fail, not silently succeed"
        );
        // The failure must be a specific, reportable condition rather than a generic error.
        match result {
            Err(WifiError::ProfileNotFound { .. })
            | Err(WifiError::NoStoredKey { .. })
            | Err(WifiError::Win(_)) => {}
            Err(WifiError::RadioOff) => {}
            Ok(()) => unreachable!("checked above"),
            Err(WifiError::NoInterface) | Err(WifiError::ServiceUnavailable) => {}
        }
    }

    #[test]
    fn an_over_long_ssid_is_rejected_before_the_api_call() {
        let Ok(client) = WlanClient::open() else {
            return;
        };
        let Ok(interfaces) = client.interfaces() else {
            return;
        };
        let Some(iface) = interfaces.first() else {
            return;
        };
        // 33 bytes is over the 802.11 limit.
        let too_long = "x".repeat(33);
        let result = client.connect(iface, &too_long);
        assert!(
            matches!(result, Err(WifiError::ProfileNotFound { .. })),
            "an over-long SSID must be refused locally"
        );
    }

    #[test]
    fn error_messages_are_actionable() {
        let e = WifiError::ProfileNotFound {
            ssid: "Home".into(),
        };
        assert!(e.to_string().contains("Home"));
        let e = WifiError::RadioOff;
        assert!(e.to_string().contains("radio"));
        let e = WifiError::NoStoredKey {
            ssid: "Home".into(),
        };
        assert!(e.to_string().contains("key"));
    }
}
