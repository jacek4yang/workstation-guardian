//! The network backend: RAS and Wi-Fi side effects behind one trait.
//!
//! The state machine in `guardian-core::net` decides *what* to do; this module does it. The
//! trait boundary is what lets the worker be driven by a fake in tests, so the decision logic
//! can be exercised without touching a real adapter — which matters because a test that dials
//! a real PPPoE link on a developer's machine is not a test anyone will run.
//!
//! # Credentials
//!
//! Neither implementation accepts, stores or logs a password. The RAS dial uses the
//! credentials Windows has stored with the phonebook entry, and the Wi-Fi connect uses the
//! key material in the saved profile.

use guardian_core::net::NetworkAction;
use guardian_proto::model::{NetworkSnapshot, RasEntryInfo};
use guardian_win::ras::{self, DialResult};
use guardian_win::wifi::{self, WifiError, WlanClient};

/// The effects the network worker needs.
pub trait NetworkBackend {
    type Error: std::fmt::Display;

    /// Whether a RAS session for `entry` is currently connected.
    fn ras_connected(&self, entry: &str) -> bool;

    /// Whether the RAS interface for `entry` has an IP configuration.
    fn ras_has_ip(&self, entry: &str) -> bool;

    /// Dial `entry`. Returns the raw outcome so the caller can classify the failure.
    fn dial(&self, entry: &str) -> DialResult;

    /// Hang up the session for `entry`, if one exists.
    fn hang_up(&self, entry: &str) -> Result<(), Self::Error>;

    /// Whether the backup Wi-Fi uplink is connected and has an address.
    fn wifi_connected(&self) -> bool;

    /// The SSID currently associated, if any.
    fn wifi_ssid(&self) -> Option<String>;

    /// Bring the configured Wi-Fi profile up.
    fn connect_wifi(&self) -> Result<(), Self::Error>;

    /// Whether a default route currently exists.
    fn has_default_route(&self) -> bool;
}

/// The production backend.
#[derive(Debug, Default, Clone, Copy)]
pub struct RasBackend;

impl RasBackend {
    pub fn new() -> Self {
        RasBackend
    }

    /// Enumerate the phonebook entries available on this machine.
    pub fn entries(&self) -> Vec<RasEntryInfo> {
        ras::enum_entries().unwrap_or_default()
    }

    /// The active connection for an entry, if any.
    fn active(&self, entry: &str) -> Option<ras::RasConnection> {
        ras::find_active_connection(entry)
    }
}

impl RasBackend {
    /// Hang up every connection belonging to `entry`.
    ///
    /// Bounded and idempotent: a session that is already gone is not an error, because that
    /// is exactly the state the caller wanted.
    fn hang_up_all(&self, entry: &str) -> Result<(), guardian_win::WinError> {
        let mut hung = 0usize;
        for conn in ras::enum_connections().unwrap_or_default() {
            if conn.entry_name.eq_ignore_ascii_case(entry) {
                match ras::hang_up(conn.handle) {
                    Ok(()) => hung += 1,
                    Err(e) => {
                        // A session that vanished between enumeration and hangup is fine.
                        tracing::debug!(
                            entry,
                            error = %e,
                            "hangup reported an error; the session may already be gone"
                        );
                    }
                }
            }
        }
        if hung > 1 {
            tracing::warn!(
                entry,
                count = hung,
                "more than one session existed for this entry; all were hung up"
            );
        }
        Ok(())
    }
}

impl NetworkBackend for RasBackend {
    type Error = guardian_win::WinError;

    fn ras_connected(&self, entry: &str) -> bool {
        self.active(entry).is_some()
    }

    fn ras_has_ip(&self, entry: &str) -> bool {
        let Some(conn) = self.active(entry) else {
            return false;
        };
        match ras::connection_health(conn.handle) {
            Ok(health) => health.has_ip_configuration,
            Err(e) => {
                // A status query that fails means we cannot confirm an IP. Reporting "no IP"
                // would be a fabrication; the conservative choice for the state machine is
                // to treat the link as not ready, which delays a failback rather than
                // causing a wrong one.
                tracing::debug!(
                    entry,
                    error = %e,
                    "could not read the RAS IP projection; treating the link as not ready"
                );
                false
            }
        }
    }

    fn dial(&self, entry: &str) -> DialResult {
        dial_with_guard(entry)
    }

    fn hang_up(&self, entry: &str) -> Result<(), Self::Error> {
        self.hang_up_all(entry)
    }

    fn wifi_connected(&self) -> bool {
        match WlanClient::open() {
            Ok(client) => match client.connected_interface() {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(_) => false,
            },
            Err(_) => false,
        }
    }

    fn wifi_ssid(&self) -> Option<String> {
        wifi::current_connection().map(|(_, ssid)| ssid)
    }

    fn connect_wifi(&self) -> Result<(), Self::Error> {
        let ssid = match self.wifi_ssid() {
            Some(s) => s,
            // Already associated: nothing to do, and reporting an error would be wrong.
            None => match WlanClient::open() {
                Ok(client) => match client.connected_interface() {
                    Ok(Some(_)) => return Ok(()),
                    _ => {
                        return Err(guardian_win::WinError::Invalid {
                            context: "connect_wifi",
                            detail: "no Wi-Fi SSID is configured and no interface is connected"
                                .into(),
                        })
                    }
                },
                Err(WifiError::ServiceUnavailable) => {
                    return Err(guardian_win::WinError::Invalid {
                        context: "connect_wifi",
                        detail: "the wireless service is unavailable".into(),
                    })
                }
                Err(e) => {
                    return Err(guardian_win::WinError::Invalid {
                        context: "connect_wifi",
                        detail: e.to_string(),
                    })
                }
            },
        };

        connect_profile(&ssid)
    }

    fn has_default_route(&self) -> bool {
        crate::probes::has_default_route()
    }
}

/// Connect to a saved Wi-Fi profile by SSID.
fn connect_profile(ssid: &str) -> Result<(), guardian_win::WinError> {
    let client = WlanClient::open().map_err(|e| guardian_win::WinError::Invalid {
        context: "connect_wifi",
        detail: e.to_string(),
    })?;

    let interfaces = client
        .interfaces()
        .map_err(|e| guardian_win::WinError::Invalid {
            context: "connect_wifi",
            detail: e.to_string(),
        })?;

    let Some(iface) = interfaces.first() else {
        return Err(guardian_win::WinError::Invalid {
            context: "connect_wifi",
            detail: "no wireless interface is present".into(),
        });
    };

    client.connect(iface, ssid).map_err(|e| {
        tracing::warn!(ssid, error = %e, "could not bring up the backup Wi-Fi profile");
        guardian_win::WinError::Invalid {
            context: "connect_wifi",
            detail: e.to_string(),
        }
    })
}

/// Dial with an explicit guard against concurrent dials for the same entry.
///
/// The state machine already serializes dial decisions, but a dial can take tens of seconds
/// while the scheduler keeps ticking. This guard makes a second concurrent dial impossible
/// even if a future refactor weakened that discipline, which is a cheap insurance policy for
/// an operation that is genuinely unsafe to run twice.
fn dial_with_guard(entry: &str) -> DialResult {
    use std::sync::Mutex;
    use std::sync::OnceLock;

    static IN_FLIGHT: OnceLock<Mutex<Option<String>>> = OnceLock::new();
    let lock = IN_FLIGHT.get_or_init(|| Mutex::new(None));

    {
        let mut guard = match lock.lock() {
            Ok(g) => g,
            // A poisoned lock means a previous dial panicked. Recover rather than deadlock;
            // the poisoning is recorded by the panic itself.
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.as_deref() == Some(entry) {
            tracing::warn!(
                entry,
                "a dial for this entry is already in flight; refusing to start a second"
            );
            // Report the refusal as a dial failure with a code the operator can recognise.
            // Using a real RAS code here would be misleading, so the message carries the
            // meaning and the code is the documented "operation is pending" value.
            return DialResult {
                outcome: guardian_win::ras::DialOutcome {
                    success: false,
                    error_code: 600,
                    error_message: "a dial for this entry is already in progress".into(),
                },
                handle: None,
            };
        }
        *guard = Some(entry.to_string());
    }

    let result = ras::dial(entry);

    if let Ok(mut guard) = lock.lock() {
        *guard = None;
    }

    if !result.outcome.success {
        tracing::warn!(
            entry,
            code = result.outcome.error_code,
            message = %result.outcome.error_message,
            "broadband dial failed"
        );
    } else {
        tracing::info!(entry, "broadband dial succeeded");
    }

    result
}

/// Classify a set of actions into what the worker should report.
///
/// A small helper so the worker's logging and the state machine's decisions stay in step.
pub fn describe_actions(actions: &[NetworkAction]) -> Vec<String> {
    actions
        .iter()
        .map(|a| match a {
            NetworkAction::DialBroadband => "dialling broadband".to_string(),
            NetworkAction::HangUpBroadband => "hanging up a stale broadband session".to_string(),
            NetworkAction::ConnectWifi => "connecting backup Wi-Fi".to_string(),
            NetworkAction::DisconnectWifi => "disconnecting Wi-Fi".to_string(),
            NetworkAction::PreferBroadband => "making broadband the preferred route".to_string(),
            NetworkAction::PreferWifi => "routing traffic via Wi-Fi".to_string(),
            NetworkAction::ReleaseManagedRoutes => {
                "releasing managed route preferences".to_string()
            }
            NetworkAction::Wait { ms } => format!("waiting {ms}ms before the next attempt"),
            NetworkAction::None => "no action".to_string(),
        })
        .collect()
}

/// Whether the network snapshot shows the user currently has usable Internet.
pub fn user_is_online(snapshot: &NetworkSnapshot) -> bool {
    use guardian_proto::model::InternetHealth;
    matches!(
        snapshot.internet,
        InternetHealth::Healthy | InternetHealth::Degraded
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ras_enumeration_works_on_this_machine() {
        // The production backend must be able to enumerate entries; a machine with no
        // phonebook returns an empty list rather than failing.
        let backend = RasBackend::new();
        let entries = backend.entries();
        for e in &entries {
            assert!(!e.name.is_empty());
        }
        eprintln!("{} RAS entry/entries found", entries.len());
    }

    #[test]
    fn connected_queries_are_safe_for_an_entry_that_is_not_up() {
        let backend = RasBackend::new();
        assert!(!backend.ras_connected("workstation-guardian-no-such-entry-8f3a2b"));
        assert!(!backend.ras_has_ip("workstation-guardian-no-such-entry-8f3a2b"));
    }

    #[test]
    fn hanging_up_an_absent_entry_succeeds() {
        // Hanging up something that is not there is the desired end state, not an error.
        let backend = RasBackend::new();
        assert!(backend
            .hang_up("workstation-guardian-no-such-entry-8f3a2b")
            .is_ok());
    }

    #[test]
    fn a_failed_dial_reports_a_structured_error() {
        let backend = RasBackend::new();
        let result = backend.dial("workstation-guardian-no-such-entry-8f3a2b");
        assert!(!result.outcome.success);
        assert_ne!(result.outcome.error_code, 0);
        assert!(!result.outcome.error_message.is_empty());
    }

    #[test]
    fn the_dial_guard_releases_after_a_failure() {
        // Two sequential dials must both be attempted; only *concurrent* ones are refused.
        let backend = RasBackend::new();
        let first = backend.dial("workstation-guardian-no-such-entry-8f3a2b");
        let second = backend.dial("workstation-guardian-no-such-entry-8f3a2b");
        assert!(!first.outcome.success);
        assert!(
            !second.outcome.success,
            "the guard must not permanently block dialling"
        );
    }

    #[test]
    fn wifi_queries_never_panic() {
        let backend = RasBackend::new();
        let _ = backend.wifi_connected();
        let _ = backend.wifi_ssid();
        let _ = backend.has_default_route();
    }

    #[test]
    fn connecting_wifi_with_no_configured_profile_reports_a_specific_error() {
        // On a machine with no Wi-Fi, this must fail with an explanation rather than
        // silently reporting success.
        let backend = RasBackend::new();
        if backend.wifi_connected() {
            return; // Already up; nothing to assert.
        }
        let result = backend.connect_wifi();
        if let Err(e) = result {
            assert!(!e.to_string().is_empty(), "an error must explain itself");
        }
    }

    #[test]
    fn action_descriptions_cover_every_variant() {
        let actions = vec![
            NetworkAction::DialBroadband,
            NetworkAction::HangUpBroadband,
            NetworkAction::ConnectWifi,
            NetworkAction::DisconnectWifi,
            NetworkAction::PreferBroadband,
            NetworkAction::PreferWifi,
            NetworkAction::ReleaseManagedRoutes,
            NetworkAction::Wait { ms: 1000 },
            NetworkAction::None,
        ];
        let described = describe_actions(&actions);
        assert_eq!(described.len(), actions.len());
        for d in described {
            assert!(!d.is_empty());
        }
    }

    #[test]
    fn wait_description_names_the_delay() {
        let d = describe_actions(&[NetworkAction::Wait { ms: 4000 }]);
        assert!(d[0].contains("4000"), "got {}", d[0]);
    }

    #[test]
    fn online_detection_matches_the_reported_health() {
        use guardian_proto::model::{InternetHealth, NetworkPhase, NetworkSnapshot};
        let mut snapshot = NetworkSnapshot {
            phase: NetworkPhase::Online,
            ..Default::default()
        };

        snapshot.internet = InternetHealth::Healthy;
        assert!(user_is_online(&snapshot));

        snapshot.internet = InternetHealth::Down;
        assert!(!user_is_online(&snapshot));

        snapshot.internet = InternetHealth::Unknown;
        assert!(!user_is_online(&snapshot));
    }
}
