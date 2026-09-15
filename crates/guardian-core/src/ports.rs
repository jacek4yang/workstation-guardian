//! Ports: the abstract effects the pure state machines depend on.
//!
//! Every state machine in this crate is generic over these traits so that the logic can be
//! exercised in unit tests without touching the host — no real registry, no real RAS dial,
//! no real clock, no possibility of rebooting the developer's machine during `cargo test`.
//!
//! The production implementations live in `guardian-win`, `guardian-update`,
//! `guardian-network` and `guardian-service`.

use guardian_proto::model::*;

/// Reads and writes the Windows Update policy surface.
///
/// Implementations must be idempotent: [`UpdatePolicyBackend::apply`] is called on every
/// verification pass, and a correct implementation writes nothing when the values already
/// match. Constant registry traffic is itself a defect, not just an inefficiency.
pub trait UpdatePolicyBackend {
    type Error: std::fmt::Display;

    /// Read the current values of everything Guardian owns, without modifying anything.
    fn read(&self) -> Result<PolicyReadback, Self::Error>;

    /// Write only the values that differ from `desired`, recording what was there before.
    ///
    /// Returns the set of values actually written (empty when already conformant), so the
    /// caller can journal a real change rather than a no-op.
    fn apply(&self, desired: &[PolicyWrite]) -> Result<Vec<PolicyWrite>, Self::Error>;

    /// Restore `original` values verbatim, used by uninstall and by rollback.
    fn restore(&self, original: &[OwnedPolicy]) -> Result<(), Self::Error>;

    /// Determine how this host's update policy is governed.
    fn management_state(&self) -> ManagementState;
}

/// A policy value Guardian intends to own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWrite {
    /// Full registry key path, e.g. `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`.
    pub key_path: String,
    pub value_name: String,
    pub value: PolValue,
}

/// What a read actually found.
#[derive(Debug, Clone, Default)]
pub struct PolicyReadback {
    /// Every value we asked about, whether present or not.
    pub values: Vec<PolicyObservation>,
    /// Key paths that could not be read at all (permissions, missing hive).
    pub unreadable_keys: Vec<String>,
    /// True when the read covered every requested key.
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyObservation {
    pub key_path: String,
    pub value_name: String,
    pub value: Option<PolValue>,
}

/// A policy value as Guardian originally found it, for exact restoration.
///
/// Distinct from [`PolicyWrite`] because `value` is optional: `None` records that the value
/// did not exist before Guardian created it, so restoring means *deleting* it. Collapsing
/// that into `PolicyWrite` would lose the ability to distinguish "restore to absent" from
/// "restore to this value", and uninstall would leave Guardian's values behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedPolicy {
    pub key_path: String,
    pub value_name: String,
    /// The value as it was, or `None` when the value did not exist.
    pub value: Option<PolValue>,
    /// True when Guardian created the key, so uninstall may remove it if it is empty.
    pub created_key: bool,
}

/// Reads pending-reboot signals from the OS.
pub trait PendingRebootSource {
    type Error: std::fmt::Display;

    /// Collect all signals. A partial read must still return the signals it obtained and
    /// mark the rest as failed, so the verdict degrades to `Unknown` rather than `NotPending`.
    fn collect(&self) -> Result<Vec<RebootSignal>, Self::Error>;
}

/// Reads Windows Event Log records, used for unexpected-reboot classification.
pub trait EventLogSource {
    type Error: std::fmt::Display;

    /// Query one channel for events with the given provider/ids in a time window.
    ///
    /// Implementations must bound the number of records returned.
    fn query(&self, channel: &str, query: &EventQuery) -> Result<Vec<EventEvidence>, Self::Error>;
}

#[derive(Debug, Clone)]
pub struct EventQuery {
    /// Provider names to match, empty means any.
    pub providers: Vec<String>,
    /// Event ids to match, empty means any.
    pub event_ids: Vec<u32>,
    /// Window start (Unix ms, inclusive).
    pub since_ms: i64,
    /// Window end (Unix ms, inclusive).
    pub until_ms: i64,
    /// Hard cap on records returned.
    pub max_records: usize,
}

/// Monotonic-ish clock. Injected so state machines are deterministic under test.
pub trait Clock {
    /// Unix milliseconds UTC.
    fn now_ms(&self) -> i64;

    /// Milliseconds since an arbitrary fixed point that does not jump when the system clock
    /// is adjusted. Used for elapsed-time decisions such as backoff and uptime.
    fn monotonic_ms(&self) -> i64;

    /// Milliseconds since the machine booted.
    fn uptime_ms(&self) -> i64;
}

/// Identity of the current boot, used to bind single-use capabilities.
pub trait BootIdentity {
    /// A value that changes on every boot. On Windows this is the boot time, which changes
    /// on every start including a fast-startup resume only in the ways that matter here.
    fn boot_id(&self) -> String;
}

#[cfg(test)]
pub mod fakes {
    //! Test doubles shared by every state-machine test in this crate.
    //!
    //! These live behind `#[cfg(test)]` so production builds carry none of it.

    use super::*;
    use std::cell::RefCell;

    /// A clock the test drives by hand.
    #[derive(Debug, Default)]
    pub struct FakeClock {
        pub now_ms: RefCell<i64>,
        pub monotonic_ms: RefCell<i64>,
        pub uptime_ms: RefCell<i64>,
    }

    impl FakeClock {
        pub fn new(start_ms: i64) -> Self {
            FakeClock {
                now_ms: RefCell::new(start_ms),
                monotonic_ms: RefCell::new(start_ms),
                uptime_ms: RefCell::new(0),
            }
        }

        /// Advance every clock by `ms`.
        pub fn advance(&self, ms: i64) {
            *self.now_ms.borrow_mut() += ms;
            *self.monotonic_ms.borrow_mut() += ms;
            *self.uptime_ms.borrow_mut() += ms;
        }

        /// Move only the wall clock, simulating an NTP correction.
        pub fn skew_wall_clock(&self, ms: i64) {
            *self.now_ms.borrow_mut() += ms;
        }
    }

    impl Clock for FakeClock {
        fn now_ms(&self) -> i64 {
            *self.now_ms.borrow()
        }
        fn monotonic_ms(&self) -> i64 {
            *self.monotonic_ms.borrow()
        }
        fn uptime_ms(&self) -> i64 {
            *self.uptime_ms.borrow()
        }
    }

    #[derive(Debug, Clone)]
    pub struct FakeBootIdentity {
        pub id: RefCell<String>,
    }

    impl FakeBootIdentity {
        pub fn new(id: &str) -> Self {
            FakeBootIdentity {
                id: RefCell::new(id.to_string()),
            }
        }
    }

    impl BootIdentity for FakeBootIdentity {
        fn boot_id(&self) -> String {
            self.id.borrow().clone()
        }
    }

    /// A configurable policy backend. Records every call so tests can assert on
    /// "did we actually avoid writing when values already matched?".
    #[derive(Debug, Default)]
    pub struct FakeUpdateBackend {
        pub store: RefCell<Vec<PolicyObservation>>,
        pub management: RefCell<ManagementState>,
        pub apply_calls: RefCell<u32>,
        pub restore_calls: RefCell<u32>,
        /// When set, every operation fails with this message.
        pub fail_with: RefCell<Option<String>>,
        /// Keys that cannot be read, simulating a locked-down hive.
        pub unreadable: RefCell<Vec<String>>,
    }

    impl FakeUpdateBackend {
        pub fn new() -> Self {
            FakeUpdateBackend {
                management: RefCell::new(ManagementState::Unmanaged),
                ..Default::default()
            }
        }

        /// Seed a value that is already present.
        pub fn set(&self, key: &str, name: &str, value: PolValue) {
            let mut s = self.store.borrow_mut();
            s.retain(|o| !(o.key_path == key && o.value_name == name));
            s.push(PolicyObservation {
                key_path: key.to_string(),
                value_name: name.to_string(),
                value: Some(value),
            });
        }

        pub fn get(&self, key: &str, name: &str) -> Option<PolValue> {
            self.store
                .borrow()
                .iter()
                .find(|o| o.key_path == key && o.value_name == name)
                .and_then(|o| o.value.clone())
        }

        /// Count values currently in the store, for "no writes happened" assertions.
        pub fn len(&self) -> usize {
            self.store.borrow().len()
        }

        pub fn is_empty(&self) -> bool {
            self.store.borrow().is_empty()
        }
    }

    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    pub struct FakeError(pub String);

    impl UpdatePolicyBackend for FakeUpdateBackend {
        type Error = FakeError;

        fn read(&self) -> Result<PolicyReadback, Self::Error> {
            if let Some(msg) = self.fail_with.borrow().as_ref() {
                return Err(FakeError(msg.clone()));
            }
            let unreadable = self.unreadable.borrow().clone();
            if !unreadable.is_empty() {
                return Ok(PolicyReadback {
                    values: self.store.borrow().clone(),
                    unreadable_keys: unreadable,
                    complete: false,
                });
            }
            Ok(PolicyReadback {
                values: self.store.borrow().clone(),
                unreadable_keys: Vec::new(),
                complete: true,
            })
        }

        fn apply(&self, desired: &[PolicyWrite]) -> Result<Vec<PolicyWrite>, Self::Error> {
            *self.apply_calls.borrow_mut() += 1;
            if let Some(msg) = self.fail_with.borrow().as_ref() {
                return Err(FakeError(msg.clone()));
            }
            let mut written = Vec::new();
            let mut store = self.store.borrow_mut();
            for w in desired {
                let existing = store
                    .iter()
                    .find(|o| o.key_path == w.key_path && o.value_name == w.value_name)
                    .and_then(|o| o.value.clone());
                if existing.as_ref() == Some(&w.value) {
                    // Already correct: no write. This is the behaviour the fake exists to
                    // verify, because writing every pass would be a real defect.
                    continue;
                }
                store.retain(|o| !(o.key_path == w.key_path && o.value_name == w.value_name));
                store.push(PolicyObservation {
                    key_path: w.key_path.clone(),
                    value_name: w.value_name.clone(),
                    value: Some(w.value.clone()),
                });
                written.push(w.clone());
            }
            Ok(written)
        }

        fn restore(&self, original: &[OwnedPolicy]) -> Result<(), Self::Error> {
            *self.restore_calls.borrow_mut() += 1;
            if let Some(msg) = self.fail_with.borrow().as_ref() {
                return Err(FakeError(msg.clone()));
            }
            let mut store = self.store.borrow_mut();
            for w in original {
                store.retain(|o| !(o.key_path == w.key_path && o.value_name == w.value_name));
                // `None` means the value did not exist before Guardian created it, so
                // restoring leaves it absent rather than writing an invented default.
                if w.value.is_none() {
                    continue;
                }
                store.push(PolicyObservation {
                    key_path: w.key_path.clone(),
                    value_name: w.value_name.clone(),
                    value: w.value.clone(),
                });
            }
            Ok(())
        }

        fn management_state(&self) -> ManagementState {
            self.management.borrow().clone()
        }
    }

    /// A reboot source the test configures directly.
    #[derive(Debug, Default)]
    pub struct FakePendingReboot {
        pub signals: RefCell<Vec<RebootSignal>>,
        pub fail: RefCell<bool>,
    }

    impl PendingRebootSource for FakePendingReboot {
        type Error = FakeError;

        fn collect(&self) -> Result<Vec<RebootSignal>, Self::Error> {
            if *self.fail.borrow() {
                return Err(FakeError("probe failed".into()));
            }
            Ok(self.signals.borrow().clone())
        }
    }

    /// An event log source returning a canned result.
    #[derive(Debug, Default)]
    pub struct FakeEventLog {
        pub events: RefCell<Vec<EventEvidence>>,
        pub fail: RefCell<bool>,
        pub queries: RefCell<u32>,
    }

    impl EventLogSource for FakeEventLog {
        type Error = FakeError;

        fn query(
            &self,
            _channel: &str,
            _q: &EventQuery,
        ) -> Result<Vec<EventEvidence>, Self::Error> {
            *self.queries.borrow_mut() += 1;
            if *self.fail.borrow() {
                return Err(FakeError("event log unavailable".into()));
            }
            Ok(self.events.borrow().clone())
        }
    }
}
