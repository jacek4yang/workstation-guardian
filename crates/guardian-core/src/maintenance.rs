//! Maintenance mode and the single-use reboot authorization.
//!
//! # State machine
//!
//! ```text
//! LOCKED
//!   | explicit user authorization
//!   v
//! MAINTENANCE
//!   | updates may be manually started
//!   v
//! UPDATE_PENDING
//!   | user explicitly chooses "Allow One Reboot"
//!   v
//! REBOOT_ARMED
//!   | one manual reboot
//!   v
//! BOOT
//!   v
//! LOCKED
//! ```
//!
//! `LOCKED` is the only state in which updates are locked by policy, and every path leads
//! back to it. A plain reboot never moves the machine out of `LOCKED`; only an explicit
//! `EnterMaintenance` call does.
//!
//! # Why the reboot permit is a capability rather than a flag
//!
//! A boolean "allow one reboot" is impossible to make single-use across a crash: the flag
//! would have to be cleared by the process that is being terminated. A capability with a
//! nonce, an expiry and a boot binding is consumed exactly once and cannot be replayed,
//! because the boot id it was issued for no longer exists afterwards.

use guardian_proto::model::*;
use serde::Serialize;

use crate::ports::{Clock, PendingRebootSource};

/// Maintenance state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenancePhase {
    /// Updates are locked. The default and the safe state.
    Locked,
    /// The user unlocked updates. No reboot is authorized yet.
    Maintenance,
    /// An update has been observed as staged and awaiting a restart.
    UpdatePending,
    /// A single-use reboot capability is live.
    RebootArmed,
    /// A reboot was performed under an authorization; waiting to confirm the new boot.
    Boot,
}

impl MaintenancePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            MaintenancePhase::Locked => "LOCKED",
            MaintenancePhase::Maintenance => "MAINTENANCE",
            MaintenancePhase::UpdatePending => "UPDATE_PENDING",
            MaintenancePhase::RebootArmed => "REBOOT_ARMED",
            MaintenancePhase::Boot => "BOOT",
        }
    }

    /// Whether Windows Update policy is currently released.
    pub fn updates_unlocked(self) -> bool {
        !matches!(self, MaintenancePhase::Locked)
    }
}

/// Events that drive the maintenance machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaintenanceEvent {
    /// The user asked to enter maintenance.
    EnterRequested {
        /// Whether protected work exists, which normally refuses the request.
        protected_work: Vec<String>,
        /// The user supplied the override phrase.
        override_phrase_provided: Option<String>,
    },
    /// The user asked to leave maintenance without rebooting.
    ExitRequested,
    /// Windows Update has staged something and wants a restart.
    UpdatePendingObserved,
    /// The user asked to authorize exactly one reboot.
    ArmRebootRequested { ttl_secs: u64, issued_by: String },
    /// The user revoked an armed reboot.
    DisarmRequested,
    /// A shutdown or restart has been observed by the service.
    ShutdownObserved { restart: bool },
    /// The service has started and determined the boot identity.
    Booted {
        boot_id: String,
        pending_reboot: PendingRebootVerdict,
    },
    /// The authorization's lifetime elapsed.
    Tick,
    /// The configured reboot-permit TTL changed.
    TtlChanged { ttl_secs: u64 },
}

/// Why a transition was refused, with text suitable for the UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// Protected work is live and no valid override was supplied.
    ProtectedWorkActive { reasons: Vec<String> },
    /// The override phrase did not match the configured phrase.
    BadOverridePhrase,
    /// The request made no sense in the current phase.
    WrongPhase {
        current: MaintenancePhase,
        event: &'static str,
    },
    /// No authorization is live.
    NoActiveAuthorization,
}

impl Refusal {
    pub fn message(&self) -> String {
        match self {
            Refusal::ProtectedWorkActive { reasons } => format!(
                "maintenance refused: {} protected workload(s) are still running: {}",
                reasons.len(),
                reasons.join("; ")
            ),
            Refusal::BadOverridePhrase => {
                "the confirmation phrase did not match; refusing to unlock updates".into()
            }
            Refusal::WrongPhase { current, event } => {
                format!("{event} is not valid in phase {}", current.as_str())
            }
            Refusal::NoActiveAuthorization => "no reboot authorization is currently armed".into(),
        }
    }
}

/// The persisted maintenance state.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct MaintenanceState {
    pub phase: MaintenancePhase,
    /// Empty in `Locked`; non-empty only while a reboot was explicitly authorized.
    pub authorization: Option<RebootAuthorization>,
    /// Reasons maintenance was last entered, kept for display.
    pub entered_at_ms: Option<i64>,
    pub entered_by: Option<String>,
    /// True when the user overrode an active-work refusal; shown prominently in the UI.
    pub entered_with_override: bool,
}

impl Default for MaintenanceState {
    fn default() -> Self {
        MaintenanceState {
            phase: MaintenancePhase::Locked,
            authorization: None,
            entered_at_ms: None,
            entered_by: None,
            entered_with_override: false,
        }
    }
}

/// Outcome of feeding an event to the machine.
#[derive(Debug, Clone)]
pub struct Transition {
    pub state: MaintenanceState,
    /// `Some` when the machine was refused and did not change.
    pub refusal: Option<Refusal>,
    /// Set when an authorization was consumed by this transition.
    pub consumed_authorization: Option<RebootAuthorization>,
    /// Set when an authorization expired during this transition.
    pub expired_authorization: Option<RebootAuthorization>,
    /// Human-readable note for the journal.
    pub note: String,
}

impl Transition {
    fn refused(state: &MaintenanceState, refusal: Refusal) -> Self {
        Transition {
            state: state.clone(),
            refusal: Some(refusal),
            consumed_authorization: None,
            expired_authorization: None,
            note: String::new(),
        }
    }
}

/// Configuration the machine needs, injected rather than read from a global.
#[derive(Debug, Clone)]
pub struct MaintenancePolicy {
    pub reboot_token_ttl_secs: u64,
    pub refuse_with_protected_work: bool,
    pub override_phrase: String,
}

impl Default for MaintenancePolicy {
    fn default() -> Self {
        MaintenancePolicy {
            reboot_token_ttl_secs: MaintenanceConfig::default().reboot_token_ttl_secs,
            refuse_with_protected_work: true,
            override_phrase: MaintenanceConfig::default().override_phrase,
        }
    }
}

/// Minimum permitted TTL. Anything shorter would expire between arming and the user
/// reaching the reboot button; anything much longer increases the window in which a
/// forgotten permit could authorize a reboot the user no longer intends.
pub const MIN_TTL_SECS: u64 = 60;
/// Maximum permitted TTL: 4 hours.
pub const MAX_TTL_SECS: u64 = 4 * 60 * 60;

/// Feed an event into the state machine.
///
/// Pure: no I/O, no clock reads. The caller supplies `now_ms` and `boot_id`, which makes
/// every branch directly testable, including the ones that would otherwise require
/// rebooting a real machine to exercise.
pub fn advance(
    state: &MaintenanceState,
    event: &MaintenanceEvent,
    policy: &MaintenancePolicy,
    now_ms: i64,
    boot_id: &str,
    nonce: &str,
) -> Transition {
    match event {
        MaintenanceEvent::EnterRequested {
            protected_work,
            override_phrase_provided,
        } => {
            if state.phase != MaintenancePhase::Locked {
                return Transition::refused(
                    state,
                    Refusal::WrongPhase {
                        current: state.phase,
                        event: "enter_maintenance",
                    },
                );
            }

            let has_work = !protected_work.is_empty();
            let mut overrode = false;

            if has_work && policy.refuse_with_protected_work {
                match override_phrase_provided {
                    Some(phrase) if phrase.trim() == policy.override_phrase.trim() => {
                        overrode = true;
                    }
                    _ => {
                        return Transition::refused(
                            state,
                            Refusal::ProtectedWorkActive {
                                reasons: protected_work.clone(),
                            },
                        );
                    }
                }
            }

            Transition {
                state: MaintenanceState {
                    phase: MaintenancePhase::Maintenance,
                    authorization: None,
                    entered_at_ms: Some(now_ms),
                    entered_by: None,
                    entered_with_override: overrode,
                },
                refusal: None,
                consumed_authorization: None,
                expired_authorization: None,
                note: if overrode {
                    "entered MAINTENANCE over active protected work".into()
                } else {
                    "entered MAINTENANCE".into()
                },
            }
        }

        MaintenanceEvent::ExitRequested => {
            if state.phase == MaintenancePhase::Locked {
                return Transition::refused(
                    state,
                    Refusal::WrongPhase {
                        current: state.phase,
                        event: "exit_maintenance",
                    },
                );
            }
            let had_auth = state.authorization.is_some();
            Transition {
                state: MaintenanceState::default(),
                refusal: None,
                consumed_authorization: None,
                expired_authorization: None,
                note: if had_auth {
                    "exited MAINTENANCE and discarded an armed reboot authorization".into()
                } else {
                    "exited MAINTENANCE; update protection reapplied".into()
                },
            }
        }

        MaintenanceEvent::UpdatePendingObserved => {
            if state.phase != MaintenancePhase::Maintenance {
                // Only meaningful from MAINTENANCE; elsewhere it is noise, not an error.
                return Transition {
                    state: state.clone(),
                    refusal: None,
                    consumed_authorization: None,
                    expired_authorization: None,
                    note: String::new(),
                };
            }
            Transition {
                state: MaintenanceState {
                    phase: MaintenancePhase::UpdatePending,
                    ..state.clone()
                },
                refusal: None,
                consumed_authorization: None,
                expired_authorization: None,
                note: "an update is staged and awaiting a restart".into(),
            }
        }

        MaintenanceEvent::ArmRebootRequested {
            ttl_secs,
            issued_by,
        } => {
            if state.phase == MaintenancePhase::Locked {
                return Transition::refused(
                    state,
                    Refusal::WrongPhase {
                        current: state.phase,
                        event: "arm_single_reboot",
                    },
                );
            }
            if state.authorization.is_some() {
                // Re-arming replaces the existing capability. Replacing is safe (the old
                // one ceases to be live), but the caller should know it happened.
                let ttl = clamp_ttl(*ttl_secs);
                let auth = RebootAuthorization {
                    id: uuid_like(nonce, "reboot"),
                    nonce: nonce.to_string(),
                    issued_at_ms: now_ms,
                    expires_at_ms: now_ms.saturating_add((ttl * 1000) as i64),
                    issued_boot_id: boot_id.to_string(),
                    consumed_at_ms: None,
                    consumed_by_boot_id: None,
                    reason: "maintenance-authorized single reboot".into(),
                    issued_by: issued_by.clone(),
                };
                let auth = auth.clone();
                return Transition {
                    state: MaintenanceState {
                        phase: MaintenancePhase::RebootArmed,
                        authorization: Some(auth),
                        ..state.clone()
                    },
                    refusal: None,
                    consumed_authorization: None,
                    expired_authorization: None,
                    note: format!(
                        "re-armed reboot authorization, replacing the previous one (ttl {}s)",
                        clamp_ttl(*ttl_secs)
                    ),
                };
            }

            let ttl = clamp_ttl(*ttl_secs);
            let auth = RebootAuthorization {
                id: uuid_like(nonce, "reboot"),
                nonce: nonce.to_string(),
                issued_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add((ttl * 1000) as i64),
                issued_boot_id: boot_id.to_string(),
                consumed_at_ms: None,
                consumed_by_boot_id: None,
                reason: "maintenance-authorized single reboot".into(),
                issued_by: issued_by.clone(),
            };

            Transition {
                state: MaintenanceState {
                    phase: MaintenancePhase::RebootArmed,
                    authorization: Some(auth),
                    ..state.clone()
                },
                refusal: None,
                consumed_authorization: None,
                expired_authorization: None,
                note: format!("armed a single-use reboot authorization (ttl {ttl}s)"),
            }
        }

        MaintenanceEvent::DisarmRequested => {
            if state.authorization.is_none() {
                return Transition::refused(state, Refusal::NoActiveAuthorization);
            }
            Transition {
                state: MaintenanceState {
                    phase: MaintenancePhase::Maintenance,
                    authorization: None,
                    ..state.clone()
                },
                refusal: None,
                consumed_authorization: None,
                expired_authorization: None,
                note: "reboot authorization revoked by user".into(),
            }
        }

        MaintenanceEvent::ShutdownObserved { restart } => {
            // A shutdown consumes a live authorization, if any, and is only "authorized"
            // when one was actually live at that moment.
            let authorized = state
                .authorization
                .as_ref()
                .map(|a| a.is_usable(now_ms, boot_id))
                .unwrap_or(false);

            if !restart {
                // A plain shutdown ends the session. It must not leave anything armed.
                return Transition {
                    state: MaintenanceState {
                        phase: MaintenancePhase::Locked,
                        authorization: None,
                        ..state.clone()
                    },
                    refusal: None,
                    consumed_authorization: None,
                    expired_authorization: state.authorization.clone(),
                    note: format!(
                        "shutdown observed (authorized={authorized}); reboot authorization cleared"
                    ),
                };
            }

            if authorized {
                let mut auth = state.authorization.clone().expect("checked above");
                auth.consumed_at_ms = Some(now_ms);
                Transition {
                    state: MaintenanceState {
                        phase: MaintenancePhase::Boot,
                        authorization: Some(auth.clone()),
                        ..state.clone()
                    },
                    refusal: None,
                    consumed_authorization: Some(auth),
                    expired_authorization: None,
                    note: "restart observed under a valid single-use authorization".into(),
                }
            } else {
                Transition {
                    state: MaintenanceState {
                        phase: MaintenancePhase::Boot,
                        authorization: None,
                        ..state.clone()
                    },
                    refusal: None,
                    consumed_authorization: None,
                    expired_authorization: state.authorization.clone(),
                    note: "restart observed without a valid authorization".into(),
                }
            }
        }

        MaintenanceEvent::Booted {
            boot_id: new_boot,
            pending_reboot,
        } => {
            // Whatever happened before, the machine is now LOCKED. A capability issued for
            // a previous boot cannot survive: the boot it was bound to is gone.
            let stale = state
                .authorization
                .clone()
                .filter(|a| a.issued_boot_id != *new_boot || a.consumed_at_ms.is_some());

            let note = match pending_reboot {
                PendingRebootVerdict::Pending => {
                    "booted with a reboot still pending; updates remain LOCKED".to_string()
                }
                PendingRebootVerdict::ProbablyPending => {
                    "booted with a reboot probably pending; updates remain LOCKED".to_string()
                }
                _ => "booted; update protection LOCKED".to_string(),
            };

            Transition {
                state: MaintenanceState {
                    phase: MaintenancePhase::Locked,
                    authorization: None,
                    entered_at_ms: None,
                    entered_by: None,
                    entered_with_override: false,
                },
                refusal: None,
                consumed_authorization: None,
                expired_authorization: stale,
                note,
            }
        }

        MaintenanceEvent::Tick => {
            let Some(auth) = state.authorization.as_ref() else {
                return Transition {
                    state: state.clone(),
                    refusal: None,
                    consumed_authorization: None,
                    expired_authorization: None,
                    note: String::new(),
                };
            };

            // Principal defect guard: a permit for a boot that is no longer current, or one
            // already consumed, must never remain armed.
            let boot_changed = auth.issued_boot_id != boot_id;
            let expired = auth.is_expired(now_ms);
            let consumed = auth.consumed_at_ms.is_some();

            if boot_changed || expired || consumed {
                let reason = if boot_changed {
                    "reboot authorization invalidated: boot identity changed"
                } else if expired {
                    "reboot authorization expired unused"
                } else {
                    "reboot authorization already consumed"
                };
                return Transition {
                    state: MaintenanceState {
                        phase: MaintenancePhase::Maintenance,
                        authorization: None,
                        ..state.clone()
                    },
                    refusal: None,
                    consumed_authorization: None,
                    expired_authorization: Some(auth.clone()),
                    note: reason.to_string(),
                };
            }

            Transition {
                state: state.clone(),
                refusal: None,
                consumed_authorization: None,
                expired_authorization: None,
                note: String::new(),
            }
        }

        MaintenanceEvent::TtlChanged { ttl_secs } => {
            let Some(auth) = state.authorization.clone() else {
                return Transition {
                    state: state.clone(),
                    refusal: None,
                    consumed_authorization: None,
                    expired_authorization: None,
                    note: String::new(),
                };
            };
            let ttl = clamp_ttl(*ttl_secs);
            let new_expiry = auth.issued_at_ms.saturating_add((ttl * 1000) as i64);
            // Only ever shorten or extend within the permitted window; never revive an
            // already-expired permit into the future beyond the new TTL from *issue*.
            let updated = RebootAuthorization {
                expires_at_ms: new_expiry,
                ..auth
            };
            Transition {
                state: MaintenanceState {
                    authorization: Some(updated),
                    ..state.clone()
                },
                refusal: None,
                consumed_authorization: None,
                expired_authorization: None,
                note: format!("reboot authorization lifetime set to {ttl}s"),
            }
        }
    }
}

fn clamp_ttl(secs: u64) -> u64 {
    secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS)
}

/// Deterministic-enough id derived from the nonce and a label.
///
/// The service supplies a fresh random nonce per arming, so this is unique without
/// pulling in a UUID dependency for a value that is never used as a secret.
fn uuid_like(nonce: &str, label: &str) -> String {
    format!("{label}-{nonce}")
}

/// Compute the refusal reasons shown in the "before allowing maintenance" dialog.
///
/// The UI displays exactly this list, so the same information that justified a refusal is
/// what the operator sees.
pub fn maintenance_blockers(
    agents: &AgentInventory,
    pending: &PendingRebootReport,
    network_phase: NetworkPhase,
    dirty_projects: &[String],
) -> Vec<String> {
    let mut reasons = Vec::new();

    for agent in &agents.agents {
        let live: Vec<_> = agent
            .instances
            .iter()
            .filter(|i| i.confidence.drives_protection())
            .collect();
        if live.is_empty() {
            continue;
        }
        let projects: Vec<&str> = live
            .iter()
            .filter_map(|i| i.project.as_ref().map(|p| p.name.as_str()))
            .collect();
        reasons.push(if projects.is_empty() {
            format!("{} x {}", agent.display_name, live.len())
        } else {
            format!(
                "{} x {} ({})",
                agent.display_name,
                live.len(),
                projects.join(", ")
            )
        });
    }

    for w in &agents.workloads {
        let owned = w
            .owner_kind
            .as_deref()
            .map(|k| format!(" under {k}"))
            .unwrap_or_default();
        reasons.push(format!(
            "{} (pid {}, running {}s){}",
            w.display_name,
            w.pid,
            w.running_ms / 1000,
            owned
        ));
    }

    if !dirty_projects.is_empty() {
        reasons.push(format!(
            "uncommitted changes in: {}",
            dirty_projects.join(", ")
        ));
    }

    if matches!(
        pending.verdict,
        PendingRebootVerdict::Pending | PendingRebootVerdict::ProbablyPending
    ) {
        reasons.push(
            format!("a restart is already {} pending", pending.verdict.as_str()).to_lowercase(),
        );
    }

    if matches!(
        network_phase,
        NetworkPhase::Offline | NetworkPhase::Dialing | NetworkPhase::Backoff
    ) {
        reasons.push("the network link is not currently up".to_string());
    }

    reasons
}

/// Convenience wrapper that runs the pending-reboot probe and the machine tick together.
///
/// Kept here so the service has one call site and cannot forget to expire permits.
pub fn tick_with_pending_reboot<S: PendingRebootSource, C: Clock>(
    state: &MaintenanceState,
    policy: &MaintenancePolicy,
    source: &S,
    clock: &C,
    boot_id: &str,
) -> Transition {
    let pending = crate::reboot::classify(source);
    let _ = pending; // The verdict influences the *note* on next boot, not the tick.
    advance(
        state,
        &MaintenanceEvent::Tick,
        policy,
        clock.now_ms(),
        boot_id,
        "",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_proto::model::{Confidence, ProcessIdentity};

    fn policy() -> MaintenancePolicy {
        MaintenancePolicy {
            reboot_token_ttl_secs: 1800,
            refuse_with_protected_work: true,
            override_phrase: "I understand the risk".into(),
        }
    }

    fn authorized_state(now: i64, boot: &str, ttl: u64) -> MaintenanceState {
        let s = MaintenanceState {
            phase: MaintenancePhase::UpdatePending,
            authorization: None,
            entered_at_ms: Some(now - 1000),
            entered_by: None,
            entered_with_override: false,
        };
        advance(
            &s,
            &MaintenanceEvent::ArmRebootRequested {
                ttl_secs: ttl,
                issued_by: "administrator".into(),
            },
            &policy(),
            now,
            boot,
            "nonce-1",
        )
        .state
    }

    #[test]
    fn default_state_is_locked() {
        let s = MaintenanceState::default();
        assert_eq!(s.phase, MaintenancePhase::Locked);
        assert!(!s.phase.updates_unlocked());
        assert!(s.authorization.is_none());
    }

    #[test]
    fn maintenance_is_refused_while_agents_run() {
        let s = MaintenanceState::default();
        let t = advance(
            &s,
            &MaintenanceEvent::EnterRequested {
                protected_work: vec!["Claude Code x 2".into()],
                override_phrase_provided: None,
            },
            &policy(),
            1000,
            "boot-1",
            "n",
        );
        assert_eq!(t.state.phase, MaintenancePhase::Locked, "must not unlock");
        assert!(matches!(
            t.refusal,
            Some(Refusal::ProtectedWorkActive { .. })
        ));
        assert!(t.refusal.unwrap().message().contains("Claude Code"));
    }

    #[test]
    fn override_requires_the_exact_phrase() {
        let s = MaintenanceState::default();
        let t = advance(
            &s,
            &MaintenanceEvent::EnterRequested {
                protected_work: vec!["Codex".into()],
                override_phrase_provided: Some("yes please".into()),
            },
            &policy(),
            1000,
            "boot-1",
            "n",
        );
        assert_eq!(t.state.phase, MaintenancePhase::Locked);
        assert!(matches!(
            t.refusal,
            Some(Refusal::ProtectedWorkActive { .. })
        ));

        let t2 = advance(
            &s,
            &MaintenanceEvent::EnterRequested {
                protected_work: vec!["Codex".into()],
                override_phrase_provided: Some("  I understand the risk  ".into()),
            },
            &policy(),
            1000,
            "boot-1",
            "n",
        );
        assert_eq!(t2.state.phase, MaintenancePhase::Maintenance);
        assert!(t2.state.entered_with_override);
        assert!(t2.refusal.is_none());
    }

    #[test]
    fn entering_with_no_protected_work_is_allowed_without_override() {
        let s = MaintenanceState::default();
        let t = advance(
            &s,
            &MaintenanceEvent::EnterRequested {
                protected_work: vec![],
                override_phrase_provided: None,
            },
            &policy(),
            1000,
            "boot-1",
            "n",
        );
        assert_eq!(t.state.phase, MaintenancePhase::Maintenance);
        assert!(!t.state.entered_with_override);
    }

    #[test]
    fn full_happy_path_locked_to_boot_to_locked() {
        let mut s = MaintenanceState::default();
        let p = policy();

        // LOCKED -> MAINTENANCE
        s = advance(
            &s,
            &MaintenanceEvent::EnterRequested {
                protected_work: vec![],
                override_phrase_provided: None,
            },
            &p,
            1_000,
            "boot-1",
            "n1",
        )
        .state;
        assert_eq!(s.phase, MaintenancePhase::Maintenance);

        // MAINTENANCE -> UPDATE_PENDING
        s = advance(
            &s,
            &MaintenanceEvent::UpdatePendingObserved,
            &p,
            2_000,
            "boot-1",
            "n1",
        )
        .state;
        assert_eq!(s.phase, MaintenancePhase::UpdatePending);

        // UPDATE_PENDING -> REBOOT_ARMED
        s = advance(
            &s,
            &MaintenanceEvent::ArmRebootRequested {
                ttl_secs: 1800,
                issued_by: "administrator".into(),
            },
            &p,
            3_000,
            "boot-1",
            "n1",
        )
        .state;
        assert_eq!(s.phase, MaintenancePhase::RebootArmed);
        assert!(s.authorization.is_some());

        // REBOOT_ARMED -> BOOT (restart consumed the capability)
        let t = advance(
            &s,
            &MaintenanceEvent::ShutdownObserved { restart: true },
            &p,
            4_000,
            "boot-1",
            "n1",
        );
        assert_eq!(t.state.phase, MaintenancePhase::Boot);
        let consumed = t.consumed_authorization.expect("consumed");
        assert_eq!(consumed.consumed_at_ms, Some(4_000));

        // BOOT -> LOCKED
        let t2 = advance(
            &t.state,
            &MaintenanceEvent::Booted {
                boot_id: "boot-2".into(),
                pending_reboot: PendingRebootVerdict::NotPending,
            },
            &p,
            10_000,
            "boot-2",
            "n1",
        );
        assert_eq!(t2.state.phase, MaintenancePhase::Locked);
        assert!(t2.state.authorization.is_none());
        assert!(!t2.state.phase.updates_unlocked());
    }

    #[test]
    fn ordinary_reboot_never_unlocks_updates() {
        // The core rule. A user rebooting for any unrelated reason must come back LOCKED.
        let s = MaintenanceState::default();
        let shutdown = advance(
            &s,
            &MaintenanceEvent::ShutdownObserved { restart: true },
            &policy(),
            1000,
            "boot-1",
            "n",
        );
        assert_eq!(shutdown.state.phase, MaintenancePhase::Boot);
        assert!(shutdown.consumed_authorization.is_none());
        assert!(shutdown.state.authorization.is_none());

        let booted = advance(
            &shutdown.state,
            &MaintenanceEvent::Booted {
                boot_id: "boot-2".into(),
                pending_reboot: PendingRebootVerdict::NotPending,
            },
            &policy(),
            2000,
            "boot-2",
            "n",
        );
        assert_eq!(booted.state.phase, MaintenancePhase::Locked);
        assert!(!booted.state.phase.updates_unlocked());
    }

    #[test]
    fn expired_permit_is_rejected_and_disarmed() {
        let now = 1_000_000;
        let s = authorized_state(now, "boot-1", 60);
        assert_eq!(s.phase, MaintenancePhase::RebootArmed);

        // Exactly at expiry: no longer usable.
        let t = advance(
            &s,
            &MaintenanceEvent::Tick,
            &policy(),
            now + 60_000,
            "boot-1",
            "",
        );
        assert_eq!(t.state.phase, MaintenancePhase::Maintenance);
        assert!(t.state.authorization.is_none());
        assert!(t.expired_authorization.is_some());

        // And the expired permit cannot authorize a restart afterwards.
        let shutdown = advance(
            &t.state,
            &MaintenanceEvent::ShutdownObserved { restart: true },
            &policy(),
            now + 61_000,
            "boot-1",
            "",
        );
        assert!(
            shutdown.consumed_authorization.is_none(),
            "an expired permit must never be consumed as valid"
        );
    }

    #[test]
    fn consumed_permit_cannot_be_reused_in_the_same_boot() {
        let now = 1_000_000;
        let s = authorized_state(now, "boot-1", 1800);

        // Restart consumes it.
        let t = advance(
            &s,
            &MaintenanceEvent::ShutdownObserved { restart: true },
            &policy(),
            now + 1000,
            "boot-1",
            "",
        );
        let consumed = t.consumed_authorization.clone().expect("consumed");
        assert!(consumed.consumed_at_ms.is_some());

        // Suppose the restart did not actually happen: the service is still on boot-1, and
        // the state still holds the consumed capability. A second restart must NOT be
        // authorized.
        let again = advance(
            &t.state,
            &MaintenanceEvent::ShutdownObserved { restart: true },
            &policy(),
            now + 2000,
            "boot-1",
            "",
        );
        assert!(
            again.consumed_authorization.is_none(),
            "a consumed permit must not authorize a second reboot"
        );

        // And a tick notices the consumed state and disarms.
        let tick = advance(
            &t.state,
            &MaintenanceEvent::Tick,
            &policy(),
            now + 3000,
            "boot-1",
            "",
        );
        assert!(tick.state.authorization.is_none());
    }

    #[test]
    fn permit_does_not_survive_an_unexpected_reboot() {
        // Arm a permit on boot-1, then the machine reboots unexpectedly (crash/power loss):
        // no shutdown event was ever processed, so the permit is still "armed" in state.
        let now = 1_000_000;
        let armed = authorized_state(now, "boot-1", 1800);

        // Service starts on boot-2 and processes the new boot identity.
        let t = advance(
            &armed,
            &MaintenanceEvent::Booted {
                boot_id: "boot-2".into(),
                pending_reboot: PendingRebootVerdict::NotPending,
            },
            &policy(),
            now + 5_000,
            "boot-2",
            "",
        );
        assert_eq!(t.state.phase, MaintenancePhase::Locked);
        assert!(t.state.authorization.is_none());
        assert!(
            t.expired_authorization.is_some(),
            "the stale permit must be reported as invalidated, not silently dropped"
        );
    }

    #[test]
    fn tick_invalidates_permit_when_boot_identity_changes() {
        let now = 1_000_000;
        let armed = authorized_state(now, "boot-1", 1800);
        let t = advance(
            &armed,
            &MaintenanceEvent::Tick,
            &policy(),
            now + 100,
            "boot-2",
            "",
        );
        assert!(t.state.authorization.is_none());
        assert!(t.note.contains("boot identity changed"));
    }

    #[test]
    fn exit_maintenance_reapplies_protection_and_drops_permit() {
        let now = 1_000_000;
        let armed = authorized_state(now, "boot-1", 1800);
        let t = advance(
            &armed,
            &MaintenanceEvent::ExitRequested,
            &policy(),
            now + 10,
            "boot-1",
            "",
        );
        assert_eq!(t.state.phase, MaintenancePhase::Locked);
        assert!(t.state.authorization.is_none());
        assert!(!t.state.phase.updates_unlocked());
        assert!(t.note.contains("discarded an armed reboot authorization"));
    }

    #[test]
    fn rearming_replaces_rather_than_stacks() {
        let now = 1_000_000;
        let first = authorized_state(now, "boot-1", 1800);
        let id1 = first.authorization.as_ref().unwrap().id.clone();

        let second = advance(
            &first,
            &MaintenanceEvent::ArmRebootRequested {
                ttl_secs: 600,
                issued_by: "administrator".into(),
            },
            &policy(),
            now + 100,
            "boot-1",
            "nonce-2",
        );
        assert_eq!(second.state.phase, MaintenancePhase::RebootArmed);
        let id2 = second.state.authorization.as_ref().unwrap().id.clone();
        assert_ne!(id1, id2, "only one capability may be live");
        // There is only ever one field, so no stacking is structurally possible.
    }

    #[test]
    fn ttl_is_clamped_into_a_sane_window() {
        let now = 1_000_000;
        let tiny = authorized_state(now, "boot-1", 1);
        let ttl = tiny.authorization.as_ref().unwrap();
        assert_eq!(
            ttl.expires_at_ms - ttl.issued_at_ms,
            (MIN_TTL_SECS * 1000) as i64
        );

        let huge = authorized_state(now, "boot-1", u64::MAX);
        let ttl = huge.authorization.as_ref().unwrap();
        assert_eq!(
            ttl.expires_at_ms - ttl.issued_at_ms,
            (MAX_TTL_SECS * 1000) as i64
        );
    }

    #[test]
    fn ttl_change_cannot_revive_an_expired_permit_indefinitely() {
        let now = 1_000_000;
        let armed = authorized_state(now, "boot-1", 60);
        // Extend it: the new expiry is measured from issue, not from now.
        let t = advance(
            &armed,
            &MaintenanceEvent::TtlChanged { ttl_secs: 3600 },
            &policy(),
            now + 120_000,
            "boot-1",
            "",
        );
        let auth = t.state.authorization.clone().expect("still armed");
        assert_eq!(
            auth.expires_at_ms,
            now + 3600 * 1000,
            "extending must not be relative to the current time, which would let a permit be refreshed forever"
        );
        // And it is still subject to the maximum.
        let t2 = advance(
            &t.state,
            &MaintenanceEvent::TtlChanged { ttl_secs: u64::MAX },
            &policy(),
            now + 120_000,
            "boot-1",
            "",
        );
        let auth2 = t2.state.authorization.expect("still armed");
        assert_eq!(auth2.expires_at_ms, now + (MAX_TTL_SECS * 1000) as i64);
    }

    #[test]
    fn disarm_without_a_permit_is_refused_not_silently_ignored() {
        let s = MaintenanceState {
            phase: MaintenancePhase::Maintenance,
            ..Default::default()
        };
        let t = advance(
            &s,
            &MaintenanceEvent::DisarmRequested,
            &policy(),
            1000,
            "b",
            "",
        );
        assert_eq!(t.refusal, Some(Refusal::NoActiveAuthorization));
    }

    #[test]
    fn arm_from_locked_is_refused() {
        let s = MaintenanceState::default();
        let t = advance(
            &s,
            &MaintenanceEvent::ArmRebootRequested {
                ttl_secs: 1800,
                issued_by: "administrator".into(),
            },
            &policy(),
            1000,
            "boot-1",
            "n",
        );
        assert!(matches!(t.refusal, Some(Refusal::WrongPhase { .. })));
        assert!(t.state.authorization.is_none());
    }

    #[test]
    fn plain_shutdown_clears_an_armed_permit() {
        // If a permit is armed and the user shuts down (not restarts), it must not survive.
        let now = 1_000_000;
        let armed = authorized_state(now, "boot-1", 1800);
        let t = advance(
            &armed,
            &MaintenanceEvent::ShutdownObserved { restart: false },
            &policy(),
            now + 10,
            "boot-1",
            "",
        );
        assert_eq!(t.state.phase, MaintenancePhase::Locked);
        assert!(t.state.authorization.is_none());
    }

    #[test]
    fn blockers_summarise_agents_workloads_and_network() {
        let mut inv = AgentInventory::default();
        inv.agents.push(AgentGroup {
            kind: "claude_code".into(),
            display_name: "Claude Code".into(),
            confidence: Confidence::Confirmed,
            instances: vec![AgentInstance {
                kind: "claude_code".into(),
                display_name: "Claude Code".into(),
                pid: 100,
                root_pid: 100,
                identity: ProcessIdentity {
                    pid: 100,
                    created_filetime: 1,
                },
                session_id: "s".into(),
                confidence: Confidence::Confirmed,
                evidence: vec![],
                started_at_filetime: 0,
                started_at_ms: 0,
                image_path: None,
                cmdline: None,
                ancestry: vec![],
                session_id_windows: 1,
                user: None,
                project: Some(ProjectContext {
                    root: r"D:\Workspace\rust-reality".into(),
                    name: "rust-reality".into(),
                    source: "claude_session_file".into(),
                    vcs: None,
                }),
                resume: ResumeCapability::Unavailable,
            }],
        });
        inv.workloads.push(ProtectedWorkload {
            rule_id: "cargo".into(),
            display_name: "cargo build".into(),
            pid: 200,
            identity: ProcessIdentity {
                pid: 200,
                created_filetime: 2,
            },
            owner_session: Some("s".into()),
            owner_kind: Some("Claude Code".into()),
            started_at_ms: 0,
            running_ms: 120_000,
            image_path: None,
            cmdline: None,
            reason: "owned by agent".into(),
        });

        let pending = PendingRebootReport {
            verdict: PendingRebootVerdict::NotPending,
            signals: vec![],
            checked_at_ms: 0,
        };
        let reasons = maintenance_blockers(&inv, &pending, NetworkPhase::Online, &[]);
        assert!(reasons
            .iter()
            .any(|r| r.contains("Claude Code") && r.contains("rust-reality")));
        assert!(reasons
            .iter()
            .any(|r| r.contains("cargo build") && r.contains("Claude Code")));
        assert!(!reasons.iter().any(|r| r.contains("uncommitted")));
    }

    #[test]
    fn blockers_flag_offline_network_and_pending_reboot() {
        let inv = AgentInventory::default();
        let pending = PendingRebootReport {
            verdict: PendingRebootVerdict::Pending,
            signals: vec![],
            checked_at_ms: 0,
        };
        let reasons = maintenance_blockers(
            &inv,
            &pending,
            NetworkPhase::Offline,
            &["repo-a".to_string()],
        );
        assert!(reasons.iter().any(|r| r.contains("not currently up")));
        assert!(reasons.iter().any(|r| r.contains("repo-a")));
        assert!(reasons.iter().any(|r| r.contains("pending")));
    }

    #[test]
    fn low_confidence_agents_do_not_block_maintenance() {
        let mut inv = AgentInventory::default();
        inv.agents.push(AgentGroup {
            kind: "maybe".into(),
            display_name: "Maybe Agent".into(),
            confidence: Confidence::Possible,
            instances: vec![AgentInstance {
                kind: "maybe".into(),
                display_name: "Maybe Agent".into(),
                pid: 1,
                root_pid: 1,
                identity: ProcessIdentity {
                    pid: 1,
                    created_filetime: 1,
                },
                session_id: "s".into(),
                confidence: Confidence::Possible,
                evidence: vec![],
                started_at_filetime: 0,
                started_at_ms: 0,
                image_path: None,
                cmdline: None,
                ancestry: vec![],
                session_id_windows: 1,
                user: None,
                project: None,
                resume: ResumeCapability::Unavailable,
            }],
        });
        let pending = PendingRebootReport {
            verdict: PendingRebootVerdict::NotPending,
            signals: vec![],
            checked_at_ms: 0,
        };
        let reasons = maintenance_blockers(&inv, &pending, NetworkPhase::Online, &[]);
        assert!(
            reasons.is_empty(),
            "Possible detections must not block maintenance"
        );
    }
}
