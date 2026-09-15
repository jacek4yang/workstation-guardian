//! Shared protection state and the coordinator that owns it.
//!
//! # The one rule
//!
//! `Protected` is reported only when every required check genuinely passed. Every other path
//! — a worker down, a read failure, external management, a configuration that disables
//! protection — resolves to `Degraded`, `Unknown` or `Unprotected`, never to `Protected`.
//! The whole point of the project is that the operator can trust that word.
//!
//! # Mode transitions
//!
//! ```text
//!   Normal ──work detected──▶ Working ──work ends──▶ Normal
//!      │                          │
//!      └──── explicit user action ┴────▶ Maintenance ──▶ (exit | armed reboot) ──▶ Locked
//! ```
//!
//! WORKING is derived from the agent inventory rather than being set by hand, so it cannot
//! drift out of step with what is actually running. MAINTENANCE is never derived: it only
//! happens because a user asked for it.

use std::sync::{Arc, RwLock};

use guardian_core::maintenance::{
    self, MaintenanceEvent, MaintenancePhase, MaintenancePolicy, MaintenanceState,
};
use guardian_core::net::NetworkPolicy;
use guardian_core::ports::{BootIdentity, Clock, PendingRebootSource};
use guardian_proto::model::*;

use crate::supervisor::HealthRegistry;

/// The snapshot the whole service shares.
#[derive(Debug, Clone)]
pub struct ServiceState {
    /// Which of the three protection modes the machine is in.
    pub mode: ProtectionMode,
    /// The latest Windows Update verification report.
    pub update: UpdateProtectionReport,
    /// The latest pending-reboot verdict.
    pub pending_reboot: PendingRebootReport,
    /// The latest agent inventory.
    pub agents: Box<AgentInventory>,
    /// The latest network snapshot.
    pub network: Box<NetworkSnapshot>,
    /// The maintenance machine's state.
    pub maintenance: MaintenanceState,
    /// Worker health, for the degraded-components list.
    pub workers: Vec<crate::supervisor::WorkerHealth>,
    /// The boot identity this process is running under.
    pub boot_id: String,
    /// When the service started (Unix ms).
    pub started_at_ms: i64,
    /// Whether the previous session ended without a clean marker.
    pub started_after_unclean_exit: bool,
    pub service_version: String,
    /// Set when the session helper last made contact.
    pub helper_connected: bool,
    /// Incidents raised since the service started, newest last.
    pub incidents: Vec<Incident>,
}

impl ServiceState {
    /// Build the state for a freshly started service.
    pub fn initial(boot_id: String, started_at_ms: i64, version: String) -> Self {
        ServiceState {
            mode: ProtectionMode::Normal,
            // Nothing has been verified yet, so protection is unknown. Starting out claiming
            // Protected would be the exact lie this design exists to prevent.
            update: UpdateProtectionReport::unavailable(
                "update protection has not been verified yet",
                started_at_ms,
            ),
            pending_reboot: PendingRebootReport::unknown(
                "the pending-reboot state has not been checked yet",
                started_at_ms,
            ),
            agents: Box::new(AgentInventory::default()),
            network: Box::new(NetworkSnapshot::default()),
            maintenance: MaintenanceState::default(),
            workers: Vec::new(),
            boot_id,
            started_at_ms,
            started_after_unclean_exit: false,
            service_version: version,
            helper_connected: false,
            incidents: Vec::new(),
        }
    }

    /// Restart protection level.
    ///
    /// Shutdown blocking is a session-helper capability, so it is only effective when a helper
    /// is actually connected. Reporting `Protected` for a subsystem that cannot act would be
    /// a false claim, so a missing helper with work in progress is reported as `Degraded`.
    pub fn restart_protection(&self) -> ProtectionLevel {
        let wants_blocking = self.mode.wants_shutdown_block();
        if !wants_blocking {
            // In NORMAL or MAINTENANCE there is no work to protect, so there is nothing to
            // block and nothing that could be failing.
            return ProtectionLevel::Protected;
        }
        if self.helper_connected {
            ProtectionLevel::Protected
        } else {
            ProtectionLevel::Degraded
        }
    }

    /// The overall service health, for the UI banner.
    pub fn service_health(&self, now_ms: i64) -> ServiceHealth {
        let degraded: Vec<String> = self
            .workers
            .iter()
            .filter(|w| w.state.is_degraded() || w.is_stale(crate::supervisor::HEARTBEAT_STALE_MS))
            .map(|w| w.name.clone())
            .collect();

        ServiceHealth {
            running: true,
            started_at_ms: self.started_at_ms,
            uptime_ms: now_ms.saturating_sub(self.started_at_ms),
            version: self.service_version.clone(),
            degraded_components: degraded,
            started_after_unclean_exit: self.started_after_unclean_exit,
        }
    }

    /// Reasons maintenance would be refused right now, for the confirmation dialog.
    pub fn maintenance_blockers(&self) -> Vec<String> {
        maintenance::maintenance_blockers(
            &self.agents,
            &self.pending_reboot,
            self.network.phase,
            &[],
        )
    }

    /// Build the status snapshot served over IPC.
    pub fn snapshot(&self, now_ms: i64) -> StatusSnapshot {
        StatusSnapshot {
            mode: self.mode,
            update: self.update.clone(),
            restart_protection: self.restart_protection(),
            pending_reboot: self.pending_reboot.clone(),
            service: self.service_health(now_ms),
            agents: self.agents.clone(),
            network: self.network.clone(),
            reboot_authorization: self.maintenance.authorization.clone(),
            maintenance_denial_reasons: self.maintenance_blockers(),
            generated_at_ms: now_ms,
            service_version: self.service_version.clone(),
            boot_id: self.boot_id.clone(),
            session_id_helper: if self.helper_connected {
                SessionHelperState::Connected
            } else {
                SessionHelperState::NotRunning
            },
        }
    }
}

/// The coordinator: owns the state, applies subsystem updates, and runs the mode machine.
pub struct ProtectionCoordinator<C: Clock, P: PendingRebootSource> {
    state: Arc<RwLock<ServiceState>>,
    clock: C,
    reboot_probe: P,
    maintenance_policy: MaintenancePolicy,
    /// Whether WORKING is derived from detections or pinned by configuration.
    auto_working: bool,
    /// Whether a standalone long build counts as protected work.
    protect_standalone_workloads: bool,
}

impl<C: Clock, P: PendingRebootSource> std::fmt::Debug for ProtectionCoordinator<C, P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtectionCoordinator")
            .field("auto_working", &self.auto_working)
            .field(
                "protect_standalone_workloads",
                &self.protect_standalone_workloads,
            )
            .finish_non_exhaustive()
    }
}

impl<C: Clock, P: PendingRebootSource> ProtectionCoordinator<C, P> {
    pub fn new(
        state: Arc<RwLock<ServiceState>>,
        clock: C,
        reboot_probe: P,
        maintenance_policy: MaintenancePolicy,
        auto_working: bool,
        protect_standalone_workloads: bool,
    ) -> Self {
        ProtectionCoordinator {
            state,
            clock,
            reboot_probe,
            maintenance_policy,
            auto_working,
            protect_standalone_workloads,
        }
    }

    pub fn shared_state(&self) -> Arc<RwLock<ServiceState>> {
        Arc::clone(&self.state)
    }

    /// Read the current state.
    pub fn read(&self) -> ServiceState {
        match self.state.read() {
            Ok(g) => g.clone(),
            // A poisoned lock means a thread panicked while holding it. Rather than
            // propagating the panic into every caller, recover the data: the state itself is
            // still valid, and protection must not stop because of a bug elsewhere.
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// Apply a mutation to the state.
    fn update(&self, f: impl FnOnce(&mut ServiceState)) {
        match self.state.write() {
            Ok(mut g) => f(&mut g),
            Err(poisoned) => f(&mut poisoned.into_inner()),
        }
    }

    /// Publish a new update-protection report and reconcile the mode.
    pub fn set_update_report(&self, report: UpdateProtectionReport, incidents: Vec<Incident>) {
        self.update(|s| {
            s.update = report;
            for i in incidents {
                push_incident(s, i);
            }
        });
        self.reconcile_mode();
    }

    /// Publish a new agent inventory and reconcile the mode.
    pub fn set_agents(&self, inventory: AgentInventory) {
        self.update(|s| *s.agents = inventory);
        self.reconcile_mode();
    }

    /// Publish a new network snapshot.
    pub fn set_network(&self, snapshot: NetworkSnapshot) {
        self.update(|s| *s.network = snapshot);
    }

    /// Refresh the pending-reboot verdict.
    pub fn refresh_pending_reboot(&self) {
        let report = guardian_core::reboot::classify(&self.reboot_probe);
        let checked_at = self.clock.now_ms();
        self.update(|s| {
            let mut report = report;
            report.checked_at_ms = checked_at;
            s.pending_reboot = report;
        });
    }

    /// Publish worker health.
    pub fn set_workers(&self, registry: &HealthRegistry) {
        let workers = registry.snapshot();
        self.update(|s| s.workers = workers);
    }

    /// Record whether the session helper is connected.
    pub fn set_helper_connected(&self, connected: bool) {
        self.update(|s| s.helper_connected = connected);
    }

    /// Record the outcome of the startup recovery check.
    pub fn set_unclean_exit(&self, unclean: bool) {
        self.update(|s| s.started_after_unclean_exit = unclean);
    }

    /// Append an incident, bounded.
    pub fn add_incident(&self, incident: Incident) {
        self.update(|s| push_incident(s, incident));
    }

    /// The current mode.
    pub fn mode(&self) -> ProtectionMode {
        self.read().mode
    }

    /// Recompute the mode from the current inventory and maintenance state.
    ///
    /// This is the single place mode is decided, so it cannot drift between callers. The
    /// precedence is deliberate:
    ///
    /// 1. MAINTENANCE wins, because it is an explicit user decision and must be visible.
    /// 2. WORKING applies when protected work is live.
    /// 3. NORMAL otherwise.
    pub fn reconcile_mode(&self) -> ProtectionMode {
        let (next, changed) = {
            let current = self.read();
            let next = if current.maintenance.phase != MaintenancePhase::Locked {
                ProtectionMode::Maintenance
            } else if self.auto_working
                && current
                    .agents
                    .warrants_working(self.protect_standalone_workloads)
            {
                ProtectionMode::Working
            } else {
                ProtectionMode::Normal
            };
            (next, next != current.mode)
        };

        if changed {
            let previous = self.read().mode;
            self.update(|s| s.mode = next);
            tracing::info!(
                from = previous.as_str(),
                to = next.as_str(),
                "protection mode changed"
            );
        }

        next
    }

    /// Enter maintenance, or refuse and explain why.
    pub fn enter_maintenance(
        &self,
        override_phrase: Option<String>,
    ) -> Result<MaintenanceState, String> {
        let current = self.read();
        let blockers = current.maintenance_blockers();

        let transition = maintenance::advance(
            &current.maintenance,
            &MaintenanceEvent::EnterRequested {
                protected_work: blockers.clone(),
                override_phrase_provided: override_phrase,
            },
            &self.maintenance_policy,
            self.clock.now_ms(),
            &current.boot_id,
            "",
        );

        if let Some(refusal) = transition.refusal {
            return Err(refusal.message());
        }

        let note = transition.note.clone();
        let state = transition.state.clone();
        self.update(|s| s.maintenance = state.clone());
        self.reconcile_mode();

        tracing::warn!(
            override_used = state.entered_with_override,
            "entered maintenance mode"
        );

        self.add_incident(Incident {
            id: format!("maint-{}", self.clock.now_ms()),
            kind: IncidentKind::MaintenanceEntered,
            at_ms: self.clock.now_ms(),
            title: "Maintenance mode entered".into(),
            summary: if state.entered_with_override {
                format!("{note}; protected work was overridden by the operator")
            } else {
                note
            },
            severity: if state.entered_with_override {
                FindingSeverity::Warning
            } else {
                FindingSeverity::Info
            },
            details: IncidentDetails::default(),
        });

        Ok(state)
    }

    /// Leave maintenance without rebooting, reapplying protection immediately.
    pub fn exit_maintenance(&self) -> Result<MaintenanceState, String> {
        let current = self.read();
        if current.maintenance.phase == MaintenancePhase::Locked {
            return Err("maintenance mode is not active".into());
        }

        let transition = maintenance::advance(
            &current.maintenance,
            &MaintenanceEvent::ExitRequested,
            &self.maintenance_policy,
            self.clock.now_ms(),
            &current.boot_id,
            "",
        );

        let state = transition.state.clone();
        self.update(|s| s.maintenance = state.clone());
        self.reconcile_mode();

        tracing::info!("exited maintenance mode; update protection reapplied");

        self.add_incident(Incident {
            id: format!("maint-exit-{}", self.clock.now_ms()),
            kind: IncidentKind::MaintenanceExited,
            at_ms: self.clock.now_ms(),
            title: "Maintenance mode exited".into(),
            summary: transition.note,
            severity: FindingSeverity::Info,
            details: IncidentDetails::default(),
        });

        Ok(state)
    }

    /// Arm a single-use reboot authorization.
    pub fn arm_reboot(
        &self,
        ttl_secs: u32,
        issued_by: String,
    ) -> Result<RebootAuthorization, String> {
        let current = self.read();

        // A nonce that includes the boot identity and the clock is unique per arming without
        // needing a random source. It is not a secret: possession of the capability is what
        // matters, and that is held by the service, not by the caller.
        let nonce = format!("{}-{}-{}", current.boot_id, self.clock.now_ms(), ttl_secs);

        let transition = maintenance::advance(
            &current.maintenance,
            &MaintenanceEvent::ArmRebootRequested {
                ttl_secs: u64::from(ttl_secs),
                issued_by,
            },
            &self.maintenance_policy,
            self.clock.now_ms(),
            &current.boot_id,
            &nonce,
        );

        if let Some(refusal) = transition.refusal {
            return Err(refusal.message());
        }

        let authorization = transition
            .state
            .authorization
            .clone()
            .ok_or_else(|| "the reboot authorization was not created".to_string())?;

        self.update(|s| s.maintenance = transition.state.clone());

        tracing::warn!(
            expires_at_ms = authorization.expires_at_ms,
            ttl_secs = authorization.remaining_ms(self.clock.now_ms()) / 1000,
            "armed a single-use reboot authorization"
        );

        self.add_incident(Incident {
            id: format!("reboot-armed-{}", authorization.id),
            kind: IncidentKind::RebootArmed,
            at_ms: self.clock.now_ms(),
            title: "One reboot authorized".into(),
            summary: format!(
                "a single reboot is authorized for {} minutes; Windows Update remains locked",
                authorization.remaining_ms(self.clock.now_ms()) / 60_000
            ),
            severity: FindingSeverity::Warning,
            details: IncidentDetails::default(),
        });

        Ok(authorization)
    }

    /// Discard an armed authorization.
    pub fn disarm_reboot(&self) -> Result<(), String> {
        let current = self.read();
        let transition = maintenance::advance(
            &current.maintenance,
            &MaintenanceEvent::DisarmRequested,
            &self.maintenance_policy,
            self.clock.now_ms(),
            &current.boot_id,
            "",
        );
        if let Some(refusal) = transition.refusal {
            return Err(refusal.message());
        }
        self.update(|s| s.maintenance = transition.state.clone());
        Ok(())
    }

    /// Advance the maintenance machine's clock: expire permits, notice a changed boot.
    pub fn tick_maintenance(&self) {
        let current = self.read();
        let transition = maintenance::advance(
            &current.maintenance,
            &MaintenanceEvent::Tick,
            &self.maintenance_policy,
            self.clock.now_ms(),
            &current.boot_id,
            "",
        );

        if transition.state != current.maintenance {
            self.update(|s| s.maintenance = transition.state.clone());
            self.reconcile_mode();

            if let Some(expired) = transition.expired_authorization {
                tracing::warn!(
                    authorized_at = expired.issued_at_ms,
                    "reboot authorization expired or was invalidated"
                );
                self.add_incident(Incident {
                    id: format!("reboot-expired-{}", expired.id),
                    kind: IncidentKind::RebootExpired,
                    at_ms: self.clock.now_ms(),
                    title: "Reboot authorization cleared".into(),
                    summary: transition.note.clone(),
                    severity: FindingSeverity::Info,
                    details: IncidentDetails::default(),
                });
            }
        }
    }

    /// Process a shutdown/restart observation.
    pub fn observe_shutdown(&self, restart: bool) -> bool {
        let current = self.read();
        let transition = maintenance::advance(
            &current.maintenance,
            &MaintenanceEvent::ShutdownObserved { restart },
            &self.maintenance_policy,
            self.clock.now_ms(),
            &current.boot_id,
            "",
        );

        let authorized = transition.consumed_authorization.is_some();
        self.update(|s| s.maintenance = transition.state.clone());

        tracing::info!(
            restart,
            authorized,
            "shutdown observed; maintenance state updated"
        );

        authorized
    }

    /// Apply a boot identity, which invalidates any permit bound to a previous boot.
    pub fn apply_boot(&self, boot_id: String, pending: PendingRebootVerdict) {
        let current = self.read();
        let transition = maintenance::advance(
            &current.maintenance,
            &MaintenanceEvent::Booted {
                boot_id: boot_id.clone(),
                pending_reboot: pending,
            },
            &self.maintenance_policy,
            self.clock.now_ms(),
            &boot_id,
            "",
        );

        if let Some(stale) = transition.expired_authorization {
            tracing::warn!(
                stale_id = %stale.id,
                issued_boot = %stale.issued_boot_id,
                "a reboot authorization from a previous boot was invalidated"
            );
            self.add_incident(Incident {
                id: format!("reboot-invalidated-{}", stale.id),
                kind: IncidentKind::RebootExpired,
                at_ms: self.clock.now_ms(),
                title: "Reboot authorization invalidated at boot".into(),
                summary: "a reboot authorization bound to a previous boot was discarded".into(),
                severity: FindingSeverity::Info,
                details: IncidentDetails::default(),
            });
        }

        self.update(|s| {
            s.boot_id = boot_id;
            s.maintenance = transition.state.clone();
        });
        self.reconcile_mode();
    }

    /// Whether updates are currently released.
    pub fn updates_unlocked(&self) -> bool {
        self.read().maintenance.phase.updates_unlocked()
    }

    /// Replace the maintenance policy after a configuration change.
    pub fn set_maintenance_policy(&mut self, policy: MaintenancePolicy) {
        self.maintenance_policy = policy;
    }

    /// Replace the agent-detection behaviour after a configuration change.
    pub fn set_agent_behaviour(&mut self, auto_working: bool, protect_standalone: bool) {
        self.auto_working = auto_working;
        self.protect_standalone_workloads = protect_standalone;
        self.reconcile_mode();
    }
}

/// Append an incident, keeping the most recent bounded.
fn push_incident(state: &mut ServiceState, incident: Incident) {
    const MAX_INCIDENTS: usize = 500;
    state.incidents.push(incident);
    if state.incidents.len() > MAX_INCIDENTS {
        let excess = state.incidents.len() - MAX_INCIDENTS;
        state.incidents.drain(..excess);
    }
}

/// Type alias for the shared state handle used across the service.
pub type SharedState = Arc<RwLock<ServiceState>>;

/// Build the initial shared state.
pub fn new_shared_state(version: &str) -> SharedState {
    let clock = guardian_win::clock::SystemClock;
    let boot_id = guardian_win::clock::SystemBootIdentity.boot_id();
    Arc::new(RwLock::new(ServiceState::initial(
        boot_id,
        clock.now_ms(),
        version.to_string(),
    )))
}

/// Build the maintenance policy from configuration.
pub fn maintenance_policy_from(config: &MaintenanceConfig) -> MaintenancePolicy {
    MaintenancePolicy {
        reboot_token_ttl_secs: config.reboot_token_ttl_secs,
        refuse_with_protected_work: config.refuse_with_protected_work,
        override_phrase: config.override_phrase.clone(),
    }
}

/// Build the network policy from configuration.
pub fn network_policy_from(config: &NetworkConfig) -> NetworkPolicy {
    NetworkPolicy::from_config(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::ports::fakes::{FakeClock, FakePendingReboot};
    use guardian_proto::model::Confidence;

    fn coordinator(
        clock: FakeClock,
        probe: FakePendingReboot,
    ) -> ProtectionCoordinator<FakeClock, FakePendingReboot> {
        let state = Arc::new(RwLock::new(ServiceState::initial(
            "boot-1".into(),
            1_000_000,
            "0.1.0".into(),
        )));
        ProtectionCoordinator::new(
            state,
            clock,
            probe,
            MaintenancePolicy {
                reboot_token_ttl_secs: 1800,
                refuse_with_protected_work: true,
                override_phrase: "I understand the risk".into(),
            },
            true,
            false,
        )
    }

    fn agent_inventory(kind: &str, confidence: Confidence) -> AgentInventory {
        let mut inv = AgentInventory::default();
        inv.agents.push(AgentGroup {
            kind: kind.into(),
            display_name: kind.into(),
            confidence,
            instances: vec![AgentInstance {
                kind: kind.into(),
                display_name: kind.into(),
                pid: 100,
                root_pid: 100,
                identity: ProcessIdentity {
                    pid: 100,
                    created_filetime: 1,
                },
                session_id: "s".into(),
                confidence,
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
        inv
    }

    #[test]
    fn a_new_service_reports_unknown_not_protected() {
        // The most important startup property: nothing has been verified, so nothing may be
        // claimed. Starting as Protected would be the exact lie the design prevents.
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        let state = c.read();
        assert_eq!(state.update.level, ProtectionLevel::Unknown);
        assert!(!state.update.level.is_protected());
        assert_eq!(state.pending_reboot.verdict, PendingRebootVerdict::Unknown);
        assert_eq!(state.mode, ProtectionMode::Normal);
    }

    #[test]
    fn work_detection_moves_the_mode_to_working_and_back() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        assert_eq!(c.mode(), ProtectionMode::Normal);

        c.set_agents(agent_inventory("claude_code", Confidence::Confirmed));
        assert_eq!(c.mode(), ProtectionMode::Working);

        c.set_agents(AgentInventory::default());
        assert_eq!(c.mode(), ProtectionMode::Normal);
    }

    #[test]
    fn low_confidence_detections_do_not_enter_working() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.set_agents(agent_inventory("maybe", Confidence::Possible));
        assert_eq!(
            c.mode(),
            ProtectionMode::Normal,
            "a Possible detection must not block shutdown"
        );
    }

    #[test]
    fn restart_protection_is_degraded_when_a_helper_is_missing_during_work() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.set_agents(agent_inventory("claude_code", Confidence::Confirmed));

        // Work is live but no helper is connected, so nothing can block a shutdown.
        c.set_helper_connected(false);
        assert_eq!(
            c.read().restart_protection(),
            ProtectionLevel::Degraded,
            "shutdown protection cannot be claimed without a helper to enforce it"
        );

        c.set_helper_connected(true);
        assert_eq!(c.read().restart_protection(), ProtectionLevel::Protected);
    }

    #[test]
    fn restart_protection_is_protected_when_there_is_nothing_to_protect() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.set_helper_connected(false);
        assert_eq!(c.read().restart_protection(), ProtectionLevel::Protected);
    }

    #[test]
    fn maintenance_is_refused_while_agents_run() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.set_agents(agent_inventory("claude_code", Confidence::Confirmed));

        let result = c.enter_maintenance(None);
        assert!(result.is_err(), "maintenance must be refused");
        let message = result.unwrap_err();
        assert!(
            message.contains("claude_code"),
            "the refusal must name what is running: {message}"
        );
        assert_eq!(
            c.mode(),
            ProtectionMode::Working,
            "the mode must not change"
        );
        assert!(!c.updates_unlocked());
    }

    #[test]
    fn maintenance_can_be_forced_with_the_exact_phrase() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.set_agents(agent_inventory("claude_code", Confidence::Confirmed));

        assert!(c.enter_maintenance(Some("wrong phrase".into())).is_err());

        let state = c
            .enter_maintenance(Some("I understand the risk".into()))
            .expect("the override must work");
        assert!(state.entered_with_override);
        assert_eq!(c.mode(), ProtectionMode::Maintenance);
        assert!(c.updates_unlocked());
    }

    #[test]
    fn maintenance_with_no_work_needs_no_override() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        let state = c.enter_maintenance(None).expect("should be allowed");
        assert!(!state.entered_with_override);
        assert_eq!(c.mode(), ProtectionMode::Maintenance);
        assert!(c.updates_unlocked());
    }

    #[test]
    fn exiting_maintenance_reapplies_protection_immediately() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.enter_maintenance(None).unwrap();
        assert!(c.updates_unlocked());

        c.exit_maintenance().expect("exit must work");
        assert!(!c.updates_unlocked(), "protection must be reapplied");
        assert_eq!(c.mode(), ProtectionMode::Normal);
    }

    #[test]
    fn exiting_maintenance_when_not_in_it_is_refused() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        assert!(c.exit_maintenance().is_err());
    }

    #[test]
    fn the_full_reboot_cycle_locks_again_afterwards() {
        let clock = FakeClock::new(1_000_000);
        let c = coordinator(clock, FakePendingReboot::default());

        c.enter_maintenance(None).unwrap();
        let auth = c.arm_reboot(1800, "administrator".into()).expect("arm");
        assert!(auth.is_usable(1_000_000, "boot-1"));

        let authorized = c.observe_shutdown(true);
        assert!(authorized, "the restart should be recognized as authorized");

        // Boot into a new session.
        c.apply_boot("boot-2".into(), PendingRebootVerdict::NotPending);

        assert!(
            !c.updates_unlocked(),
            "protection must be locked after boot"
        );
        assert_eq!(c.mode(), ProtectionMode::Normal);
        assert!(
            c.read().maintenance.authorization.is_none(),
            "the permit must be consumed and gone"
        );
    }

    #[test]
    fn an_ordinary_reboot_does_not_unlock_updates() {
        // The core rule. A reboot for any unrelated reason must come back locked.
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        assert!(!c.updates_unlocked());

        let authorized = c.observe_shutdown(true);
        assert!(!authorized, "no authorization was armed");
        c.apply_boot("boot-2".into(), PendingRebootVerdict::NotPending);

        assert!(!c.updates_unlocked());
        assert_eq!(c.mode(), ProtectionMode::Normal);
    }

    #[test]
    fn a_permit_bound_to_a_previous_boot_is_invalidated_at_boot() {
        let clock = FakeClock::new(1_000_000);
        let c = coordinator(clock, FakePendingReboot::default());
        c.enter_maintenance(None).unwrap();
        c.arm_reboot(1800, "administrator".into()).unwrap();

        // The machine reboots without the service seeing a shutdown (a crash or power loss).
        c.apply_boot("boot-2".into(), PendingRebootVerdict::NotPending);

        let state = c.read();
        assert!(state.maintenance.authorization.is_none());
        assert!(!c.updates_unlocked());
        assert!(
            state
                .incidents
                .iter()
                .any(|i| i.kind == IncidentKind::RebootExpired),
            "the invalidated permit must be visible in the incident log"
        );
    }

    #[test]
    fn an_expired_permit_is_cleared_by_a_tick() {
        let clock = FakeClock::new(1_000_000);
        let c = coordinator(clock, FakePendingReboot::default());
        c.enter_maintenance(None).unwrap();
        c.arm_reboot(60, "administrator".into()).unwrap();

        // Advance beyond the (clamped) minimum TTL.
        c.clock.advance(61_000);
        c.tick_maintenance();

        assert!(c.read().maintenance.authorization.is_none());
        assert!(c
            .read()
            .incidents
            .iter()
            .any(|i| i.kind == IncidentKind::RebootExpired));
    }

    #[test]
    fn the_mode_cannot_be_maintenance_without_the_maintenance_state() {
        // The mode is derived, so it cannot disagree with the machine that owns it.
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        assert_ne!(c.mode(), ProtectionMode::Maintenance);

        c.enter_maintenance(None).unwrap();
        assert_eq!(c.mode(), ProtectionMode::Maintenance);

        c.exit_maintenance().unwrap();
        assert_ne!(c.mode(), ProtectionMode::Maintenance);
    }

    #[test]
    fn maintenance_takes_precedence_over_working() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.set_agents(agent_inventory("claude_code", Confidence::Confirmed));
        assert_eq!(c.mode(), ProtectionMode::Working);

        // With work running, entering maintenance requires the explicit override. The refusal
        // path itself is covered by `maintenance_is_refused_while_agents_run`.
        c.enter_maintenance(Some("I understand the risk".into()))
            .expect("the override must be accepted");
        assert_eq!(
            c.mode(),
            ProtectionMode::Maintenance,
            "an explicit user decision outranks a derived mode"
        );

        // And leaving maintenance returns to the derived mode rather than staying NORMAL.
        c.exit_maintenance().unwrap();
        assert_eq!(
            c.mode(),
            ProtectionMode::Working,
            "the mode must be re-derived from the live inventory on exit"
        );
    }

    #[test]
    fn worker_degradation_appears_in_service_health() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        let registry = HealthRegistry::new();
        registry.mark_running("network");
        registry.mark_failed("agents", "boom".into(), 5);

        c.set_workers(&registry);
        let health = c.read().service_health(1_000_500);
        assert!(health.running);
        assert!(
            health.degraded_components.contains(&"agents".to_string()),
            "a failed worker must be visible: {:?}",
            health.degraded_components
        );
        assert!(!health.degraded_components.contains(&"network".to_string()));
    }

    #[test]
    fn pending_reboot_is_refreshed_from_the_probe() {
        let probe = FakePendingReboot::default();
        *probe.signals.borrow_mut() = vec![RebootSignal {
            id: "cbs.reboot_pending".into(),
            source: RebootSignalSource::ComponentServicing,
            present: true,
            weight: RebootSignalWeight::Conclusive,
            detail: "servicing wants a restart".into(),
            read_failed: false,
        }];
        let c = coordinator(FakeClock::new(1_000_000), probe);

        c.refresh_pending_reboot();
        assert_eq!(
            c.read().pending_reboot.verdict,
            PendingRebootVerdict::Pending
        );
    }

    #[test]
    fn a_pending_reboot_is_a_maintenance_blocker() {
        let probe = FakePendingReboot::default();
        *probe.signals.borrow_mut() = vec![RebootSignal {
            id: "cbs.reboot_pending".into(),
            source: RebootSignalSource::ComponentServicing,
            present: true,
            weight: RebootSignalWeight::Conclusive,
            detail: "servicing wants a restart".into(),
            read_failed: false,
        }];
        let c = coordinator(FakeClock::new(1_000_000), probe);
        c.refresh_pending_reboot();

        let blockers = c.read().maintenance_blockers();
        assert!(
            blockers.iter().any(|b| b.contains("pending")),
            "a pending restart must be shown before maintenance: {blockers:?}"
        );
    }

    #[test]
    fn incidents_are_bounded() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        for i in 0..600 {
            c.add_incident(Incident {
                id: format!("i{i}"),
                kind: IncidentKind::NetworkOutage,
                at_ms: 0,
                title: "t".into(),
                summary: "s".into(),
                severity: FindingSeverity::Info,
                details: IncidentDetails::default(),
            });
        }
        assert!(
            c.read().incidents.len() <= 500,
            "incident history must be bounded, got {}",
            c.read().incidents.len()
        );
    }

    #[test]
    fn the_status_snapshot_is_consistent_with_the_state() {
        let c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.set_agents(agent_inventory("claude_code", Confidence::Confirmed));
        c.set_helper_connected(true);

        let snapshot = c.read().snapshot(1_000_500);
        assert_eq!(snapshot.mode, ProtectionMode::Working);
        assert_eq!(snapshot.restart_protection, ProtectionLevel::Protected);
        assert_eq!(snapshot.session_id_helper, SessionHelperState::Connected);
        assert_eq!(snapshot.boot_id, "boot-1");
        assert!(snapshot.service.running);
        assert_eq!(snapshot.service.uptime_ms, 500);
    }

    #[test]
    fn auto_working_can_be_disabled() {
        let state = Arc::new(RwLock::new(ServiceState::initial(
            "boot-1".into(),
            0,
            "0.1.0".into(),
        )));
        let c = ProtectionCoordinator::new(
            state,
            FakeClock::new(0),
            FakePendingReboot::default(),
            MaintenancePolicy::default(),
            false, // auto_working off
            false,
        );

        c.set_agents(agent_inventory("claude_code", Confidence::Confirmed));
        assert_eq!(
            c.mode(),
            ProtectionMode::Normal,
            "with auto_working off, detections are reported but do not change the mode"
        );
    }

    #[test]
    fn a_policy_setting_change_is_applied() {
        let mut c = coordinator(FakeClock::new(1_000_000), FakePendingReboot::default());
        c.set_agents(agent_inventory("claude_code", Confidence::Confirmed));
        assert_eq!(c.mode(), ProtectionMode::Working);

        c.set_agent_behaviour(false, false);
        assert_eq!(c.mode(), ProtectionMode::Normal);
    }

    #[test]
    fn a_poisoned_state_lock_does_not_propagate_a_panic() {
        // If some thread panics while holding the write lock, protection must continue rather
        // than the whole service unwinding.
        let state = Arc::new(RwLock::new(ServiceState::initial(
            "boot-1".into(),
            0,
            "0.1.0".into(),
        )));

        let state2 = Arc::clone(&state);
        let _ = std::thread::spawn(move || {
            let _guard = state2.write().unwrap();
            panic!("deliberate panic while holding the lock");
        })
        .join();

        let c = ProtectionCoordinator::new(
            state,
            FakeClock::new(0),
            FakePendingReboot::default(),
            MaintenancePolicy::default(),
            true,
            false,
        );

        // Reading and writing must both still work.
        let _ = c.read();
        c.set_agents(AgentInventory::default());
        assert_eq!(c.mode(), ProtectionMode::Normal);
    }

    #[test]
    fn maintenance_policy_is_built_from_configuration() {
        let config = MaintenanceConfig {
            reboot_token_ttl_secs: 600,
            refuse_with_protected_work: false,
            override_phrase: "go".into(),
        };
        let policy = maintenance_policy_from(&config);
        assert_eq!(policy.reboot_token_ttl_secs, 600);
        assert!(!policy.refuse_with_protected_work);
        assert_eq!(policy.override_phrase, "go");
    }

    #[test]
    fn network_policy_is_built_from_configuration() {
        let config = NetworkConfig {
            failure_quorum: 3,
            stabilize_secs: 45,
            ..Default::default()
        };
        let policy = network_policy_from(&config);
        assert_eq!(policy.failure_quorum, 3);
        assert_eq!(policy.stabilize_secs, 45);
    }
}
