//! Shared data model: protection state, agents, network, incidents, configuration.
//!
//! These types are pure data. No Win32, no I/O, no clocks — the pure state machines in
//! `guardian-core` operate on them and are unit-testable without a host.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Protection state
// ---------------------------------------------------------------------------

/// The three global protection states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtectionMode {
    /// Automatic update activity locked, reboot blocked, guardians active.
    #[default]
    Normal,
    /// As `Normal`, plus active developer/agent workload and shutdown protection.
    Working,
    /// Explicitly entered by a user. Updates may be started manually; an automatic
    /// Windows Update reboot is still never silently authorized.
    Maintenance,
}

impl ProtectionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ProtectionMode::Normal => "NORMAL",
            ProtectionMode::Working => "WORKING",
            ProtectionMode::Maintenance => "MAINTENANCE",
        }
    }

    /// Whether shutdown protection should be requested from the session helper.
    pub fn wants_shutdown_block(self) -> bool {
        matches!(self, ProtectionMode::Working)
    }
}

/// Reported health of a single protection subsystem.
///
/// The cardinal rule: `Protected` is only ever reported when every required check
/// genuinely passed. Ambiguity resolves to `Unknown`/`Degraded`, never to `Protected`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionLevel {
    /// Every required check passed and nothing is externally overridden.
    Protected,
    /// Protection is applied but something weakens it (e.g. external policy wins).
    Degraded,
    /// The user explicitly unlocked this subsystem (maintenance mode).
    Maintenance,
    /// Not yet verified, backend unreachable, or evidence is contradictory.
    Unknown,
    /// Protection is known to be absent.
    Unprotected,
}

impl ProtectionLevel {
    /// True only for the fully-verified case. Used to gate the UI word "Protected".
    pub fn is_protected(self) -> bool {
        matches!(self, ProtectionLevel::Protected)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ProtectionLevel::Protected => "Protected",
            ProtectionLevel::Degraded => "Degraded",
            ProtectionLevel::Maintenance => "Maintenance",
            ProtectionLevel::Unknown => "Unknown",
            ProtectionLevel::Unprotected => "Unprotected",
        }
    }
}

/// Status of a single Guardian-owned Windows Update policy value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyValueStatus {
    /// Registry value name, e.g. `NoAutoUpdate`.
    pub name: String,
    /// What Guardian intends the value to be.
    pub desired: PolValue,
    /// What was actually read, or `None` when absent.
    pub observed: Option<PolValue>,
    /// True when `observed == desired`.
    pub matches: bool,
    /// Set when this value is externally controlled and Guardian must not fight it.
    pub external_owner: Option<String>,
}

impl PolicyValueStatus {
    pub fn conforms(&self) -> bool {
        self.external_owner.is_none() && self.matches
    }
}

/// A registry value Guardian manages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum PolValue {
    Dword(u32),
    String(String),
    ExpandString(String),
    MultiString(Vec<String>),
}

impl PolValue {
    pub fn as_dword(&self) -> Option<u32> {
        match self {
            PolValue::Dword(v) => Some(*v),
            _ => None,
        }
    }
}

/// Outcome of one verification pass over the Windows Update policy surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProtectionReport {
    pub level: ProtectionLevel,
    /// Whether `NoAutoUpdate=1` is genuinely in effect (the primary protection).
    pub primary_lock_effective: bool,
    /// Per-value detail for everything Guardian owns.
    pub values: Vec<PolicyValueStatus>,
    /// Deadline/deferral policies that would undermine the lock if left enabled.
    pub neutralized_deadlines: Vec<DeadlinePolicyStatus>,
    /// Management state of the host.
    pub management: ManagementState,
    /// Human-readable explanations for anything that is not `Protected`.
    pub findings: Vec<Finding>,
    /// When this report was produced (Unix ms, UTC).
    pub checked_at_ms: i64,
    pub backend_error: Option<String>,
}

impl UpdateProtectionReport {
    /// A report that could not be produced. Fail-closed: this is **not** `Protected`.
    pub fn unavailable(reason: impl Into<String>, at_ms: i64) -> Self {
        UpdateProtectionReport {
            level: ProtectionLevel::Unknown,
            primary_lock_effective: false,
            values: Vec::new(),
            neutralized_deadlines: Vec::new(),
            management: ManagementState::Unknown,
            findings: vec![Finding {
                severity: FindingSeverity::Error,
                code: "update.backend_unavailable".into(),
                message: reason.into(),
            }],
            checked_at_ms: at_ms,
            backend_error: Some("backend unavailable".into()),
        }
    }
}

/// Status of a Windows Update deadline policy that could force a reboot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlinePolicyStatus {
    pub name: String,
    /// What was observed before Guardian acted, if anything.
    pub observed: Option<PolValue>,
    /// True when Guardian has ensured it cannot force a reboot.
    pub neutralized: bool,
    pub external_owner: Option<String>,
}

/// How this machine's update policy is governed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ManagementState {
    /// Not domain joined, no MDM enterprise enrollment. Local policy is authoritative.
    Unmanaged,
    /// Domain joined. Local policy may be overwritten by Group Policy at any refresh.
    DomainJoined { domain: String },
    /// MDM/Intune enrolled; `PolicyManager` may win over local policy.
    MdmEnrolled { provider: String },
    /// Both, or an unexpected combination.
    DomainAndMdm { domain: String, provider: String },
    /// Could not determine. Treated as at-risk.
    ///
    /// This is the `Default` deliberately: an unknown management state must never be
    /// treated as "unmanaged", because that would let Guardian claim protection it may not
    /// actually have.
    #[default]
    Unknown,
}

impl ManagementState {
    /// Whether an external authority could plausibly override local policy.
    pub fn is_externally_managed(&self) -> bool {
        !matches!(self, ManagementState::Unmanaged)
    }

    pub fn describe(&self) -> String {
        match self {
            ManagementState::Unmanaged => "not externally managed".into(),
            ManagementState::DomainJoined { domain } => {
                format!("domain joined ({domain})")
            }
            ManagementState::MdmEnrolled { provider } => {
                format!("MDM enrolled ({provider})")
            }
            ManagementState::DomainAndMdm { domain, provider } => {
                format!("domain joined ({domain}) and MDM enrolled ({provider})")
            }
            ManagementState::Unknown => "management state could not be determined".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: FindingSeverity,
    /// Stable machine-readable code, e.g. `update.external_policy`.
    pub code: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Pending reboot
// ---------------------------------------------------------------------------

/// Aggregated pending-reboot verdict. Deliberately not a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingRebootVerdict {
    NotPending,
    ProbablyPending,
    Pending,
    Unknown,
}

impl PendingRebootVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            PendingRebootVerdict::NotPending => "NotPending",
            PendingRebootVerdict::ProbablyPending => "ProbablyPending",
            PendingRebootVerdict::Pending => "Pending",
            PendingRebootVerdict::Unknown => "Unknown",
        }
    }
}

/// One servicing signal that contributes to the pending-reboot verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebootSignal {
    /// Stable id, e.g. `cbs.reboot_pending`.
    pub id: String,
    /// Where the signal came from.
    pub source: RebootSignalSource,
    pub present: bool,
    /// Weight toward `Pending` when present. High-weight signals are unambiguous.
    pub weight: RebootSignalWeight,
    /// Plain-language explanation suitable for the UI.
    pub detail: String,
    /// True when the signal could not be read at all (counts toward `Unknown`).
    pub read_failed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootSignalSource {
    Registry,
    FileSystem,
    WindowsUpdate,
    ComponentServicing,
    EventLog,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebootSignalWeight {
    /// Weak/ambiguous on its own (e.g. `PendingFileRenameOperations`).
    Weak,
    /// Strong: a well-established indicator.
    Strong,
    /// Conclusive on its own.
    Conclusive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRebootReport {
    pub verdict: PendingRebootVerdict,
    pub signals: Vec<RebootSignal>,
    pub checked_at_ms: i64,
}

impl PendingRebootReport {
    pub fn unknown(reason: impl Into<String>, at_ms: i64) -> Self {
        PendingRebootReport {
            verdict: PendingRebootVerdict::Unknown,
            signals: vec![RebootSignal {
                id: "probe.failed".into(),
                source: RebootSignalSource::Registry,
                present: false,
                weight: RebootSignalWeight::Weak,
                detail: reason.into(),
                read_failed: true,
            }],
            checked_at_ms: at_ms,
        }
    }

    /// Human-readable list of why the machine believes a reboot is pending.
    pub fn reasons(&self) -> Vec<&str> {
        self.signals
            .iter()
            .filter(|s| s.present || s.read_failed)
            .map(|s| s.detail.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------

/// Confidence in an agent detection.
///
/// Only `Confirmed` and `High` create WORKING protection. `Possible` is surfaced in the UI
/// and diagnostics but never blocks shutdown, which is what keeps false positives from
/// becoming a permanent nuisance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Unknown,
    Possible,
    High,
    Confirmed,
}

impl Confidence {
    /// Whether this confidence is strong enough to trigger WORKING protection.
    pub fn drives_protection(self) -> bool {
        matches!(self, Confidence::Confirmed | Confidence::High)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Confirmed => "Confirmed",
            Confidence::High => "High",
            Confidence::Possible => "Possible",
            Confidence::Unknown => "Unknown",
        }
    }
}

/// One piece of evidence supporting (or refuting) a detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Stable code, e.g. `image_path`, `package_path`, `parent_process`, `cmdline_flag`.
    pub code: String,
    /// What specifically matched, e.g. the regex id or the literal string. Never secrets.
    pub matched: String,
    /// Confidence contribution, added to the total.
    pub weight: i32,
    /// Human-readable explanation for the UI and logs.
    pub detail: String,
}

impl Evidence {
    pub fn new(
        code: impl Into<String>,
        matched: impl Into<String>,
        weight: i32,
        detail: impl Into<String>,
    ) -> Self {
        Evidence {
            code: code.into(),
            matched: matched.into(),
            weight,
            detail: detail.into(),
        }
    }
}

/// Neutral, agent-independent snapshot of a process. Produced by `guardian-process`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub pid: u32,
    pub parent_pid: u32,
    /// Image file name, e.g. `node.exe`.
    pub name: String,
    /// Full image path when readable.
    pub image_path: Option<String>,
    /// Command line when readable (requires appropriate access; often unavailable for
    /// processes owned by other users or protected processes).
    pub cmdline: Option<String>,
    /// Process creation time as a Windows FILETIME (100 ns since 1601 UTC). Used together
    /// with `pid` to defeat PID reuse.
    pub created_filetime: u64,
    /// Windows session id. 0 for services.
    pub session_id: u32,
    /// Owning user SID string when resolvable.
    pub user_sid: Option<String>,
    /// True when `cmdline` could not be read due to permissions rather than the process
    /// having no command line.
    pub cmdline_denied: bool,
}

impl ProcessSnapshot {
    /// Stable identity: PID alone is not enough because of PID reuse.
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            created_filetime: self.created_filetime,
        }
    }

    /// Lowercased image name for case-insensitive matching on Windows.
    pub fn name_lower(&self) -> String {
        self.name.to_ascii_lowercase()
    }

    pub fn image_path_lower(&self) -> Option<String> {
        self.image_path.as_ref().map(|p| p.to_ascii_lowercase())
    }

    pub fn cmdline_lower(&self) -> Option<String> {
        self.cmdline.as_ref().map(|c| c.to_ascii_lowercase())
    }
}

/// A process identity that is stable across PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub created_filetime: u64,
}

/// A single detected agent instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstance {
    /// Signature id that produced this detection, e.g. `claude_code`.
    pub kind: String,
    /// Human-readable name, e.g. `Claude Code`.
    pub display_name: String,
    /// Pid of the process that matched the signature.
    pub pid: u32,
    /// Root pid of the owning agent session (may equal `pid`).
    pub root_pid: u32,
    /// Identity of the matched process, for PID-reuse-safe bookkeeping.
    pub identity: ProcessIdentity,
    /// Stable id grouping this instance with its descendants.
    pub session_id: String,
    pub confidence: Confidence,
    pub evidence: Vec<Evidence>,
    pub started_at_filetime: u64,
    pub started_at_ms: i64,
    pub image_path: Option<String>,
    pub cmdline: Option<String>,
    /// Ancestor chain from immediate parent outward (name + pid), for the UI.
    pub ancestry: Vec<AncestorRef>,
    pub session_id_windows: u32,
    pub user: Option<String>,
    /// Best-known working directory/project, if a reliable adapter supplied it.
    pub project: Option<ProjectContext>,
    /// Whether an adapter believes this session can be resumed.
    pub resume: ResumeCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AncestorRef {
    pub pid: u32,
    pub name: String,
}

/// Project context, only populated from reliable sources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectContext {
    /// Absolute path to the project root.
    pub root: String,
    /// Final path component, for display.
    pub name: String,
    /// Where the path came from, e.g. `claude_session_file`, `grok_active_sessions`.
    pub source: String,
    pub vcs: Option<VcsState>,
}

/// Version-control state of the project, when it could be read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VcsState {
    pub kind: String,
    pub branch: Option<String>,
    pub head: Option<String>,
    /// True when there are uncommitted changes; `None` when unknown.
    pub dirty: Option<bool>,
    /// Files with uncommitted changes, capped for readability.
    pub dirty_files: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResumeCapability {
    /// A resume handle is available and the session can be resumed.
    Available {
        /// Agent-specific identifier (session id / rollout id). Not a secret.
        handle: String,
        /// How an operator would resume, for display only. Never executed automatically.
        hint: String,
    },
    /// The agent supports resume but no handle was found.
    Unsupported,
    /// Nothing is known about resuming this session. The default, because offering a resume
    /// the agent cannot honour is worse than offering none.
    #[default]
    Unavailable,
}

/// An agent plus all detected instances of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentGroup {
    pub kind: String,
    pub display_name: String,
    pub instances: Vec<AgentInstance>,
    /// Highest confidence across instances.
    pub confidence: Confidence,
}

/// A process judged to be protected long-running development work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedWorkload {
    /// Rule id that matched, e.g. `cargo`, `rustc`, or a user rule id.
    pub rule_id: String,
    pub display_name: String,
    pub pid: u32,
    pub identity: ProcessIdentity,
    /// Agent session this belongs to, when it is a descendant of a detected agent.
    pub owner_session: Option<String>,
    pub owner_kind: Option<String>,
    pub started_at_ms: i64,
    pub running_ms: i64,
    pub image_path: Option<String>,
    pub cmdline: Option<String>,
    /// Why this is protected; shown in the maintenance-denial dialog.
    pub reason: String,
}

/// A candidate the discovery engine thinks might be an agent but cannot confirm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCandidate {
    /// Stable id derived from the evidence, so promotions are reproducible.
    pub candidate_id: String,
    pub pid: u32,
    pub identity: ProcessIdentity,
    pub name: String,
    pub image_path: Option<String>,
    pub cmdline: Option<String>,
    pub confidence: Confidence,
    /// What made this look agent-like.
    pub evidence: Vec<Evidence>,
    pub first_seen_ms: i64,
    pub last_seen_ms: i64,
    /// Processes still alive under this candidate; used to avoid promoting dead noise.
    pub observations: u32,
}

/// The whole picture of what is running.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInventory {
    pub agents: Vec<AgentGroup>,
    pub workloads: Vec<ProtectedWorkload>,
    /// Unconfirmed agent-like processes.
    pub candidates: Vec<AgentCandidate>,
    pub updated_at_ms: i64,
    /// Health of the underlying process monitor.
    pub monitor: MonitorHealth,
}

impl AgentInventory {
    /// Counts only instances at or above `threshold`.
    pub fn count_at_least(&self, threshold: Confidence) -> usize {
        self.agents
            .iter()
            .flat_map(|g| g.instances.iter())
            .filter(|i| i.confidence >= threshold)
            .count()
    }

    /// Whether WORKING protection is warranted.
    ///
    /// Only `Confirmed`/`High` agents, or protected workloads owned by them, count.
    /// A standalone long build with no agent counts only when it is explicitly configured
    /// to (see `WorkloadRule::protects_standalone`), which keeps an idle background `node`
    /// from blocking shutdown forever.
    pub fn warrants_working(&self, protect_standalone_builds: bool) -> bool {
        if self.count_at_least(Confidence::High) > 0 {
            return true;
        }
        self.workloads.iter().any(|w| {
            w.owner_session.is_some() || (protect_standalone_builds && w.rule_id != "unknown")
        })
    }

    pub fn agent_count(&self) -> usize {
        self.agents.iter().map(|g| g.instances.len()).sum()
    }
}

/// Health of the process monitor, surfaced so a silent failure cannot masquerade as
/// "no agents running".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorHealth {
    /// True when the monitor has produced a fresh inventory within its expected interval.
    pub healthy: bool,
    /// True when the event-driven source is active; false means polling fallback only.
    pub event_source_active: bool,
    pub last_inventory_ms: i64,
    /// Age of the last successful full sweep.
    pub last_sweep_age_ms: i64,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
}

impl Default for MonitorHealth {
    fn default() -> Self {
        MonitorHealth {
            healthy: false,
            event_source_active: false,
            last_inventory_ms: 0,
            last_sweep_age_ms: i64::MAX,
            consecutive_failures: 0,
            last_error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPhase {
    Start,
    CheckRas,
    Online,
    Suspect,
    Offline,
    Cleanup,
    Dialing,
    Authenticating,
    Verifying,
    Backoff,
    /// No suitable entry configured; the user must choose one.
    Unconfigured,
    /// PPPoE is not managed on this machine (feature disabled by config).
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternetHealth {
    Healthy,
    Degraded,
    Down,
    Unknown,
}

impl InternetHealth {
    pub fn as_str(self) -> &'static str {
        match self {
            InternetHealth::Healthy => "healthy",
            InternetHealth::Degraded => "degraded",
            InternetHealth::Down => "down",
            InternetHealth::Unknown => "unknown",
        }
    }
}

/// One configured connectivity probe and its last result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub id: String,
    pub kind: ProbeKind,
    pub target: String,
    pub ok: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Tcp,
    Dns,
    /// Reads the RAS connection state directly (no network traffic).
    RasState,
    /// Interface link state + default route.
    Interface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RasConnectionState {
    Connected,
    Disconnected,
    Connecting,
    Disconnecting,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutageRecord {
    pub id: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub downtime_ms: Option<i64>,
    /// Why the state machine concluded the link was down.
    pub reason: String,
    pub dial_attempts: u32,
    /// Raw RAS error codes observed, with translations.
    pub ras_errors: Vec<RasErrorRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RasErrorRecord {
    pub code: u32,
    pub message: String,
    pub at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub phase: NetworkPhase,
    pub internet: InternetHealth,
    pub entry_name: Option<String>,
    pub ras_state: RasConnectionState,
    /// Milliseconds since the current connection was established.
    pub uptime_ms: Option<i64>,
    pub online_since_ms: Option<i64>,
    pub last_reconnect_ms: Option<i64>,
    pub probes: Vec<ProbeResult>,
    /// Consecutive probes that must fail before declaring the link down.
    pub quorum_required: u32,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub dial_attempts_current_outage: u32,
    pub backoff_ms: u64,
    pub current_outage: Option<OutageRecord>,
    pub recent_outages: Vec<OutageRecord>,
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
}

impl Default for NetworkSnapshot {
    fn default() -> Self {
        NetworkSnapshot {
            phase: NetworkPhase::Start,
            internet: InternetHealth::Unknown,
            entry_name: None,
            ras_state: RasConnectionState::Unknown,
            uptime_ms: None,
            online_since_ms: None,
            last_reconnect_ms: None,
            probes: Vec::new(),
            quorum_required: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            dial_attempts_current_outage: 0,
            backoff_ms: 0,
            current_outage: None,
            recent_outages: Vec::new(),
            last_error: None,
            updated_at_ms: 0,
        }
    }
}

/// A RAS phonebook entry discovered on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RasEntryInfo {
    pub name: String,
    /// `RASENTRY.type` bitmask.
    pub entry_type: u32,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    /// True when the entry looks like a broadband/PPPoE connection.
    pub looks_like_broadband: bool,
}

// ---------------------------------------------------------------------------
// Incidents / recovery
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentKind {
    /// Prior session did not terminate cleanly.
    UnexpectedRestart,
    /// Guardian-owned policy was changed by something else.
    PolicyTamper,
    /// Protection could not be verified or applied.
    ProtectionDegraded,
    /// A worker failed and was restarted.
    WorkerFailure,
    /// Network outage that exceeded a configured threshold.
    NetworkOutage,
    /// Maintenance mode was entered.
    MaintenanceEntered,
    /// Maintenance mode was exited without rebooting.
    MaintenanceExited,
    /// A single-use reboot authorization was armed.
    RebootArmed,
    /// A reboot authorization expired unused.
    RebootExpired,
    /// Config was rejected as invalid.
    ConfigRejected,
}

/// How confident the classification is. Never claim a cause when evidence is ambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CauseConfidence {
    Confirmed,
    Likely,
    Possible,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsUpdateRelation {
    Yes,
    No,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incident {
    pub id: String,
    pub kind: IncidentKind,
    pub at_ms: i64,
    pub title: String,
    pub summary: String,
    pub severity: FindingSeverity,
    pub details: IncidentDetails,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IncidentDetails {
    /// Only set for `UnexpectedRestart`.
    pub unexpected_restart: Option<UnexpectedRestart>,
    /// Only set for `PolicyTamper`.
    pub policy_tamper: Option<PolicyTamper>,
    /// Only set for `WorkerFailure`.
    pub worker_failure: Option<WorkerFailure>,
    /// Extra structured fields that are safe to display and never contain secrets.
    pub extra: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnexpectedRestart {
    pub detected_at_ms: i64,
    pub previous_boot_id: String,
    pub current_boot_id: String,
    /// What Windows records suggest started the shutdown, if anything.
    pub likely_initiator: Option<String>,
    pub reason: Option<String>,
    pub confidence: CauseConfidence,
    pub windows_update_related: WindowsUpdateRelation,
    /// Evidence pulled from the event log, so the claim is auditable.
    pub evidence: Vec<EventEvidence>,
    pub agents_lost: Vec<LostAgent>,
    pub protected_jobs_lost: usize,
    pub last_heartbeat_ms: Option<i64>,
    pub last_network_state: Option<String>,
    /// Previous session had armed a reboot authorization.
    pub reboot_was_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEvidence {
    /// e.g. `User32`, `Kernel-Power`, `EventLog`.
    pub provider: String,
    pub event_id: u32,
    pub at_ms: i64,
    /// Rendered message, truncated and redacted.
    pub message: String,
}

/// An agent that was running before an unclean termination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LostAgent {
    pub kind: String,
    pub display_name: String,
    pub pid: u32,
    pub session_id: String,
    pub project: Option<String>,
    pub last_seen_ms: i64,
    pub resume: ResumeCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyTamper {
    pub value_name: String,
    pub expected: PolValue,
    pub observed: Option<PolValue>,
    /// Which registry key, for auditability.
    pub key_path: String,
    pub detected_at_ms: i64,
    /// True when Guardian successfully restored the value.
    pub restored: bool,
    pub restore_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerFailure {
    pub worker: String,
    pub error: String,
    pub restarts: u32,
    pub at_ms: i64,
}

// ---------------------------------------------------------------------------
// Reboot authorization
// ---------------------------------------------------------------------------

/// A persisted, single-use capability permitting exactly one reboot.
///
/// Invariants enforced by `guardian-core::maintenance`:
/// * only one may be live at a time;
/// * it expires (`expires_at_ms`);
/// * it is consumed exactly once, by the boot it authorized;
/// * it can never authorize a *second* reboot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebootAuthorization {
    pub id: String,
    /// Random nonce; possession implies the capability. Not a secret from the operator.
    pub nonce: String,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    /// Boot id that existed when the capability was issued.
    pub issued_boot_id: String,
    /// Set once a shutdown/restart is observed under this capability.
    pub consumed_at_ms: Option<i64>,
    /// Boot id observed after the reboot that consumed it.
    pub consumed_by_boot_id: Option<String>,
    /// Why it was armed, for the audit trail.
    pub reason: String,
    /// Who armed it (principal string).
    pub issued_by: String,
}

impl RebootAuthorization {
    /// Whether the capability is still usable at `now_ms` for `boot_id`.
    ///
    /// A capability is *not* usable once a reboot has been observed under it, and it never
    /// survives a boot change, which is what stops reuse after an unexpected reboot.
    pub fn is_usable(&self, now_ms: i64, boot_id: &str) -> bool {
        self.consumed_at_ms.is_none()
            && now_ms < self.expires_at_ms
            && self.issued_boot_id == boot_id
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at_ms
    }

    pub fn remaining_ms(&self, now_ms: i64) -> i64 {
        (self.expires_at_ms - now_ms).max(0)
    }
}

// ---------------------------------------------------------------------------
// Status snapshot (the UI's single source of truth)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub mode: ProtectionMode,
    pub update: UpdateProtectionReport,
    pub restart_protection: ProtectionLevel,
    pub pending_reboot: PendingRebootReport,
    pub service: ServiceHealth,
    pub agents: Box<AgentInventory>,
    pub network: Box<NetworkSnapshot>,
    pub reboot_authorization: Option<RebootAuthorization>,
    pub maintenance_denial_reasons: Vec<String>,
    pub generated_at_ms: i64,
    pub service_version: String,
    pub boot_id: String,
    pub session_id_helper: SessionHelperState,
}

/// Health of the Windows service itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealth {
    pub running: bool,
    pub started_at_ms: i64,
    pub uptime_ms: i64,
    pub version: String,
    /// Set when the service is up but one or more subsystems are degraded.
    pub degraded_components: Vec<String>,
    /// Set when the service is running from a recovery restart after a crash.
    pub started_after_unclean_exit: bool,
}

impl ServiceHealth {
    /// Render this health as a set of doctor-style checks.
    ///
    /// Kept next to the type so the service and `guardianctl doctor` cannot disagree about
    /// what "healthy" means.
    pub fn into_health_report(self) -> HealthReport {
        let mut checks = vec![
            HealthCheck {
                id: "service.running".into(),
                name: "Service running".into(),
                ok: self.running,
                severity: if self.running {
                    FindingSeverity::Info
                } else {
                    FindingSeverity::Error
                },
                detail: if self.running {
                    format!("running for {}s", self.uptime_ms / 1000)
                } else {
                    "the service is not running".into()
                },
            },
            HealthCheck {
                id: "service.components".into(),
                name: "Subsystems healthy".into(),
                ok: self.degraded_components.is_empty(),
                severity: if self.degraded_components.is_empty() {
                    FindingSeverity::Info
                } else {
                    FindingSeverity::Warning
                },
                detail: if self.degraded_components.is_empty() {
                    "every subsystem is running and has reported progress".into()
                } else {
                    format!("degraded: {}", self.degraded_components.join(", "))
                },
            },
        ];

        if self.started_after_unclean_exit {
            checks.push(HealthCheck {
                id: "service.unclean_exit".into(),
                name: "Previous session ended cleanly".into(),
                ok: false,
                severity: FindingSeverity::Warning,
                detail: "the previous session did not shut down cleanly; see the incident log"
                    .into(),
            });
        }

        HealthReport {
            checks,
            generated_at_ms: crate::model::now_ms_for_report(),
        }
    }
}

/// Current Unix time in milliseconds.
///
/// A small helper so the model crate can stamp a report without depending on a clock
/// abstraction; the service uses its injected clock for everything that affects a decision.
pub(crate) fn now_ms_for_report() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionHelperState {
    Connected,
    NotRunning,
    Disconnected,
    VersionMismatch,
}

/// Result of `guardianctl doctor`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub checks: Vec<HealthCheck>,
    pub generated_at_ms: i64,
}

impl HealthReport {
    pub fn worst(&self) -> FindingSeverity {
        self.checks
            .iter()
            .map(|c| c.severity)
            .max()
            .unwrap_or(FindingSeverity::Info)
    }

    pub fn all_ok(&self) -> bool {
        self.checks.iter().all(|c| c.ok)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheck {
    /// Stable id, e.g. `service.running`.
    pub id: String,
    /// Human-readable name, e.g. "Service running".
    pub name: String,
    pub ok: bool,
    pub severity: FindingSeverity,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Current configuration schema version. Bumped on breaking changes; migrations handle
/// forward movement. Unknown *fields* are preserved on round-trip so an older build does
/// not destroy a newer build's settings.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigDocument {
    pub schema_version: u32,
    /// Wrapper that captures unknown fields so they survive a downgrade.
    #[serde(flatten)]
    pub body: ConfigBody,
}

impl Default for ConfigDocument {
    fn default() -> Self {
        ConfigDocument {
            schema_version: CONFIG_SCHEMA_VERSION,
            body: ConfigBody::default(),
        }
    }
}

/// Live configuration, with unknown future fields retained in `unknown`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ConfigBody {
    #[serde(default)]
    pub update: UpdateConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub agents: AgentConfig,
    #[serde(default)]
    pub maintenance: MaintenanceConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub notifications: NotificationConfig,
    /// Unknown fields from a newer schema, preserved verbatim.
    #[serde(flatten, default)]
    pub unknown: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Apply the local Windows Update lock. Turning this off is an explicit, auditable
    /// choice; it is still restored to `true` after any config-load failure.
    pub protect: bool,
    /// Re-apply policy when a mismatch is detected (as opposed to only reporting it).
    pub auto_restore: bool,
    /// Seconds between verification passes. Deliberately low-frequency: the policy is
    /// stable and constant registry traffic is itself a bug.
    pub verify_interval_secs: u64,
    /// Whether to disable automatic restart after a BSOD.
    ///
    /// This is *not* protection against the crash — it keeps the failure observable.
    /// Shown during setup because it changes unrelated system behaviour.
    pub disable_bsod_auto_restart: bool,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        UpdateConfig {
            protect: true,
            auto_restore: true,
            verify_interval_secs: 120,
            disable_bsod_auto_restart: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub enabled: bool,
    /// Selected RAS entry name. `None` means "auto-select when unambiguous".
    pub entry_name: Option<String>,
    /// Seconds between connectivity checks while online.
    pub check_interval_secs: u64,
    /// Consecutive probe rounds that must fail before declaring the link down.
    pub failure_quorum: u32,
    /// Consecutive successful rounds required before declaring the link healthy again.
    pub success_quorum: u32,
    /// How long the link must stay healthy before the backoff resets.
    pub stabilize_secs: u64,
    /// Minimum time to wait before hanging up a stale session, to avoid flapping.
    pub stale_grace_secs: u64,
    /// Whether Guardian may resume a case where a non-Guardian RAS session holds the link.
    pub adopt_existing_sessions: bool,
    pub probes: Vec<ProbeConfig>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        NetworkConfig {
            enabled: true,
            entry_name: None,
            check_interval_secs: 20,
            failure_quorum: 2,
            success_quorum: 2,
            stabilize_secs: 120,
            stale_grace_secs: 30,
            adopt_existing_sessions: true,
            probes: default_probes(),
        }
    }
}

/// Independent connectivity probes. Several providers, none of them authoritative alone.
pub fn default_probes() -> Vec<ProbeConfig> {
    vec![
        ProbeConfig {
            id: "cloudflare-dns-tcp".into(),
            kind: ProbeKind::Tcp,
            target: "1.1.1.1:443".into(),
            timeout_ms: 2000,
            enabled: true,
        },
        ProbeConfig {
            id: "google-dns-tcp".into(),
            kind: ProbeKind::Tcp,
            target: "8.8.8.8:443".into(),
            timeout_ms: 2000,
            enabled: true,
        },
        ProbeConfig {
            id: "system-dns".into(),
            kind: ProbeKind::Dns,
            target: "www.msftconnecttest.com".into(),
            timeout_ms: 3000,
            enabled: true,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeConfig {
    pub id: String,
    pub kind: ProbeKind,
    /// `host:port` for Tcp, a hostname for Dns.
    pub target: String,
    pub timeout_ms: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Enable the agent detector at all.
    pub enabled: bool,
    /// Automatically treat `Confirmed`/`High` detections as WORKING.
    pub auto_working: bool,
    /// Whether a standalone (non-agent-owned) long build is enough for WORKING.
    /// Default false: a stray background `node` should not block shutdown forever.
    pub protect_standalone_workloads: bool,
    /// Seconds between full process sweeps when the event source is healthy.
    pub sweep_interval_secs: u64,
    /// Seconds between sweeps when running on the polling fallback.
    pub fallback_poll_interval_secs: u64,
    /// Runtime threshold before an unowned workload rule matches.
    pub standalone_min_runtime_secs: u64,
    /// User signatures merged over the built-in database.
    pub user_signatures: Vec<AgentSignature>,
    /// User workload rules merged over the built-in set.
    pub user_workload_rules: Vec<WorkloadRule>,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            enabled: true,
            auto_working: true,
            protect_standalone_workloads: false,
            sweep_interval_secs: 5,
            fallback_poll_interval_secs: 3,
            standalone_min_runtime_secs: 300,
            user_signatures: Vec::new(),
            user_workload_rules: Vec::new(),
        }
    }
}

/// A data-driven agent signature. Built-ins and user signatures share this shape, so
/// adding a new agent never requires touching detection code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSignature {
    /// Stable id, e.g. `claude_code`.
    pub id: String,
    pub display_name: String,
    /// Whether this signature ships with Guardian or was added by the user.
    #[serde(default)]
    pub user_defined: bool,
    /// How this signature contributes to confidence.
    pub confidence: SignatureConfidence,
    pub rules: SignatureRules,
    /// Whether Guardian may attempt to read local session state for this agent.
    #[serde(default)]
    pub adapter: Option<AgentAdapterKind>,
    /// Human-readable notes shown in the UI.
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureConfidence {
    /// Matching the required rules alone is conclusive.
    Confirmed,
    /// Matching the required rules alone is strong evidence.
    High,
    /// Matching the required rules alone is a hint; corroboration is needed.
    Possible,
}

/// Which adapter can supply project/resume metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAdapterKind {
    ClaudeCode,
    Codex,
    Grok,
    /// Reads nothing; keeps the process-level detection only.
    None,
}

/// Evidence rules for a signature.
///
/// A signature matches when:
/// * `any_of` is non-empty and at least one rule matches, **or**
/// * `all_of` matches entirely, and
/// * no `none_of` rule matches (these are hard vetoes, e.g. "this is an MCP helper, not
///   the agent itself").
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignatureRules {
    #[serde(default)]
    pub any_of: Vec<Rule>,
    #[serde(default)]
    pub all_of: Vec<Rule>,
    #[serde(default)]
    pub none_of: Vec<Rule>,
}

/// A single evidence rule. `pattern` is validated as an anchored, bounded regex at load
/// time; pathological patterns are rejected before they can be compiled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub field: RuleField,
    /// A regular expression, matched case-insensitively against the field.
    pub pattern: String,
    /// Confidence contribution when this rule matches.
    pub weight: i32,
    /// Shown in the UI and in detection logs when this rule fires.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleField {
    /// Image file name only, e.g. `claude.exe`.
    ProcessName,
    /// Full image path.
    ImagePath,
    /// Full command line.
    CommandLine,
    /// Parent process image file name.
    ParentName,
    /// Parent image path or command line (bounded to the parent only).
    ParentPath,
    /// True when the process has a child whose name matches (e.g. agent CLI spawns `node`).
    ChildName,
    /// A path fragment appearing in the command line, e.g. a package directory.
    PackagePath,
}

/// A rule describing long-running development work worth protecting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkloadRule {
    pub id: String,
    pub display_name: String,
    /// Regex over the image file name.
    pub name_pattern: String,
    /// Optional regex the command line must match.
    #[serde(default)]
    pub cmdline_pattern: Option<String>,
    /// Seconds this must run before it counts, when not owned by an agent.
    pub min_runtime_secs: u64,
    /// Whether this alone can trigger WORKING without an owning agent.
    pub protects_standalone: bool,
    #[serde(default)]
    pub user_defined: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MaintenanceConfig {
    /// Default lifetime of a reboot authorization.
    pub reboot_token_ttl_secs: u64,
    /// Whether entering maintenance is refused while protected work exists.
    pub refuse_with_protected_work: bool,
    /// The exact phrase a user must type to override a refusal.
    pub override_phrase: String,
}

impl Default for MaintenanceConfig {
    fn default() -> Self {
        MaintenanceConfig {
            reboot_token_ttl_secs: 1800,
            refuse_with_protected_work: true,
            override_phrase: "I understand the risk".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Machine-wide state root. Defaults to `%ProgramData%\WorkstationGuardian`.
    pub data_dir: Option<String>,
    /// Whether the crash journal is written at the WORKING frequency as well as NORMAL.
    pub journal_working_frequency: bool,
    /// Maximum size of the journal file before it is compacted.
    pub journal_max_bytes: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        StorageConfig {
            data_dir: None,
            journal_working_frequency: true,
            journal_max_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// `error`, `warn`, `info`, `debug`, `trace`.
    pub level: String,
    /// Total size cap for the log directory.
    pub max_total_bytes: u64,
    /// Number of rotated files to keep.
    pub max_files: u32,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        LoggingConfig {
            level: "info".into(),
            max_total_bytes: 16 * 1024 * 1024,
            max_files: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationConfig {
    pub tray_notifications: bool,
    /// Notify when the update protection degrades.
    pub notify_on_degraded: bool,
    /// Notify when policy is tampered with.
    pub notify_on_tamper: bool,
    /// Notify when an unexpected restart is detected.
    pub notify_on_unexpected_restart: bool,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        NotificationConfig {
            tray_notifications: true,
            notify_on_degraded: true,
            notify_on_tamper: true,
            notify_on_unexpected_restart: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(pid: u32, root: u32, conf: Confidence, _owner: Option<&str>) -> AgentInstance {
        AgentInstance {
            kind: "test".into(),
            display_name: "Test".into(),
            pid,
            root_pid: root,
            identity: ProcessIdentity {
                pid,
                created_filetime: 1,
            },
            session_id: format!("s{root}"),
            confidence: conf,
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
        }
    }

    #[test]
    fn only_high_confidence_triggers_working() {
        let mut inv = AgentInventory::default();
        inv.agents.push(AgentGroup {
            kind: "a".into(),
            display_name: "A".into(),
            instances: vec![inst(1, 1, Confidence::Possible, None)],
            confidence: Confidence::Possible,
        });
        assert!(
            !inv.warrants_working(false),
            "a Possible detection must not block shutdown by default"
        );

        inv.agents.push(AgentGroup {
            kind: "b".into(),
            display_name: "B".into(),
            instances: vec![inst(2, 2, Confidence::High, None)],
            confidence: Confidence::High,
        });
        assert!(inv.warrants_working(false));
    }

    #[test]
    fn standalone_workload_only_protects_when_configured() {
        let mut inv = AgentInventory::default();
        inv.workloads.push(ProtectedWorkload {
            rule_id: "cargo".into(),
            display_name: "cargo".into(),
            pid: 10,
            identity: ProcessIdentity {
                pid: 10,
                created_filetime: 5,
            },
            owner_session: None,
            owner_kind: None,
            started_at_ms: 0,
            running_ms: 600_000,
            image_path: None,
            cmdline: None,
            reason: "long build".into(),
        });
        assert!(!inv.warrants_working(false));
        assert!(inv.warrants_working(true));
    }

    #[test]
    fn reboot_authorization_is_single_use_and_boot_bound() {
        let auth = RebootAuthorization {
            id: "a".into(),
            nonce: "n".into(),
            issued_at_ms: 1_000,
            expires_at_ms: 1_801_000,
            issued_boot_id: "boot-1".into(),
            consumed_at_ms: None,
            consumed_by_boot_id: None,
            reason: "test".into(),
            issued_by: "administrator".into(),
        };
        assert!(auth.is_usable(1_500, "boot-1"));
        // Expired -> unusable even on the right boot.
        assert!(!auth.is_usable(2_000_000, "boot-1"));
        // Wrong boot -> unusable (an unexpected reboot must not inherit the permit).
        assert!(!auth.is_usable(1_500, "boot-2"));

        let consumed = RebootAuthorization {
            consumed_at_ms: Some(1_600),
            consumed_by_boot_id: Some("boot-2".into()),
            ..auth.clone()
        };
        assert!(!consumed.is_usable(1_700, "boot-1"));
        assert!(!consumed.is_usable(1_700, "boot-2"));
    }

    #[test]
    fn protected_word_requires_all_checks() {
        assert!(ProtectionLevel::Protected.is_protected());
        for lvl in [
            ProtectionLevel::Degraded,
            ProtectionLevel::Maintenance,
            ProtectionLevel::Unknown,
            ProtectionLevel::Unprotected,
        ] {
            assert!(!lvl.is_protected(), "{lvl:?} must not read as Protected");
        }
    }

    #[test]
    fn externally_owned_policy_never_conforms() {
        let v = PolicyValueStatus {
            name: "NoAutoUpdate".into(),
            desired: PolValue::Dword(1),
            observed: Some(PolValue::Dword(1)),
            matches: true,
            external_owner: Some("Group Policy".into()),
        };
        assert!(!v.conforms());
    }

    #[test]
    fn config_preserves_unknown_fields() {
        let raw = serde_json::json!({
            "schema_version": 1,
            "update": { "protect": true, "auto_restore": true, "verify_interval_secs": 60,
                        "disable_bsod_auto_restart": false, "future_flag": 7 },
            "totally_new_section": { "x": 1 }
        });
        let doc: ConfigDocument = serde_json::from_value(raw).expect("decode");
        assert_eq!(
            doc.body.unknown.get("totally_new_section"),
            Some(&serde_json::json!({"x": 1})),
            "unknown top-level section must survive"
        );
        let re = serde_json::to_value(&doc).expect("encode");
        assert_eq!(
            re.get("totally_new_section"),
            Some(&serde_json::json!({"x": 1})),
            "unknown section must round-trip"
        );
    }

    #[test]
    fn unavailable_report_is_not_protected() {
        let r = UpdateProtectionReport::unavailable("registry unreadable", 42);
        assert_eq!(r.level, ProtectionLevel::Unknown);
        assert!(!r.level.is_protected());
        assert!(!r.primary_lock_effective);
    }
}
