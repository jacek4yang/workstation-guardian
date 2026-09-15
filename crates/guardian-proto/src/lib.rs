//! Versioned wire protocol shared by `guardian-service`, `guardian-session`,
//! `guardian-ui` and `guardianctl`.
//!
//! Design rules (see `docs/security.md`):
//!
//! * The protocol is **closed**. It exposes named operations, never primitives such as
//!   "run command" or "write registry value". The LocalSystem service must not be usable as
//!   a generic privilege-escalation primitive.
//! * Every frame is length-prefixed JSON with an explicit protocol version. Unknown fields
//!   are ignored on decode so that a newer CLI can still talk to an older service for the
//!   operations they share.
//! * Frames are bounded (`MAX_FRAME_LEN`) so a hostile local client cannot exhaust service
//!   memory by announcing a huge payload.

use serde::{Deserialize, Serialize};

pub mod model;

pub use model::*;

/// Current protocol version. Bumped on incompatible changes.
pub const PROTOCOL_VERSION: u16 = 1;

/// Hard cap on a single encoded frame (request or response).
///
/// Snapshots are small; 1 MiB is far above any legitimate payload while still bounding the
/// memory a hostile local client can make the service allocate for one frame.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

/// Default named-pipe name (no `\\.\pipe\` prefix) used by the service.
pub const PIPE_NAME: &str = "workstation-guardian-v1";

/// Full pipe path for `CreateFile`/`ConnectNamedPipe`.
pub const PIPE_PATH: &str = r"\\.\pipe\workstation-guardian-v1";

/// The principal a client claims to be, as validated by the service.
///
/// This is derived by the service from the *connecting token*, never from client-supplied
/// data. It exists on the wire only so clients can pre-check whether they should bother
/// asking; the service re-derives and enforces it on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Principal {
    /// LocalSystem or a system-integrity process.
    System,
    /// An elevated administrator.
    Administrator,
    /// A non-elevated local interactive user.
    InteractiveUser,
}

impl Principal {
    /// Whether this principal may mutate protection configuration.
    pub fn may_mutate_config(self) -> bool {
        matches!(self, Principal::System | Principal::Administrator)
    }

    /// Whether this principal may enter/exit maintenance mode and arm a reboot.
    pub fn may_control_maintenance(self) -> bool {
        matches!(self, Principal::System | Principal::Administrator)
    }

    /// Whether this principal may request a network reconnect.
    pub fn may_reconnect(self) -> bool {
        // A non-elevated interactive user may reconnect their own dial-up link; this is the
        // operation that most often needs to be fast, and it has no privilege impact.
        true
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Principal::System => "system",
            Principal::Administrator => "administrator",
            Principal::InteractiveUser => "interactive_user",
        }
    }
}

/// A request from a client to the service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Liveness + version negotiation.
    Hello { protocol: u16 },

    // ---- read-only status surface (any authenticated principal) ----
    GetStatus,
    GetAgents,
    GetIncidents { limit: u16 },
    GetNetwork,
    GetPendingReboot,
    GetConfig,
    /// Process/worker health of the service itself, for `guardianctl doctor`.
    GetHealth,

    // ---- privileged operations ----
    /// Try to reconnect the configured PPPoE entry now.
    Reconnect { reason: String },
    /// Ask to leave `LOCKED`. Denied when protected work exists unless `override_guard` is
    /// true, in which case a second confirmation is required by the UI.
    EnterMaintenance {
        override_protected_work: bool,
        confirmation: String,
    },
    /// Abandon maintenance without rebooting; protection is reapplied immediately.
    ExitMaintenance,
    /// Convert a live maintenance session into a single-use reboot authorization.
    ArmSingleReboot { ttl_secs: u32 },
    /// Discard an armed reboot authorization.
    DisarmReboot,
    GetRebootAuthorization,

    // ---- session-helper specific ----
    /// Long-poll for protection-state pushes. The service keeps the connection open and
    /// streams `Push` messages; this is how the session helper learns it must (un)block
    /// shutdown without polling.
    Subscribe { client: SubscriberKind },

    // ---- configuration ----
    /// Replace the whole configuration document (already validated by the service).
    UpdateConfig { config: Box<ConfigDocument> },
    /// Append a user-defined agent signature.
    AddAgentSignature { signature: Box<AgentSignature> },
    /// Remove a user-defined agent signature by id.
    RemoveAgentSignature { id: String },
    /// Promote a candidate found by the discovery engine into a local signature.
    PromoteCandidate { candidate_id: String },
}

impl Request {
    /// Minimum principal required for this request.
    pub fn required_principal(&self) -> Principal {
        match self {
            Request::Hello { .. }
            | Request::GetStatus
            | Request::GetAgents
            | Request::GetIncidents { .. }
            | Request::GetNetwork
            | Request::GetPendingReboot
            | Request::GetHealth
            | Request::GetRebootAuthorization => Principal::InteractiveUser,

            Request::GetConfig | Request::Subscribe { .. } | Request::Reconnect { .. } => {
                Principal::InteractiveUser
            }

            Request::EnterMaintenance { .. }
            | Request::ExitMaintenance
            | Request::ArmSingleReboot { .. }
            | Request::DisarmReboot => Principal::Administrator,

            Request::UpdateConfig { .. }
            | Request::AddAgentSignature { .. }
            | Request::RemoveAgentSignature { .. }
            | Request::PromoteCandidate { .. } => Principal::Administrator,
        }
    }

    /// Short operation name for logging without leaking payload (paths, config bodies).
    pub fn op_name(&self) -> &'static str {
        match self {
            Request::Hello { .. } => "hello",
            Request::GetStatus => "get_status",
            Request::GetAgents => "get_agents",
            Request::GetIncidents { .. } => "get_incidents",
            Request::GetNetwork => "get_network",
            Request::GetPendingReboot => "get_pending_reboot",
            Request::GetConfig => "get_config",
            Request::GetHealth => "get_health",
            Request::Reconnect { .. } => "reconnect",
            Request::EnterMaintenance { .. } => "enter_maintenance",
            Request::ExitMaintenance => "exit_maintenance",
            Request::ArmSingleReboot { .. } => "arm_single_reboot",
            Request::DisarmReboot => "disarm_reboot",
            Request::GetRebootAuthorization => "get_reboot_authorization",
            Request::Subscribe { .. } => "subscribe",
            Request::UpdateConfig { .. } => "update_config",
            Request::AddAgentSignature { .. } => "add_agent_signature",
            Request::RemoveAgentSignature { .. } => "remove_agent_signature",
            Request::PromoteCandidate { .. } => "promote_candidate",
        }
    }
}

/// Which kind of client opened a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriberKind {
    /// The per-user shutdown blocker.
    SessionHelper,
    /// The tray/control-panel UI (push-based updates, no polling).
    Ui,
    /// A one-shot diagnostics client that wants a single snapshot.
    Diagnostics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Hello {
        protocol: u16,
        service_version: String,
        /// Server time (UTC) so clients can render relative ages without clock skew.
        server_time: i64,
    },
    Status(Box<StatusSnapshot>),
    Agents(Box<AgentInventory>),
    Incidents(Vec<Incident>),
    Network(Box<NetworkSnapshot>),
    PendingReboot(Box<PendingRebootReport>),
    Config(Box<ConfigDocument>),
    Health(Box<HealthReport>),
    RebootAuthorization(Box<Option<RebootAuthorization>>),
    Ok { message: String },
    Error(ProtocolError),
}

/// A protocol-level error. Distinct from transport errors.
#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum ProtocolError {
    #[error("unsupported protocol version {client}, service speaks {server}")]
    VersionMismatch { client: u16, server: u16 },

    #[error("operation {op} requires {required:?} privilege (you are {actual:?})")]
    NotPermitted {
        op: String,
        required: Principal,
        actual: Principal,
    },

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("operation refused: {0}")]
    Refused(String),

    #[error("internal error: {0}")]
    Internal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_round_trips() {
        // Table-driven so adding a variant without a test is obvious.
        let cases: Vec<Request> = vec![
            Request::Hello {
                protocol: PROTOCOL_VERSION,
            },
            Request::GetStatus,
            Request::GetIncidents { limit: 25 },
            Request::Reconnect {
                reason: "user pressed reconnect".into(),
            },
            Request::EnterMaintenance {
                override_protected_work: false,
                confirmation: String::new(),
            },
            Request::ArmSingleReboot { ttl_secs: 1800 },
            Request::Subscribe {
                client: SubscriberKind::SessionHelper,
            },
        ];
        for req in cases {
            let s = serde_json::to_string(&req).expect("encode");
            let back: Request = serde_json::from_str(&s).expect("decode");
            assert_eq!(req.op_name(), back.op_name());
        }
    }

    #[test]
    fn unknown_fields_are_ignored_on_decode() {
        // Forward compatibility: a newer *client* may send extra fields; an older service
        // must still decode the operation it understands.
        let raw = json!({
            "op": "get_incidents",
            "limit": 5,
            "future_field": {"nested": [1, 2, 3]}
        });
        let req: Request = serde_json::from_value(raw).expect("decode with unknown field");
        assert_eq!(req.op_name(), "get_incidents");
    }

    #[test]
    fn privilege_classes_are_asymmetric() {
        // The whole point of the closed protocol: config mutation is not a user operation.
        assert_eq!(Request::GetStatus.required_principal(), Principal::InteractiveUser);
        assert_eq!(
            Request::EnterMaintenance {
                override_protected_work: true,
                confirmation: "yes".into()
            }
            .required_principal(),
            Principal::Administrator
        );
        assert!(Principal::Administrator.may_mutate_config());
        assert!(!Principal::InteractiveUser.may_mutate_config());
        assert!(!Principal::InteractiveUser.may_control_maintenance());
    }
}
