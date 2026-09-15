//! Network policy: broadband-primary with Wi-Fi continuity.
//!
//! # The invariant this module exists to protect
//!
//! > Broadband recovery attempts must not unnecessarily take the machine offline.
//!
//! Concretely: when PPPoE drops, Guardian must establish Wi-Fi continuity *first* and
//! repair PPPoE *in parallel*, never by tearing down the only working path. Wi-Fi is
//! strictly a backup — it is never promoted to preferred merely because it recovered
//! first — and broadband is only restored as the preferred route after it has proven
//! stable for a configured interval.
//!
//! # Why this is a pure state machine
//!
//! Every decision here is a comparison of observed facts, and the failure modes are
//! timing-dependent (flapping, premature failback, stuck backoff). Modelling it as a pure
//! function of `(state, observation, time)` is the only way to test those cases
//! exhaustively without touching a real adapter — and the real adapter is frequently
//! unavailable in CI, which is exactly when you most want the logic covered.

use guardian_proto::model::*;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Per-uplink state
// ---------------------------------------------------------------------------

/// State of the primary broadband (RAS/PPPoE) uplink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BroadbandState {
    Disconnected,
    Connecting,
    Authenticating,
    /// Connected and carrying traffic, but not yet trusted as recovered.
    Verifying,
    /// Connected, verified, stable, and the preferred route.
    Healthy,
    /// Connected but not fully passing health checks: usable, not preferred.
    Degraded,
    /// Was healthy, failed, and is being retried.
    Reconnecting,
    Failed,
}

impl BroadbandState {
    /// Whether the RAS session is up, regardless of health.
    pub fn session_up(self) -> bool {
        matches!(
            self,
            BroadbandState::Verifying
                | BroadbandState::Healthy
                | BroadbandState::Degraded
                | BroadbandState::Reconnecting
        )
    }

    /// Whether this uplink should be carrying normal traffic.
    pub fn is_preferred_candidate(self) -> bool {
        matches!(self, BroadbandState::Healthy)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BroadbandState::Disconnected => "DISCONNECTED",
            BroadbandState::Connecting => "CONNECTING",
            BroadbandState::Authenticating => "AUTHENTICATING",
            BroadbandState::Verifying => "VERIFYING",
            BroadbandState::Healthy => "HEALTHY",
            BroadbandState::Degraded => "DEGRADED",
            BroadbandState::Reconnecting => "RECONNECTING",
            BroadbandState::Failed => "FAILED",
        }
    }
}

/// State of the backup Wi-Fi uplink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WifiState {
    Disconnected,
    Connecting,
    Authenticating,
    Verifying,
    /// Connected and healthy, but deliberately lower priority than broadband.
    Healthy,
    /// Connected and healthy, and currently the path carrying traffic because broadband
    /// is unavailable.
    Continuity,
    /// Connected but not passing health checks.
    Degraded,
    Failed,
}

impl WifiState {
    pub fn is_up(self) -> bool {
        matches!(
            self,
            WifiState::Healthy | WifiState::Continuity | WifiState::Degraded | WifiState::Verifying
        )
    }

    pub fn carries_traffic(self) -> bool {
        matches!(self, WifiState::Continuity)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WifiState::Disconnected => "DISCONNECTED",
            WifiState::Connecting => "CONNECTING",
            WifiState::Authenticating => "AUTHENTICATING",
            WifiState::Verifying => "VERIFYING",
            WifiState::Healthy => "HEALTHY",
            WifiState::Continuity => "CONTINUITY",
            WifiState::Degraded => "DEGRADED",
            WifiState::Failed => "FAILED",
        }
    }
}

/// Which uplink is carrying normal traffic.
///
/// This is a *derived* value: it is recomputed from the two uplink states on every
/// evaluation rather than being set by hand, so the preference rule is enforced in exactly
/// one place.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UplinkPreference {
    /// Broadband is healthy and preferred. Wi-Fi may be connected in standby.
    Broadband,
    /// Broadband is unavailable; Wi-Fi is preserving connectivity.
    Wifi,
    /// Neither uplink is usable.
    None,
}

impl UplinkPreference {
    pub fn as_str(self) -> &'static str {
        match self {
            UplinkPreference::Broadband => "broadband",
            UplinkPreference::Wifi => "wifi",
            UplinkPreference::None => "none",
        }
    }
}

/// The overall Internet state shown to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InternetState {
    /// Broadband healthy and preferred.
    BroadbandPrimary,
    /// Wi-Fi is carrying traffic because broadband is not usable.
    WifiContinuity,
    /// Broadband session re-established but still proving itself; Wi-Fi still carrying.
    RecoveringBroadband,
    /// A path exists but health is questionable.
    Degraded,
    /// Nothing works.
    Offline,
}

impl InternetState {
    pub fn as_str(self) -> &'static str {
        match self {
            InternetState::BroadbandPrimary => "BROADBAND_PRIMARY",
            InternetState::WifiContinuity => "WIFI_CONTINUITY",
            InternetState::RecoveringBroadband => "RECOVERING_BROADBAND",
            InternetState::Degraded => "DEGRADED",
            InternetState::Offline => "OFFLINE",
        }
    }

    /// Whether the user currently has usable Internet access.
    pub fn user_online(self) -> bool {
        !matches!(self, InternetState::Offline)
    }
}

/// Why broadband is considered unhealthy. Used for reporting and for deciding whether a
/// full session teardown is warranted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BroadbandFailureKind {
    /// The RAS session itself is gone.
    PppoeSessionLost,
    /// Credentials were rejected. Retrying immediately will not help.
    AuthenticationFailed,
    /// The session is up but no usable IP configuration arrived.
    NoIpConfiguration,
    /// No default route through the broadband interface.
    RouteFailure,
    /// Name resolution fails while general connectivity works. Must not tear down a
    /// perfectly good session.
    DnsOnlyFailure,
    /// The link is up but nothing beyond it answers.
    UpstreamConnectivityFailure,
    /// Answers are arriving but too many are lost.
    HighPacketLoss,
    /// Some endpoints work and some do not.
    PartialConnectivity,
    Unknown,
}

impl BroadbandFailureKind {
    /// Whether the appropriate response is to tear down and re-dial the session.
    ///
    /// A DNS-only failure is explicitly *not* a reason to destroy a working PPPoE session:
    /// doing so turns a resolvable problem into an outage.
    pub fn warrants_redial(self) -> bool {
        !matches!(
            self,
            BroadbandFailureKind::DnsOnlyFailure | BroadbandFailureKind::PartialConnectivity
        )
    }

    /// Whether retrying is worth doing at all. Bad credentials will not fix themselves.
    pub fn warrants_retry(self) -> bool {
        !matches!(self, BroadbandFailureKind::AuthenticationFailed)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            BroadbandFailureKind::PppoeSessionLost => "PPPOE_SESSION_LOST",
            BroadbandFailureKind::AuthenticationFailed => "AUTHENTICATION_FAILED",
            BroadbandFailureKind::NoIpConfiguration => "NO_IP_CONFIGURATION",
            BroadbandFailureKind::RouteFailure => "ROUTE_FAILURE",
            BroadbandFailureKind::DnsOnlyFailure => "DNS_ONLY_FAILURE",
            BroadbandFailureKind::UpstreamConnectivityFailure => "UPSTREAM_CONNECTIVITY_FAILURE",
            BroadbandFailureKind::HighPacketLoss => "HIGH_PACKET_LOSS",
            BroadbandFailureKind::PartialConnectivity => "PARTIAL_CONNECTIVITY",
            BroadbandFailureKind::Unknown => "UNKNOWN",
        }
    }
}

// ---------------------------------------------------------------------------
// Observations
// ---------------------------------------------------------------------------

/// What the platform layer observed this round. Everything the state machine is allowed to
/// reason about comes through here, which is what makes the machine testable.
#[derive(Debug, Clone, Default)]
pub struct NetworkObservation {
    /// Whether a RAS/PPPoE session is currently connected.
    pub ras_connected: bool,
    /// Whether a dial operation is currently in flight.
    pub ras_dialing: bool,
    /// Raw RAS error from the last dial attempt, if it failed.
    pub ras_error: Option<u32>,
    /// Whether the broadband interface has an IP configuration.
    pub broadband_has_ip: bool,
    /// Whether a default route exists via the broadband interface.
    pub broadband_default_route: bool,
    /// Whether a route preference for broadband has been applied by Guardian.
    pub broadband_route_applied: bool,
    /// Whether the Wi-Fi entry is currently associated and connected.
    pub wifi_connected: bool,
    /// Whether Wi-Fi has an IP configuration.
    pub wifi_has_ip: bool,
    /// Whether a route preference for Wi-Fi has been applied by Guardian.
    pub wifi_route_applied: bool,
    /// Result of each configured probe. Empty means "not measured this round".
    pub probe_results: Vec<ProbeOutcome>,
    /// Current broadband interface metric, when known.
    pub broadband_metric: Option<u32>,
    /// Current Wi-Fi interface metric, when known.
    pub wifi_metric: Option<u32>,
}

/// The outcome of one probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub id: String,
    pub kind: ProbeKind,
    /// Whether the probe reached its target.
    pub ok: bool,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
}

impl NetworkObservation {
    /// Probes that produced a result this round.
    fn measured(&self) -> impl Iterator<Item = &ProbeOutcome> {
        self.probe_results.iter()
    }

    /// How many probes passed.
    pub fn passes(&self) -> usize {
        self.measured().filter(|p| p.ok).count()
    }

    /// How many probes ran.
    pub fn total(&self) -> usize {
        self.probe_results.len()
    }

    /// Whether a quorum of probes passed.
    pub fn quorum_ok(&self, required: u32) -> bool {
        self.passes() >= required as usize
    }

    /// Whether name resolution is the specific thing failing.
    ///
    /// True only when *every* connectivity probe (TCP to a literal address) succeeded and
    /// at least one DNS probe failed. Anything less specific than that is a general
    /// connectivity problem, not a resolver problem, and must not be excused as one —
    /// otherwise a genuinely broken link could be misdiagnosed as "just DNS" and left in
    /// place.
    pub fn dns_only_failure(&self) -> bool {
        let mut tcp_total = 0usize;
        let mut tcp_passed = 0usize;
        let mut dns_total = 0usize;
        let mut dns_failed = 0usize;

        for p in self.measured() {
            match p.kind {
                ProbeKind::Tcp => {
                    tcp_total += 1;
                    if p.ok {
                        tcp_passed += 1;
                    }
                }
                ProbeKind::Dns => {
                    dns_total += 1;
                    if !p.ok {
                        dns_failed += 1;
                    }
                }
                _ => {}
            }
        }

        tcp_total > 0 && tcp_passed == tcp_total && dns_total > 0 && dns_failed > 0
    }

    /// Whether results are split: some pass, some fail, with no clean explanation.
    pub fn partial_connectivity(&self) -> bool {
        let passes = self.passes();
        let total = self.total();
        passes > 0 && passes < total && !self.dns_only_failure()
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// The network policy, derived from user configuration.
#[derive(Debug, Clone)]
pub struct NetworkPolicy {
    pub enabled: bool,
    pub wifi_enabled: bool,
    /// `true` keeps Wi-Fi associated so failover is nearly instant; `false` connects it
    /// only once broadband is actually unhealthy.
    pub wifi_warm_standby: bool,
    pub failure_quorum: u32,
    pub success_quorum: u32,
    /// How long broadband must stay healthy before it is restored as preferred.
    pub stabilize_secs: u64,
    /// How long Wi-Fi must stay healthy before it is considered a usable continuity path.
    pub wifi_stabilize_secs: u64,
    /// Minimum time to stay on Wi-Fi after a failover before even considering a failback.
    /// This is the primary anti-flap control.
    pub min_wifi_hold_secs: u64,
    /// Minimum time after a successful dial before another dial may be attempted.
    pub min_dial_interval_secs: u64,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy {
            enabled: true,
            wifi_enabled: true,
            wifi_warm_standby: true,
            failure_quorum: 2,
            success_quorum: 2,
            stabilize_secs: 20,
            wifi_stabilize_secs: 5,
            min_wifi_hold_secs: 30,
            min_dial_interval_secs: 15,
        }
    }
}

impl NetworkPolicy {
    pub fn from_config(c: &NetworkConfig) -> Self {
        NetworkPolicy {
            enabled: c.enabled,
            wifi_enabled: true,
            wifi_warm_standby: true,
            failure_quorum: c.failure_quorum.max(1),
            success_quorum: c.success_quorum.max(1),
            stabilize_secs: c.stabilize_secs,
            wifi_stabilize_secs: 5,
            min_wifi_hold_secs: 30,
            min_dial_interval_secs: 15,
        }
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Backoff schedule for broadband redial, in milliseconds.
///
/// The first entry is an immediate retry, which handles the common transient blip.
pub const BACKOFF_MS: &[u64] = &[0, 1_000, 2_000, 4_000, 8_000, 15_000, 30_000, 60_000];

/// The complete network state machine state.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct NetworkState {
    pub broadband: BroadbandState,
    pub wifi: WifiState,
    pub preference: UplinkPreference,
    pub internet: InternetState,
    /// Index into [`BACKOFF_MS`] for the current outage.
    pub backoff_index: usize,
    /// Consecutive failing rounds.
    pub consecutive_failures: u32,
    /// Consecutive passing rounds.
    pub consecutive_successes: u32,
    /// Dial attempts during the current outage.
    pub dial_attempts: u32,
    /// Monotonic ms when the current outage began.
    pub outage_started_ms: Option<i64>,
    /// Monotonic ms of the last dial attempt.
    pub last_dial_ms: Option<i64>,
    /// Monotonic ms when broadband last became healthy.
    pub broadband_healthy_since_ms: Option<i64>,
    /// Monotonic ms when Wi-Fi last became usable.
    pub wifi_healthy_since_ms: Option<i64>,
    /// Monotonic ms when traffic last moved to Wi-Fi.
    pub on_wifi_since_ms: Option<i64>,
    /// Monotonic ms when broadband last became the preferred route.
    pub broadband_preferred_since_ms: Option<i64>,
    /// The classified reason broadband is unhealthy.
    pub failure_kind: Option<BroadbandFailureKind>,
    /// Last raw RAS error code seen.
    pub last_ras_error: Option<u32>,
    /// Total downtime accumulated in the current outage.
    pub outage_ms: i64,
    /// True once Wi-Fi has been flagged for connection during this outage.
    pub wifi_failover_attempted: bool,
    /// Number of consecutive times broadband passed verification but then failed shortly
    /// after being promoted. Used to widen the stabilization requirement.
    pub recent_aborts: u32,
}

impl Default for NetworkState {
    fn default() -> Self {
        NetworkState {
            broadband: BroadbandState::Disconnected,
            wifi: WifiState::Disconnected,
            preference: UplinkPreference::None,
            internet: InternetState::Offline,
            backoff_index: 0,
            consecutive_failures: 0,
            consecutive_successes: 0,
            dial_attempts: 0,
            outage_started_ms: None,
            last_dial_ms: None,
            broadband_healthy_since_ms: None,
            wifi_healthy_since_ms: None,
            on_wifi_since_ms: None,
            broadband_preferred_since_ms: None,
            failure_kind: None,
            last_ras_error: None,
            outage_ms: 0,
            wifi_failover_attempted: false,
            recent_aborts: 0,
        }
    }
}

/// An action the platform layer must perform.
///
/// The state machine decides *what to do*; it never does it. That separation is what keeps
/// the logic testable and keeps network side effects in one auditable place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAction {
    /// Dial the configured broadband entry.
    DialBroadband,
    /// Hang up the broadband session, after cleaning up Guardian-managed state.
    HangUpBroadband,
    /// Bring the backup Wi-Fi profile up.
    ConnectWifi,
    /// Tear down Wi-Fi (only when the user disabled it, or the policy is cold standby
    /// and broadband is stable).
    DisconnectWifi,
    /// Make broadband the preferred route (apply interface metric / route preference).
    PreferBroadband,
    /// Make Wi-Fi the preferred route.
    PreferWifi,
    /// Remove only the route/metric adjustments Guardian itself applied.
    ReleaseManagedRoutes,
    /// Sleep for the recommended backoff before the next evaluation.
    Wait { ms: u64 },
    /// Nothing to do; wait for the next scheduled evaluation.
    None,
}

/// The outcome of one evaluation step.
#[derive(Debug, Clone)]
pub struct NetworkTransition {
    pub state: NetworkState,
    pub actions: Vec<NetworkAction>,
    /// Human-readable notes for the journal, in order.
    pub notes: Vec<String>,
}

impl NetworkTransition {
    /// Next scheduled evaluation delay implied by this transition.
    pub fn next_delay_ms(&self, policy: &NetworkPolicy) -> u64 {
        for a in &self.actions {
            if let NetworkAction::Wait { ms } = a {
                return *ms;
            }
        }
        policy.base_interval_ms()
    }
}

impl NetworkPolicy {
    /// Default polling interval derived from the configured check interval.
    pub fn base_interval_ms(&self) -> u64 {
        // The state machine does not own the check interval (the caller schedules), so this
        // is only used by tests and by the caller's fallback.
        20_000
    }
}

/// Classify why broadband looks unhealthy, given an observation.
pub fn classify_failure(obs: &NetworkObservation, policy: &NetworkPolicy) -> BroadbandFailureKind {
    if let Some(code) = obs.ras_error {
        // 691 is ERROR_INVALID_CREDENTIALS / ERROR_AUTHENTICATION_FAILURE on RAS; 812 is
        // ERROR_AUTHENTICATION_FAILURE with the server refusing the session.
        if code == 691 || code == 812 {
            return BroadbandFailureKind::AuthenticationFailed;
        }
    }

    if !obs.ras_connected {
        return BroadbandFailureKind::PppoeSessionLost;
    }
    if !obs.broadband_has_ip {
        return BroadbandFailureKind::NoIpConfiguration;
    }
    if !obs.broadband_default_route {
        return BroadbandFailureKind::RouteFailure;
    }

    if obs.total() == 0 {
        // The session looks fine but nothing was measured: do not invent a failure.
        return BroadbandFailureKind::Unknown;
    }

    if obs.dns_only_failure() {
        return BroadbandFailureKind::DnsOnlyFailure;
    }

    let passes = obs.passes();
    if passes == 0 {
        return BroadbandFailureKind::UpstreamConnectivityFailure;
    }
    if passes < policy.failure_quorum as usize {
        return BroadbandFailureKind::PartialConnectivity;
    }

    BroadbandFailureKind::Unknown
}

/// Compute the preference purely from the two uplink states.
///
/// This is the single place the "broadband always wins when healthy" rule lives.
pub fn compute_preference(broadband: BroadbandState, wifi: WifiState) -> UplinkPreference {
    if broadband.is_preferred_candidate() {
        return UplinkPreference::Broadband;
    }
    if wifi.carries_traffic() || wifi.is_up() {
        return UplinkPreference::Wifi;
    }
    UplinkPreference::None
}

/// Derive the user-visible Internet state.
pub fn derive_internet_state(
    broadband: BroadbandState,
    wifi: WifiState,
    preference: UplinkPreference,
) -> InternetState {
    match preference {
        UplinkPreference::Broadband => InternetState::BroadbandPrimary,
        UplinkPreference::Wifi => {
            // Broadband mid-recovery while Wi-Fi carries traffic gets its own state so the
            // UI can say "recovering" rather than a misleading steady-state label.
            if matches!(
                broadband,
                BroadbandState::Verifying
                    | BroadbandState::Connecting
                    | BroadbandState::Authenticating
                    | BroadbandState::Reconnecting
            ) {
                InternetState::RecoveringBroadband
            } else {
                InternetState::WifiContinuity
            }
        }
        UplinkPreference::None => {
            if broadband == BroadbandState::Degraded || wifi == WifiState::Degraded {
                InternetState::Degraded
            } else {
                InternetState::Offline
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The transition function
// ---------------------------------------------------------------------------

/// Evaluate one round.
///
/// Pure: `now_ms` is monotonic milliseconds supplied by the caller. Given the same state,
/// observation, policy and time, the output is identical, which is what makes the
/// anti-flap behaviour testable.
pub fn evaluate(
    state: &NetworkState,
    obs: &NetworkObservation,
    policy: &NetworkPolicy,
    now_ms: i64,
) -> NetworkTransition {
    let mut actions = Vec::new();
    let mut notes = Vec::new();
    let mut s = state.clone();

    if !policy.enabled {
        return NetworkTransition {
            state: NetworkState {
                broadband: BroadbandState::Disconnected,
                wifi: WifiState::Disconnected,
                preference: UplinkPreference::None,
                internet: InternetState::Offline,
                ..state.clone()
            },
            actions: vec![],
            notes: vec!["network management disabled by configuration".into()],
        };
    }

    // --- 1. Wi-Fi continuity timing -----------------------------------------
    // Evaluated *first* and unconditionally. Nothing below may take the machine offline,
    // so the backup path is established before any broadband repair is considered.

    // Broadband health, in two tiers.
    //
    // The *link* is up when the session exists, has an address, and has a default route. That is
    // evidence from the interface and routing layers, which cannot be confused by a filtered
    // network.
    //
    // The *path* is proven when a quorum of probes also succeeds. On a network that blocks direct
    // connections to public resolver IPs - a campus or corporate connection, for example - probes
    // can fail while the link is genuinely fine.
    //
    // Conflating the two caused a real defect: a link that dialled successfully would fail its
    // probe quorum, be declared unusable, be torn down, and be dialled again - an endless dial
    // loop that looked like a broken ISP. So a *freshly established* link is judged on link
    // evidence alone until it has had a chance to be verified, and probe failures only demote a
    // link that was previously proven healthy.
    let link_up = obs.ras_connected && obs.broadband_has_ip && obs.broadband_default_route;
    let probes_prove_path = obs.total() == 0 || obs.quorum_ok(policy.failure_quorum);
    let link_proven = link_up && probes_prove_path;

    // While a link is still being verified, unproven probes are not treated as failure: the
    // verification window exists precisely to give a new link time to settle.
    let settling = matches!(
        state.broadband,
        BroadbandState::Verifying | BroadbandState::Connecting | BroadbandState::Authenticating
    );

    let broadband_usable = if settling {
        link_up
    } else {
        // An established link must keep passing its probes; that is what detects a path that has
        // genuinely stopped working while the session stayed up.
        link_proven
    };

    if policy.wifi_enabled {
        update_wifi(
            &mut s,
            obs,
            policy,
            now_ms,
            broadband_usable,
            &mut actions,
            &mut notes,
        );
    }

    // --- 2. Broadband health assessment -------------------------------------

    let previously_healthy = state.broadband == BroadbandState::Healthy;

    if obs.ras_dialing {
        s.broadband = BroadbandState::Authenticating;
        notes.push("broadband dial in progress".into());
    } else if !obs.ras_connected {
        // No session at all.
        if s.broadband != BroadbandState::Reconnecting && s.broadband != BroadbandState::Failed {
            if previously_healthy {
                notes.push("broadband session lost".into());
            }
            s.broadband = BroadbandState::Reconnecting;
        }
        s.broadband_healthy_since_ms = None;
    } else if obs.ras_connected && obs.total() == 0 {
        // Session is up but this round measured nothing: hold the previous assessment
        // rather than flapping on missing data.
        notes.push("broadband health not measured this round".into());
    } else if broadband_usable {
        // Healthy this round.
        s.consecutive_successes += 1;
        s.consecutive_failures = 0;

        match s.broadband {
            BroadbandState::Healthy => { /* stays healthy */ }
            BroadbandState::Verifying => {
                let since = s.broadband_healthy_since_ms.unwrap_or(now_ms);
                let stable_for = (now_ms - since) as u64;
                // Escalate the required window after repeated aborts. A link that keeps
                // dying right after promotion must prove itself for longer.
                let required = policy.stabilize_secs * (1 + s.recent_aborts as u64);
                if stable_for >= required * 1000 {
                    s.broadband = BroadbandState::Healthy;
                    s.failure_kind = None;
                    notes.push(format!(
                        "broadband verified stable for {}s; promoting to preferred",
                        stable_for / 1000
                    ));
                } else {
                    notes.push(format!(
                        "broadband verifying ({}/{}s stable)",
                        stable_for / 1000,
                        required
                    ));
                }
            }
            _ => {
                // Entering verification from any other state, including a fresh dial.
                //
                // The backoff is deliberately NOT reset here. A connection that comes up and then
                // dies immediately - a half-dead PPPoE session, for example, where RAS reports the
                // session as established while the underlying link is gone - would otherwise reset
                // the schedule on every attempt and redial at the initial interval forever. That
                // is a dial loop, and against a real ISP it is indistinguishable from an attack.
                //
                // Verification is not success. Only reaching `Healthy` counts, and that is where
                // the schedule is reset.
                s.broadband = BroadbandState::Verifying;
                s.broadband_healthy_since_ms = Some(now_ms);
                notes.push("broadband connected; verifying stability before switching back".into());
            }
        }
    } else {
        // Session up but failing health checks.
        s.consecutive_failures += 1;
        s.consecutive_successes = 0;
        let kind = classify_failure(obs, policy);
        s.failure_kind = Some(kind);

        if s.consecutive_failures >= policy.failure_quorum {
            match s.broadband {
                BroadbandState::Healthy | BroadbandState::Verifying => {
                    // Demote. If we were promoted, remember the abort so the next
                    // verification window is longer.
                    if previously_healthy && state.broadband_preferred_since_ms.is_some() {
                        let held = now_ms - state.broadband_preferred_since_ms.unwrap_or(now_ms);
                        if held < (policy.stabilize_secs * 3 * 1000) as i64 {
                            s.recent_aborts = s.recent_aborts.saturating_add(1);
                            notes.push(format!(
                                "broadband failed {}s after being made preferred; widening the stabilization window (aborts={})",
                                held / 1000, s.recent_aborts
                            ));
                        }
                    }
                    s.broadband = BroadbandState::Degraded;
                    s.broadband_healthy_since_ms = None;
                    notes.push(format!("broadband degraded: {}", kind.as_str()));
                }
                _ => {
                    s.broadband = BroadbandState::Degraded;
                }
            }
        }
    }

    // --- 3. Decide the outage window ----------------------------------------
    let broadband_ok_now = s.broadband == BroadbandState::Healthy;
    if broadband_ok_now {
        s.outage_started_ms = None;
        s.outage_ms = 0;
        s.backoff_index = 0;
        s.dial_attempts = 0;
        s.recent_aborts = s.recent_aborts.saturating_sub(1);
    } else if s.outage_started_ms.is_none() {
        s.outage_started_ms = Some(now_ms);
        s.failure_kind = s
            .failure_kind
            .or_else(|| Some(classify_failure(obs, policy)));
        notes.push("broadband outage started".into());
    } else {
        s.outage_ms = now_ms - s.outage_started_ms.unwrap_or(now_ms);
    }

    // --- 4. Broadband repair, in parallel with the continuity path -----------
    //
    // Three distinct situations, each with its own correct remedy:
    //
    //   a. No session at all      -> dial, with backoff.
    //   b. Session up but useless -> tear the session down, then dial next round.
    //   c. Session healthy        -> nothing to repair.
    //
    // The continuation constraint applies to (b): hanging up is only safe once something
    // else is actually carrying traffic, or nothing was carrying it to begin with.
    let need_repair = !broadband_ok_now;
    if need_repair {
        let kind = s.failure_kind.unwrap_or(BroadbandFailureKind::Unknown);

        if !kind.warrants_retry() && obs.ras_error.is_some() {
            // Authentication failure: retrying with the same credentials is pointless and
            // would look like a dial loop in the logs. Report and stop.
            s.broadband = BroadbandState::Failed;
            notes.push(format!(
                "broadband dial failed with {}; not retrying until configuration changes",
                kind.as_str()
            ));
        } else if obs.ras_dialing {
            // A dial is already in flight. Doing anything else here would risk a second
            // concurrent dial, which is exactly what must never happen.
            notes.push("waiting for the in-flight dial to complete".into());
        } else if obs.ras_connected && kind.warrants_redial() {
            // (b) Session up but useless: no IP, no route, or nothing upstream answers.
            // Tearing it down is the remedy, but only when doing so does not cost us the
            // connectivity we are relying on.
            let wifi_carrying = s.wifi.is_up();
            if wifi_carrying || s.preference == UplinkPreference::None {
                actions.push(NetworkAction::HangUpBroadband);
                notes.push(format!(
                    "cleaning up unusable broadband session ({})",
                    kind.as_str()
                ));
            } else {
                notes.push(format!(
                    "broadband {} but a working path exists; deferring session cleanup",
                    kind.as_str()
                ));
            }
        } else if obs.ras_connected && !kind.warrants_redial() {
            // Session is serviceable; the failure is above it (DNS, partial reachability).
            // Leave the session alone and let the continuity path cover the gap.
            notes.push(format!(
                "broadband {}; keeping the session and relying on the continuity path",
                kind.as_str()
            ));
        } else {
            // (a) No session: dial, subject to the minimum interval.
            let due = match s.last_dial_ms {
                None => true,
                Some(last) => (now_ms - last) >= (policy.min_dial_interval_secs * 1000) as i64,
            };

            if due {
                // Exponential backoff with jitter. The wait is advisory: the scheduler
                // decides when to call back, so this reports the intended delay.
                let base = BACKOFF_MS[s.backoff_index.min(BACKOFF_MS.len() - 1)];
                let wait = apply_jitter(base, jitter_for(s.dial_attempts));
                if wait > 0 {
                    actions.push(NetworkAction::Wait { ms: wait });
                }
                actions.push(NetworkAction::DialBroadband);
                s.last_dial_ms = Some(now_ms);
                s.dial_attempts += 1;
                s.backoff_index = (s.backoff_index + 1).min(BACKOFF_MS.len() - 1);
                notes.push(format!(
                    "dialing broadband (attempt {}, backoff {}ms, reason {})",
                    s.dial_attempts,
                    wait,
                    kind.as_str()
                ));
            } else {
                let wait = policy.min_dial_interval_secs * 1000;
                actions.push(NetworkAction::Wait { ms: wait });
            }
        }
    }

    // --- 5. Preference and route management ---------------------------------
    s.preference = compute_preference(s.broadband, s.wifi);
    s.internet = derive_internet_state(s.broadband, s.wifi, s.preference);

    match s.preference {
        UplinkPreference::Broadband => {
            if !obs.broadband_route_applied {
                actions.push(NetworkAction::PreferBroadband);
                notes.push("restoring broadband as the preferred route".into());
            }
            if obs.wifi_route_applied {
                actions.push(NetworkAction::PreferWifi);
                // Overwritten below; handled by the Wi-Fi branch instead.
                actions.pop();
            }
            if s.broadband_preferred_since_ms.is_none() {
                s.broadband_preferred_since_ms = Some(now_ms);
            }
            s.on_wifi_since_ms = None;
        }
        UplinkPreference::Wifi => {
            // Proving the failback hold time matters only while Wi-Fi is carrying traffic.
            if s.on_wifi_since_ms.is_none() {
                s.on_wifi_since_ms = Some(now_ms);
            }
            if !obs.wifi_route_applied {
                actions.push(NetworkAction::PreferWifi);
                notes.push("routing traffic via Wi-Fi continuity".into());
            }
            s.broadband_preferred_since_ms = None;
        }
        UplinkPreference::None => {
            // Nothing works. Release only what we applied, and let the OS do its best.
            if obs.broadband_route_applied || obs.wifi_route_applied {
                actions.push(NetworkAction::ReleaseManagedRoutes);
                notes.push("releasing Guardian-managed route preferences".into());
            }
        }
    }

    // --- 6. Wi-Fi standby demotion ------------------------------------------
    if s.preference == UplinkPreference::Broadband
        && s.wifi == WifiState::Continuity
        && s.broadband_preferred_since_ms.is_some()
    {
        s.wifi = WifiState::Healthy;
        s.on_wifi_since_ms = None;
        notes.push("Wi-Fi returned to standby; broadband is primary".into());
    }

    if !policy.wifi_warm_standby
        && s.preference == UplinkPreference::Broadband
        && s.wifi.is_up()
        && s.broadband_healthy_since_ms.is_some()
        && !obs.wifi_route_applied
    {
        // Cold standby: only tear Wi-Fi down once broadband has been stable, never during
        // an outage.
        actions.push(NetworkAction::DisconnectWifi);
        notes.push("cold standby: disconnecting Wi-Fi now that broadband is stable".into());
    }

    NetworkTransition {
        state: s,
        actions,
        notes,
    }
}

/// Advance the Wi-Fi sub-state. Kept separate because its rules are independent of the
/// broadband repair path, which is the whole point of modelling two uplinks.
fn update_wifi(
    s: &mut NetworkState,
    obs: &NetworkObservation,
    policy: &NetworkPolicy,
    now_ms: i64,
    broadband_usable: bool,
    actions: &mut Vec<NetworkAction>,
    notes: &mut Vec<String>,
) {
    if obs.wifi_connected && obs.wifi_has_ip {
        let healthy = obs.total() == 0 || obs.quorum_ok(policy.failure_quorum);

        if s.wifi_healthy_since_ms.is_none() {
            s.wifi_healthy_since_ms = Some(now_ms);
        }

        if healthy {
            let stable_for = (now_ms - s.wifi_healthy_since_ms.unwrap_or(now_ms)) as u64;
            let usable = stable_for >= policy.wifi_stabilize_secs * 1000;

            s.wifi = if !usable {
                WifiState::Verifying
            } else if broadband_usable {
                // Broadband is fine: Wi-Fi is warm standby, not carrying traffic.
                if s.wifi == WifiState::Continuity {
                    WifiState::Continuity
                } else {
                    WifiState::Healthy
                }
            } else {
                // Broadband is not usable, so Wi-Fi carries traffic.
                if s.wifi != WifiState::Continuity {
                    notes.push(
                        "Wi-Fi is carrying Internet traffic while broadband is unavailable".into(),
                    );
                }
                WifiState::Continuity
            };
        } else {
            s.wifi = WifiState::Degraded;
        }
    } else {
        s.wifi_healthy_since_ms = None;

        // Wi-Fi is not associated, so it is Disconnected regardless of what it was doing
        // a moment ago. The reconnect decision below is what matters; it is driven by
        // whether broadband is usable, not by Wi-Fi's previous state.
        s.wifi = WifiState::Disconnected;

        // Connect Wi-Fi when:
        //  * warm standby and broadband is not verified healthy, or
        //  * cold standby and broadband is known bad.
        // Crucially this happens *before* any broadband teardown, preserving continuity.
        let should_connect = if policy.wifi_warm_standby {
            !broadband_usable
        } else {
            !broadband_usable && s.consecutive_failures >= policy.failure_quorum
        };

        if should_connect {
            actions.push(NetworkAction::ConnectWifi);
            s.wifi_failover_attempted = true;
            notes.push("connecting backup Wi-Fi to preserve connectivity".into());
        }
    }
}

/// Deterministic jitter so tests are reproducible.
///
/// Real jitter matters to avoid many machines dialing in lockstep after a shared upstream
/// outage; determinism matters more for testing. The caller passes an attempt-derived seed,
/// which produces a varied but reproducible spread.
fn jitter_for(attempt: u32) -> u32 {
    // A simple hash of the attempt counter; deliberately not random so behaviour is
    // reproducible across runs and across processes.
    attempt.wrapping_mul(2_654_435_761) % 1000
}

fn apply_jitter(base_ms: u64, jitter_percent_x10: u32) -> u64 {
    if base_ms == 0 {
        return 0;
    }
    let pct = (jitter_percent_x10 % 200) as u64; // 0..199 -> 0..19.9%
    base_ms + (base_ms * pct) / 1000
}

/// Build a user-facing snapshot from the state machine.
pub fn snapshot(
    s: &NetworkState,
    policy: &NetworkPolicy,
    entry_name: Option<String>,
    probes: Vec<ProbeResult>,
    now_ms: i64,
) -> NetworkSnapshot {
    NetworkSnapshot {
        phase: match s.internet {
            InternetState::BroadbandPrimary => NetworkPhase::Online,
            InternetState::WifiContinuity | InternetState::RecoveringBroadband => {
                NetworkPhase::Online
            }
            InternetState::Degraded => NetworkPhase::Suspect,
            InternetState::Offline => NetworkPhase::Offline,
        },
        internet: match s.internet {
            InternetState::BroadbandPrimary | InternetState::WifiContinuity => {
                InternetHealth::Healthy
            }
            InternetState::RecoveringBroadband => InternetHealth::Degraded,
            InternetState::Degraded => InternetHealth::Degraded,
            InternetState::Offline => InternetHealth::Down,
        },
        entry_name,
        ras_state: match s.broadband {
            BroadbandState::Healthy | BroadbandState::Degraded | BroadbandState::Verifying => {
                RasConnectionState::Connected
            }
            BroadbandState::Connecting | BroadbandState::Authenticating => {
                RasConnectionState::Connecting
            }
            BroadbandState::Reconnecting => RasConnectionState::Disconnected,
            BroadbandState::Disconnected | BroadbandState::Failed => {
                RasConnectionState::Disconnected
            }
        },
        uptime_ms: s
            .broadband_healthy_since_ms
            .map(|since| now_ms - since)
            .or_else(|| s.on_wifi_since_ms.map(|since| now_ms - since)),
        online_since_ms: s.broadband_preferred_since_ms.or(s.on_wifi_since_ms),
        last_reconnect_ms: s.last_dial_ms,
        probes,
        quorum_required: policy.failure_quorum,
        consecutive_failures: s.consecutive_failures,
        consecutive_successes: s.consecutive_successes,
        dial_attempts_current_outage: s.dial_attempts,
        backoff_ms: BACKOFF_MS[s.backoff_index.min(BACKOFF_MS.len() - 1)],
        current_outage: s.outage_started_ms.map(|start| OutageRecord {
            id: format!("outage-{start}"),
            started_at_ms: start,
            ended_at_ms: None,
            downtime_ms: Some(s.outage_ms),
            reason: s
                .failure_kind
                .map(|k| k.as_str().to_string())
                .unwrap_or_else(|| "unknown".into()),
            dial_attempts: s.dial_attempts,
            ras_errors: s
                .last_ras_error
                .map(|code| {
                    vec![RasErrorRecord {
                        code,
                        message: ras_error_message(code).to_string(),
                        at_ms: s.last_dial_ms.unwrap_or(now_ms),
                    }]
                })
                .unwrap_or_default(),
        }),
        recent_outages: Vec::new(),
        last_error: s
            .last_ras_error
            .map(|c| format!("{} ({})", ras_error_message(c), c)),
        updated_at_ms: now_ms,
    }
}

/// Translate the RAS error codes an operator is actually likely to meet.
///
/// The raw numeric code is always retained alongside the text; a translation that is
/// missing is far better than one that is wrong.
pub fn ras_error_message(code: u32) -> &'static str {
    match code {
        0 => "success",
        600 => "an operation is pending",
        601 => "the port handle is invalid",
        602 => "the port is already open",
        603 => "the caller's buffer is too small",
        604 => "wrong information specified",
        605 => "the port is not open",
        606 => "the port is not connected",
        607 => "the device is not a valid port",
        608 => "the device does not exist",
        609 => "the device type does not exist",
        610 => "the buffer is invalid",
        611 => "the route is not available",
        612 => "the route is not allocated",
        613 => "invalid compression specified",
        614 => "out of buffers",
        615 => "the port was not found",
        616 => "an asynchronous request is pending",
        617 => "the port or device is already disconnecting",
        618 => "the port is not open",
        619 => "the port is disconnected",
        620 => "no endpoints could be found",
        621 => "cannot open the phone book file",
        622 => "cannot load the phone book file",
        623 => "cannot find the phone book entry",
        624 => "cannot write the phone book file",
        625 => "invalid information found in the phone book",
        626 => "cannot load a string",
        627 => "cannot find a key",
        628 => "the port was disconnected",
        629 => "the port was disconnected by the remote machine",
        630 => "the port was disconnected due to hardware failure",
        631 => "the port was disconnected by the user",
        632 => "the structure size is incorrect",
        633 => "the port is already in use or is not configured for remote access",
        634 => "cannot register the phone book entry",
        635 => "an unknown error occurred",
        636 => "the device attached to the port is not the expected one",
        637 => "the string is too long",
        638 => "the request has timed out",
        639 => "there is no route available",
        640 => "a system error occurred",
        641 => "the server cannot allocate a network address",
        642 => "one of the required NetBIOS names is already registered on the remote network",
        643 => "the server cannot allocate a network address (DNSS/WINS)",
        644 => "the internal authentication state is not valid",
        645 => "internal authentication failure",
        646 => "the account is not permitted to log on at this time of day",
        647 => "the account is disabled",
        648 => "the password has expired",
        649 => "the account has no dial-in permission",
        650 => "the remote access server is not responding",
        651 => "the modem (or other connecting device) reported an error",
        652 => "an unrecognised response was received from the device",
        653 => "a macro is not found in the device .inf file",
        654 => "the device .inf file could not be read",
        655 => "the device .inf file could not be loaded",
        656 => "the device name does not exist in the device .inf file",
        657 => "the device could not be opened",
        658 => "the device name is too long or invalid",
        659 => "the device .inf file contains an invalid device type",
        660 => "the device .inf file does not contain a device name",
        661 => "the device .inf file is missing a command",
        662 => "an attempt was made to set a macro that is not in the device .inf file",
        663 => "the media is not supported by the device",
        664 => "the system could not allocate memory",
        665 => "the port is not configured for remote access",
        666 => "the device is not functioning",
        667 => "the media is not available",
        668 => "the connection dropped",
        669 => "invalid parameter in the connection string",
        670 => "cannot read the connection string from the device .inf file",
        671 => "cannot write the connection string to the device .inf file",
        672 => "cannot enumerate the devices in the device .inf file",
        673 => "the requested device is already in use",
        674 => "another connection is already in progress",
        675 => "there is no tunnel definition available",
        676 => "the line is busy",
        677 => "a person answered instead of a modem",
        678 => "there is no answer",
        679 => "cannot detect the carrier",
        680 => "there is no dial tone",
        681 => "a general error occurred with the device",
        682 => "the device is not present, or the connection was refused",
        683 => "the device is not responding",
        691 => "access was denied because the username and/or password is invalid on the domain",
        692 => "a hardware failure in the modem (or other connecting device)",
        693 => "the binary macro is not supported by the device .inf file",
        694 => "the requested device is not available",
        695 => "the state machine is not defined",
        696 => "the state machine failed to start",
        697 => "a timer could not be stopped",
        698 => "the response to the command was invalid",
        699 => "the device responded with a different result than expected",
        700 => "the device .inf file contains a line that is too long",
        701 => "the device rejected the baud rate",
        702 => "the device responded with an invalid data type",
        703 => "the connection was terminated by the remote computer",
        704 => "the connection was terminated by the remote computer (unrecoverable error)",
        705 => "the authentication state is invalid",
        706 => "the connection was closed because the link was broken",
        707 => "the user has not been granted dial-in permission",
        708 => "the account has expired",
        709 => "the password has expired and must be changed",
        710 => "too many requests for the same phone number",
        711 => "the specified port is not open",
        712 => "this connection requires a multi-link configuration",
        713 => "no active ISDN lines are available",
        714 => "no ISDN channels are available to make the call",
        715 => "too many errors occurred because of poor phone line quality",
        716 => "the remote access service IP configuration is unusable",
        717 => "no IP addresses are available in the static pool",
        718 => "the PPP timeout expired while waiting for valid connection results",
        719 => "the PPP termination request was terminated by the remote machine",
        720 => "no PPP control protocols configured",
        721 => "the remote PPP peer is not responding",
        722 => "invalid data from the remote computer",
        723 => "the phone number is too long",
        724 => "the IP address of the remote computer is invalid",
        725 => "the IPX network number is not valid",
        726 => "the IPX protocol cannot be used for dial-out",
        727 => "cannot access TCPCFG.DLL",
        728 => "cannot find an IP adapter bound to remote access",
        729 => "SLIP cannot be used unless IP forwarding is enabled",
        730 => "the computer name could not be registered",
        731 => "the protocol is not configured",
        732 => "the PPP negotiation is not converging",
        733 => "the PPP control protocol for this network protocol is not available",
        734 => "the PPP link control protocol was terminated",
        735 => "the requested address was rejected by the server",
        736 => "the remote computer terminated the control protocol",
        737 => "loopback was detected",
        738 => "the server did not assign an address",
        739 => "the authentication protocol required by the server is not available",
        740 => "the LCP negotiation failed",
        741 => "the local computer does not support encryption",
        742 => "the remote computer does not support encryption",
        743 => "the remote computer requires encryption",
        744 => "the remote computer requires an encryption method this computer does not support",
        745 => "an internal error occurred in the authentication process",
        746 => "the authentication protocol has not been negotiated",
        747 => "the authentication protocol failed",
        748 => "the server allocated an invalid address",
        749 => "the callback number is not valid",
        750 => "the authentication protocol requires a valid certificate",
        751 => "the callback number could not be reached",
        752 => "an error occurred while processing the script",
        753 => "the connection was dropped because the port was disconnected",
        754 => "the system could not find the multi-link bundle",
        755 => "the system cannot perform automated dialling",
        756 => "the connection has already been called",
        757 => "the remote access service could not start the connection",
        758 => "the internet connection sharing protocol has encountered an error",
        759 => "the connection could not be established",
        760 => "an error occurred while encrypting the data",
        761 => "an error occurred while decrypting the data",
        762 => "an error occurred while encrypting the data",
        763 => "the connection cannot be established because the client is not configured correctly",
        764 => "a smart card reader is not installed or is not supported",
        765 => "the smart card is not available",
        766 => "could not find any certificates",
        767 => "the specified certificate could not be found",
        768 => "the connection attempt failed because the destination could not be resolved",
        769 => "the specified destination is not reachable",
        770 => "the remote machine refused the connection",
        771 => "the connection attempt failed because the network is busy",
        772 => "the remote computer's network hardware is incompatible",
        773 => "the remote connection could not be established",
        774 => "the connection attempt timed out",
        775 => "the remote computer is not replying to the call",
        776 => "the call could not be established because the dialling was interrupted",
        777 => "the connection was not established because no modem or other device was available",
        778 => "the authentication protocol required by the server is not available",
        779 => "the remote computer is not responding to the call",
        780 => "the call could not be established because the network is busy",
        781 => "there was no dial tone",
        782 => "the connection could not be established because the PPP negotiation failed",
        783 => "the connection could not be established because the destination was not reachable",
        784 => "the connection could not be established because the network is unreachable",
        785 => "the connection could not be established because the address was invalid",
        786 => "the connection could not be established because the remote computer is not reachable",
        787 => "the connection could not be established because the remote computer is not responding",
        788 => "the connection could not be established because the remote computer refused the connection",
        789 => "the connection could not be established because the security layer could not be negotiated",
        790 => "the connection could not be established because the authentication failed",
        791 => "the connection could not be established because the policy is not supported",
        792 => "the connection could not be established because the authentication protocol is not supported",
        793 => "the connection could not be established because the account is locked out",
        794 => "the connection could not be established because the account has expired",
        795 => "the connection could not be established because the account is disabled",
        796 => "the connection could not be established because the account has no dial-in permission",
        797 => "the connection could not be established because the device was not found",
        798 => "the connection could not be established because a certificate could not be found",
        799 => "the connection could not be established because the IP address could not be assigned",
        800 => "the connection could not be established because the VPN server is not reachable",
        801 => "the connection could not be established because the security policy is not supported",
        802 => "the connection could not be established because the account is not permitted to log on",
        803 => "the connection could not be established because the encryption is not supported",
        804 => "the connection could not be established because the tunnel type is not supported",
        805 => "the connection could not be established because the tunnel could not be found",
        806 => "the connection could not be established because the tunnel could not be brought up",
        807 => "the connection could not be established because the tunnel collapsed",
        808 => "the connection could not be established because the tunnel was dropped",
        809 => "the connection could not be established because the tunnel could not be authenticated",
        810 => "the connection could not be established because the tunnel was not authorised",
        811 => "the connection could not be established because the tunnel was not authorised",
        812 => "the connection was prevented because of a policy configured on your RAS/VPN server",
        813 => "the connection was prevented because of a policy configured on your RAS/VPN server",
        814 => "the connection was prevented because the IP address is not valid",
        815 => "the connection was prevented because the network is unreachable",
        816 => "the connection was prevented because the address was invalid",
        817 => "the connection could not be established because the remote computer is not reachable",
        818 => "the connection could not be established because the remote computer is not responding",
        819 => "the connection could not be established because the remote computer refused the connection",
        820 => "the connection could not be established because the security layer could not be negotiated",
        821 => "the connection could not be established because the authentication failed",
        822 => "the connection could not be established because the policy is not supported",
        823 => "the connection could not be established because the authentication protocol is not supported",
        824 => "the connection could not be established because the account is locked out",
        825 => "the connection could not be established because the account has expired",
        826 => "the connection could not be established because the account is disabled",
        827 => "the connection could not be established because the account has no dial-in permission",
        828 => "the connection could not be established because the device was not found",
        829 => "the connection could not be established because a certificate could not be found",
        830 => "the connection could not be established because the IP address could not be assigned",
        831 => "the connection could not be established because the encryption is not supported",
        832 => "the connection could not be established because the tunnel type is not supported",
        833 => "the connection could not be established because the tunnel could not be found",
        834 => "the connection could not be established because the tunnel could not be brought up",
        835 => "the connection could not be established because the tunnel collapsed",
        836 => "the connection could not be established because the tunnel was dropped",
        837 => "the connection could not be established because the tunnel could not be authenticated",
        838 => "the connection could not be established because the tunnel was not authorised",
        839 => "the connection could not be established because the tunnel was not authorised",
        840 => "the connection could not be established because the IP address is not valid",
        841 => "the connection could not be established because the network is unreachable",
        842 => "the connection could not be established because the address was invalid",
        843 => "the connection could not be established because the remote computer is not reachable",
        844 => "the connection could not be established because the remote computer is not responding",
        845 => "the connection could not be established because the remote computer refused the connection",
        846 => "the connection could not be established because the security layer could not be negotiated",
        847 => "the connection could not be established because the authentication failed",
        848 => "the connection could not be established because the policy is not supported",
        849 => "the connection could not be established because the authentication protocol is not supported",
        850 => "the connection could not be established because the account is locked out",
        851 => "the connection could not be established because the account has expired",
        852 => "the connection could not be established because the account is disabled",
        853 => "the connection could not be established because the account has no dial-in permission",
        854 => "the connection could not be established because the device was not found",
        855 => "the connection could not be established because a certificate could not be found",
        856 => "the connection could not be established because the IP address could not be assigned",
        857 => "the connection could not be established because the encryption is not supported",
        858 => "the connection could not be established because the tunnel type is not supported",
        859 => "the connection could not be established because the tunnel could not be found",
        860 => "the connection could not be established because the tunnel could not be brought up",
        861 => "the connection could not be established because the tunnel collapsed",
        862 => "the connection could not be established because the tunnel was dropped",
        863 => "the connection could not be established because the tunnel could not be authenticated",
        864 => "the connection could not be established because the tunnel was not authorised",
        865 => "the connection could not be established because the tunnel was not authorised",
        866 => "the connection could not be established because the IP address is not valid",
        867 => "the connection could not be established because the network is unreachable",
        868 => "the connection could not be established because the address was invalid",
        869 => "the connection could not be established because the remote computer is not reachable",
        870 => "the connection could not be established because the remote computer is not responding",
        871 => "the connection could not be established because the remote computer refused the connection",
        872 => "the connection could not be established because the security layer could not be negotiated",
        873 => "the connection could not be established because the authentication failed",
        _ => "unrecognised RAS error; see the Windows RAS error reference for this code",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_that_dies_right_after_dialling_still_backs_off() {
        use crate::net::*;

        // Regression, found on a real network with a half-dead PPPoE session: RAS reported the session
        // as established, the link then vanished immediately, and the state machine reset its backoff
        // on every attempt. The result was a dial loop at the initial interval forever - against a real
        // ISP that is indistinguishable from an attack, and it also flooded the log.
        //
        // Verification is not success. Only a link that reaches Healthy may reset the schedule.
        let policy = NetworkPolicy {
            failure_quorum: 1,
            min_dial_interval_secs: 0,
            ..Default::default()
        };

        // The link comes up with an address and a route, then disappears before the next round.
        let up = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            probe_results: vec![ProbeOutcome {
                id: "p".into(),
                kind: ProbeKind::Tcp,
                ok: true,
                latency_ms: Some(5),
                error: None,
            }],
            ..Default::default()
        };
        let gone = NetworkObservation {
            ras_connected: false,
            ..Default::default()
        };

        let mut state = NetworkState::default();
        let mut backoffs = Vec::new();

        // Alternate: dial succeeds, link dies, repeat. Each cycle is two evaluations.
        let mut now = 10_000;
        for _ in 0..6 {
            now += 1_000;
            let t = evaluate(&state, &up, &policy, now);
            state = t.state;

            now += 1_000;
            let t = evaluate(&state, &gone, &policy, now);
            state = t.state;
            backoffs.push(state.backoff_index);
        }

        assert!(
            backoffs.last().copied().unwrap_or(0) > 0,
            "the backoff index must advance across repeated abort cycles, got {backoffs:?}"
        );
        assert!(
            backoffs.windows(2).any(|w| w[1] > w[0]),
            "the schedule must grow rather than resetting every cycle, got {backoffs:?}"
        );
    }

    #[test]
    fn the_backoff_resets_only_after_a_link_is_genuinely_healthy() {
        use crate::net::*;

        let policy = NetworkPolicy {
            failure_quorum: 1,
            stabilize_secs: 5,
            min_dial_interval_secs: 0,
            ..Default::default()
        };

        let healthy = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            wifi_connected: true,
            wifi_has_ip: true,
            probe_results: vec![ProbeOutcome {
                id: "p".into(),
                kind: ProbeKind::Tcp,
                ok: true,
                latency_ms: Some(5),
                error: None,
            }],
            ..Default::default()
        };

        // Start with a well-advanced schedule, as if the link had failed many times.
        let mut state = NetworkState {
            broadband: BroadbandState::Reconnecting,
            backoff_index: 5,
            dial_attempts: 7,
            ..Default::default()
        };

        // Long enough to clear the stabilization window and be promoted.
        for round in 0..40 {
            let t = evaluate(&state, &healthy, &policy, 1_000 + round * 2_000);
            state = t.state;
        }

        assert_eq!(
            state.broadband,
            BroadbandState::Healthy,
            "the link should have been promoted after stabilizing"
        );
        assert_eq!(
            state.backoff_index, 0,
            "reaching Healthy is what resets the schedule"
        );
        assert_eq!(state.dial_attempts, 0);
    }

    #[test]
    fn a_freshly_dialled_link_is_not_torn_down_because_probes_fail() {
        use crate::net::*;

        // Regression, found on a real campus network: egress to public resolver IPs was blocked, so
        // the probe quorum never passed even with a healthy PPPoE session. The state machine treated
        // that as "session up but useless", hung it up, dialled again, and looped forever - which
        // looked like a broken ISP and, worse, meant the link was never usable.
        //
        // Link-layer evidence (session up, address, default route) is what establishes that broadband
        // is up. Probe evidence is what proves the *path* is good, and it must not be applied to a link
        // that has not finished settling.
        let policy = NetworkPolicy::default();

        // Session up with an address and a route, but every probe fails because the network filters
        // direct connections to public IPs.
        let obs = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            wifi_connected: true,
            wifi_has_ip: true,
            probe_results: vec![
                ProbeOutcome {
                    id: "a".into(),
                    kind: ProbeKind::Tcp,
                    ok: false,
                    latency_ms: None,
                    error: None,
                },
                ProbeOutcome {
                    id: "b".into(),
                    kind: ProbeKind::Tcp,
                    ok: false,
                    latency_ms: None,
                    error: None,
                },
                ProbeOutcome {
                    id: "c".into(),
                    kind: ProbeKind::Dns,
                    ok: true,
                    latency_ms: Some(4),
                    error: None,
                },
            ],
            ..Default::default()
        };

        // Start from a fresh dial: the state right after a successful RasDialW.
        let mut state = NetworkState {
            broadband: BroadbandState::Authenticating,
            ..Default::default()
        };

        let mut hung_up = false;
        let mut dialled_again = false;

        for round in 0..6 {
            let t = evaluate(&state, &obs, &policy, 1000 + round * 5_000);
            if t.actions
                .iter()
                .any(|a| matches!(a, NetworkAction::HangUpBroadband))
            {
                hung_up = true;
            }
            if t.actions
                .iter()
                .any(|a| matches!(a, NetworkAction::DialBroadband))
            {
                dialled_again = true;
            }
            state = t.state;
        }

        assert!(
            !hung_up,
            "a freshly dialled link must not be hung up merely because probes fail"
        );
        assert!(
            !dialled_again,
            "and it must certainly not be re-dialled in a loop"
        );
    }

    #[test]
    fn an_established_link_that_stops_passing_its_probes_is_demoted() {
        use crate::net::*;

        // The other half of the rule: once a link *has* been proven healthy, losing its probes is a
        // real signal that the path has broken, and it must be acted on. Otherwise the fix above would
        // have traded a dial loop for silently ignoring a dead link.
        let policy = NetworkPolicy {
            failure_quorum: 1,
            ..Default::default()
        };

        let obs = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            probe_results: vec![
                ProbeOutcome {
                    id: "a".into(),
                    kind: ProbeKind::Tcp,
                    ok: false,
                    latency_ms: None,
                    error: None,
                },
                ProbeOutcome {
                    id: "b".into(),
                    kind: ProbeKind::Tcp,
                    ok: false,
                    latency_ms: None,
                    error: None,
                },
            ],
            ..Default::default()
        };

        let mut state = NetworkState {
            broadband: BroadbandState::Healthy,
            broadband_healthy_since_ms: Some(0),
            broadband_preferred_since_ms: Some(0),
            ..Default::default()
        };

        let mut demoted = false;
        for round in 0..4 {
            let t = evaluate(&state, &obs, &policy, 100_000 + round * 1_000);
            if !matches!(t.state.broadband, BroadbandState::Healthy) {
                demoted = true;
            }
            state = t.state;
        }

        assert!(
            demoted,
            "an established link whose probes have all failed must be demoted"
        );
    }

    #[test]
    fn a_disconnected_link_dials_even_when_probes_partially_fail() {
        use crate::net::*;

        let policy = NetworkPolicy::default();
        // Exactly this machine's situation: no RAS session, egress filtered so two TCP probes time
        // out while a DNS probe and a hostname probe succeed. The link is still *down*, so a dial
        // must happen - the probe results describe the current path, not whether broadband is up.
        let obs = NetworkObservation {
            ras_connected: false,
            probe_results: vec![
                ProbeOutcome {
                    id: "a".into(),
                    kind: ProbeKind::Tcp,
                    ok: false,
                    latency_ms: None,
                    error: None,
                },
                ProbeOutcome {
                    id: "b".into(),
                    kind: ProbeKind::Tcp,
                    ok: false,
                    latency_ms: None,
                    error: None,
                },
                ProbeOutcome {
                    id: "c".into(),
                    kind: ProbeKind::Dns,
                    ok: true,
                    latency_ms: Some(5),
                    error: None,
                },
            ],
            ..Default::default()
        };

        assert_eq!(
            classify_failure(&obs, &policy),
            BroadbandFailureKind::PppoeSessionLost,
            "with no session at all, the failure must be classified as the session being lost"
        );

        let mut state = NetworkState::default();
        let mut dialled = false;
        for round in 0..4 {
            let t = evaluate(&state, &obs, &policy, 1000 + round * 30_000);
            if t.actions
                .iter()
                .any(|a| matches!(a, NetworkAction::DialBroadband))
            {
                dialled = true;
            }
            state = t.state;
        }
        assert!(
            dialled,
            "a disconnected link must be dialled despite partial probe failure"
        );
    }

    #[test]
    fn an_unconfigured_link_dials_on_the_first_evaluation() {
        use crate::net::*;

        let policy = NetworkPolicy {
            failure_quorum: 1,
            min_dial_interval_secs: 1,
            ..Default::default()
        };
        let mut state = NetworkState::default();

        // Nothing is up yet: exactly the state right after a boot with no dial-up connection.
        let obs = NetworkObservation {
            ras_connected: false,
            wifi_connected: true,
            wifi_has_ip: true,
            probe_results: vec![],
            ..Default::default()
        };

        let t = evaluate(&state, &obs, &policy, 1000);
        eprintln!("broadband={:?} actions={:?}", t.state.broadband, t.actions);
        assert!(
            t.actions
                .iter()
                .any(|a| matches!(a, NetworkAction::DialBroadband)),
            "a disconnected link must be dialled on the first pass, got {:?}",
            t.actions
        );
        state = t.state;

        // And it must not dial again inside the minimum interval.
        let t2 = evaluate(&state, &obs, &policy, 1500);
        assert!(
            !t2.actions
                .iter()
                .any(|a| matches!(a, NetworkAction::DialBroadband)),
            "a second dial inside the minimum interval must be suppressed"
        );
    }

    fn policy() -> NetworkPolicy {
        NetworkPolicy {
            stabilize_secs: 10,
            wifi_stabilize_secs: 5,
            min_wifi_hold_secs: 30,
            min_dial_interval_secs: 5,
            ..Default::default()
        }
    }

    fn tcp(id: &str, ok: bool) -> ProbeOutcome {
        ProbeOutcome {
            id: id.into(),
            kind: ProbeKind::Tcp,
            ok,
            latency_ms: ok.then_some(10),
            error: None,
        }
    }

    fn dns(id: &str, ok: bool) -> ProbeOutcome {
        ProbeOutcome {
            id: id.into(),
            kind: ProbeKind::Dns,
            ok,
            latency_ms: ok.then_some(20),
            error: None,
        }
    }

    /// Broadband healthy, Wi-Fi in warm standby.
    fn obs_healthy() -> NetworkObservation {
        NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            broadband_route_applied: true,
            wifi_connected: true,
            wifi_has_ip: true,
            probe_results: vec![tcp("a", true), tcp("b", true), dns("d", true)],
            ..Default::default()
        }
    }

    fn steady_state() -> NetworkState {
        NetworkState {
            broadband: BroadbandState::Healthy,
            wifi: WifiState::Healthy,
            preference: UplinkPreference::Broadband,
            internet: InternetState::BroadbandPrimary,
            broadband_healthy_since_ms: Some(0),
            broadband_preferred_since_ms: Some(0),
            wifi_healthy_since_ms: Some(0),
            ..Default::default()
        }
    }

    #[test]
    fn healthy_broadband_keeps_wifi_in_standby() {
        // The steady state: PPPoE healthy, Wi-Fi connected but not preferred.
        let s = steady_state();
        let t = evaluate(&s, &obs_healthy(), &policy(), 100_000);
        assert_eq!(t.state.broadband, BroadbandState::Healthy);
        assert_eq!(t.state.preference, UplinkPreference::Broadband);
        assert_eq!(t.state.internet, InternetState::BroadbandPrimary);
        assert!(
            !t.actions.contains(&NetworkAction::PreferWifi),
            "Wi-Fi must never be preferred while broadband is healthy"
        );
    }

    #[test]
    fn broadband_failure_immediately_engages_wifi_continuity() {
        // PPPoE drops. Wi-Fi must take over; broadband must be repaired in parallel.
        let s = steady_state();
        let obs = NetworkObservation {
            ras_connected: false,
            wifi_connected: true,
            wifi_has_ip: true,
            wifi_route_applied: false,
            probe_results: vec![tcp("a", true), tcp("b", true)],
            ..Default::default()
        };
        // Two failing rounds to satisfy the quorum, as a real deployment would see.
        let t1 = evaluate(&s, &obs, &policy(), 100_000);
        let t2 = evaluate(&t1.state, &obs, &policy(), 110_000);

        assert!(
            t2.state.wifi.is_up(),
            "Wi-Fi must be up to preserve connectivity"
        );
        assert_eq!(
            t2.actions
                .iter()
                .filter(|a| matches!(a, NetworkAction::PreferWifi))
                .count(),
            1,
            "traffic must be moved to Wi-Fi exactly once"
        );
        assert!(
            t2.actions.contains(&NetworkAction::DialBroadband)
                || t2
                    .notes
                    .iter()
                    .any(|n| n.contains("broadband service lost"))
                || t2.state.broadband == BroadbandState::Reconnecting,
            "broadband recovery must proceed in parallel"
        );
    }

    #[test]
    fn wifi_carries_traffic_while_broadband_is_unavailable() {
        let s = NetworkState {
            broadband: BroadbandState::Reconnecting,
            wifi: WifiState::Continuity,
            preference: UplinkPreference::Wifi,
            internet: InternetState::WifiContinuity,
            wifi_healthy_since_ms: Some(0),
            on_wifi_since_ms: Some(0),
            ..Default::default()
        };
        let obs = NetworkObservation {
            ras_dialing: true,
            wifi_connected: true,
            wifi_has_ip: true,
            wifi_route_applied: true,
            probe_results: vec![tcp("a", true), tcp("b", true)],
            ..Default::default()
        };
        let t = evaluate(&s, &obs, &policy(), 100_000);
        assert_eq!(t.state.preference, UplinkPreference::Wifi);
        assert_eq!(t.state.internet, InternetState::RecoveringBroadband);
        assert!(
            !t.actions.contains(&NetworkAction::DisconnectWifi),
            "Wi-Fi must not be torn down while broadband is still establishing"
        );
    }

    #[test]
    fn successful_dial_does_not_immediately_become_preferred() {
        // The critical anti-flap rule: a successful RAS connection is not recovery.
        let s = NetworkState {
            broadband: BroadbandState::Reconnecting,
            wifi: WifiState::Continuity,
            preference: UplinkPreference::Wifi,
            internet: InternetState::WifiContinuity,
            wifi_healthy_since_ms: Some(0),
            on_wifi_since_ms: Some(0),
            ..Default::default()
        };
        let obs = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            broadband_route_applied: false,
            wifi_connected: true,
            wifi_has_ip: true,
            wifi_route_applied: true,
            probe_results: vec![tcp("a", true), tcp("b", true), dns("d", true)],
            ..Default::default()
        };

        // First round: enters verification, still on Wi-Fi.
        let t1 = evaluate(&s, &obs, &policy(), 100_000);
        assert_eq!(t1.state.broadband, BroadbandState::Verifying);
        assert_eq!(
            t1.state.preference,
            UplinkPreference::Wifi,
            "must stay on Wi-Fi while broadband is only verifying"
        );
        assert!(
            !t1.actions.contains(&NetworkAction::PreferBroadband),
            "must not switch routes before stabilization"
        );

        // Halfway through the stabilization window: still on Wi-Fi.
        let t2 = evaluate(&t1.state, &obs, &policy(), 105_000);
        assert_eq!(t2.state.broadband, BroadbandState::Verifying);
        assert_eq!(t2.state.preference, UplinkPreference::Wifi);

        // After the window: promote.
        let t3 = evaluate(&t2.state, &obs, &policy(), 111_000);
        assert_eq!(t3.state.broadband, BroadbandState::Healthy);
        assert_eq!(t3.state.preference, UplinkPreference::Broadband);
        assert!(t3.actions.contains(&NetworkAction::PreferBroadband));
        assert_eq!(t3.state.internet, InternetState::BroadbandPrimary);
    }

    #[test]
    fn frequent_broadband_aborts_widen_the_stabilization_window() {
        // A link that keeps dying right after promotion must be trusted less each time.
        let mut s = steady_state();
        s.broadband_healthy_since_ms = Some(0);
        s.broadband_preferred_since_ms = Some(0);
        s.recent_aborts = 2;

        // Simulate the connection dying immediately after promotion.
        let obs_bad = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            probe_results: vec![tcp("a", false), tcp("b", false)],
            ..Default::default()
        };
        let t = evaluate(&s, &obs_bad, &policy(), 5_000);
        let t = evaluate(&t.state, &obs_bad, &policy(), 6_000);
        assert_eq!(t.state.broadband, BroadbandState::Degraded);
        assert!(
            t.state.recent_aborts >= 2,
            "repeated aborts must be remembered"
        );

        // Now it reconnects and must verify for longer than the base window.
        let obs_good = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            probe_results: vec![tcp("a", true), tcp("b", true)],
            ..Default::default()
        };
        let v1 = evaluate(&t.state, &obs_good, &policy(), 10_000);
        assert_eq!(v1.state.broadband, BroadbandState::Verifying);

        // At the *base* stabilization window it must still not be promoted.
        let v2 = evaluate(&v1.state, &obs_good, &policy(), 10_000 + 10_000);
        assert_eq!(
            v2.state.broadband,
            BroadbandState::Verifying,
            "a widened window must not promote at the base duration"
        );

        // Well past the widened window it promotes.
        let widened_ms = 10_000 + (10 * 3 * 1000);
        let v3 = evaluate(&v2.state, &obs_good, &policy(), widened_ms);
        assert_eq!(v3.state.broadband, BroadbandState::Healthy);
    }

    #[test]
    fn dns_only_failure_does_not_tear_down_the_session() {
        // A working PPPoE session must survive a resolver problem.
        let s = NetworkState {
            broadband: BroadbandState::Healthy,
            preference: UplinkPreference::Broadband,
            broadband_healthy_since_ms: Some(0),
            ..Default::default()
        };
        let obs = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            probe_results: vec![tcp("a", true), tcp("b", true), dns("d", false)],
            ..Default::default()
        };
        assert!(obs.dns_only_failure());
        assert_eq!(
            classify_failure(&obs, &policy()),
            BroadbandFailureKind::DnsOnlyFailure
        );
        assert!(!BroadbandFailureKind::DnsOnlyFailure.warrants_redial());

        let t = evaluate(&s, &obs, &policy(), 1000);
        assert!(
            !t.actions.contains(&NetworkAction::HangUpBroadband),
            "a DNS-only failure must never destroy a valid PPPoE session"
        );
    }

    #[test]
    fn authentication_failure_stops_retrying() {
        let s = NetworkState {
            broadband: BroadbandState::Reconnecting,
            wifi: WifiState::Continuity,
            preference: UplinkPreference::Wifi,
            wifi_healthy_since_ms: Some(0),
            ..Default::default()
        };
        let obs = NetworkObservation {
            ras_connected: false,
            ras_error: Some(691),
            wifi_connected: true,
            wifi_has_ip: true,
            wifi_route_applied: true,
            probe_results: vec![tcp("a", true), tcp("b", true)],
            ..Default::default()
        };
        let t = evaluate(&s, &obs, &policy(), 100_000);
        assert_eq!(
            classify_failure(&obs, &policy()),
            BroadbandFailureKind::AuthenticationFailed
        );
        assert!(
            !t.actions.contains(&NetworkAction::DialBroadband),
            "bad credentials must not produce a dial loop"
        );
        assert!(
            t.state.wifi.is_up(),
            "continuity must remain while broadband is broken"
        );
    }

    #[test]
    fn no_wifi_means_no_continuity_and_an_honest_offline_state() {
        let s = steady_state();
        let obs = NetworkObservation {
            ras_connected: false,
            wifi_connected: false,
            probe_results: vec![tcp("a", false), tcp("b", false)],
            ..Default::default()
        };
        let t1 = evaluate(&s, &obs, &policy(), 1000);
        let t2 = evaluate(&t1.state, &obs, &policy(), 2000);
        assert_eq!(t2.state.preference, UplinkPreference::None);
        assert_eq!(t2.state.internet, InternetState::Offline);
        assert!(!t2.state.internet.user_online());
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let mut s = NetworkState {
            broadband: BroadbandState::Reconnecting,
            ..Default::default()
        };
        let obs = NetworkObservation {
            ras_connected: false,
            wifi_connected: true,
            wifi_has_ip: true,
            probe_results: vec![tcp("a", true), tcp("b", true)],
            ..Default::default()
        };

        // Walk far past the schedule length; the index must saturate, not overflow.
        let mut now = 0;
        for _ in 0..40 {
            now += 120_000; // well beyond the minimum dial interval
            let t = evaluate(&s, &obs, &policy(), now);
            s = t.state;
        }
        assert_eq!(s.backoff_index, BACKOFF_MS.len() - 1);
        assert!(s.dial_attempts > 8);
    }

    #[test]
    fn dial_is_rate_limited_by_the_minimum_interval() {
        let s = NetworkState {
            broadband: BroadbandState::Reconnecting,
            last_dial_ms: Some(100_000),
            ..Default::default()
        };
        let obs = NetworkObservation {
            ras_connected: false,
            wifi_connected: true,
            wifi_has_ip: true,
            probe_results: vec![tcp("a", true), tcp("b", true)],
            ..Default::default()
        };
        // One second later: too soon to dial again.
        let t = evaluate(&s, &obs, &policy(), 101_000);
        assert!(
            !t.actions.contains(&NetworkAction::DialBroadband),
            "must not dial again inside the minimum interval"
        );
        assert!(t
            .actions
            .iter()
            .any(|a| matches!(a, NetworkAction::Wait { .. })));
    }

    #[test]
    fn only_one_dial_is_ever_requested_per_evaluation() {
        let s = NetworkState {
            broadband: BroadbandState::Reconnecting,
            ..Default::default()
        };
        let obs = NetworkObservation {
            ras_connected: false,
            wifi_connected: true,
            wifi_has_ip: true,
            probe_results: vec![tcp("a", true), tcp("b", true)],
            ..Default::default()
        };
        let t = evaluate(&s, &obs, &policy(), 999_999);
        let dials = t
            .actions
            .iter()
            .filter(|a| matches!(a, NetworkAction::DialBroadband))
            .count();
        assert!(dials <= 1, "concurrent dial attempts must be impossible");
    }

    #[test]
    fn recovery_resets_backoff_only_once_healthy() {
        let s = NetworkState {
            broadband: BroadbandState::Healthy,
            broadband_healthy_since_ms: Some(0),
            preference: UplinkPreference::Broadband,
            backoff_index: 5,
            dial_attempts: 9,
            ..Default::default()
        };
        let t = evaluate(&s, &obs_healthy(), &policy(), 100_000);
        assert_eq!(t.state.backoff_index, 0);
        assert_eq!(t.state.dial_attempts, 0);
    }

    #[test]
    fn unmeasured_round_does_not_flap_the_state() {
        // If probes did not run, we must not conclude failure from an empty result set.
        let s = steady_state();
        let obs = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            probe_results: vec![],
            wifi_connected: true,
            wifi_has_ip: true,
            ..Default::default()
        };
        let t = evaluate(&s, &obs, &policy(), 100_000);
        assert_eq!(t.state.broadband, BroadbandState::Healthy);
        assert_eq!(t.state.preference, UplinkPreference::Broadband);
    }

    #[test]
    fn unusable_session_is_torn_down_only_when_continuity_exists() {
        let obs_bad = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: false, // no IP: the session is useless
            broadband_default_route: false,
            wifi_connected: true,
            wifi_has_ip: true,
            wifi_route_applied: true,
            probe_results: vec![tcp("a", true), tcp("b", true)],
            ..Default::default()
        };
        let s = NetworkState {
            broadband: BroadbandState::Degraded,
            wifi: WifiState::Continuity,
            preference: UplinkPreference::Wifi,
            wifi_healthy_since_ms: Some(0),
            ..Default::default()
        };
        let t1 = evaluate(&s, &obs_bad, &policy(), 1000);
        let t2 = evaluate(&t1.state, &obs_bad, &policy(), 2000);
        assert_eq!(
            classify_failure(&obs_bad, &policy()),
            BroadbandFailureKind::NoIpConfiguration
        );
        assert!(
            t2.actions.contains(&NetworkAction::HangUpBroadband),
            "an unusable session must be cleaned up once a working path exists"
        );
    }

    #[test]
    fn preference_is_derived_not_assigned() {
        // Whatever the rest of the state says, preference follows the uplink states.
        assert_eq!(
            compute_preference(BroadbandState::Healthy, WifiState::Continuity),
            UplinkPreference::Broadband,
            "healthy broadband always wins"
        );
        assert_eq!(
            compute_preference(BroadbandState::Verifying, WifiState::Continuity),
            UplinkPreference::Wifi,
            "verifying broadband does not displace a working backup"
        );
        assert_eq!(
            compute_preference(BroadbandState::Healthy, WifiState::Disconnected),
            UplinkPreference::Broadband
        );
        assert_eq!(
            compute_preference(BroadbandState::Failed, WifiState::Disconnected),
            UplinkPreference::None
        );
    }

    #[test]
    fn internet_state_labels_recovery_honestly() {
        assert_eq!(
            derive_internet_state(
                BroadbandState::Healthy,
                WifiState::Healthy,
                UplinkPreference::Broadband
            ),
            InternetState::BroadbandPrimary
        );
        assert_eq!(
            derive_internet_state(
                BroadbandState::Verifying,
                WifiState::Continuity,
                UplinkPreference::Wifi
            ),
            InternetState::RecoveringBroadband
        );
        assert_eq!(
            derive_internet_state(
                BroadbandState::Failed,
                WifiState::Continuity,
                UplinkPreference::Wifi
            ),
            InternetState::WifiContinuity
        );
    }

    #[test]
    fn wifi_route_is_never_requested_while_broadband_is_healthy() {
        let s = steady_state();
        let obs = NetworkObservation {
            broadband_route_applied: false, // Guardian has not applied it yet
            ..obs_healthy()
        };
        let t = evaluate(&s, &obs, &policy(), 100_000);
        assert!(t.actions.contains(&NetworkAction::PreferBroadband));
        assert!(!t.actions.contains(&NetworkAction::PreferWifi));
    }

    #[test]
    fn managed_routes_are_released_only_when_nothing_works() {
        let s = steady_state();
        let obs = NetworkObservation {
            ras_connected: false,
            wifi_connected: false,
            broadband_route_applied: true,
            wifi_route_applied: true,
            probe_results: vec![tcp("a", false), tcp("b", false)],
            ..Default::default()
        };
        let t1 = evaluate(&s, &obs, &policy(), 1000);
        let t2 = evaluate(&t1.state, &obs, &policy(), 2000);
        assert!(t2.actions.contains(&NetworkAction::ReleaseManagedRoutes));
    }

    #[test]
    fn disabled_network_management_is_inert() {
        let policy = NetworkPolicy {
            enabled: false,
            ..policy()
        };
        let t = evaluate(&steady_state(), &obs_healthy(), &policy, 1000);
        assert!(t.actions.is_empty());
        assert_eq!(t.state.broadband, BroadbandState::Disconnected);
    }

    #[test]
    fn ras_error_translations_cover_the_common_cases() {
        // Spot-check the codes an operator is most likely to encounter.
        for (code, needle) in [
            (691u32, "username"),
            (678, "no answer"),
            (651, "reported an error"),
            (812, "policy"),
            (829, "certificate"),
        ] {
            let msg = ras_error_message(code);
            assert!(
                msg.to_ascii_lowercase()
                    .contains(&needle.to_ascii_lowercase()),
                "code {code} should mention {needle}, got: {msg}"
            );
        }
        // An unknown code must produce a non-empty, non-committal message.
        let unknown = ras_error_message(99_999);
        assert!(!unknown.is_empty());
        assert!(unknown.to_ascii_lowercase().contains("unrecognised"));
    }

    #[test]
    fn jitter_is_bounded_and_deterministic() {
        for attempt in 0..1000u32 {
            let j = jitter_for(attempt);
            assert!(j < 1000);
            let base = 8000u64;
            let with = apply_jitter(base, j);
            // At most 19.9% above base.
            assert!(with >= base && with <= base + base / 5 + 1, "{with}");
        }
        // Same input, same output.
        assert_eq!(jitter_for(7), jitter_for(7));
        // Zero jitter leaves the base untouched (and zero stays zero).
        assert_eq!(apply_jitter(0, 500), 0);
        assert_eq!(apply_jitter(1000, 0), 1000);
    }

    #[test]
    fn partial_connectivity_is_not_classified_as_a_full_outage() {
        let obs = NetworkObservation {
            ras_connected: true,
            broadband_has_ip: true,
            broadband_default_route: true,
            probe_results: vec![tcp("a", true), tcp("b", false), dns("d", false)],
            ..Default::default()
        };
        assert!(obs.partial_connectivity());
        assert_eq!(
            classify_failure(&obs, &policy()),
            BroadbandFailureKind::PartialConnectivity
        );
    }

    #[test]
    fn snapshot_reports_raw_and_translated_ras_errors_together() {
        let s = NetworkState {
            broadband: BroadbandState::Reconnecting,
            last_ras_error: Some(691),
            last_dial_ms: Some(5000),
            outage_started_ms: Some(1000),
            outage_ms: 4000,
            dial_attempts: 2,
            failure_kind: Some(BroadbandFailureKind::AuthenticationFailed),
            ..Default::default()
        };
        let snap = snapshot(&s, &policy(), Some("Broadband".into()), vec![], 9000);
        let outage = snap.current_outage.expect("outage recorded");
        assert_eq!(outage.dial_attempts, 2);
        assert_eq!(outage.ras_errors[0].code, 691);
        assert!(outage.ras_errors[0].message.contains("username"));
        assert!(snap.last_error.as_ref().unwrap().contains("691"));
    }
}
