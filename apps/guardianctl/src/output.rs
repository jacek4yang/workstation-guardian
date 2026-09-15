//! Human-readable rendering of protocol responses.
//!
//! Deliberately plain: a diagnostics tool's output is read in a terminal, often over a remote
//! session, and columns that line up are worth more than colour. The text is also stable enough
//! that an operator can diff two runs.

use guardian_proto::model::{
    AgentInstance, AgentInventory, Confidence, Incident, IncidentKind, InternetHealth,
    NetworkSnapshot, PendingRebootReport, ProtectionLevel, StatusSnapshot,
};
use guardian_proto::Response;

/// Render any response.
pub fn render_response(response: &Response) -> String {
    match response {
        Response::Hello {
            protocol,
            service_version,
            ..
        } => format!("service version {service_version} (protocol {protocol})"),
        Response::Status(s) => status_text(s),
        Response::Agents(a) => agents_text(a),
        Response::Network(n) => network_text(n),
        Response::Incidents(v) => incidents_text(v),
        Response::PendingReboot(p) => pending_reboot_text(p),
        Response::Config(c) => match serde_json::to_string_pretty(c) {
            Ok(s) => s,
            Err(e) => format!("could not render the configuration: {e}"),
        },
        Response::Health(h) => crate::doctor::render(h),
        Response::RebootAuthorization(a) => match a.as_ref() {
            Some(auth) => format!(
                "A single reboot is authorized.\n  Issued at    {}\n  Expires at   {}\n  Issued by    {}\n  Consumed     {}",
                format_ms(auth.issued_at_ms),
                format_ms(auth.expires_at_ms),
                auth.issued_by,
                auth.consumed_at_ms
                    .map(format_ms)
                    .unwrap_or_else(|| "not yet".into())
            ),
            None => "No reboot is authorized.".to_string(),
        },
        Response::Ok { message } => message.clone(),
        Response::Error(e) => format!("error: {e}"),
    }
}

/// Render the main status screen.
pub fn status_text(s: &StatusSnapshot) -> String {
    let mut out = String::new();

    out.push_str("WORKSTATION GUARDIAN\n\n");

    out.push_str("Protection\n");
    out.push_str(&format!(
        "  {:<24}{}\n",
        "Update Protection",
        level_label(s.update.level)
    ));
    out.push_str(&format!(
        "  {:<24}{}\n",
        "Restart Protection",
        level_label(s.restart_protection)
    ));
    out.push_str(&format!(
        "  {:<24}{}\n",
        "Service",
        if s.service.running {
            "Running"
        } else {
            "Stopped"
        }
    ));
    out.push_str(&format!("  {:<24}{}\n", "Mode", s.mode.as_str()));
    out.push_str(&format!(
        "  {:<24}{}\n",
        "Uptime",
        format_duration(s.service.uptime_ms)
    ));
    if !s.service.degraded_components.is_empty() {
        out.push_str(&format!(
            "  {:<24}{}\n",
            "Degraded",
            s.service.degraded_components.join(", ")
        ));
    }

    out.push('\n');
    out.push_str("Network\n");
    out.push_str(&format!(
        "  {:<24}{}\n",
        "Internet",
        internet_label(s.network.internet)
    ));
    out.push_str(&format!(
        "  {:<24}{}\n",
        "PPPoE",
        s.network
            .entry_name
            .as_deref()
            .unwrap_or("(not configured)")
    ));
    out.push_str(&format!("  {:<24}{:?}\n", "RAS state", s.network.ras_state));
    if let Some(uptime) = s.network.uptime_ms {
        out.push_str(&format!(
            "  {:<24}{}\n",
            "Connection uptime",
            format_duration(uptime)
        ));
    }
    if let Some(last) = s.network.last_reconnect_ms {
        out.push_str(&format!("  {:<24}{}\n", "Last reconnect", format_ms(last)));
    }
    if let Some(outage) = &s.network.current_outage {
        out.push_str(&format!(
            "  {:<24}ongoing, {} ({} attempts)\n",
            "Outage",
            format_duration(outage.downtime_ms.unwrap_or(0)),
            outage.dial_attempts
        ));
    }

    out.push('\n');
    out.push_str("Active Work\n");
    let agents = &s.agents;
    if agents.agent_count() == 0 && agents.workloads.is_empty() {
        out.push_str("  (nothing detected)\n");
    } else {
        for group in &agents.agents {
            let live: Vec<&AgentInstance> = group
                .instances
                .iter()
                .filter(|i| i.confidence.drives_protection())
                .collect();
            if live.is_empty() {
                continue;
            }
            out.push_str(&format!("  {:<24}{}\n", group.display_name, live.len()));
        }
        // Report the ones that are only possible, so they are visible without being counted.
        for group in &agents.agents {
            let possible: Vec<&AgentInstance> = group
                .instances
                .iter()
                .filter(|i| i.confidence == Confidence::Possible)
                .collect();
            if !possible.is_empty() {
                out.push_str(&format!(
                    "  {:<24}{} (unconfirmed)\n",
                    group.display_name,
                    possible.len()
                ));
            }
        }
        if !agents.workloads.is_empty() {
            out.push_str(&format!("  {:<24}{}\n", "Builds", agents.workloads.len()));
        }
    }

    out.push('\n');
    out.push_str("Pending reboot\n");
    out.push_str(&format!(
        "  {:<24}{}\n",
        s.pending_reboot.verdict.as_str(),
        s.pending_reboot.reasons().join("; ")
    ));

    if let Some(auth) = &s.reboot_authorization {
        out.push('\n');
        out.push_str("Maintenance\n");
        out.push_str(&format!(
            "  {:<24}{} until {}\n",
            "One reboot authorized",
            "armed",
            format_ms(auth.expires_at_ms)
        ));
    }

    if !s.maintenance_denial_reasons.is_empty() {
        out.push('\n');
        out.push_str("Maintenance would currently be refused:\n");
        for r in &s.maintenance_denial_reasons {
            out.push_str(&format!("  {r}\n"));
        }
    }

    out
}

/// Render the agent inventory.
pub fn agents_text(inventory: &AgentInventory) -> String {
    let mut out = String::new();

    if inventory.agent_count() == 0 {
        out.push_str("No AI coding agents detected.\n");
    } else {
        out.push_str(&format!(
            "{} agent(s) detected\n\n",
            inventory.agent_count()
        ));
    }

    for group in &inventory.agents {
        for instance in &group.instances {
            out.push_str(&format!("{}\n", instance.display_name));
            out.push_str(&format!(
                "  {:<16}{}\n",
                "Confidence",
                instance.confidence.as_str()
            ));
            out.push_str(&format!(
                "  {:<16}{} / {}\n",
                "PID / root", instance.pid, instance.root_pid
            ));
            out.push_str(&format!("  {:<16}{}\n", "Session", instance.session_id));
            if let Some(path) = &instance.image_path {
                out.push_str(&format!("  {:<16}{}\n", "Image", path));
            }
            if let Some(project) = &instance.project {
                out.push_str(&format!(
                    "  {:<16}{} (from {})\n",
                    "Project", project.name, project.source
                ));
            }
            match &instance.resume {
                guardian_proto::model::ResumeCapability::Available { handle, hint } => {
                    out.push_str(&format!("  {:<16}{}\n", "Resumable", handle));
                    out.push_str(&format!("  {:<16}{hint}\n", "Resume with"));
                }
                guardian_proto::model::ResumeCapability::Unsupported => {
                    out.push_str(&format!("  {:<16}unavailable\n", "Resumable"));
                }
                guardian_proto::model::ResumeCapability::Unavailable => {}
            }
            if !instance.evidence.is_empty() {
                out.push_str(&format!("  {:<16}\n", "Evidence"));
                for e in &instance.evidence {
                    out.push_str(&format!("    [{}] {} — {}\n", e.code, e.matched, e.detail));
                }
            }
            out.push('\n');
        }
    }

    if !inventory.workloads.is_empty() {
        out.push_str("Protected workloads\n\n");
        for w in &inventory.workloads {
            out.push_str(&format!("{}\n", w.display_name));
            out.push_str(&format!("  {:<16}{}\n", "PID", w.pid));
            out.push_str(&format!(
                "  {:<16}{}\n",
                "Running",
                format_duration(w.running_ms)
            ));
            if let Some(owner) = &w.owner_kind {
                out.push_str(&format!("  {:<16}{owner}\n", "Owner"));
            }
            out.push_str(&format!("  {:<16}{}\n", "Reason", w.reason));
        }
    }

    if !inventory.candidates.is_empty() {
        out.push_str("\nUnconfirmed candidates (reported, not protected)\n\n");
        for c in &inventory.candidates {
            out.push_str(&format!(
                "  {} (pid {}) — {}\n",
                c.name,
                c.pid,
                c.evidence
                    .first()
                    .map(|e| e.detail.clone())
                    .unwrap_or_default()
            ));
        }
        out.push_str(
            "\nThese never block shutdown. Promote one with a custom agent signature if it is \
             really an agent.\n",
        );
    }

    out
}

/// Render the network snapshot.
pub fn network_text(n: &NetworkSnapshot) -> String {
    let mut out = String::new();

    out.push_str("NETWORK\n\n");
    out.push_str(&format!(
        "  {:<20}{}\n",
        "Internet",
        internet_label(n.internet)
    ));
    out.push_str(&format!("  {:<20}{:?}\n", "Phase", n.phase));
    out.push_str(&format!(
        "  {:<20}{}\n",
        "PPPoE entry",
        n.entry_name.as_deref().unwrap_or("(not configured)")
    ));
    out.push_str(&format!("  {:<20}{:?}\n", "RAS state", n.ras_state));

    if let Some(uptime) = n.uptime_ms {
        out.push_str(&format!("  {:<20}{}\n", "Uptime", format_duration(uptime)));
    }
    if let Some(last) = n.last_reconnect_ms {
        out.push_str(&format!("  {:<20}{}\n", "Last reconnect", format_ms(last)));
    }

    out.push_str(&format!(
        "  {:<20}{} of {} required\n",
        "Quorum", n.consecutive_successes, n.quorum_required
    ));
    out.push_str(&format!(
        "  {:<20}{}\n",
        "Backoff",
        format_duration(n.backoff_ms as i64)
    ));

    if let Some(err) = &n.last_error {
        out.push_str(&format!("  {:<20}{err}\n", "Last error"));
    }

    out.push_str("\n  Probes\n");
    if n.probes.is_empty() {
        out.push_str("    (none configured)\n");
    }
    for p in &n.probes {
        out.push_str(&format!(
            "    {:<24}{:<6}{}\n",
            p.id,
            if p.ok { "ok" } else { "FAIL" },
            p.error.clone().unwrap_or_else(|| {
                p.latency_ms.map(|ms| format!("{ms}ms")).unwrap_or_default()
            })
        ));
    }

    if let Some(outage) = &n.current_outage {
        out.push_str("\n  Current outage\n");
        out.push_str(&format!(
            "    {:<22}{}\n",
            "Started",
            format_ms(outage.started_at_ms)
        ));
        out.push_str(&format!(
            "    {:<22}{}\n",
            "Duration",
            format_duration(outage.downtime_ms.unwrap_or(0))
        ));
        out.push_str(&format!("    {:<22}{}\n", "Reason", outage.reason));
        out.push_str(&format!(
            "    {:<22}{}\n",
            "Dial attempts", outage.dial_attempts
        ));
        for e in &outage.ras_errors {
            out.push_str(&format!("    RAS error {} — {}\n", e.code, e.message));
        }
    }

    if !n.recent_outages.is_empty() {
        out.push_str("\n  Recent outages\n");
        for o in &n.recent_outages {
            out.push_str(&format!(
                "    {} for {} ({}, {} attempts)\n",
                format_ms(o.started_at_ms),
                format_duration(o.downtime_ms.unwrap_or(0)),
                o.reason,
                o.dial_attempts
            ));
        }
    }

    out
}

/// Render incidents.
pub fn incidents_text(incidents: &[Incident]) -> String {
    if incidents.is_empty() {
        return "No incidents recorded.\n".to_string();
    }

    let mut out = format!("{} incident(s), newest first\n\n", incidents.len());

    for i in incidents {
        out.push_str(&format!(
            "{}  [{:?}] {}\n",
            format_ms(i.at_ms),
            i.severity,
            i.title
        ));
        out.push_str(&format!("  {}\n", i.summary));

        match i.kind {
            IncidentKind::UnexpectedRestart => {
                if let Some(r) = &i.details.unexpected_restart {
                    out.push_str(&format!(
                        "  Boot: {} -> {}\n",
                        r.previous_boot_id, r.current_boot_id
                    ));
                    if let Some(initiator) = &r.likely_initiator {
                        out.push_str(&format!("  Likely initiator: {initiator}\n"));
                    }
                    out.push_str(&format!(
                        "  Confidence: {:?}, Windows Update related: {:?}\n",
                        r.confidence, r.windows_update_related
                    ));
                    if !r.agents_lost.is_empty() {
                        out.push_str("  Agents lost:\n");
                        for a in &r.agents_lost {
                            out.push_str(&format!(
                                "    {} (pid {}, project {})\n",
                                a.display_name,
                                a.pid,
                                a.project.as_deref().unwrap_or("unknown")
                            ));
                        }
                    }
                    if !r.evidence.is_empty() {
                        out.push_str("  Evidence:\n");
                        for e in r.evidence.iter().take(10) {
                            out.push_str(&format!(
                                "    {}/{}: {}\n",
                                e.provider,
                                e.event_id,
                                truncate(&e.message, 120)
                            ));
                        }
                    }
                }
            }
            IncidentKind::PolicyTamper => {
                if let Some(t) = &i.details.policy_tamper {
                    out.push_str(&format!(
                        "  {}\\{}: {:?} -> {:?}, restored: {}\n",
                        t.key_path, t.value_name, t.expected, t.observed, t.restored
                    ));
                }
            }
            IncidentKind::WorkerFailure => {
                if let Some(w) = &i.details.worker_failure {
                    out.push_str(&format!(
                        "  Worker '{}' failed {} time(s): {}\n",
                        w.worker, w.restarts, w.error
                    ));
                }
            }
            _ => {}
        }

        for (k, v) in &i.details.extra {
            out.push_str(&format!("  {k}: {v}\n"));
        }

        out.push('\n');
    }

    out
}

/// Render a pending-reboot report.
pub fn pending_reboot_text(report: &PendingRebootReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("Pending reboot: {}\n", report.verdict.as_str()));
    out.push_str(&format!(
        "Checked at: {}\n\n",
        format_ms(report.checked_at_ms)
    ));

    if report.signals.is_empty() {
        out.push_str("No indicators were probed.\n");
        return out;
    }

    out.push_str("Indicators:\n");
    for s in &report.signals {
        let state = if s.read_failed {
            "UNREADABLE".to_string()
        } else if s.present {
            format!("PRESENT ({:?})", s.weight)
        } else {
            "absent".to_string()
        };
        out.push_str(&format!("  {:<40}{}\n", s.id, state));
        out.push_str(&format!("      {}\n", s.detail));
    }

    out
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

/// The label shown for a protection level.
///
/// `Protected` is the only value that reads as reassuring; everything else is stated plainly.
pub fn level_label(level: ProtectionLevel) -> &'static str {
    match level {
        ProtectionLevel::Protected => "Protected",
        ProtectionLevel::Degraded => "Degraded",
        ProtectionLevel::Maintenance => "Maintenance",
        ProtectionLevel::Unknown => "Unknown",
        ProtectionLevel::Unprotected => "NOT PROTECTED",
    }
}

/// The label shown for Internet health.
pub fn internet_label(health: InternetHealth) -> &'static str {
    match health {
        InternetHealth::Healthy => "Healthy",
        InternetHealth::Degraded => "Degraded",
        InternetHealth::Down => "Down",
        InternetHealth::Unknown => "Unknown",
    }
}

/// Render a Unix millisecond timestamp.
pub fn format_ms(ms: i64) -> String {
    // Rendered as a local-ish ISO-like string without pulling in a calendar dependency for what
    // is purely a display concern. The epoch offset is computed in whole days.
    if ms <= 0 {
        return "never".to_string();
    }
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    format!(
        "day+{days} {:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Render a millisecond duration compactly.
pub fn format_duration(ms: i64) -> String {
    if ms < 0 {
        return "unknown".to_string();
    }
    let secs = ms / 1000;
    if secs < 60 {
        return format!("{secs}s");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m {:02}s", secs % 60);
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h {:02}m", mins % 60);
    }
    format!("{}d {:02}h", hours / 24, hours % 24)
}

/// Truncate for display.
fn truncate(s: &str, max: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max {
            out.push('…');
            break;
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_proto::model::UpdateProtectionReport;
    use guardian_proto::model::*;

    fn sample_status() -> StatusSnapshot {
        StatusSnapshot {
            mode: ProtectionMode::Working,
            update: UpdateProtectionReport {
                level: ProtectionLevel::Protected,
                primary_lock_effective: true,
                values: vec![],
                neutralized_deadlines: vec![],
                management: ManagementState::Unmanaged,
                findings: vec![],
                checked_at_ms: 1_000_000,
                backend_error: None,
            },
            restart_protection: ProtectionLevel::Protected,
            pending_reboot: PendingRebootReport {
                verdict: PendingRebootVerdict::NotPending,
                signals: vec![],
                checked_at_ms: 1_000_000,
            },
            service: ServiceHealth {
                running: true,
                started_at_ms: 1_000_000,
                uptime_ms: 3_600_000,
                version: "0.1.0".into(),
                degraded_components: vec![],
                started_after_unclean_exit: false,
            },
            agents: Box::new(AgentInventory::default()),
            network: Box::new(NetworkSnapshot::default()),
            reboot_authorization: None,
            maintenance_denial_reasons: vec![],
            generated_at_ms: 1_000_000,
            service_version: "0.1.0".into(),
            boot_id: "boot-1".into(),
            session_id_helper: SessionHelperState::Connected,
        }
    }

    #[test]
    fn the_status_screen_names_every_section() {
        let text = status_text(&sample_status());
        for section in [
            "WORKSTATION GUARDIAN",
            "Protection",
            "Network",
            "Active Work",
        ] {
            assert!(text.contains(section), "missing '{section}' in:\n{text}");
        }
        assert!(text.contains("Update Protection"));
        assert!(text.contains("Protected"));
        assert!(text.contains("WORKING"));
    }

    #[test]
    fn an_unprotected_machine_does_not_render_the_word_protected() {
        let mut s = sample_status();
        s.update.level = ProtectionLevel::Unprotected;
        s.update.primary_lock_effective = false;
        let text = status_text(&s);
        assert!(
            text.contains("NOT PROTECTED"),
            "an unprotected machine must say so plainly:\n{text}"
        );
    }

    #[test]
    fn degraded_components_are_shown() {
        let mut s = sample_status();
        s.service.degraded_components = vec!["network".into(), "agents".into()];
        let text = status_text(&s);
        assert!(text.contains("Degraded"));
        assert!(text.contains("network"));
        assert!(text.contains("agents"));
    }

    #[test]
    fn maintenance_denial_reasons_are_listed() {
        let mut s = sample_status();
        s.maintenance_denial_reasons = vec!["Claude Code x 2".into()];
        let text = status_text(&s);
        assert!(text.contains("Claude Code x 2"));
        assert!(text.contains("refused"));
    }

    #[test]
    fn an_armed_reboot_is_visible() {
        let mut s = sample_status();
        s.reboot_authorization = Some(RebootAuthorization {
            id: "a".into(),
            nonce: "n".into(),
            issued_at_ms: 1_000_000,
            expires_at_ms: 1_800_000,
            issued_boot_id: "boot-1".into(),
            consumed_at_ms: None,
            consumed_by_boot_id: None,
            reason: "test".into(),
            issued_by: "administrator".into(),
        });
        let text = status_text(&s);
        assert!(text.contains("One reboot authorized"));
    }

    #[test]
    fn an_empty_agent_list_says_so() {
        let text = agents_text(&AgentInventory::default());
        assert!(text.contains("No AI coding agents detected"));
    }

    #[test]
    fn agents_text_includes_evidence_and_resume() {
        let mut inv = AgentInventory::default();
        inv.agents.push(AgentGroup {
            kind: "claude_code".into(),
            display_name: "Claude Code".into(),
            confidence: Confidence::Confirmed,
            instances: vec![AgentInstance {
                kind: "claude_code".into(),
                display_name: "Claude Code".into(),
                pid: 42,
                root_pid: 42,
                identity: ProcessIdentity {
                    pid: 42,
                    created_filetime: 1,
                },
                session_id: "42".into(),
                confidence: Confidence::Confirmed,
                evidence: vec![Evidence::new(
                    "process_name",
                    "claude.exe",
                    100,
                    "the Claude Code CLI executable",
                )],
                started_at_filetime: 0,
                started_at_ms: 0,
                image_path: Some(r"C:\Users\dev\.local\bin\claude.exe".into()),
                cmdline: None,
                ancestry: vec![],
                session_id_windows: 3,
                user: None,
                project: Some(ProjectContext {
                    root: r"D:\Workspace\app".into(),
                    name: "app".into(),
                    source: "claude_session_file".into(),
                    vcs: None,
                }),
                resume: ResumeCapability::Available {
                    handle: "abc".into(),
                    hint: "claude --resume abc".into(),
                },
            }],
        });

        let text = agents_text(&inv);
        assert!(text.contains("Claude Code"));
        assert!(text.contains("Confirmed"));
        assert!(text.contains("claude.exe"), "evidence must be shown");
        assert!(text.contains("app"), "the project must be shown");
        assert!(text.contains("--resume"), "the resume hint must be shown");
    }

    #[test]
    fn candidates_are_shown_but_flagged_as_unprotected() {
        let mut inv = AgentInventory::default();
        inv.candidates.push(AgentCandidate {
            candidate_id: "mystery.exe:weak".into(),
            pid: 9,
            identity: ProcessIdentity {
                pid: 9,
                created_filetime: 1,
            },
            name: "mystery.exe".into(),
            image_path: None,
            cmdline: None,
            confidence: Confidence::Possible,
            evidence: vec![Evidence::new("near_miss", "weak", 10, "below threshold")],
            first_seen_ms: 0,
            last_seen_ms: 0,
            observations: 1,
        });

        let text = agents_text(&inv);
        assert!(text.contains("mystery.exe"));
        assert!(
            text.contains("never block shutdown"),
            "the UI must state that candidates are not protected: {text}"
        );
    }

    #[test]
    fn network_text_shows_probes_and_outages() {
        let mut n = NetworkSnapshot {
            internet: InternetHealth::Healthy,
            ..Default::default()
        };
        n.probes = vec![ProbeResult {
            id: "tcp-a".into(),
            kind: ProbeKind::Tcp,
            target: "1.1.1.1:443".into(),
            ok: true,
            latency_ms: Some(12),
            error: None,
        }];
        n.current_outage = Some(OutageRecord {
            id: "o".into(),
            started_at_ms: 1_000_000,
            ended_at_ms: None,
            downtime_ms: Some(30_000),
            reason: "PPPOE_SESSION_LOST".into(),
            dial_attempts: 3,
            ras_errors: vec![RasErrorRecord {
                code: 678,
                message: "there is no answer".into(),
                at_ms: 1_000_000,
            }],
        });

        let text = network_text(&n);
        assert!(text.contains("Healthy"));
        assert!(text.contains("tcp-a"));
        assert!(text.contains("12ms"));
        assert!(text.contains("PPPOE_SESSION_LOST"));
        assert!(text.contains("678"));
        assert!(text.contains("there is no answer"));
    }

    #[test]
    fn network_text_says_so_when_no_probes_are_configured() {
        let n = NetworkSnapshot::default();
        let text = network_text(&n);
        assert!(text.contains("none configured"));
    }

    #[test]
    fn incidents_text_handles_the_empty_case() {
        assert!(incidents_text(&[]).contains("No incidents"));
    }

    #[test]
    fn incidents_text_renders_an_unexpected_restart() {
        let incident = Incident {
            id: "i".into(),
            kind: IncidentKind::UnexpectedRestart,
            at_ms: 1_000_000,
            title: "Unexpected restart detected".into(),
            summary: "the machine restarted uncleanly".into(),
            severity: FindingSeverity::Warning,
            details: IncidentDetails {
                unexpected_restart: Some(UnexpectedRestart {
                    detected_at_ms: 1_000_000,
                    previous_boot_id: "boot-1".into(),
                    current_boot_id: "boot-2".into(),
                    likely_initiator: Some("Windows Update".into()),
                    reason: Some("planned".into()),
                    confidence: CauseConfidence::Likely,
                    windows_update_related: WindowsUpdateRelation::Yes,
                    evidence: vec![EventEvidence {
                        provider: "User32".into(),
                        event_id: 1074,
                        at_ms: 999_000,
                        message: "the process ... initiated the restart".into(),
                    }],
                    agents_lost: vec![LostAgent {
                        kind: "claude_code".into(),
                        display_name: "Claude Code".into(),
                        pid: 42,
                        session_id: "s".into(),
                        project: Some("app".into()),
                        last_seen_ms: 999_000,
                        resume: ResumeCapability::Unavailable,
                    }],
                    protected_jobs_lost: 2,
                    last_heartbeat_ms: Some(999_000),
                    last_network_state: Some("healthy".into()),
                    reboot_was_authorized: false,
                }),
                ..Default::default()
            },
        };

        let text = incidents_text(&[incident]);
        assert!(text.contains("Unexpected restart"));
        assert!(text.contains("boot-1 -> boot-2"));
        assert!(text.contains("Windows Update"));
        assert!(text.contains("Claude Code"), "lost agents must be listed");
        assert!(text.contains("User32"), "evidence must be listed");
    }

    #[test]
    fn pending_reboot_text_lists_indicators() {
        let report = PendingRebootReport {
            verdict: PendingRebootVerdict::ProbablyPending,
            signals: vec![
                RebootSignal {
                    id: "cbs.reboot_pending".into(),
                    source: RebootSignalSource::ComponentServicing,
                    present: false,
                    weight: RebootSignalWeight::Conclusive,
                    detail: "component servicing reports a restart is required".into(),
                    read_failed: false,
                },
                RebootSignal {
                    id: "sm.pending_file_rename".into(),
                    source: RebootSignalSource::Registry,
                    present: true,
                    weight: RebootSignalWeight::Strong,
                    detail: "file operations are queued".into(),
                    read_failed: false,
                },
            ],
            checked_at_ms: 1_000_000,
        };

        let text = pending_reboot_text(&report);
        assert!(text.contains("ProbablyPending"));
        assert!(text.contains("cbs.reboot_pending"));
        assert!(text.contains("absent"));
        assert!(text.contains("PRESENT"));
    }

    #[test]
    fn duration_formatting_is_readable_across_magnitudes() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(5_000), "5s");
        assert_eq!(format_duration(90_000), "1m 30s");
        assert_eq!(format_duration(3_600_000), "1h 00m");
        assert_eq!(format_duration(90_000_000), "1d 01h");
        assert_eq!(format_duration(-1), "unknown");
    }

    #[test]
    fn timestamp_formatting_handles_the_never_case() {
        assert_eq!(format_ms(0), "never");
        assert_eq!(format_ms(-5), "never");
        assert!(format_ms(1_000_000).starts_with("day+"));
    }

    #[test]
    fn every_response_variant_renders_something() {
        // A rendering gap would show as an empty line in a terminal, which is easy to miss.
        let responses = vec![
            Response::Hello {
                protocol: 1,
                service_version: "0.1.0".into(),
                server_time: 0,
            },
            Response::Status(Box::new(sample_status())),
            Response::Agents(Box::default()),
            Response::Network(Box::default()),
            Response::Incidents(vec![]),
            Response::PendingReboot(Box::new(PendingRebootReport {
                verdict: PendingRebootVerdict::NotPending,
                signals: vec![],
                checked_at_ms: 0,
            })),
            Response::RebootAuthorization(Box::new(None)),
            Response::Ok {
                message: "done".into(),
            },
            Response::Error(guardian_proto::ProtocolError::Refused("no".into())),
        ];

        for r in responses {
            let text = render_response(&r);
            assert!(!text.trim().is_empty(), "response rendered as empty: {r:?}");
        }
    }

    #[test]
    fn level_labels_never_overstate_protection() {
        assert_eq!(level_label(ProtectionLevel::Protected), "Protected");
        for level in [
            ProtectionLevel::Degraded,
            ProtectionLevel::Maintenance,
            ProtectionLevel::Unknown,
        ] {
            assert_ne!(
                level_label(level),
                "Protected",
                "{level:?} must not render as Protected"
            );
        }
        assert_eq!(level_label(ProtectionLevel::Unprotected), "NOT PROTECTED");
    }

    #[test]
    fn truncation_is_character_safe_and_marks_elision() {
        assert_eq!(truncate("short", 10), "short");
        let truncated = truncate("日本語のとても長い文字列", 5);
        assert!(truncated.starts_with("日本語"));
        assert!(truncated.ends_with('…'));
    }
}
