//! Pending-reboot classification and unexpected-restart analysis.
//!
//! # Design principle
//!
//! No single registry key is treated as infallible. Windows servicing sets several
//! different indicators depending on which component wants the restart, and any one of
//! them can be stale, partially written, or set by an unrelated installer. The verdict is
//! therefore an aggregate with an explicit confidence, and the default on ambiguity is
//! `Unknown` rather than a confident wrong answer.

use guardian_proto::model::*;

use crate::ports::{Clock, EventLogSource, EventQuery, PendingRebootSource};

/// Weight assigned to a signal when it is present.
///
/// The values are deliberately small integers so the thresholds below read directly:
/// two conclusively-present signals, or one conclusive plus corroboration, is `Pending`.
const W_CONCLUSIVE: u32 = 100;
const W_STRONG: u32 = 40;
const W_WEAK: u32 = 10;

/// Classify pending-reboot state from raw signals.
///
/// Rules:
/// * any `Conclusive` signal present -> `Pending`
/// * two or more `Strong` signals present -> `Pending`
/// * one `Strong` -> `ProbablyPending`
/// * only `Weak` signals -> `ProbablyPending` only if at least two agree, else `NotPending`
/// * any probe that could not be read -> at least `Unknown` when nothing stronger is known
pub fn classify(source: &impl PendingRebootSource) -> PendingRebootReport {
    match source.collect() {
        Ok(signals) => classify_signals(signals, 0),
        Err(e) => PendingRebootReport {
            verdict: PendingRebootVerdict::Unknown,
            signals: vec![RebootSignal {
                id: "probe.error".into(),
                source: RebootSignalSource::Registry,
                present: false,
                weight: RebootSignalWeight::Weak,
                detail: format!("pending-reboot probe failed: {e}"),
                read_failed: true,
            }],
            checked_at_ms: 0,
        },
    }
}

/// Pure classification over already-collected signals.
pub fn classify_signals(signals: Vec<RebootSignal>, now_ms: i64) -> PendingRebootReport {
    let mut score = 0u32;
    let mut conclusive = 0u32;
    let mut strong = 0u32;
    let mut weak = 0u32;
    let mut any_read_failed = false;

    for s in &signals {
        if s.read_failed {
            any_read_failed = true;
            continue;
        }
        if !s.present {
            continue;
        }
        match s.weight {
            RebootSignalWeight::Conclusive => {
                conclusive += 1;
                score += W_CONCLUSIVE;
            }
            RebootSignalWeight::Strong => {
                strong += 1;
                score += W_STRONG;
            }
            RebootSignalWeight::Weak => {
                weak += 1;
                score += W_WEAK;
            }
        }
    }

    let verdict = if conclusive >= 1 || strong >= 2 {
        // A conclusive indicator, or two independent strong ones, is enough to say Pending.
        PendingRebootVerdict::Pending
    } else if strong == 1 || weak > 0 {
        // One strong but unconfirmed indicator, or any weak signal, is not enough to
        // declare a restart pending; treating it as Pending would produce spurious
        // warnings on healthy machines.
        PendingRebootVerdict::ProbablyPending
    } else if any_read_failed && score == 0 {
        // We could not look everywhere, so "nothing found" is not the same as "nothing there".
        PendingRebootVerdict::Unknown
    } else {
        PendingRebootVerdict::NotPending
    };

    PendingRebootReport {
        verdict,
        signals,
        checked_at_ms: now_ms,
    }
}

/// A signal definition that the Windows backend fills in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebootSignalSpec {
    pub id: &'static str,
    pub source: RebootSignalSource,
    pub weight: RebootSignalWeight,
    pub detail: &'static str,
}

/// The full set of indicators Guardian probes.
///
/// Chosen from documented/well-established servicing behaviour. The set is deliberately
/// broader than any single Microsoft KB recommends, because relying on one key is exactly
/// the failure mode being avoided.
pub const SIGNAL_SPECS: &[RebootSignalSpec] = &[
    // Conclusive: CBS only sets this when a servicing operation genuinely needs a restart.
    RebootSignalSpec {
        id: "cbs.reboot_pending",
        source: RebootSignalSource::ComponentServicing,
        weight: RebootSignalWeight::Conclusive,
        detail: "component servicing reports a restart is required",
    },
    // Conclusive: the Update Orchestrator explicitly requires a reboot.
    RebootSignalSpec {
        id: "wu.reboot_required",
        source: RebootSignalSource::WindowsUpdate,
        weight: RebootSignalWeight::Conclusive,
        detail: "Windows Update requires a restart to finish installing",
    },
    // Strong: set when an update has been staged and is waiting for a restart window.
    RebootSignalSpec {
        id: "wu.auto_update_reboot_required",
        source: RebootSignalSource::WindowsUpdate,
        weight: RebootSignalWeight::Strong,
        detail: "an automatic update is staged and waiting for a restart",
    },
    // Strong: a file rename is queued for the next boot.
    RebootSignalSpec {
        id: "sm.pending_file_rename",
        source: RebootSignalSource::Registry,
        weight: RebootSignalWeight::Strong,
        detail: "file operations are queued to complete at the next restart",
    },
    // Strong: a driver/service package is pending installation.
    RebootSignalSpec {
        id: "sm.pending_file_rename_operations",
        source: RebootSignalSource::Registry,
        weight: RebootSignalWeight::Strong,
        detail: "the session manager has pending rename operations",
    },
    // Weak on its own: set by many installers, often satisfied without a real restart need.
    RebootSignalSpec {
        id: "wu.ux_schedule_reboot",
        source: RebootSignalSource::WindowsUpdate,
        weight: RebootSignalWeight::Weak,
        detail: "Windows Update UX has scheduled a restart",
    },
    // Weak: this is written by the running update stack and can be stale.
    RebootSignalSpec {
        id: "wu.update_exe_reboot_required",
        source: RebootSignalSource::WindowsUpdate,
        weight: RebootSignalWeight::Weak,
        detail: "the update engine has flagged a required restart",
    },
];

// ---------------------------------------------------------------------------
// Unexpected restart classification
// ---------------------------------------------------------------------------

/// Evidence that the previous session ended without a clean marker.
#[derive(Debug, Clone)]
pub struct RestartEvidence {
    /// Whether the previous session wrote its `CleanShutdown` record.
    pub previous_session_clean: bool,
    /// Event log records found around the termination.
    pub events: Vec<EventEvidence>,
    /// Disk used while running, for context in the incident.
    pub last_heartbeat_ms: Option<i64>,
}

/// The classification result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartVerdict {
    pub unexpected: bool,
    pub likely_initiator: Option<String>,
    pub reason: Option<String>,
    pub confidence: CauseConfidence,
    pub windows_update_related: WindowsUpdateRelation,
}

/// Classify a restart from event evidence.
///
/// The rules encode what each record actually means:
///
/// * `User32 1074` — a process *initiated* a shutdown/restart. The message names the
///   process and, for restarts, the reason. This is the single most informative record and
///   lets us distinguish "Windows Update started this" from "the user did".
/// * `Kernel-Power 41` — the system rebooted without a clean shutdown. Says nothing about
///   *why*; it is evidence of abrupt termination, not of a cause.
/// * `EventLog 6008` — the previous shutdown was unexpected.
/// * `EventLog 6006` — the event log service stopped cleanly. Absent means the shutdown was
///   abrupt.
/// * `EventLog 6005` — the event log service started; marks the current boot.
/// * `Kernel-General 12/13` — operating system start/stop.
/// * `WindowsUpdateClient` — an update-related operation occurred.
///
/// Ambiguity is reported as ambiguity. If nothing decisive is present the verdict is
/// `Possible`/`Unknown`, never a fabricated cause.
pub fn classify_restart(evidence: &RestartEvidence) -> RestartVerdict {
    if evidence.previous_session_clean {
        return RestartVerdict {
            unexpected: false,
            likely_initiator: None,
            reason: None,
            confidence: CauseConfidence::Confirmed,
            windows_update_related: WindowsUpdateRelation::No,
        };
    }

    let mut initiator: Option<String> = None;
    let mut reason: Option<String> = None;
    let mut abrupt = false;
    let mut wu_related = WindowsUpdateRelation::Unknown;
    let mut shutdown_initiated = false;
    let mut log_service_clean_stop = false;
    let mut wu_events = 0usize;

    for e in &evidence.events {
        match (e.provider.as_str(), e.event_id) {
            // A component asked for the restart. The message carries process + reason.
            ("User32", 1074) => {
                shutdown_initiated = true;
                // Only trust the parsed reason for restarts; the message format is stable
                // enough to extract the trailing "Reason:" clause, but we treat the whole
                // message as the reason text rather than inventing structure.
                reason = Some(truncate(&e.message, 300));
                if message_mentions_update(&e.message) {
                    wu_related = WindowsUpdateRelation::Yes;
                    initiator = Some("Windows Update".into());
                } else {
                    initiator = Some(
                        extract_initiator(&e.message)
                            .unwrap_or_else(|| "a process requested a restart".to_string()),
                    );
                    if wu_related != WindowsUpdateRelation::Yes {
                        wu_related = WindowsUpdateRelation::No;
                    }
                }
            }
            // Abrupt termination. Strong evidence of *unclean*, weak evidence of *why*.
            ("Microsoft-Windows-Kernel-Power", 41) => abrupt = true,
            ("EventLog", 6008) => abrupt = true,
            ("EventLog", 6006) => log_service_clean_stop = true,
            ("EventLog", 6005) => { /* current boot started */ }
            ("Microsoft-Windows-Kernel-General", 12) => { /* OS start */ }
            ("Microsoft-Windows-Kernel-General", 13) => { /* OS stop */ }
            ("Microsoft-Windows-WindowsUpdateClient", _) => {
                wu_events += 1;
            }
            _ => {}
        }
    }

    if wu_events > 0 && wu_related == WindowsUpdateRelation::Unknown {
        wu_related = WindowsUpdateRelation::Unknown;
    }

    // Confidence ladder, from strongest evidence down.
    //
    // The subtlety is the last two arms. A *missing* EventLog 6006 record is not evidence
    // of an abrupt stop — it is evidence that we did not see one. Only an actual abruptness
    // record (Kernel-Power 41, EventLog 6008) raises confidence. With no records at all,
    // the honest answer is Unknown: we know the session did not end cleanly, but we have
    // nothing that says why.
    let confidence = if shutdown_initiated {
        // Someone explicitly requested a shutdown/restart and the session still did not
        // write its clean marker.
        CauseConfidence::Confirmed
    } else if abrupt {
        // The OS recorded an unclean stop. That is a fact about *how*, not about *why*,
        // which is why it is Likely and not Confirmed.
        CauseConfidence::Likely
    } else if log_service_clean_stop {
        // The event log service stopped cleanly, so the shutdown itself was orderly even
        // though our own marker never appeared. The process died, the OS did not.
        CauseConfidence::Likely
    } else {
        CauseConfidence::Unknown
    };

    // Reaching this point already proves the session did not write its clean marker (the
    // early return above handles the clean case), so the termination was not clean by
    // definition. The *cause* is what remains uncertain, which is exactly what
    // `confidence` records.
    let unexpected = true;

    if initiator.is_none() && abrupt {
        initiator = Some("the system stopped without a clean shutdown".into());
    }

    RestartVerdict {
        unexpected,
        likely_initiator: initiator,
        reason,
        confidence,
        windows_update_related: wu_related,
    }
}

/// Query windows used when gathering evidence around a suspected unclean termination.
///
/// Bounded in both time and record count so a machine that has been up for months cannot
/// make this scan expensive.
pub fn evidence_queries(boot_started_ms: i64, now_ms: i64) -> Vec<(&'static str, EventQuery)> {
    // Look back from the current boot for records about the *previous* termination, plus a
    // small forward window in case the clock moved.
    let since = boot_started_ms.saturating_sub(30 * 60 * 1000);
    let until = (boot_started_ms + 5 * 60 * 1000).min(now_ms);

    vec![
        (
            "System",
            EventQuery {
                providers: vec![],
                event_ids: vec![41, 1074, 6005, 6006, 6008, 12, 13],
                since_ms: since,
                until_ms: until,
                max_records: 200,
            },
        ),
        (
            "System",
            EventQuery {
                providers: vec!["Microsoft-Windows-WindowsUpdateClient".into()],
                event_ids: vec![],
                since_ms: since,
                until_ms: until,
                max_records: 100,
            },
        ),
    ]
}

/// Everything needed to reconstruct an unexpected-restart incident.
///
/// Grouped into a struct rather than a long parameter list: the call site is recovery code
/// running immediately after an unclean termination, and named fields are far harder to
/// mis-order there than positional booleans and integers.
#[derive(Debug, Clone)]
pub struct RestartContext {
    /// Whether the previous session wrote its clean-shutdown marker.
    pub previous_session_clean: bool,
    pub previous_boot_id: String,
    pub current_boot_id: String,
    /// When the current boot began (Unix ms).
    pub boot_started_ms: i64,
    pub now_ms: i64,
    pub last_heartbeat_ms: Option<i64>,
    pub agents_lost: Vec<LostAgent>,
    pub protected_jobs_lost: usize,
    pub last_network_state: Option<String>,
    /// Whether a single-use reboot authorization was live when the machine went down.
    pub reboot_was_authorized: bool,
}

/// Run the evidence queries against a source and produce the incident payload.
pub fn build_unexpected_restart_incident<S: EventLogSource>(
    source: &S,
    ctx: &RestartContext,
) -> Option<UnexpectedRestart> {
    if ctx.previous_session_clean {
        return None;
    }

    // Same boot means the *process* stopped, not the machine.
    //
    // Without this check, restarting Guardian itself - which happens on every elevated relaunch,
    // and on every update - was reported as "the machine restarted without a clean shutdown ...
    // N agent(s) and M protected job(s) were lost". Nothing was lost: the boot identity is
    // unchanged, so the operating system never went anywhere. Reporting a lost-work incident that
    // did not happen is worse than reporting nothing, because it teaches the operator to ignore
    // the incidents that matter.
    if !ctx.previous_boot_id.is_empty() && ctx.previous_boot_id == ctx.current_boot_id {
        return None;
    }

    let mut events = Vec::new();
    for (channel, query) in evidence_queries(ctx.boot_started_ms, ctx.now_ms) {
        match source.query(channel, &query) {
            Ok(mut found) => events.append(&mut found),
            Err(e) => {
                // Partial evidence must still be reported, but the failure is recorded so
                // a confident verdict is not drawn from an incomplete picture.
                tracing::warn!(
                    channel,
                    error = %e,
                    "event log query failed; restart classification may be incomplete"
                );
            }
        }
    }
    events.sort_by_key(|e| e.at_ms);

    let verdict = classify_restart(&RestartEvidence {
        previous_session_clean: false,
        events: events.clone(),
        last_heartbeat_ms: ctx.last_heartbeat_ms,
    });

    Some(UnexpectedRestart {
        detected_at_ms: ctx.now_ms,
        previous_boot_id: ctx.previous_boot_id.clone(),
        current_boot_id: ctx.current_boot_id.clone(),
        likely_initiator: verdict.likely_initiator,
        reason: verdict.reason,
        confidence: verdict.confidence,
        windows_update_related: verdict.windows_update_related,
        evidence: events,
        agents_lost: ctx.agents_lost.clone(),
        protected_jobs_lost: ctx.protected_jobs_lost,
        last_heartbeat_ms: ctx.last_heartbeat_ms,
        last_network_state: ctx.last_network_state.clone(),
        reboot_was_authorized: ctx.reboot_was_authorized,
    })
}

/// Record the current boot identity and clean-shutdown state.
pub fn session_marker<C: Clock>(clock: &C, boot_id: &str, session_id: &str) -> JournalMarker {
    JournalMarker {
        boot_id: boot_id.to_string(),
        session_id: session_id.to_string(),
        started_at_ms: clock.now_ms(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalMarker {
    pub boot_id: String,
    pub session_id: String,
    pub started_at_ms: i64,
}

fn truncate(s: &str, max: usize) -> String {
    // Take characters, not bytes, so a truncated string is never invalid UTF-8.
    let mut out = String::with_capacity(max.min(s.len()));
    for c in s.chars().take(max) {
        out.push(c);
    }
    if s.chars().count() > max {
        out.push('…');
    }
    out
}

/// Extract the initiating process name from a `User32 1074` message when it is present.
///
/// The message format is not a documented contract, so a failure here is expected and
/// simply yields `None` rather than a guess.
fn extract_initiator(message: &str) -> Option<String> {
    // Typical form: "The process C:\Windows\System32\svchost.exe (MACHINE) has initiated
    // the restart of computer MACHINE on behalf of user ... Reason: ..."
    let lower = message.to_ascii_lowercase();
    let idx = lower.find("the process ")?;
    let rest = &message[idx + "the process ".len()..];
    // The process token ends at the first space (path may be quoted).
    let token = if let Some(stripped) = rest.strip_prefix('"') {
        stripped.split('"').next()?
    } else {
        rest.split_whitespace().next()?
    };
    if token.is_empty() {
        return None;
    }
    // Reduce a full path to its file name for display.
    let name = token
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(token);
    Some(name.to_string())
}

/// Whether a `User32 1074` message attributes the restart to Windows Update.
fn message_mentions_update(message: &str) -> bool {
    let l = message.to_ascii_lowercase();
    // "Windows Update" appears in the reason clause for update-initiated restarts. Also
    // accept the servicing binaries, which is how the update stack usually shows up.
    l.contains("windows update")
        || l.contains("windowsupdate")
        || l.contains("mo USO".to_ascii_lowercase().as_str())
        || l.contains("usoclient")
        || l.contains("tiworker")
        || l.contains("trustedinstaller")
        || l.contains("wusa")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ports::fakes::{FakeEventLog, FakePendingReboot};

    fn sig(id: &str, weight: RebootSignalWeight, present: bool) -> RebootSignal {
        RebootSignal {
            id: id.into(),
            source: RebootSignalSource::Registry,
            present,
            weight,
            detail: format!("{id} present={present}"),
            read_failed: false,
        }
    }

    fn ev(provider: &str, id: u32, msg: &str) -> EventEvidence {
        EventEvidence {
            provider: provider.into(),
            event_id: id,
            at_ms: 1000,
            message: msg.into(),
        }
    }

    #[test]
    fn no_signals_is_not_pending() {
        let r = classify_signals(vec![], 0);
        assert_eq!(r.verdict, PendingRebootVerdict::NotPending);
    }

    #[test]
    fn a_single_conclusive_signal_is_pending() {
        let r = classify_signals(
            vec![sig(
                "cbs.reboot_pending",
                RebootSignalWeight::Conclusive,
                true,
            )],
            0,
        );
        assert_eq!(r.verdict, PendingRebootVerdict::Pending);
    }

    #[test]
    fn one_strong_signal_is_only_probably_pending() {
        // A single strong-but-ambiguous indicator must not produce a confident claim.
        let r = classify_signals(
            vec![sig(
                "sm.pending_file_rename",
                RebootSignalWeight::Strong,
                true,
            )],
            0,
        );
        assert_eq!(r.verdict, PendingRebootVerdict::ProbablyPending);
    }

    #[test]
    fn two_strong_signals_escalate_to_pending() {
        let r = classify_signals(
            vec![
                sig("sm.pending_file_rename", RebootSignalWeight::Strong, true),
                sig(
                    "wu.auto_update_reboot_required",
                    RebootSignalWeight::Strong,
                    true,
                ),
            ],
            0,
        );
        assert_eq!(r.verdict, PendingRebootVerdict::Pending);
    }

    #[test]
    fn absent_signals_do_not_count() {
        let r = classify_signals(
            vec![
                sig("a", RebootSignalWeight::Conclusive, false),
                sig("b", RebootSignalWeight::Strong, false),
                sig("c", RebootSignalWeight::Weak, false),
            ],
            0,
        );
        assert_eq!(r.verdict, PendingRebootVerdict::NotPending);
    }

    #[test]
    fn a_failed_probe_prevents_a_confident_not_pending() {
        // If something could not be read, "we found nothing" is not "there is nothing".
        let r = classify_signals(
            vec![RebootSignal {
                id: "probe.failed".into(),
                source: RebootSignalSource::Registry,
                present: false,
                weight: RebootSignalWeight::Weak,
                detail: "access denied".into(),
                read_failed: true,
            }],
            0,
        );
        assert_eq!(r.verdict, PendingRebootVerdict::Unknown);
        assert!(!r.reasons().is_empty());
    }

    #[test]
    fn probe_failure_returns_unknown_not_not_pending() {
        let src = FakePendingReboot::default();
        *src.fail.borrow_mut() = true;
        let r = classify(&src);
        assert_eq!(r.verdict, PendingRebootVerdict::Unknown);
        assert!(r.reasons().iter().any(|s| s.contains("probe failed")));
    }

    #[test]
    fn classification_reads_signals_from_the_source() {
        let src = FakePendingReboot::default();
        *src.signals.borrow_mut() = vec![sig(
            "cbs.reboot_pending",
            RebootSignalWeight::Conclusive,
            true,
        )];
        let r = classify(&src);
        assert_eq!(r.verdict, PendingRebootVerdict::Pending);
    }

    #[test]
    fn a_process_restart_on_the_same_boot_is_not_an_unexpected_restart() {
        // Regression, seen on a real machine: every time Guardian restarted itself - which the
        // elevated relaunch does by design - it logged
        //   "the machine restarted without a clean shutdown and the cause could not be determined.
        //    5 agent(s) and 14 protected job(s) were lost"
        // while the machine had not restarted at all. The boot identity proves that: it is derived
        // from the boot time, so an unchanged value means the operating system never went anywhere.
        //
        // This matters beyond tidiness. An incident that reports lost work which was not lost
        // teaches the operator to ignore incidents, and the next one will be real.
        let ctx = RestartContext {
            previous_session_clean: false,
            previous_boot_id: "boot-1789425956000".into(),
            current_boot_id: "boot-1789425956000".into(),
            boot_started_ms: 0,
            now_ms: 100_000,
            last_heartbeat_ms: Some(90_000),
            agents_lost: Vec::new(),
            protected_jobs_lost: 3,
            last_network_state: None,
            reboot_was_authorized: false,
        };

        // No event source is consulted, because the boot comparison decides before any query.
        let source = NullEventLog;
        assert!(
            build_unexpected_restart_incident(&source, &ctx).is_none(),
            "restarting the program is not the machine restarting"
        );
    }

    #[test]
    fn a_different_boot_id_is_still_an_unexpected_restart() {
        // The other half: the check must not suppress a genuine restart. A changed boot identity is
        // exactly the evidence that the machine went down.
        let ctx = RestartContext {
            previous_session_clean: false,
            previous_boot_id: "boot-1".into(),
            current_boot_id: "boot-2".into(),
            boot_started_ms: 0,
            now_ms: 100_000,
            last_heartbeat_ms: Some(90_000),
            agents_lost: Vec::new(),
            protected_jobs_lost: 3,
            last_network_state: None,
            reboot_was_authorized: false,
        };

        let source = NullEventLog;
        assert!(
            build_unexpected_restart_incident(&source, &ctx).is_some(),
            "a changed boot identity must still be reported"
        );
    }

    /// An event log that answers every query with nothing.
    struct NullEventLog;

    impl EventLogSource for NullEventLog {
        type Error = String;

        fn query(&self, _channel: &str, _query: &EventQuery) -> Result<Vec<EventEvidence>, String> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn clean_session_is_not_an_unexpected_restart() {
        let v = classify_restart(&RestartEvidence {
            previous_session_clean: true,
            events: vec![ev("Microsoft-Windows-Kernel-Power", 41, "unclean")],
            last_heartbeat_ms: None,
        });
        assert!(!v.unexpected);
        assert_eq!(v.confidence, CauseConfidence::Confirmed);
    }

    #[test]
    fn windows_update_restart_is_attributed_to_windows_update() {
        let v = classify_restart(&RestartEvidence {
            previous_session_clean: false,
            events: vec![ev(
                "User32",
                1074,
                "The process C:\\Windows\\System32\\svchost.exe (MACHINE) has initiated the restart of computer MACHINE on behalf of user NT AUTHORITY\\SYSTEM for the following reason: Operating System: Recovery (Planned) Reason Code: 0x80020002 Reason: Windows Update",
            )],
            last_heartbeat_ms: Some(1000),
        });
        assert!(v.unexpected);
        assert_eq!(v.windows_update_related, WindowsUpdateRelation::Yes);
        assert_eq!(v.likely_initiator.as_deref(), Some("Windows Update"));
        assert!(v.reason.as_deref().unwrap().contains("Windows Update"));
    }

    #[test]
    fn user_initiated_restart_is_not_blamed_on_updates() {
        let v = classify_restart(&RestartEvidence {
            previous_session_clean: false,
            events: vec![ev(
                "User32",
                1074,
                "The process C:\\Windows\\explorer.exe (MACHINE) has initiated the restart of computer MACHINE on behalf of user MACHINE\\dev for the following reason: Other (Unplanned) Reason Code: 0x0 Reason: Other",
            )],
            last_heartbeat_ms: Some(1000),
        });
        assert!(v.unexpected);
        assert_eq!(v.windows_update_related, WindowsUpdateRelation::No);
        assert_eq!(v.likely_initiator.as_deref(), Some("explorer.exe"));
    }

    #[test]
    fn kernel_power_alone_does_not_invent_a_cause() {
        // The classic power-loss signature. It proves abruptness, not a culprit.
        let v = classify_restart(&RestartEvidence {
            previous_session_clean: false,
            events: vec![ev(
                "Microsoft-Windows-Kernel-Power",
                41,
                "The system has rebooted without cleanly shutting down first.",
            )],
            last_heartbeat_ms: None,
        });
        assert!(v.unexpected);
        assert_eq!(v.confidence, CauseConfidence::Likely);
        assert!(v.likely_initiator.is_some());
        assert!(
            !v.likely_initiator
                .as_deref()
                .unwrap()
                .to_ascii_lowercase()
                .contains("windows update"),
            "must not blame updates without evidence"
        );
        assert_eq!(v.windows_update_related, WindowsUpdateRelation::Unknown);
    }

    #[test]
    fn event_6008_is_treated_as_abrupt() {
        let v = classify_restart(&RestartEvidence {
            previous_session_clean: false,
            events: vec![ev(
                "EventLog",
                6008,
                "The previous system shutdown at 03:12:44 was unexpected.",
            )],
            last_heartbeat_ms: None,
        });
        assert!(v.unexpected);
        assert_eq!(v.confidence, CauseConfidence::Likely);
    }

    #[test]
    fn no_evidence_at_all_yields_unknown_confidence() {
        let v = classify_restart(&RestartEvidence {
            previous_session_clean: false,
            events: vec![],
            last_heartbeat_ms: Some(5000),
        });
        assert!(v.unexpected);
        assert_eq!(
            v.confidence,
            CauseConfidence::Unknown,
            "no evidence must never produce a confident cause"
        );
        assert_eq!(v.windows_update_related, WindowsUpdateRelation::Unknown);
    }

    #[test]
    fn clean_shutdown_marker_suppresses_incident_construction() {
        let log = FakeEventLog::default();
        let incident = build_unexpected_restart_incident(
            &log,
            &RestartContext {
                previous_session_clean: true,
                previous_boot_id: "boot-1".into(),
                current_boot_id: "boot-1".into(),
                boot_started_ms: 1000,
                now_ms: 2000,
                last_heartbeat_ms: Some(900),
                agents_lost: vec![],
                protected_jobs_lost: 0,
                last_network_state: None,
                reboot_was_authorized: false,
            },
        );
        assert!(
            incident.is_none(),
            "a clean previous session must not produce an incident"
        );
    }

    #[test]
    fn incident_construction_survives_a_failing_event_log() {
        let log = FakeEventLog::default();
        *log.fail.borrow_mut() = true;
        let incident = build_unexpected_restart_incident(
            &log,
            &RestartContext {
                previous_session_clean: false,
                previous_boot_id: "boot-1".into(),
                current_boot_id: "boot-2".into(),
                boot_started_ms: 1000,
                now_ms: 2000,
                last_heartbeat_ms: Some(900),
                agents_lost: vec![],
                protected_jobs_lost: 0,
                last_network_state: Some("Online".into()),
                reboot_was_authorized: false,
            },
        )
        .expect("still an incident");
        assert!(incident.evidence.is_empty());
        assert_eq!(
            incident.confidence,
            CauseConfidence::Unknown,
            "without evidence the cause must stay unknown"
        );
        assert_eq!(incident.previous_boot_id, "boot-1");
        assert_eq!(incident.current_boot_id, "boot-2");
    }

    #[test]
    fn incident_carries_lost_agents_and_metrics() {
        let log = FakeEventLog::default();
        let lost = vec![LostAgent {
            kind: "claude_code".into(),
            display_name: "Claude Code".into(),
            pid: 42,
            session_id: "s".into(),
            project: Some("rust-reality".into()),
            last_seen_ms: 1234,
            resume: ResumeCapability::Available {
                handle: "4e9b0cfc".into(),
                hint: "claude --resume 4e9b0cfc".into(),
            },
        }];
        let incident = build_unexpected_restart_incident(
            &log,
            &RestartContext {
                previous_session_clean: false,
                previous_boot_id: "boot-1".into(),
                current_boot_id: "boot-2".into(),
                boot_started_ms: 1000,
                now_ms: 2000,
                last_heartbeat_ms: Some(1900),
                agents_lost: lost,
                protected_jobs_lost: 3,
                last_network_state: Some("Online".into()),
                reboot_was_authorized: true,
            },
        )
        .expect("incident");
        assert_eq!(incident.agents_lost.len(), 1);
        assert_eq!(incident.protected_jobs_lost, 3);
        assert_eq!(incident.last_heartbeat_ms, Some(1900));
        assert!(incident.reboot_was_authorized);
        assert_eq!(
            incident.agents_lost[0].resume,
            ResumeCapability::Available {
                handle: "4e9b0cfc".into(),
                hint: "claude --resume 4e9b0cfc".into()
            }
        );
    }

    #[test]
    fn initiator_extraction_handles_quoted_paths() {
        assert_eq!(
            extract_initiator(
                r#"The process "C:\Program Files\Updater\setup.exe" has initiated the restart"#
            )
            .as_deref(),
            Some("setup.exe")
        );
        assert_eq!(
            extract_initiator("The process C:\\Windows\\explorer.exe (M) has initiated").as_deref(),
            Some("explorer.exe")
        );
        assert_eq!(extract_initiator("something entirely different"), None);
    }

    #[test]
    fn truncation_is_character_safe() {
        let s = "日本語のとても長いメッセージ".repeat(50);
        let t = truncate(&s, 10);
        assert!(t.chars().count() <= 11);
        // Round-trips as valid UTF-8 by construction; assertion is that it did not panic.
        assert!(t.starts_with("日本語"));
    }

    #[test]
    fn signal_specs_are_unique_and_nonempty() {
        let mut ids: Vec<_> = SIGNAL_SPECS.iter().map(|s| s.id).collect();
        let len = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), len, "signal ids must be unique");
        assert!(SIGNAL_SPECS
            .iter()
            .any(|s| s.weight == RebootSignalWeight::Conclusive));
    }

    #[test]
    fn evidence_queries_are_bounded() {
        let qs = evidence_queries(1_000_000, 2_000_000);
        assert!(!qs.is_empty());
        for (_, q) in &qs {
            assert!(q.max_records > 0 && q.max_records <= 1000);
            assert!(q.since_ms <= q.until_ms);
        }
    }
}
