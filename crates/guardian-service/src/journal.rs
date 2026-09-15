//! Recovery journal and unclean-session classification.
//!
//! # What this is for
//!
//! On every service start, determine whether the *previous* session ended cleanly. If it did
//! not, work may have been lost, and the operator deserves to know what was running and why it
//! stopped. That is the difference between "the machine rebooted overnight" and "your four
//! agents were killed at 03:14 by a Windows Update restart".
//!
//! # Fail-safe classification
//!
//! A cause is only claimed when the evidence supports it. A `Kernel-Power 41` record proves
//! the stop was abrupt; it says nothing about *why*, and the report says so. When there is no
//! usable evidence the confidence is `Unknown` and the incident is still raised, because
//! losing the fact that something went wrong would be worse than reporting it vaguely.

use std::path::PathBuf;

use guardian_core::ports::{Clock, EventLogSource};
use guardian_core::reboot::{build_unexpected_restart_incident, RestartContext};
use guardian_proto::model::{
    AgentInventory, FindingSeverity, Incident, IncidentDetails, IncidentKind, LostAgent,
    NetworkSnapshot, RebootAuthorization, RebootSignalWeight, ResumeCapability,
};
use guardian_storage::{Journal, JournalRead, JournalRecord, PersistentState, StorageError, Store};

use guardian_win::clock::filetime_to_unix_ms;

/// The recovery journal: an append-only record of what the service was doing.
pub struct RecoveryJournal {
    journal: Journal,
    session_id: String,
    boot_id: String,
    started_at_ms: i64,
    /// Cached so a checkpoint does not need to re-read the file.
    bytes_written: u64,
}

impl std::fmt::Debug for RecoveryJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryJournal")
            .field("session_id", &self.session_id)
            .field("boot_id", &self.boot_id)
            .field("bytes_written", &self.bytes_written)
            .finish_non_exhaustive()
    }
}

impl RecoveryJournal {
    /// Open the journal for a new session and write the session-start marker.
    pub fn open(
        path: PathBuf,
        max_bytes: u64,
        version: &str,
        clock: &impl Clock,
        boot_id: &str,
    ) -> Result<Self, StorageError> {
        let mut journal = Journal::open(path, max_bytes)?;
        let started_at_ms = clock.now_ms();
        // The session id includes the boot id and the start time, so two sessions can never
        // share an id even across a clock adjustment.
        let session_id = format!("{boot_id}-{started_at_ms}");

        journal.append(
            &JournalRecord::SessionStart {
                boot_id: boot_id.to_string(),
                session_id: session_id.clone(),
                started_at_ms,
                version: version.to_string(),
            },
            // Synchronous: if this record is lost, the next boot cannot tell whether this
            // session existed at all.
            true,
        )?;

        let bytes_written = journal.bytes_written();
        Ok(RecoveryJournal {
            journal,
            session_id,
            boot_id: boot_id.to_string(),
            started_at_ms,
            bytes_written,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Write a periodic checkpoint.
    ///
    /// `sync` is false for routine checkpoints: the data is visible to any reader, which fully
    /// covers a process crash, and the last few records may be lost on power loss — which is
    /// acceptable for a heartbeat and avoids an fsync every few seconds forever. The critical
    /// transitions pass `sync = true`.
    pub fn checkpoint(
        &mut self,
        clock: &impl Clock,
        snapshot: CheckpointInput<'_>,
    ) -> Result<(), StorageError> {
        let checkpoint = guardian_storage::Checkpoint {
            written_at_ms: clock.now_ms(),
            boot_id: self.boot_id.clone(),
            session_id: self.session_id.clone(),
            mode: snapshot.mode.to_string(),
            update_protection: snapshot.update_protection.to_string(),
            agents: Box::new(snapshot.agents.clone()),
            network: Box::new(snapshot.network.clone()),
            reboot_authorization: snapshot.authorization.cloned(),
            protected_work_live: snapshot.protected_work_live,
        };

        self.journal.append(
            &JournalRecord::Checkpoint(Box::new(checkpoint)),
            snapshot.sync,
        )?;
        self.bytes_written = self.journal.bytes_written();
        Ok(())
    }

    /// Record a protection-mode change.
    pub fn mode_change(&mut self, clock: &impl Clock, from: &str, to: &str, reason: &str) {
        let _ = self.journal.append(
            &JournalRecord::ModeChange {
                from: from.to_string(),
                to: to.to_string(),
                at_ms: clock.now_ms(),
                reason: reason.to_string(),
            },
            // Synchronous: a mode change is exactly the kind of event an investigator needs.
            true,
        );
        self.bytes_written = self.journal.bytes_written();
    }

    /// Record that a shutdown or restart was observed.
    pub fn shutdown_observed(
        &mut self,
        clock: &impl Clock,
        restart: bool,
        reason: Option<String>,
        authorized: bool,
    ) {
        let _ = self.journal.append(
            &JournalRecord::ShutdownObserved {
                at_ms: clock.now_ms(),
                shutdown_kind: if restart { "restart" } else { "shutdown" }.to_string(),
                reason,
                authorized,
            },
            true,
        );
        self.bytes_written = self.journal.bytes_written();
    }

    /// Record a tamper event.
    pub fn policy_tamper(
        &mut self,
        clock: &impl Clock,
        value: &str,
        expected: &str,
        observed: &str,
        restored: bool,
    ) {
        let _ = self.journal.append(
            &JournalRecord::PolicyTamper {
                value_name: value.to_string(),
                expected: expected.to_string(),
                observed: observed.to_string(),
                at_ms: clock.now_ms(),
                restored,
            },
            true,
        );
        self.bytes_written = self.journal.bytes_written();
    }

    /// Record a worker failure.
    pub fn worker_failure(&mut self, clock: &impl Clock, worker: &str, error: &str) {
        let _ = self.journal.append(
            &JournalRecord::WorkerFailure {
                worker: worker.to_string(),
                error: error.to_string(),
                at_ms: clock.now_ms(),
            },
            false,
        );
        self.bytes_written = self.journal.bytes_written();
    }

    /// Record a network event worth remembering.
    pub fn network_event(&mut self, clock: &impl Clock, detail: &str) {
        let _ = self.journal.append(
            &JournalRecord::NetworkEvent {
                at_ms: clock.now_ms(),
                detail: detail.to_string(),
            },
            false,
        );
        self.bytes_written = self.journal.bytes_written();
    }

    /// Flush everything to disk and write the clean-shutdown marker.
    ///
    /// This is the *only* thing that makes the next session consider this one clean. It is
    /// called from the service's stop path and from preshutdown, and it must run before the
    /// process exits.
    pub fn mark_clean_shutdown(&mut self, clock: &impl Clock) {
        let uptime = clock.now_ms().saturating_sub(self.started_at_ms);
        let _ = self.journal.append(
            &JournalRecord::CleanShutdown {
                at_ms: clock.now_ms(),
                uptime_ms: uptime,
            },
            true,
        );
        let _ = self.journal.sync();
        self.bytes_written = self.journal.bytes_written();
    }

    /// Force everything to disk.
    pub fn sync(&mut self) {
        let _ = self.journal.sync();
    }

    /// The underlying journal path.
    pub fn path(&self) -> &std::path::Path {
        self.journal.path()
    }
}

/// The fields a checkpoint records.
///
/// Grouped rather than passed positionally: two adjacent `&str` parameters in a long argument
/// list are easy to transpose, and a checkpoint written with the protection level in the mode
/// field would be actively misleading during a later investigation.
#[derive(Debug, Clone)]
pub struct CheckpointInput<'a> {
    pub mode: &'a str,
    pub update_protection: &'a str,
    pub agents: &'a AgentInventory,
    pub network: &'a NetworkSnapshot,
    pub authorization: Option<&'a RebootAuthorization>,
    pub protected_work_live: bool,
    /// Whether to flush to disk. True for the transitions an investigation depends on.
    pub sync: bool,
}

/// What the previous session looked like.
#[derive(Debug, Clone, PartialEq)]
pub struct PreviousSession {
    /// Whether the previous session wrote its clean-shutdown marker.
    pub clean: bool,
    /// The previous boot identity, when it was recorded.
    pub boot_id: Option<String>,
    /// The previous session id, when it was recorded.
    pub session_id: Option<String>,
    /// The newest checkpoint, which is what recovery is built from.
    pub checkpoint: Option<guardian_storage::Checkpoint>,
    /// Records discarded because they were torn or failed their checksum.
    pub discarded_records: u32,
    /// Whether the journal ended in a torn tail, which is itself evidence of an abrupt stop.
    pub truncated: bool,
}

impl PreviousSession {
    /// Whether work was believed live when the previous session stopped.
    pub fn protected_work_live(&self) -> bool {
        self.checkpoint
            .as_ref()
            .map(|c| c.protected_work_live)
            .unwrap_or(false)
    }

    /// The agents that were live, as recovery information.
    pub fn lost_agents(&self) -> Vec<LostAgent> {
        let Some(checkpoint) = &self.checkpoint else {
            return Vec::new();
        };

        checkpoint
            .agents
            .agents
            .iter()
            .flat_map(|group| group.instances.iter())
            .filter(|i| i.confidence.drives_protection())
            .map(|i| LostAgent {
                kind: i.kind.clone(),
                display_name: i.display_name.clone(),
                pid: i.pid,
                session_id: i.session_id.clone(),
                project: i.project.as_ref().map(|p| p.name.clone()),
                last_seen_ms: checkpoint.written_at_ms,
                // A lost session can only be offered for resume if an adapter had recorded a
                // handle at the time of the checkpoint.
                resume: i.resume.clone(),
            })
            .collect()
    }

    /// The number of protected jobs that were live.
    ///
    /// Workloads live inside the inventory, so this reads through it rather than duplicating
    /// the list in the checkpoint.
    pub fn lost_jobs(&self) -> usize {
        self.checkpoint
            .as_ref()
            .map(|c| c.agents.workloads.len())
            .unwrap_or(0)
    }
}

/// Read the previous session from the journal.
///
/// Never fails: a journal that cannot be read is reported as "not clean" with no checkpoint,
/// because the conservative interpretation of an unreadable journal is that something went
/// wrong. That is the fail-closed direction.
pub fn read_previous_session(path: &std::path::Path) -> PreviousSession {
    let read = match Journal::read_all(path) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "could not read the recovery journal; treating the previous session as unclean"
            );
            return PreviousSession {
                clean: false,
                boot_id: None,
                session_id: None,
                checkpoint: None,
                discarded_records: 0,
                truncated: false,
            };
        }
    };

    let last_session: Option<String> = read.records.iter().rev().find_map(|r| match r {
        JournalRecord::SessionStart { session_id, .. } => Some(session_id.clone()),
        _ => None,
    });

    let clean = last_session
        .as_deref()
        .map(|s| read.session_ended_cleanly(s))
        .unwrap_or(false);

    let last_start = read.records.iter().rev().find_map(|r| match r {
        JournalRecord::SessionStart {
            boot_id,
            session_id,
            ..
        } => Some((boot_id.clone(), session_id.clone())),
        _ => None,
    });

    PreviousSession {
        clean,
        boot_id: last_start.as_ref().map(|(b, _)| b.clone()),
        session_id: last_start.map(|(_, s)| s),
        checkpoint: read.latest_checkpoint().cloned(),
        discarded_records: read.discarded_tail_records,
        truncated: read.truncated,
    }
}

/// Build the unexpected-restart incident for an unclean previous session.
///
/// `None` when the previous session was clean.
pub fn build_restart_incident<S: EventLogSource>(
    event_log: &S,
    previous: &PreviousSession,
    current_boot_id: &str,
    boot_started_ms: i64,
    now_ms: i64,
) -> Option<Incident> {
    if previous.clean {
        return None;
    }

    let authorized = previous
        .checkpoint
        .as_ref()
        .and_then(|c| c.reboot_authorization.as_ref())
        .map(|a| a.consumed_at_ms.is_some())
        .unwrap_or(false);

    let context = RestartContext {
        previous_session_clean: false,
        previous_boot_id: previous.boot_id.clone().unwrap_or_else(|| "unknown".into()),
        current_boot_id: current_boot_id.to_string(),
        boot_started_ms,
        now_ms,
        last_heartbeat_ms: previous.checkpoint.as_ref().map(|c| c.written_at_ms),
        agents_lost: previous.lost_agents(),
        protected_jobs_lost: previous.lost_jobs(),
        last_network_state: previous
            .checkpoint
            .as_ref()
            .map(|c| c.network.internet.as_str().to_string()),
        reboot_was_authorized: authorized,
    };

    let detail = build_unexpected_restart_incident(event_log, &context)?;

    let agents = detail.agents_lost.len();
    let jobs = detail.protected_jobs_lost;

    let summary = match (&detail.likely_initiator, detail.windows_update_related) {
        (Some(initiator), guardian_proto::model::WindowsUpdateRelation::Yes) => format!(
            "the machine restarted without a clean shutdown; Windows Update appears to have \
             initiated it ({initiator}). {agents} agent(s) and {jobs} protected job(s) were lost"
        ),
        (Some(initiator), _) => format!(
            "the machine restarted without a clean shutdown; the likely initiator was \
             {initiator}. {agents} agent(s) and {jobs} protected job(s) were lost"
        ),
        (None, _) => format!(
            "the machine restarted without a clean shutdown and the cause could not be \
             determined. {agents} agent(s) and {jobs} protected job(s) were lost"
        ),
    };

    // An unexpected restart is either unexplained, or demonstrably cost work. Both warrant
    // attention; only a confidently-explained restart with nothing lost is informational.
    let costly = agents > 0 || jobs > 0;
    let unexplained = detail.confidence == guardian_proto::model::CauseConfidence::Unknown;
    let severity = if costly || unexplained {
        FindingSeverity::Warning
    } else {
        FindingSeverity::Info
    };

    Some(Incident {
        id: format!("restart-{now_ms}"),
        kind: IncidentKind::UnexpectedRestart,
        at_ms: now_ms,
        title: "Unexpected restart detected".into(),
        summary,
        severity,
        details: IncidentDetails {
            unexpected_restart: Some(detail),
            extra: {
                let mut extra = vec![(
                    "journal".to_string(),
                    if previous.truncated {
                        format!(
                            "ended in a torn tail ({} record(s) discarded)",
                            previous.discarded_records
                        )
                    } else {
                        "ended cleanly at the record level".to_string()
                    },
                )];
                if authorized {
                    extra.push((
                        "reboot_authorization".to_string(),
                        "a single-use authorization was consumed by this restart".to_string(),
                    ));
                }
                extra
            },
            ..Default::default()
        },
    })
}

/// Load persisted state, reconciling it with reality.
///
/// A state document that cannot be read yields defaults plus a warning; the caller then
/// applies protection from scratch, which is the safe direction.
pub fn load_state(store: &Store) -> (PersistentState, Option<String>) {
    let (state, error) = store.load_state();
    match error {
        Some(e) => {
            tracing::warn!(
                error = %e,
                "persistent state was unreadable; falling back to defaults and re-applying protection"
            );
            (state, Some(e.to_string()))
        }
        None => (state, None),
    }
}

/// Persist state, reporting failure without aborting.
///
/// A failure to persist is a degradation, not a reason to stop protecting. The caller records
/// it and continues.
pub fn save_state(store: &Store, state: &PersistentState) -> Option<String> {
    match store.save_state(state) {
        Ok(()) => None,
        Err(e) => {
            tracing::error!(error = %e, "could not persist service state");
            Some(e.to_string())
        }
    }
}

/// Read the last boot time from the system, as Unix milliseconds.
///
/// Used to compute the window for event-log queries around the previous termination.
pub fn last_boot_ms(clock: &impl Clock) -> i64 {
    let now = clock.now_ms();
    let uptime = clock.uptime_ms();
    now.saturating_sub(uptime)
}

/// A one-line description of the previous session, for logging at startup.
pub fn describe_previous(previous: &PreviousSession) -> String {
    if previous.clean {
        return "the previous session ended cleanly".to_string();
    }

    let mut parts = vec!["the previous session did not end cleanly".to_string()];

    if let Some(cp) = &previous.checkpoint {
        parts.push(format!("last mode {}", cp.mode));
        parts.push(format!("last protection {}", cp.update_protection));
        let agents: usize = cp.agents.agent_count();
        if agents > 0 {
            parts.push(format!("{agents} agent(s) were running"));
        }
        if cp.protected_work_live {
            parts.push("protected work was live".to_string());
        }
        let age = guardian_win::clock::unix_now_ms().saturating_sub(cp.written_at_ms);
        parts.push(format!("last checkpoint {}s before the stop", age / 1000));
    } else {
        parts.push("no checkpoint was recorded".to_string());
    }

    if previous.truncated {
        parts.push(format!(
            "the journal ended in a torn tail ({} record(s) discarded)",
            previous.discarded_records
        ));
    }

    parts.join("; ")
}

/// Convert a Windows FILETIME to Unix milliseconds, re-exported for callers that need it.
pub fn filetime_ms(filetime: u64) -> i64 {
    filetime_to_unix_ms(filetime)
}

/// The weight of a reboot signal, for diagnostics formatting.
pub fn signal_weight(id: &str) -> Option<RebootSignalWeight> {
    guardian_win::boot::weight_of(id)
}

/// A `ResumeCapability` that offers nothing, for callers building a lost-agent record from
/// incomplete information.
pub fn no_resume() -> ResumeCapability {
    ResumeCapability::Unavailable
}

/// Read the journal at `path` and return its raw contents, for diagnostics.
pub fn raw_journal(path: &std::path::Path) -> JournalRead {
    Journal::read_all(path).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::ports::fakes::{FakeClock, FakeEventLog};
    use guardian_proto::model::{
        AgentGroup, AgentInstance, Confidence, EventEvidence, ProcessIdentity,
    };

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "guardian-journal-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).expect("temp dir");
            TempDir(p)
        }
        fn journal_path(&self) -> PathBuf {
            self.0.join("journal.log")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn agent_inventory() -> AgentInventory {
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
                session_id: "s".into(),
                confidence: Confidence::Confirmed,
                evidence: vec![],
                started_at_filetime: 0,
                started_at_ms: 0,
                image_path: None,
                cmdline: None,
                ancestry: vec![],
                session_id_windows: 3,
                user: None,
                project: Some(guardian_proto::model::ProjectContext {
                    root: r"D:\Workspace\rust-reality".into(),
                    name: "rust-reality".into(),
                    source: "claude_session_file".into(),
                    vcs: None,
                }),
                resume: ResumeCapability::Available {
                    handle: "4e9b0cfc".into(),
                    hint: "claude --resume 4e9b0cfc".into(),
                },
            }],
        });
        inv
    }

    #[test]
    fn a_clean_session_is_recognized_as_clean() {
        let dir = TempDir::new("clean");
        let clock = FakeClock::new(1_000_000);

        {
            let mut j =
                RecoveryJournal::open(dir.journal_path(), 1 << 20, "0.1.0", &clock, "boot-1")
                    .unwrap();
            j.checkpoint(
                &clock,
                CheckpointInput {
                    mode: "NORMAL",
                    update_protection: "Protected",
                    agents: &AgentInventory::default(),
                    network: &NetworkSnapshot::default(),
                    authorization: None,
                    protected_work_live: false,
                    sync: false,
                },
            )
            .unwrap();
            j.mark_clean_shutdown(&clock);
        }

        let previous = read_previous_session(&dir.journal_path());
        assert!(previous.clean, "the clean marker must be found");
        assert_eq!(previous.boot_id.as_deref(), Some("boot-1"));
    }

    #[test]
    fn a_session_without_a_clean_marker_is_unclean() {
        let dir = TempDir::new("unclean");
        let clock = FakeClock::new(1_000_000);

        {
            // Open and checkpoint, then simply drop the journal: no clean marker is written,
            // which is exactly what a crash or power loss looks like.
            let mut j =
                RecoveryJournal::open(dir.journal_path(), 1 << 20, "0.1.0", &clock, "boot-1")
                    .unwrap();
            j.checkpoint(
                &clock,
                CheckpointInput {
                    mode: "WORKING",
                    update_protection: "Protected",
                    agents: &agent_inventory(),
                    network: &NetworkSnapshot::default(),
                    authorization: None,
                    protected_work_live: true,
                    sync: true,
                },
            )
            .unwrap();
        }

        let previous = read_previous_session(&dir.journal_path());
        assert!(!previous.clean, "a session with no marker is unclean");

        let cp = previous
            .checkpoint
            .expect("the checkpoint must be recovered");
        assert_eq!(cp.mode, "WORKING");
        assert!(cp.protected_work_live);
        assert_eq!(cp.agents.agent_count(), 1);
    }

    #[test]
    fn lost_agents_carry_project_and_resume_information() {
        let dir = TempDir::new("lost");
        let clock = FakeClock::new(1_000_000);

        {
            let mut j =
                RecoveryJournal::open(dir.journal_path(), 1 << 20, "0.1.0", &clock, "boot-1")
                    .unwrap();
            j.checkpoint(
                &clock,
                CheckpointInput {
                    mode: "WORKING",
                    update_protection: "Protected",
                    agents: &agent_inventory(),
                    network: &NetworkSnapshot::default(),
                    authorization: None,
                    protected_work_live: true,
                    sync: false,
                },
            )
            .unwrap();
        }

        let previous = read_previous_session(&dir.journal_path());
        let lost = previous.lost_agents();
        assert_eq!(lost.len(), 1);
        assert_eq!(lost[0].display_name, "Claude Code");
        assert_eq!(lost[0].project.as_deref(), Some("rust-reality"));
        assert!(matches!(lost[0].resume, ResumeCapability::Available { .. }));
    }

    #[test]
    fn a_low_confidence_agent_is_not_reported_as_lost_work() {
        // A Possible detection was never driving protection, so it is not "lost work".
        let dir = TempDir::new("lost-low");
        let clock = FakeClock::new(1_000_000);

        let mut inv = agent_inventory();
        inv.agents[0].instances[0].confidence = Confidence::Possible;
        inv.agents[0].confidence = Confidence::Possible;

        {
            let mut j =
                RecoveryJournal::open(dir.journal_path(), 1 << 20, "0.1.0", &clock, "boot-1")
                    .unwrap();
            j.checkpoint(
                &clock,
                CheckpointInput {
                    mode: "NORMAL",
                    update_protection: "Protected",
                    agents: &inv,
                    network: &NetworkSnapshot::default(),
                    authorization: None,
                    protected_work_live: false,
                    sync: false,
                },
            )
            .unwrap();
        }

        let previous = read_previous_session(&dir.journal_path());
        assert!(previous.lost_agents().is_empty());
    }

    #[test]
    fn a_missing_journal_is_unclean_and_carries_no_checkpoint() {
        // Conservative: no evidence of a clean stop means we do not assume one.
        let dir = TempDir::new("missing");
        let previous = read_previous_session(&dir.journal_path());
        assert!(!previous.clean);
        assert!(previous.checkpoint.is_none());
        assert!(previous.lost_agents().is_empty());
    }

    #[test]
    fn a_torn_journal_still_yields_the_last_good_checkpoint() {
        let dir = TempDir::new("torn");
        let clock = FakeClock::new(1_000_000);

        {
            let mut j =
                RecoveryJournal::open(dir.journal_path(), 1 << 20, "0.1.0", &clock, "boot-1")
                    .unwrap();
            j.checkpoint(
                &clock,
                CheckpointInput {
                    mode: "WORKING",
                    update_protection: "Protected",
                    agents: &agent_inventory(),
                    network: &NetworkSnapshot::default(),
                    authorization: None,
                    protected_work_live: true,
                    sync: false,
                },
            )
            .unwrap();
            j.network_event(&clock, "outage started");
        }

        // Truncate, as a power loss would.
        let path = dir.journal_path();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 9]).unwrap();

        let previous = read_previous_session(&path);
        assert!(!previous.clean);
        assert!(
            previous.checkpoint.is_some(),
            "the last complete checkpoint must survive a torn tail"
        );
        assert!(previous.truncated);
        assert!(previous.discarded_records > 0);
    }

    #[test]
    fn a_garbage_journal_is_handled_without_panicking() {
        let dir = TempDir::new("garbage");
        std::fs::write(dir.journal_path(), vec![0x5Au8; 5000]).unwrap();
        let previous = read_previous_session(&dir.journal_path());
        assert!(!previous.clean);
        assert!(previous.checkpoint.is_none());
    }

    #[test]
    fn a_clean_previous_session_produces_no_incident() {
        let log = FakeEventLog::default();
        let previous = PreviousSession {
            clean: true,
            boot_id: Some("boot-1".into()),
            session_id: Some("s1".into()),
            checkpoint: None,
            discarded_records: 0,
            truncated: false,
        };

        let incident = build_restart_incident(&log, &previous, "boot-2", 1000, 2000);
        assert!(incident.is_none(), "a clean stop is not an incident");
    }

    #[test]
    fn an_unclean_session_produces_an_incident_naming_what_was_lost() {
        let log = FakeEventLog::default();
        let previous = PreviousSession {
            clean: false,
            boot_id: Some("boot-1".into()),
            session_id: Some("s1".into()),
            checkpoint: Some(guardian_storage::Checkpoint {
                written_at_ms: 900,
                boot_id: "boot-1".into(),
                session_id: "s1".into(),
                mode: "WORKING".into(),
                update_protection: "Protected".into(),
                agents: Box::new(agent_inventory()),
                network: Box::new(NetworkSnapshot::default()),
                reboot_authorization: None,
                protected_work_live: true,
            }),
            discarded_records: 0,
            truncated: false,
        };

        let incident = build_restart_incident(&log, &previous, "boot-2", 1000, 2000)
            .expect("an unclean stop must be reported");
        assert_eq!(incident.kind, IncidentKind::UnexpectedRestart);
        assert!(
            incident.summary.contains("1 agent(s)"),
            "{}",
            incident.summary
        );

        let detail = incident.details.unexpected_restart.expect("detail");
        assert_eq!(detail.previous_boot_id, "boot-1");
        assert_eq!(detail.current_boot_id, "boot-2");
        assert_eq!(detail.agents_lost.len(), 1);
    }

    #[test]
    fn an_incident_with_windows_update_evidence_says_so() {
        let log = FakeEventLog::default();
        *log.events.borrow_mut() = vec![EventEvidence {
            provider: "User32".into(),
            event_id: 1074,
            at_ms: 950,
            message: "The process C:\\Windows\\System32\\svchost.exe has initiated the restart \
                      of computer MACHINE for the following reason: Reason: Windows Update"
                .into(),
        }];

        let previous = PreviousSession {
            clean: false,
            boot_id: Some("boot-1".into()),
            session_id: None,
            checkpoint: None,
            discarded_records: 0,
            truncated: false,
        };

        let incident = build_restart_incident(&log, &previous, "boot-2", 1000, 2000).unwrap();
        assert!(
            incident.summary.contains("Windows Update"),
            "the evidence must be reflected in the summary: {}",
            incident.summary
        );
        let detail = incident.details.unexpected_restart.unwrap();
        assert_eq!(
            detail.windows_update_related,
            guardian_proto::model::WindowsUpdateRelation::Yes
        );
    }

    #[test]
    fn an_incident_with_no_evidence_does_not_invent_a_cause() {
        let log = FakeEventLog::default();
        *log.fail.borrow_mut() = true;

        let previous = PreviousSession {
            clean: false,
            boot_id: Some("boot-1".into()),
            session_id: None,
            checkpoint: None,
            discarded_records: 0,
            truncated: false,
        };

        let incident = build_restart_incident(&log, &previous, "boot-2", 1000, 2000).unwrap();
        assert!(
            incident.summary.contains("could not be determined"),
            "an unknown cause must be admitted: {}",
            incident.summary
        );
        let detail = incident.details.unexpected_restart.unwrap();
        assert_eq!(
            detail.confidence,
            guardian_proto::model::CauseConfidence::Unknown
        );
    }

    #[test]
    fn a_consumed_authorization_is_noted_in_the_incident() {
        let log = FakeEventLog::default();
        let previous = PreviousSession {
            clean: false,
            boot_id: Some("boot-1".into()),
            session_id: None,
            checkpoint: Some(guardian_storage::Checkpoint {
                written_at_ms: 900,
                boot_id: "boot-1".into(),
                session_id: "s".into(),
                mode: "REBOOT_ARMED".into(),
                update_protection: "Maintenance".into(),
                agents: Box::new(AgentInventory::default()),
                network: Box::new(NetworkSnapshot::default()),
                reboot_authorization: Some(RebootAuthorization {
                    id: "a".into(),
                    nonce: "n".into(),
                    issued_at_ms: 100,
                    expires_at_ms: 2_000_000,
                    issued_boot_id: "boot-1".into(),
                    consumed_at_ms: Some(950),
                    consumed_by_boot_id: Some("boot-2".into()),
                    reason: "maintenance".into(),
                    issued_by: "administrator".into(),
                }),
                protected_work_live: false,
            }),
            discarded_records: 0,
            truncated: false,
        };

        let incident = build_restart_incident(&log, &previous, "boot-2", 1000, 2000).unwrap();
        assert!(incident
            .details
            .extra
            .iter()
            .any(|(k, _)| k == "reboot_authorization"));
    }

    #[test]
    fn describe_previous_is_informative_for_both_cases() {
        let clean = PreviousSession {
            clean: true,
            boot_id: None,
            session_id: None,
            checkpoint: None,
            discarded_records: 0,
            truncated: false,
        };
        assert!(describe_previous(&clean).contains("cleanly"));

        let unclean = PreviousSession {
            clean: false,
            boot_id: Some("boot-1".into()),
            session_id: None,
            checkpoint: Some(guardian_storage::Checkpoint {
                written_at_ms: 900,
                boot_id: "boot-1".into(),
                session_id: "s".into(),
                mode: "WORKING".into(),
                update_protection: "Protected".into(),
                agents: Box::new(agent_inventory()),
                network: Box::new(NetworkSnapshot::default()),
                reboot_authorization: None,
                protected_work_live: true,
            }),
            discarded_records: 0,
            truncated: true,
        };
        let text = describe_previous(&unclean);
        assert!(text.contains("WORKING"));
        assert!(text.contains("agent"));
        assert!(text.contains("torn tail"));
    }

    #[test]
    fn mode_changes_and_tamper_events_are_recorded() {
        let dir = TempDir::new("events");
        let clock = FakeClock::new(1_000_000);

        {
            let mut j =
                RecoveryJournal::open(dir.journal_path(), 1 << 20, "0.1.0", &clock, "boot-1")
                    .unwrap();
            j.mode_change(&clock, "NORMAL", "WORKING", "an agent started");
            j.policy_tamper(&clock, "NoAutoUpdate", "Dword(1)", "Dword(0)", true);
            j.worker_failure(&clock, "network", "boom");
            j.network_event(&clock, "outage started");
            j.shutdown_observed(&clock, true, None, false);
        }

        let read = raw_journal(&dir.journal_path());
        let tags: Vec<&str> = read.records.iter().map(|r| r.tag()).collect();
        assert!(tags.contains(&"mode_change"));
        assert!(tags.contains(&"policy_tamper"));
        assert!(tags.contains(&"worker_failure"));
        assert!(tags.contains(&"network_event"));
        assert!(tags.contains(&"shutdown_observed"));
    }

    #[test]
    fn a_rotated_journal_does_not_lose_the_current_session() {
        // The size cap is small, so the journal rotates. The current session's records must
        // still be found after rotation.
        let dir = TempDir::new("rotate");
        let clock = FakeClock::new(1_000_000);
        let big = "x".repeat(4096);

        {
            let mut j =
                RecoveryJournal::open(dir.journal_path(), 64 * 1024, "0.1.0", &clock, "boot-1")
                    .unwrap();
            for i in 0..40 {
                j.network_event(&clock, &format!("{big}{i}"));
            }
            j.mark_clean_shutdown(&clock);
        }

        let previous = read_previous_session(&dir.journal_path());
        assert!(
            previous.clean,
            "the clean marker must survive rotation within the current session"
        );
    }

    #[test]
    fn last_boot_time_is_in_the_past() {
        let clock = FakeClock::new(2_000_000);
        let boot = last_boot_ms(&clock);
        assert!(boot <= clock.now_ms());
    }

    #[test]
    fn signal_weight_lookup_is_available_for_diagnostics() {
        assert_eq!(
            signal_weight("cbs.reboot_pending"),
            Some(RebootSignalWeight::Conclusive)
        );
        assert_eq!(signal_weight("nonexistent"), None);
    }
}
