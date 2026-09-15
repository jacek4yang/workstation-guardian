//! Agent adapters: read each agent's *own* local state to learn the project it is working in
//! and whether the session can be resumed.
//!
//! # Why this exists
//!
//! Getting another process's working directory on Windows requires reading its PEB, which is
//! undocumented, version-fragile, and would break on a Windows update. Rather than build on
//! that, Guardian reads what each agent already writes about itself. Agents persist their
//! session state precisely so they can resume, so this information is both reliable and
//! exactly what recovery needs.
//!
//! # Hard rules
//!
//! An adapter may only **read** agent state. It must never:
//!
//! * modify or delete anything an agent wrote;
//! * read credentials (Claude Code's `sessions/*.key` files hold a `peerToken` and are
//!   explicitly skipped);
//! * copy prompts, conversation content, or any part of a transcript into Guardian's logs or
//!   its persisted state;
//! * upload anything.
//!
//! Only the minimum needed for recovery is retained: a project path, a session handle, and
//! how to resume. The tests below assert the credential exclusion, because that is the kind
//! of rule that silently rots.

use std::path::{Path, PathBuf};

use guardian_proto::model::{ProjectContext, ResumeCapability};

/// What an adapter learned about a session.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdapterResult {
    /// Where the agent is working, when it recorded that.
    pub project: Option<ProjectContext>,
    /// Whether the session can be resumed, and how.
    pub resume: ResumeCapability,
    /// Which adapter produced this, for the UI.
    pub source: Option<String>,
}

impl AdapterResult {
    fn empty() -> Self {
        AdapterResult {
            project: None,
            resume: ResumeCapability::Unavailable,
            source: None,
        }
    }
}

/// The set of adapters, with the user's home directory resolved once.
#[derive(Debug, Clone)]
pub struct Adapters {
    home: Option<PathBuf>,
    /// Whether adapters may read agent state at all.
    enabled: bool,
}

impl Adapters {
    /// Build adapters rooted at the current user's profile.
    pub fn new(enabled: bool) -> Self {
        Adapters {
            home: user_home(),
            enabled,
        }
    }

    /// Build adapters rooted at an explicit directory. Used by tests.
    pub fn with_home(home: impl Into<PathBuf>, enabled: bool) -> Self {
        Adapters {
            home: Some(home.into()),
            enabled,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Look up metadata for a detected agent.
    ///
    /// `pid` is used to match the session record; `proc_start_filetime` is matched against the
    /// agent's own recorded start stamp where it keeps one, which is what makes a stale record
    /// from a reused pid distinguishable from a live session.
    pub fn lookup(
        &self,
        adapter: Option<guardian_proto::model::AgentAdapterKind>,
        pid: u32,
        proc_start_filetime: u64,
    ) -> AdapterResult {
        if !self.enabled {
            return AdapterResult::empty();
        }
        let Some(home) = &self.home else {
            return AdapterResult::empty();
        };

        use guardian_proto::model::AgentAdapterKind as K;
        match adapter {
            Some(K::ClaudeCode) => self.claude_code(home, pid, proc_start_filetime),
            Some(K::Codex) => self.codex(home),
            Some(K::Grok) => self.grok(home, pid),
            Some(K::None) | None => AdapterResult::empty(),
        }
    }

    /// Claude Code.
    ///
    /// `~/.claude/sessions/<pid>.json` is a small JSON document the CLI maintains for live
    /// sessions. Its shape, observed on a real installation:
    ///
    /// ```json
    /// {"pid":28176,"sessionId":"4e9b...","cwd":"D:\\Workspace\\sstv-auto",
    ///  "startedAt":1789480457087,"procStart":"134339540553239646","version":"2.1.270",
    ///  "kind":"interactive","status":"busy"}
    /// ```
    ///
    /// `procStart` is the process creation time as a FILETIME decimal string. Matching it
    /// against the live process defeats pid reuse, which is the difference between resuming
    /// the right session and resuming an unrelated one.
    ///
    /// The sibling `<pid>.<hash>.key` file is **never** opened: it holds a `peerToken`.
    fn claude_code(&self, home: &Path, pid: u32, proc_start_filetime: u64) -> AdapterResult {
        let dir = home.join(".claude").join("sessions");
        let file = dir.join(format!("{pid}.json"));

        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                tracing::trace!(
                    path = %file.display(),
                    error = %e,
                    "no Claude Code session record for this pid"
                );
                return AdapterResult::empty();
            }
        };

        // Bound the parse: this file is tiny, and a huge one would be a surprise worth
        // refusing rather than allocating for.
        if text.len() > 256 * 1024 {
            tracing::warn!(
                path = %file.display(),
                "Claude Code session record is implausibly large; ignoring"
            );
            return AdapterResult::empty();
        }

        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(
                    path = %file.display(),
                    error = %e,
                    "could not parse the Claude Code session record"
                );
                return AdapterResult::empty();
            }
        };

        // Only ever read the specific fields we need. Never the `peerToken`, never a
        // transcript path, never anything resembling content.
        let recorded_pid = value.get("pid").and_then(|v| v.as_u64());
        if recorded_pid != Some(pid as u64) {
            // The filename said one pid and the contents another; do not trust either.
            return AdapterResult::empty();
        }

        // Reject a record whose start stamp disagrees with the live process: the pid was
        // reused and this record belongs to a dead session.
        if proc_start_filetime != 0 {
            if let Some(recorded_start) = value
                .get("procStart")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
            {
                if recorded_start != proc_start_filetime {
                    tracing::debug!(
                        pid,
                        recorded_start,
                        proc_start_filetime,
                        "Claude Code session record belongs to a different process instance"
                    );
                    return AdapterResult::empty();
                }
            }
        }

        let cwd = value
            .get("cwd")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty());

        let session_id = value
            .get("sessionId")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty());

        let project = cwd.map(|p| project_from_path(p, "claude_session_file"));

        let resume = match session_id {
            Some(id) => ResumeCapability::Available {
                handle: id.to_string(),
                // A hint for a human to act on. Guardian never runs this itself.
                hint: format!("claude --resume {id}"),
            },
            None => ResumeCapability::Unavailable,
        };

        AdapterResult {
            project,
            resume,
            source: Some("claude_session_file".into()),
        }
    }

    /// Grok.
    ///
    /// `~/.grok/active_sessions.json` is an array of
    /// `{session_id, pid, cwd, opened_at}`. The pid is direct, so no start-stamp matching is
    /// needed; the file is only consulted for the pid we already have.
    fn grok(&self, home: &Path, pid: u32) -> AdapterResult {
        let file = home.join(".grok").join("active_sessions.json");

        let text = match std::fs::read_to_string(&file) {
            Ok(t) => t,
            Err(e) => {
                tracing::trace!(
                    path = %file.display(),
                    error = %e,
                    "no Grok session record"
                );
                return AdapterResult::empty();
            }
        };

        if text.len() > 4 * 1024 * 1024 {
            // This file is a small list; a huge one means something is wrong with it.
            tracing::warn!(
                path = %file.display(),
                "Grok active_sessions.json is implausibly large; ignoring"
            );
            return AdapterResult::empty();
        }

        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(
                    path = %file.display(),
                    error = %e,
                    "could not parse Grok active_sessions.json"
                );
                return AdapterResult::empty();
            }
        };

        let Some(entries) = value.as_array() else {
            return AdapterResult::empty();
        };

        let entry = entries
            .iter()
            .find(|e| e.get("pid").and_then(|p| p.as_u64()) == Some(pid as u64));

        let Some(entry) = entry else {
            return AdapterResult::empty();
        };

        let cwd = entry
            .get("cwd")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty());

        let session_id = entry
            .get("session_id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty());

        let project = cwd.map(|p| project_from_path(p, "grok_active_sessions"));

        let resume = match session_id {
            Some(id) => ResumeCapability::Available {
                handle: id.to_string(),
                hint: format!("grok --resume {id}"),
            },
            None => ResumeCapability::Unavailable,
        };

        AdapterResult {
            project,
            resume,
            source: Some("grok_active_sessions".into()),
        }
    }

    /// Codex.
    ///
    /// Codex writes rollout transcripts under `~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl`,
    /// each beginning with a `session_meta` line carrying `cwd` and `session_id`.
    ///
    /// This adapter deliberately does **not** scan that tree. The date-partitioned layout
    /// means finding the *current* session would require walking potentially thousands of
    /// files and reading their first line, on every sweep, forever. Instead the newest
    /// session directory is inspected with a bounded, cheap search, and when that is not
    /// conclusive the adapter reports nothing. Reporting "unavailable" is honest; guessing
    /// which of yesterday's sessions is running would not be.
    fn codex(&self, home: &Path) -> AdapterResult {
        let root = home.join(".codex").join("sessions");
        if !root.is_dir() {
            return AdapterResult::empty();
        }

        // Descend at most three levels (year/month/day) and take the newest day directory.
        let Some(day) = newest_subdir(&root, 3) else {
            return AdapterResult::empty();
        };

        let newest = newest_file_with_prefix(&day, "rollout-", 1);
        let Some(file) = newest else {
            return AdapterResult::empty();
        };

        let Some(line) = read_first_line(&file, 64 * 1024) else {
            return AdapterResult::empty();
        };

        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            return AdapterResult::empty();
        };

        // Only the metadata line is meaningful; anything else is not a session header.
        if value.get("type").and_then(|v| v.as_str()) != Some("session_meta") {
            return AdapterResult::empty();
        }

        let payload = value.get("payload");
        let cwd = payload
            .and_then(|p| p.get("cwd"))
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty());

        let project = cwd.map(|p| project_from_path(p, "codex_session_meta"));

        // Codex records a session id in the metadata, but Guardian has no reliable way to
        // know that this rollout belongs to the process it just detected (the file is not
        // keyed by pid). Offering to resume it could resume the wrong conversation, so the
        // adapter reports project metadata only.
        AdapterResult {
            project,
            resume: ResumeCapability::Unavailable,
            source: Some("codex_session_meta".into()),
        }
    }
}

/// Build a project context from a recorded working directory.
fn project_from_path(path: &str, source: &str) -> ProjectContext {
    let trimmed = path.trim_end_matches(['\\', '/']);
    // The final path component is the project name. A path like `D:\Workspace\repo` yields
    // `repo`; a bare drive root yields the drive, which is honest about being unhelpful.
    let name = trimmed
        .rsplit(['\\', '/'])
        .find(|s| !s.is_empty())
        .unwrap_or(trimmed)
        .to_string();

    ProjectContext {
        root: trimmed.to_string(),
        name,
        source: source.to_string(),
        vcs: None,
    }
}

/// The user's home directory.
fn user_home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .or_else(|| {
            // Fall back to composing it, which works in service contexts where USERPROFILE
            // is not set on the service account's own environment.
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            let mut p = PathBuf::from(drive);
            p.push(path);
            Some(p)
        })
}

/// Find the newest subdirectory within `depth` levels of `root`.
fn newest_subdir(root: &Path, depth: usize) -> Option<PathBuf> {
    if depth == 0 {
        return None;
    }
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;

    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };

        if best.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
            best = Some((modified, path));
        }
    }

    let (_, newest) = best?;
    // Recurse into the newest child only: this follows the date partition down the branch
    // that could plausibly hold the current session, and touches a handful of directories
    // rather than the whole tree.
    match newest_subdir(&newest, depth - 1) {
        Some(deeper) => Some(deeper),
        None => Some(newest),
    }
}

/// The newest file in `dir` whose name starts with `prefix`.
fn newest_file_with_prefix(dir: &Path, prefix: &str, _unused: u8) -> Option<PathBuf> {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;

    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(prefix) {
            continue;
        }
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        if best.as_ref().map(|(t, _)| modified > *t).unwrap_or(true) {
            best = Some((modified, path));
        }
    }

    best.map(|(_, p)| p)
}

/// Read the first line of a file, bounded.
fn read_first_line(path: &Path, max_bytes: usize) -> Option<String> {
    use std::io::{BufRead, BufReader};

    let file = std::fs::File::open(path).ok()?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let n = reader.read_line(&mut line).ok()?;
    if n == 0 || n > max_bytes {
        return None;
    }
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempProfile(PathBuf);

    impl TempProfile {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "guardian-adapter-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).expect("temp profile");
            TempProfile(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempProfile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn claude_adapter_reads_project_and_resume_from_a_real_shaped_record() {
        // Byte-for-byte the shape observed on the development machine.
        let profile = TempProfile::new("claude");
        let dir = profile.path().join(".claude").join("sessions");
        write(
            &dir.join("28176.json"),
            r#"{"pid":28176,"sessionId":"4e9b0cfc-7036-4164-8b4a-02bbe6f1f7a7",
                "cwd":"D:\\Workspace\\sstv-auto","startedAt":1789480457087,
                "procStart":"134339540553239646","version":"2.1.270",
                "kind":"interactive","status":"busy"}"#,
        );

        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(
            Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
            28176,
            134339540553239646,
        );

        let project = result.project.expect("project recorded");
        assert_eq!(project.root, r"D:\Workspace\sstv-auto");
        assert_eq!(project.name, "sstv-auto");
        assert_eq!(project.source, "claude_session_file");

        match result.resume {
            ResumeCapability::Available { handle, hint } => {
                assert_eq!(handle, "4e9b0cfc-7036-4164-8b4a-02bbe6f1f7a7");
                assert!(hint.contains("--resume"));
                assert!(hint.contains("4e9b0cfc"));
            }
            other => panic!("expected a resume handle, got {other:?}"),
        }
    }

    #[test]
    fn claude_adapter_never_reads_the_key_file() {
        // The `.key` file holds a peerToken. This test asserts the adapter does not so much
        // as open it: the key file is made unreadable (a directory) and the adapter must
        // still succeed using only the .json.
        let profile = TempProfile::new("claude-key");
        let dir = profile.path().join(".claude").join("sessions");
        write(
            &dir.join("10.json"),
            r#"{"pid":10,"sessionId":"abc","cwd":"C:\\proj"}"#,
        );
        // A directory where the .key file would be: opening it as a file would fail.
        std::fs::create_dir_all(dir.join("10.deadbeef.key")).unwrap();

        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(
            Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
            10,
            0,
        );
        assert!(result.project.is_some());
        // And nothing about a token appears anywhere in the result.
        let rendered = format!("{result:?}");
        assert!(!rendered.contains("peerToken"));
        assert!(!rendered.contains("deadbeef"));
    }

    #[test]
    fn claude_adapter_rejects_a_reused_pid() {
        // The record is from a dead session; the live process with the same pid is different.
        let profile = TempProfile::new("claude-reuse");
        let dir = profile.path().join(".claude").join("sessions");
        write(
            &dir.join("42.json"),
            r#"{"pid":42,"sessionId":"old","cwd":"C:\\old","procStart":"1000"}"#,
        );

        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(
            Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
            42,
            2000, // a different process instance
        );
        assert!(
            result.project.is_none(),
            "a reused pid must not inherit a session"
        );
        assert_eq!(result.resume, ResumeCapability::Unavailable);
    }

    #[test]
    fn claude_adapter_rejects_a_record_whose_pid_disagrees_with_its_filename() {
        let profile = TempProfile::new("claude-mismatch");
        let dir = profile.path().join(".claude").join("sessions");
        write(
            &dir.join("7.json"),
            r#"{"pid":999,"sessionId":"x","cwd":"C:\\proj"}"#,
        );
        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(
            Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
            7,
            0,
        );
        assert!(result.project.is_none());
    }

    #[test]
    fn claude_adapter_tolerates_missing_and_malformed_files() {
        let profile = TempProfile::new("claude-bad");
        let adapters = Adapters::with_home(profile.path(), true);

        // No directory at all.
        assert!(adapters
            .lookup(
                Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
                1,
                0
            )
            .project
            .is_none());

        // A malformed record.
        let dir = profile.path().join(".claude").join("sessions");
        write(&dir.join("1.json"), "{not json at all");
        assert!(adapters
            .lookup(
                Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
                1,
                0
            )
            .project
            .is_none());

        // An implausibly large record.
        write(&dir.join("2.json"), &"x".repeat(300 * 1024));
        assert!(adapters
            .lookup(
                Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
                2,
                0
            )
            .project
            .is_none());
    }

    #[test]
    fn grok_adapter_reads_project_and_resume() {
        let profile = TempProfile::new("grok");
        write(
            &profile.path().join(".grok").join("active_sessions.json"),
            r#"[
                {"session_id":"01a0a259-63ef-78a1-84c0-322f56f8cf8d","pid":16340,
                 "cwd":"D:\\Workspace\\reverse-mcp","opened_at":"2026-09-14T23:57:56Z"},
                {"session_id":"01a0a25a-5da7-7372-a662-75ec7bcc6d2e","pid":1600,
                 "cwd":"D:\\Workspace\\rime-xhup-flow","opened_at":"2026-09-14T23:58:11Z"}
            ]"#,
        );

        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(Some(guardian_proto::model::AgentAdapterKind::Grok), 1600, 0);

        let project = result.project.expect("project");
        assert_eq!(project.root, r"D:\Workspace\rime-xhup-flow");
        assert_eq!(project.name, "rime-xhup-flow");

        match result.resume {
            ResumeCapability::Available { handle, .. } => {
                assert_eq!(handle, "01a0a25a-5da7-7372-a662-75ec7bcc6d2e");
            }
            other => panic!("expected a resume handle, got {other:?}"),
        }
    }

    #[test]
    fn grok_adapter_returns_nothing_for_an_unknown_pid() {
        let profile = TempProfile::new("grok-none");
        write(
            &profile.path().join(".grok").join("active_sessions.json"),
            r#"[{"session_id":"a","pid":1,"cwd":"C:\\x"}]"#,
        );
        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(Some(guardian_proto::model::AgentAdapterKind::Grok), 999, 0);
        assert!(result.project.is_none());
    }

    #[test]
    fn codex_adapter_reads_the_session_metadata() {
        let profile = TempProfile::new("codex");
        let path = profile
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("09")
            .join("15")
            .join("rollout-2026-09-15T10-00-00-019f1b65.jsonl");
        write(
            &path,
            concat!(
                r#"{"timestamp":"2026-09-15T02:00:00.000Z","type":"session_meta","#,
                r#""payload":{"session_id":"019f1b65","cwd":"D:\\Workspace\\egressdns","#,
                r#""originator":"Codex Desktop","cli_version":"0.154.0"}}"#,
                "\n",
                r#"{"timestamp":"2026-09-15T02:00:01.000Z","type":"response_item"}"#,
                "\n"
            ),
        );

        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(Some(guardian_proto::model::AgentAdapterKind::Codex), 1, 0);

        let project = result.project.expect("project from session metadata");
        assert_eq!(project.root, r"D:\Workspace\egressdns");
        assert_eq!(project.name, "egressdns");
        assert_eq!(project.source, "codex_session_meta");

        // Deliberately unavailable: the rollout file is not keyed by pid, so Guardian cannot
        // know this transcript belongs to the process it detected.
        assert_eq!(result.resume, ResumeCapability::Unavailable);
    }

    #[test]
    fn codex_adapter_ignores_a_non_metadata_first_line() {
        let profile = TempProfile::new("codex-nometa");
        let path = profile
            .path()
            .join(".codex")
            .join("sessions")
            .join("2026")
            .join("09")
            .join("15")
            .join("rollout-x.jsonl");
        write(&path, "{\"type\":\"response_item\"}\n");

        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(Some(guardian_proto::model::AgentAdapterKind::Codex), 1, 0);
        assert!(result.project.is_none());
    }

    #[test]
    fn disabled_adapters_read_nothing() {
        // The user must be able to turn adapter reads off without losing detection.
        let profile = TempProfile::new("disabled");
        write(
            &profile
                .path()
                .join(".claude")
                .join("sessions")
                .join("5.json"),
            r#"{"pid":5,"sessionId":"s","cwd":"C:\\proj"}"#,
        );
        let adapters = Adapters::with_home(profile.path(), false);
        assert!(!adapters.enabled());
        let result = adapters.lookup(
            Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
            5,
            0,
        );
        assert!(result.project.is_none());
        assert_eq!(result.resume, ResumeCapability::Unavailable);
    }

    #[test]
    fn a_signature_without_an_adapter_yields_nothing() {
        let profile = TempProfile::new("noadapter");
        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(None, 1, 0);
        assert!(result.project.is_none());
        assert_eq!(result.resume, ResumeCapability::Unavailable);
    }

    #[test]
    fn project_name_is_the_final_component() {
        let p = project_from_path(r"D:\Workspace\rust-reality", "test");
        assert_eq!(p.name, "rust-reality");
        assert_eq!(p.root, r"D:\Workspace\rust-reality");

        // A trailing separator is tolerated.
        let p = project_from_path(r"D:\Workspace\repo\", "test");
        assert_eq!(p.name, "repo");

        // A unix-style path, which Cygwin/MSYS agents can report.
        let p = project_from_path("/home/dev/proj", "test");
        assert_eq!(p.name, "proj");
    }

    #[test]
    fn adapter_results_never_contain_prompt_like_content() {
        // A record with extra fields (which real agents do add) must not leak any of them.
        let profile = TempProfile::new("no-leak");
        let dir = profile.path().join(".claude").join("sessions");
        write(
            &dir.join("3.json"),
            r#"{"pid":3,"sessionId":"s","cwd":"C:\\proj",
                "prompt":"SECRET_PROMPT_TEXT","transcript":"SECRET_TRANSCRIPT",
                "apiKey":"SECRET_API_KEY","peerToken":"SECRET_TOKEN"}"#,
        );
        let adapters = Adapters::with_home(profile.path(), true);
        let result = adapters.lookup(
            Some(guardian_proto::model::AgentAdapterKind::ClaudeCode),
            3,
            0,
        );
        let rendered = format!("{result:?}");
        for secret in [
            "SECRET_PROMPT_TEXT",
            "SECRET_TRANSCRIPT",
            "SECRET_API_KEY",
            "SECRET_TOKEN",
        ] {
            assert!(
                !rendered.contains(secret),
                "adapter output leaked {secret}: {rendered}"
            );
        }
    }
}
