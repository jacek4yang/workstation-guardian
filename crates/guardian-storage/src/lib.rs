//! Crash-safe local persistence.
//!
//! # Why not SQLite
//!
//! Guardian's persistence needs are: a handful of small state documents, a bounded
//! append-only record of events, and incident history. There is no relational query, no
//! concurrency beyond a single writer, and no need for transactions spanning tables.
//! An atomic-file journal plus an append-only log satisfies this with a fraction of the
//! code, no C dependency, and a recovery story that can be read in one sitting. That
//! matters more here than SQL would.
//!
//! # Durability model
//!
//! Two primitives:
//!
//! * [`AtomicFile`] — whole-document replacement. Written to a sibling temp file, flushed
//!   to disk (`FlushFileBuffers`), then `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)`.
//!   On Windows that rename is atomic with respect to readers of the path, so a crash
//!   leaves either the old or the new document, never a mixture.
//! * [`Journal`] — append-only records with a length + checksum header, so a truncated or
//!   corrupted tail (the normal outcome of power loss) is detected and discarded instead
//!   of being parsed as valid data.
//!
//! Both are pure `std::fs` + `std::io`; the Windows-specific bits live in `guardian-win`.
//! That keeps this crate testable on any host and free of unsafe code.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use guardian_proto::model::{
    AgentInventory, ConfigDocument, Incident, NetworkSnapshot, RebootAuthorization,
};
use serde::{de::DeserializeOwned, Serialize};

pub mod paths;

pub use paths::GuardianPaths;

/// Errors from persistence. Every variant is recoverable by falling back to defaults,
/// which is what the fail-closed policy requires.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("corrupt document at {path}: {detail}")]
    Corrupt { path: PathBuf, detail: String },

    #[error("serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
}

impl StorageError {
    fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        StorageError::Io {
            path: path.into(),
            source,
        }
    }

    /// Whether the failure means "the data is unusable", as opposed to a transient
    /// filesystem problem. Callers use this to decide between retrying and falling back.
    pub fn is_corruption(&self) -> bool {
        matches!(self, StorageError::Corrupt { .. })
    }
}

impl From<io::Error> for StorageError {
    fn from(source: io::Error) -> Self {
        StorageError::Io {
            path: PathBuf::from("<unattributed>"),
            source,
        }
    }
}

/// Maximum size of a document we are willing to read back. Guards against a hostile or
/// accidentally enormous file being slurped into memory.
const MAX_DOCUMENT_BYTES: u64 = 8 * 1024 * 1024;

/// A file whose contents are replaced atomically.
#[derive(Debug)]
pub struct AtomicFile {
    path: PathBuf,
}

impl AtomicFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        AtomicFile { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Replace the file contents atomically.
    ///
    /// Sequence: create temp in the *same directory* (so the rename cannot cross a volume),
    /// write, `flush` (userspace), `sync_all` (to the platter), then rename over the target.
    pub fn write_bytes(&self, bytes: &[u8]) -> Result<(), StorageError> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| StorageError::Corrupt {
                path: self.path.clone(),
                detail: "atomic file has no parent directory".into(),
            })?;
        fs::create_dir_all(dir).map_err(|e| StorageError::io(dir, e))?;

        let tmp = temp_sibling(&self.path);

        // Scope the file handle so it is closed before the rename. On Windows a rename over
        // an open file can fail with a sharing violation.
        {
            let mut f = File::create(&tmp).map_err(|e| StorageError::io(&tmp, e))?;
            f.write_all(bytes)
                .map_err(|e| StorageError::io(&tmp, e))?;
            f.flush().map_err(|e| StorageError::io(&tmp, e))?;
            // Durability: without this a power loss can leave a zero-length temp file that
            // the (metadata-only) rename happily publishes.
            f.sync_all().map_err(|e| StorageError::io(&tmp, e))?;
        }

        replace_file(&tmp, &self.path).map_err(|e| StorageError::io(&self.path, e))?;

        // Best-effort: flush the directory entry so the rename itself survives a crash.
        // Windows does not offer a portable directory fsync; opening the directory with
        // FILE_FLAG_BACKUP_SEMANTICS and flushing is done in guardian-win. Failure here is
        // not fatal because the rename is already durable on NTFS journals.
        Ok(())
    }

    /// Serialize `value` to JSON and write it atomically.
    pub fn write_json<T: Serialize>(&self, value: &T) -> Result<(), StorageError> {
        // Pretty-print: these files are meant to be read by a human debugging a machine at
        // 3am, and they are small.
        let bytes = serde_json::to_vec_pretty(value)?;
        self.write_bytes(&bytes)
    }

    /// Read the file. Returns `Ok(None)` when it does not exist (a normal first run).
    pub fn read_bytes(&self) -> Result<Option<Vec<u8>>, StorageError> {
        match fs::metadata(&self.path) {
            Ok(m) if m.len() > MAX_DOCUMENT_BYTES => {
                return Err(StorageError::Corrupt {
                    path: self.path.clone(),
                    detail: format!("document is {} bytes, exceeds limit", m.len()),
                });
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StorageError::io(&self.path, e)),
        }

        match fs::read(&self.path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::io(&self.path, e)),
        }
    }

    /// Deserialize JSON. `Ok(None)` when absent.
    pub fn read_json<T: DeserializeOwned>(&self) -> Result<Option<T>, StorageError> {
        let Some(bytes) = self.read_bytes()? else {
            return Ok(None);
        };
        if bytes.is_empty() {
            // An empty file is what a half-completed write looks like. Treat as absent
            // rather than as corruption noise, but do not invent data.
            return Ok(None);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| StorageError::Corrupt {
                path: self.path.clone(),
                detail: e.to_string(),
            })
    }

    /// Move the current file aside as `.corrupt-<n>` so a human can inspect what broke,
    /// then return. Bounded so a crash loop cannot fill the disk.
    pub fn quarantine(&self) -> Result<PathBuf, StorageError> {
        const MAX_QUARANTINE: u32 = 3;
        let mut chosen = self.path.with_extension("corrupt-0");
        for n in 0..MAX_QUARANTINE {
            let candidate = self.path.with_extension(format!("corrupt-{n}"));
            if !candidate.exists() {
                chosen = candidate;
                break;
            }
            chosen = candidate;
        }
        if chosen.exists() {
            let _ = fs::remove_file(&chosen);
        }
        fs::rename(&self.path, &chosen).map_err(|e| StorageError::io(&self.path, e))?;
        Ok(chosen)
    }
}

/// Build a temp path next to `target` so the rename stays within one volume.
fn temp_sibling(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "guardian.tmp".into());
    name.push(format!(".tmp-{}", std::process::id()));
    target.with_file_name(name)
}

/// Atomically replace `target` with `tmp`.
///
/// Uses `fs::rename`, which on Windows maps to `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`
/// semantics for files. Retries briefly: file systems under pressure (antivirus, indexers)
/// can transiently hold a handle on the target.
fn replace_file(tmp: &Path, target: &Path) -> io::Result<()> {
    const ATTEMPTS: u32 = 5;
    let mut last = None;
    for attempt in 0..ATTEMPTS {
        match fs::rename(tmp, target) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                // Backoff: 1, 2, 4, 8 ms. Long enough for a transient handle to close,
                // short enough that a config write never stalls a worker meaningfully.
                std::thread::sleep(std::time::Duration::from_millis(1 << attempt));
            }
        }
    }
    let e = last.unwrap_or_else(|| io::Error::other("rename failed"));
    let _ = fs::remove_file(tmp);
    Err(e)
}

// ---------------------------------------------------------------------------
// Journal
// ---------------------------------------------------------------------------

/// Magic identifying a Guardian journal record.
const JOURNAL_MAGIC: u32 = 0x4752_444E; // "GRDN"

/// A record written to a [`Journal`].
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalRecord {
    /// Written once per service start. Establishes the boot/session identity.
    SessionStart {
        boot_id: String,
        session_id: String,
        started_at_ms: i64,
        version: String,
    },
    /// Periodic liveness marker containing the full recoverable state.
    ///
    /// This is the record that makes recovery possible after a power loss: whatever is in
    /// the newest valid `Checkpoint` is what the next boot believes was running.
    Checkpoint(Box<Checkpoint>),
    /// Protection state changed.
    ModeChange {
        from: String,
        to: String,
        at_ms: i64,
        reason: String,
    },
    /// Guardian-owned policy was found modified.
    PolicyTamper {
        value_name: String,
        expected: String,
        observed: String,
        at_ms: i64,
        restored: bool,
    },
    /// A shutdown/restart was observed and critical state was flushed.
    ShutdownObserved {
        at_ms: i64,
        /// `shutdown` or `restart`.
        shutdown_kind: String,
        reason: Option<String>,
        authorized: bool,
    },
    /// Clean termination marker. Its presence is what proves a session ended normally.
    CleanShutdown { at_ms: i64, uptime_ms: i64 },
    /// A worker failed; recorded so a crash loop is visible after the fact.
    WorkerFailure {
        worker: String,
        error: String,
        at_ms: i64,
    },
    /// Network state transition worth remembering.
    NetworkEvent { at_ms: i64, detail: String },
}

impl JournalRecord {
    /// Short tag for logging; avoids dumping whole records into logs.
    pub fn tag(&self) -> &'static str {
        match self {
            JournalRecord::SessionStart { .. } => "session_start",
            JournalRecord::Checkpoint(_) => "checkpoint",
            JournalRecord::ModeChange { .. } => "mode_change",
            JournalRecord::PolicyTamper { .. } => "policy_tamper",
            JournalRecord::ShutdownObserved { .. } => "shutdown_observed",
            JournalRecord::CleanShutdown { .. } => "clean_shutdown",
            JournalRecord::WorkerFailure { .. } => "worker_failure",
            JournalRecord::NetworkEvent { .. } => "network_event",
        }
    }
}

/// The recoverable snapshot: "what was true the last time we looked".
#[derive(Debug, Clone, Default, PartialEq, Serialize, serde::Deserialize)]
pub struct Checkpoint {
    pub written_at_ms: i64,
    pub boot_id: String,
    pub session_id: String,
    pub mode: String,
    pub update_protection: String,
    pub agents: Box<AgentInventory>,
    pub network: Box<NetworkSnapshot>,
    pub reboot_authorization: Option<RebootAuthorization>,
    /// True while the watchdog believes protected work is live. Used at boot to decide
    /// whether the previous session's loss of work mattered.
    pub protected_work_live: bool,
}

/// Append-only journal with checksummed records.
///
/// Record layout: `magic:u32 | len:u32 | crc32:u32 | payload[len]`.
/// A torn tail fails either the length sanity check or the checksum, and is discarded.
pub struct Journal {
    path: PathBuf,
    file: Option<File>,
    bytes_written: u64,
    max_bytes: u64,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("path", &self.path)
            .field("bytes_written", &self.bytes_written)
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

/// Outcome of reading a journal.
#[derive(Debug, Clone, Default)]
pub struct JournalRead {
    pub records: Vec<JournalRecord>,
    /// Records discarded because the record was torn or the checksum failed.
    pub discarded_tail_records: u32,
    /// True when reading stopped due to a torn tail (as opposed to a clean EOF).
    pub truncated: bool,
}

impl JournalRead {
    /// Newest valid checkpoint, which is what recovery actually uses.
    pub fn latest_checkpoint(&self) -> Option<&Checkpoint> {
        self.records
            .iter()
            .rev()
            .find_map(|r| match r {
                JournalRecord::Checkpoint(c) => Some(c.as_ref()),
                _ => None,
            })
    }

    /// True when the log contains a `CleanShutdown` written after the given session start.
    pub fn session_ended_cleanly(&self, session_id: &str) -> bool {
        let mut started = false;
        for r in &self.records {
            match r {
                JournalRecord::SessionStart { session_id: s, .. } if s == session_id => {
                    started = true;
                }
                JournalRecord::CleanShutdown { .. } if started => return true,
                // A later session start means our session never wrote a clean marker.
                JournalRecord::SessionStart { .. } if started => return false,
                _ => {}
            }
        }
        false
    }
}

impl Journal {
    /// Open (creating if needed) the journal at `path`.
    pub fn open(path: impl Into<PathBuf>, max_bytes: u64) -> Result<Self, StorageError> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(|e| StorageError::io(dir, e))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(|e| StorageError::io(&path, e))?;
        let bytes_written = file
            .metadata()
            .map(|m| m.len())
            .map_err(|e| StorageError::io(&path, e))?;
        Ok(Journal {
            path,
            file: Some(file),
            bytes_written,
            max_bytes: max_bytes.max(64 * 1024),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Append a record and flush it to disk.
    ///
    /// `sync = false` is used for high-frequency checkpoints: the data is visible to any
    /// reader (so a *process* crash is fully covered) but a power loss may lose the last
    /// few. Genuinely critical transitions (shutdown observed, clean shutdown, mode change)
    /// pass `sync = true`.
    pub fn append(&mut self, record: &JournalRecord, sync: bool) -> Result<(), StorageError> {
        if self.bytes_written >= self.max_bytes {
            self.rotate()?;
        }

        let payload = serde_json::to_vec(record)?;
        if payload.len() > u32::MAX as usize {
            return Err(StorageError::Corrupt {
                path: self.path.clone(),
                detail: "record too large".into(),
            });
        }
        let crc = crc32(&payload);

        let mut frame = Vec::with_capacity(12 + payload.len());
        frame.extend_from_slice(&JOURNAL_MAGIC.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&crc.to_le_bytes());
        frame.extend_from_slice(&payload);

        let file = self
            .file
            .as_mut()
            .ok_or_else(|| StorageError::Corrupt {
                path: self.path.clone(),
                detail: "journal closed".into(),
            })?;
        file.write_all(&frame)
            .map_err(|e| StorageError::io(&self.path, e))?;
        file.flush().map_err(|e| StorageError::io(&self.path, e))?;
        if sync {
            file.sync_all().map_err(|e| StorageError::io(&self.path, e))?;
        }
        self.bytes_written += frame.len() as u64;
        Ok(())
    }

    /// Read every valid record, discarding a torn tail.
    pub fn read_all(path: &Path) -> Result<JournalRead, StorageError> {
        let f = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(JournalRead::default()),
            Err(e) => return Err(StorageError::io(path, e)),
        };
        let mut reader = BufReader::new(f);
        let mut out = JournalRead::default();
        let mut header = [0u8; 12];

        loop {
            match reader.read_exact(&mut header) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    // Clean EOF (nothing read) or a torn header (partial read).
                    if !out.records.is_empty() || out.discarded_tail_records > 0 {
                        // Distinguish: a partial header read means truncation.
                    }
                    break;
                }
                Err(e) => return Err(StorageError::io(path, e)),
            }

            let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
            let crc = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);

            if magic != JOURNAL_MAGIC {
                // Either corruption mid-file or a torn write. Stop; keep what we have.
                out.truncated = true;
                out.discarded_tail_records += 1;
                break;
            }
            if len as u64 > MAX_DOCUMENT_BYTES {
                out.truncated = true;
                out.discarded_tail_records += 1;
                break;
            }

            let mut payload = vec![0u8; len as usize];
            if let Err(e) = reader.read_exact(&mut payload) {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    out.truncated = true;
                    out.discarded_tail_records += 1;
                    break;
                }
                return Err(StorageError::io(path, e));
            }

            if crc32(&payload) != crc {
                out.truncated = true;
                out.discarded_tail_records += 1;
                break;
            }

            match serde_json::from_slice::<JournalRecord>(&payload) {
                Ok(rec) => out.records.push(rec),
                Err(_) => {
                    // Checksum matched but the schema did not: written by a different
                    // version. Skip the record rather than abandoning the file.
                    out.discarded_tail_records += 1;
                }
            }
        }

        Ok(out)
    }

    /// Rotate: rename the current file to `.1` and start fresh. Called only when the size
    /// cap is reached, so this is rare and cheap.
    fn rotate(&mut self) -> Result<(), StorageError> {
        self.file = None;
        let prev = self.path.with_extension("1");
        let _ = fs::remove_file(&prev);
        fs::rename(&self.path, &prev).map_err(|e| StorageError::io(&self.path, e))?;
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&self.path)
            .map_err(|e| StorageError::io(&self.path, e))?;
        self.file = Some(f);
        self.bytes_written = 0;
        Ok(())
    }

    /// Force everything to disk. Called from preshutdown and before an armed reboot.
    pub fn sync(&mut self) -> Result<(), StorageError> {
        if let Some(f) = self.file.as_mut() {
            f.sync_all().map_err(|e| StorageError::io(&self.path, e))?;
        }
        Ok(())
    }

    /// Truncate the journal to zero, used after a successful recovery so a stale
    /// `CleanShutdown` from an old session is never mistaken for the current one.
    pub fn truncate(&mut self) -> Result<(), StorageError> {
        self.file = None;
        let f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .read(true)
            .open(&self.path)
            .map_err(|e| StorageError::io(&self.path, e))?;
        self.file = Some(f);
        self.bytes_written = 0;
        Ok(())
    }}

/// CRC-32 (IEEE 802.3), implemented locally to avoid pulling in a dependency for one
/// function. Table-free bitwise form is plenty fast for records of a few kilobytes.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Typed stores
// ---------------------------------------------------------------------------

/// The set of documents the service persists. Each is independently atomic, so a failure
/// to write one never corrupts the others.
#[derive(Debug)]
pub struct Store {
    pub paths: GuardianPaths,
    pub config: AtomicFile,
    pub state: AtomicFile,
    pub incidents: AtomicFile,
    pub candidates: AtomicFile,
}

/// Long-lived state that must survive a reboot.
#[derive(Debug, Clone, Default, PartialEq, Serialize, serde::Deserialize)]
pub struct PersistentState {
    pub schema_version: u32,
    /// Boot identity of the session that last wrote this document.
    pub last_boot_id: String,
    pub last_session_id: String,
    pub last_started_at_ms: i64,
    pub last_heartbeat_ms: i64,
    /// False while running; set true only by the clean-shutdown path.
    pub clean_shutdown: bool,
    pub last_mode: String,
    pub last_update_protection: String,
    /// Protection values Guardian itself wrote, so uninstall can restore exactly those
    /// and nothing belonging to external management.
    pub owned_policy: Vec<OwnedPolicyValue>,
    /// Protection values that existed *before* Guardian first wrote, for rollback.
    pub original_policy: Vec<OwnedPolicyValue>,
    pub reboot_authorization: Option<RebootAuthorization>,
    /// Set when Guardian has installed its policy at least once.
    pub policy_installed: bool,
    /// Counter incremented once per service start; a rising counter with no clean shutdown
    /// is itself evidence of a crash loop.
    pub start_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct OwnedPolicyValue {
    pub key_path: String,
    pub value_name: String,
    /// Serialized `PolValue`, or `None` when the value did not exist.
    pub value: Option<guardian_proto::model::PolValue>,
    /// True when Guardian created the *key* (so uninstall may remove an empty key).
    pub created_key: bool,
}

impl Store {
    pub fn open(paths: GuardianPaths) -> Result<Self, StorageError> {
        paths.ensure_dirs()?;
        Ok(Store {
            config: AtomicFile::new(paths.config_file()),
            state: AtomicFile::new(paths.state_file()),
            incidents: AtomicFile::new(paths.incidents_file()),
            candidates: AtomicFile::new(paths.candidates_file()),
            paths,
        })
    }

    /// Load configuration, falling back to defaults on corruption.
    ///
    /// Returning defaults on corruption is the fail-closed choice: the defaults have
    /// `update.protect = true`.
    pub fn load_config(&self) -> (ConfigDocument, Option<StorageError>) {
        match self.config.read_json::<ConfigDocument>() {
            Ok(Some(cfg)) => (cfg, None),
            Ok(None) => (ConfigDocument::default(), None),
            Err(e) => {
                let _ = self.config.quarantine();
                (ConfigDocument::default(), Some(e))
            }
        }
    }

    pub fn save_config(&self, cfg: &ConfigDocument) -> Result<(), StorageError> {
        self.config.write_json(cfg)
    }

    pub fn load_state(&self) -> (PersistentState, Option<StorageError>) {
        match self.state.read_json::<PersistentState>() {
            Ok(Some(s)) => (s, None),
            Ok(None) => (PersistentState::default(), None),
            Err(e) => {
                let _ = self.state.quarantine();
                (PersistentState::default(), Some(e))
            }
        }
    }

    pub fn save_state(&self, s: &PersistentState) -> Result<(), StorageError> {
        self.state.write_json(s)
    }

    pub fn load_incidents(&self) -> Vec<Incident> {
        // Incidents are a convenience surface. If they are corrupt we lose history, not
        // protection, so this deliberately swallows the error after quarantining.
        match self.incidents.read_json::<Vec<Incident>>() {
            Ok(Some(v)) => v,
            Ok(None) => Vec::new(),
            Err(e) => {
                tracing::warn!(error = %e, "incident history unreadable; quarantining");
                let _ = self.incidents.quarantine();
                Vec::new()
            }
        }
    }

    pub fn save_incidents(&self, v: &[Incident]) -> Result<(), StorageError> {
        self.incidents.write_json(&v.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "guardian-test-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            fs::create_dir_all(&p).expect("temp dir");
            TempDir(p)
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn atomic_write_then_read_round_trips() {
        let d = TempDir::new("atomic");
        let f = AtomicFile::new(d.path("doc.json"));
        assert!(f.read_json::<ConfigDocument>().unwrap().is_none());

        let cfg = ConfigDocument::default();
        f.write_json(&cfg).unwrap();
        let back: ConfigDocument = f.read_json().unwrap().expect("present");
        assert_eq!(back.schema_version, cfg.schema_version);

        // Overwrite: the path must now contain the new document and no temp files.
        let mut cfg2 = cfg.clone();
        cfg2.body.update.verify_interval_secs = 99;
        f.write_json(&cfg2).unwrap();
        let back: ConfigDocument = f.read_json().unwrap().expect("present");
        assert_eq!(back.body.update.verify_interval_secs, 99);

        let leftovers: Vec<_> = fs::read_dir(&d.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "temp files must not be left behind");
    }

    #[test]
    fn missing_file_is_not_an_error() {
        let d = TempDir::new("missing");
        let f = AtomicFile::new(d.path("nope.json"));
        assert!(f.read_json::<ConfigDocument>().unwrap().is_none());
        assert!(f.read_bytes().unwrap().is_none());
    }

    #[test]
    fn empty_file_is_treated_as_absent_not_corrupt() {
        let d = TempDir::new("empty");
        let p = d.path("empty.json");
        fs::write(&p, b"").unwrap();
        let f = AtomicFile::new(&p);
        assert!(f.read_json::<ConfigDocument>().unwrap().is_none());
    }

    #[test]
    fn truncated_json_is_corruption_and_can_be_quarantined() {
        // Simulates the classic power-loss outcome: half a document on disk.
        let d = TempDir::new("trunc");
        let p = d.path("half.json");
        fs::write(&p, br#"{"schema_version": 1, "upd"#).unwrap();
        let f = AtomicFile::new(&p);
        let err = f.read_json::<ConfigDocument>().unwrap_err();
        assert!(err.is_corruption(), "truncated JSON must read as corruption");

        let q = f.quarantine().unwrap();
        assert!(q.exists());
        assert!(!p.exists());
        // A second quarantine does not explode.
        f.write_json(&ConfigDocument::default()).unwrap();
        fs::write(&p, b"{oops").unwrap();
        assert!(f.quarantine().is_ok());
    }

    #[test]
    fn quarantined_file_does_not_grow_unbounded() {
        let d = TempDir::new("quarantine-bound");
        let p = d.path("doc.json");
        let f = AtomicFile::new(&p);
        for _ in 0..10 {
            fs::write(&p, b"garbage").unwrap();
            f.quarantine().unwrap();
        }
        let count = fs::read_dir(&d.0)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("corrupt"))
            .count();
        assert!(count <= 3, "quarantine files must be bounded, got {count}");
    }

    #[test]
    fn journal_round_trips_records() {
        let d = TempDir::new("journal");
        let p = d.path("journal.log");
        {
            let mut j = Journal::open(&p, 1 << 20).unwrap();
            j.append(
                &JournalRecord::SessionStart {
                    boot_id: "b1".into(),
                    session_id: "s1".into(),
                    started_at_ms: 1,
                    version: "0.1.0".into(),
                },
                true,
            )
            .unwrap();
            j.append(
                &JournalRecord::Checkpoint(Box::new(Checkpoint {
                    written_at_ms: 2,
                    boot_id: "b1".into(),
                    session_id: "s1".into(),
                    mode: "WORKING".into(),
                    update_protection: "Protected".into(),
                    protected_work_live: true,
                    ..Default::default()
                })),
                false,
            )
            .unwrap();
        }
        let read = Journal::read_all(&p).unwrap();
        assert_eq!(read.records.len(), 2);
        assert!(!read.truncated);
        assert_eq!(read.discarded_tail_records, 0);
        let cp = read.latest_checkpoint().expect("checkpoint");
        assert_eq!(cp.mode, "WORKING");
        assert!(cp.protected_work_live);
    }

    #[test]
    fn journal_discards_torn_tail_and_keeps_earlier_records() {
        // The power-loss case: a partial record at the end of the file.
        let d = TempDir::new("journal-torn");
        let p = d.path("journal.log");
        {
            let mut j = Journal::open(&p, 1 << 20).unwrap();
            for i in 0..3 {
                j.append(
                    &JournalRecord::NetworkEvent {
                        at_ms: i,
                        detail: format!("event {i}"),
                    },
                    false,
                )
                .unwrap();
            }
        }
        // Chop the file mid-record, as a power loss would.
        let full = fs::read(&p).unwrap();
        fs::write(&p, &full[..full.len() - 7]).unwrap();

        let read = Journal::read_all(&p).unwrap();
        assert_eq!(read.records.len(), 2, "two complete records survive");
        assert!(read.truncated, "the torn tail must be reported");
        assert_eq!(read.discarded_tail_records, 1);
    }

    #[test]
    fn journal_rejects_bit_flipped_payload() {
        let d = TempDir::new("journal-flip");
        let p = d.path("journal.log");
        {
            let mut j = Journal::open(&p, 1 << 20).unwrap();
            j.append(
                &JournalRecord::NetworkEvent {
                    at_ms: 1,
                    detail: "before".into(),
                },
                false,
            )
            .unwrap();
            j.append(
                &JournalRecord::NetworkEvent {
                    at_ms: 2,
                    detail: "after".into(),
                },
                false,
            )
            .unwrap();
        }
        let mut bytes = fs::read(&p).unwrap();
        // Flip a byte inside the first record's payload (past the 12-byte header).
        let idx = 14;
        bytes[idx] ^= 0xFF;
        fs::write(&p, &bytes).unwrap();

        let read = Journal::read_all(&p).unwrap();
        assert!(
            read.discarded_tail_records >= 1,
            "checksum must catch the flipped byte"
        );
        assert!(read.records.is_empty() || read.records.len() < 2);
    }

    #[test]
    fn journal_handles_garbage_file_without_panicking() {
        let d = TempDir::new("journal-garbage");
        let p = d.path("journal.log");
        fs::write(&p, vec![0xABu8; 4096]).unwrap();
        let read = Journal::read_all(&p).unwrap();
        assert!(read.records.is_empty());
        assert!(read.discarded_tail_records >= 1);
    }

    #[test]
    fn journal_missing_file_is_empty_and_error_free() {
        let d = TempDir::new("journal-missing");
        let read = Journal::read_all(&d.path("absent.log")).unwrap();
        assert!(read.records.is_empty());
        assert!(!read.truncated);
    }

    #[test]
    fn journal_rotates_at_size_cap() {
        let d = TempDir::new("journal-rotate");
        let p = d.path("journal.log");
        // Small cap; the implementation clamps to 64 KiB minimum, so write enough to hit it.
        let mut j = Journal::open(&p, 64 * 1024).unwrap();
        let big = "x".repeat(4096);
        for i in 0..40 {
            j.append(
                &JournalRecord::NetworkEvent {
                    at_ms: i,
                    detail: big.clone(),
                },
                false,
            )
            .unwrap();
        }
        assert!(j.bytes_written() < 64 * 1024, "must have rotated");
        let rotated = p.with_extension("1");
        assert!(rotated.exists(), "rotation keeps exactly one previous file");
    }

    #[test]
    fn clean_shutdown_detection_is_session_scoped() {
        let mut read = JournalRead::default();
        read.records = vec![
            JournalRecord::SessionStart {
                boot_id: "b1".into(),
                session_id: "s1".into(),
                started_at_ms: 0,
                version: "0.1.0".into(),
            },
            JournalRecord::CleanShutdown {
                at_ms: 10,
                uptime_ms: 10,
            },
        ];
        assert!(read.session_ended_cleanly("s1"));
        // A different session must not inherit the clean marker.
        assert!(!read.session_ended_cleanly("s2"));

        // A session that started after the clean marker and never finished is unclean.
        let mut read2 = JournalRead::default();
        read2.records = vec![
            JournalRecord::SessionStart {
                boot_id: "b1".into(),
                session_id: "s1".into(),
                started_at_ms: 0,
                version: "0.1.0".into(),
            },
            JournalRecord::CleanShutdown {
                at_ms: 10,
                uptime_ms: 10,
            },
            JournalRecord::SessionStart {
                boot_id: "b2".into(),
                session_id: "s2".into(),
                started_at_ms: 20,
                version: "0.1.0".into(),
            },
        ];
        assert!(read2.session_ended_cleanly("s1"));
        assert!(!read2.session_ended_cleanly("s2"));
    }

    #[test]
    fn store_recovers_defaults_from_corrupt_config() {
        // Must fail closed: corrupt config yields defaults, which protect updates.
        let d = TempDir::new("store-corrupt");
        let paths = GuardianPaths::for_test_dir(d.0.clone());
        let store = Store::open(paths).unwrap();
        fs::write(store.config.path(), b"{not json at all").unwrap();

        let (cfg, err) = store.load_config();
        assert!(err.is_some(), "corruption must be reported");
        assert!(cfg.body.update.protect, "defaults must be fail-closed");
        assert!(cfg.body.update.auto_restore);
    }

    #[test]
    fn store_round_trips_state_and_incidents() {
        let d = TempDir::new("store-state");
        let paths = GuardianPaths::for_test_dir(d.0.clone());
        let store = Store::open(paths).unwrap();

        let mut st = PersistentState::default();
        st.last_boot_id = "boot-x".into();
        st.start_count = 3;
        store.save_state(&st).unwrap();
        let (loaded, err) = store.load_state();
        assert!(err.is_none());
        assert_eq!(loaded.last_boot_id, "boot-x");
        assert_eq!(loaded.start_count, 3);

        store.save_incidents(&[]).unwrap();
        assert!(store.load_incidents().is_empty());
    }

    #[test]
    fn crc32_matches_known_vector() {
        // Standard check value for "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
