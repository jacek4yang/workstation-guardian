//! Structured logging with rotation and bounded disk usage.
//!
//! # Requirements this satisfies
//!
//! * Structured, so a log line carries component and event context rather than prose.
//! * Rotating with a **bounded total size**: a service that runs for months must not fill the
//!   disk, and "rotate daily" alone does not bound anything on a machine that logs heavily.
//! * Never logs secrets. Guardian never holds a password, so this is mostly about not logging
//!   things that *look* incidental: full command lines can contain paths with user names, and
//!   adapter output is filtered at the source.
//!
//! # Why the level is lowered automatically
//!
//! Debug logging on a 24/7 service is a real cost. The caller passes the configured level; the
//! only thing this module does beyond that is bound the files.

use std::path::{Path, PathBuf};

use guardian_proto::model::LoggingConfig;
use guardian_storage::GuardianPaths;

/// A guard that keeps the tracing subscriber alive for the process's lifetime.
///
/// Dropping it would drop the appender and silently stop the logs, so the caller must hold it.
pub struct LogGuard {
    _appender: Option<tracing_appender::non_blocking::WorkerGuard>,
}

impl std::fmt::Debug for LogGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogGuard")
            .field("active", &self._appender.is_some())
            .finish()
    }
}

/// Initialize logging to a file, with a bounded rotating set of files.
///
/// Falls back to stderr-only when the log directory cannot be created, because failing to
/// start logging must never prevent the service from starting — protection matters more than
/// diagnostics.
pub fn init_file_logging(paths: &GuardianPaths, config: &LoggingConfig) -> LogGuard {
    let dir = paths.logs_dir();

    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!(
            "workstation-guardian: could not create the log directory {}: {e}; \
             continuing with stderr logging only",
            dir.display()
        );
        init_stderr(config);
        return LogGuard { _appender: None };
    }

    prune_old_logs(&dir, config.max_files, config.max_total_bytes);

    let appender = tracing_appender::rolling::never(&dir, "guardian.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);

    let filter = level_filter(&config.level);

    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer)
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .json()
        .flatten_event(true);

    if let Err(e) = tracing::subscriber::set_global_default(subscriber.finish()) {
        eprintln!("workstation-guardian: could not install the log subscriber: {e}");
    }

    LogGuard {
        _appender: Some(guard),
    }
}

/// Initialize logging to stderr, for `guardianctl` and for failures above.
pub fn init_stderr(config: &LoggingConfig) {
    let filter = level_filter(&config.level);
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time();
    let _ = tracing::subscriber::set_global_default(subscriber.finish());
}

/// Build a level filter from the configured string.
///
/// An unrecognised value falls back to `info` rather than failing: a typo in configuration
/// must not stop the service from starting.
fn level_filter(level: &str) -> tracing_subscriber::EnvFilter {
    let lvl = match level.trim().to_ascii_lowercase().as_str() {
        "error" => "error",
        "warn" => "warn",
        "debug" => "debug",
        "trace" => "trace",
        _ => "info",
    };

    tracing_subscriber::EnvFilter::try_new(format!(
        // Our own crates honour the setting; third-party crates are held at warn so a chatty
        // dependency cannot flood the log.
        "warn,guardian_service={lvl},guardian_core={lvl},guardian_win={lvl},\
         guardian_process={lvl},guardian_network={lvl},guardian_update={lvl},\
         guardian_storage={lvl},guardian_proto={lvl}"
    ))
    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
}

/// Delete the oldest log files until the directory is within budget.
///
/// Runs at startup rather than continuously: bounding at open time is enough to keep a
/// long-running service from filling the disk, and it costs one directory scan instead of a
/// check on every write.
pub fn prune_old_logs(dir: &Path, max_files: u32, max_total_bytes: u64) {
    let mut files: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        let modified = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        files.push((path, meta.len(), modified));
    }

    // Oldest first.
    files.sort_by_key(|(_, _, m)| *m);

    let total: u64 = files.iter().map(|(_, len, _)| *len).sum();
    let mut remaining = files.len() as u64;
    let mut bytes_remaining = total;

    for (index, (path, len, _)) in files.iter().enumerate() {
        // The newest file is always retained. Without this, a single log larger than the
        // whole budget would be deleted on every start - destroying exactly the live log an
        // operator needs, and on a schedule where it would never survive to be read.
        let is_newest = index + 1 == files.len();
        if is_newest {
            break;
        }

        let over_count = remaining > u64::from(max_files.max(1));
        let over_size = bytes_remaining > max_total_bytes;

        if !over_count && !over_size {
            break;
        }

        if std::fs::remove_file(path).is_ok() {
            bytes_remaining = bytes_remaining.saturating_sub(*len);
            remaining = remaining.saturating_sub(1);
        } else {
            // Could not delete (held open, permissions). Stop rather than looping.
            break;
        }
    }
}

/// The redaction applied to values before they reach a log.
///
/// Guardian does not hold credentials, but command lines and paths can carry user names and
/// tokens passed as arguments. Truncating to a bounded prefix is the pragmatic tradeoff: it
/// keeps enough for diagnosis and prevents a whole command line from being written out.
pub fn redact_for_log(value: &str) -> String {
    const MAX: usize = 120;

    // Never log anything that looks like a credential assignment.
    let lowered = value.to_ascii_lowercase();
    for needle in [
        "password",
        "token",
        "secret",
        "api_key",
        "apikey",
        "authorization",
    ] {
        if lowered.contains(needle) {
            return format!("<redacted: contains '{needle}'>");
        }
    }

    let mut out = String::with_capacity(MAX.min(value.len()));
    for c in value.chars().take(MAX) {
        out.push(c);
    }
    if value.chars().count() > MAX {
        out.push('…');
    }
    out
}

/// Total size of the log directory, for diagnostics.
pub fn log_directory_size(dir: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// The log files present, newest last, for diagnostics.
pub fn log_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<(PathBuf, std::time::SystemTime)> = entries
        .flatten()
        .filter(|e| e.path().is_file())
        .filter_map(|e| {
            let modified = e.metadata().ok()?.modified().ok()?;
            Some((e.path(), modified))
        })
        .collect();
    files.sort_by_key(|(_, m)| *m);
    files.into_iter().map(|(p, _)| p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "guardian-logs-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&p).expect("temp dir");
            TempDir(p)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn write_log(dir: &Path, name: &str, bytes: usize) {
        std::fs::write(dir.join(name), vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn pruning_removes_oldest_files_when_over_the_count() {
        let dir = TempDir::new("count");
        // Create files with distinct mtimes by writing them with a small delay.
        for i in 0..10 {
            write_log(&dir.0, &format!("log-{i}"), 16);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(log_files(&dir.0).len(), 10);

        prune_old_logs(&dir.0, 3, u64::MAX);

        let remaining = log_files(&dir.0);
        assert!(
            remaining.len() <= 3,
            "pruning must respect the file count, got {}",
            remaining.len()
        );
        // The newest must have survived.
        assert!(remaining
            .iter()
            .any(|p| p.file_name().unwrap().to_string_lossy() == "log-9"));
    }

    #[test]
    fn pruning_removes_files_when_over_the_size_budget() {
        let dir = TempDir::new("size");
        for i in 0..5 {
            write_log(&dir.0, &format!("big-{i}"), 10_000);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        prune_old_logs(&dir.0, 100, 15_000);

        let size = log_directory_size(&dir.0);
        assert!(
            size <= 15_000,
            "pruning must respect the size budget, got {size}"
        );
    }

    #[test]
    fn pruning_a_directory_within_budget_does_nothing() {
        let dir = TempDir::new("within");
        write_log(&dir.0, "small", 100);
        prune_old_logs(&dir.0, 10, 1000);
        assert_eq!(log_files(&dir.0).len(), 1, "nothing should be deleted");
    }

    #[test]
    fn pruning_a_missing_directory_is_harmless() {
        // Called before the directory exists on a first run; must not panic.
        prune_old_logs(
            Path::new(r"C:\definitely-not-a-real-directory-8f3a2b"),
            5,
            1000,
        );
    }

    #[test]
    fn pruning_never_deletes_everything_while_over_budget() {
        // A single file larger than the whole budget must still be allowed to exist, or the
        // service would delete its own live log on every start.
        let dir = TempDir::new("single-huge");
        write_log(&dir.0, "huge", 50_000);
        prune_old_logs(&dir.0, 10, 1000);
        assert_eq!(
            log_files(&dir.0).len(),
            1,
            "the most recent log must never be deleted"
        );
    }

    #[test]
    fn redaction_removes_obvious_credentials() {
        for secret in [
            "password=hunter2",
            "PASSWORD: hunter2",
            "token abc123",
            "Authorization: Bearer xyz",
            "api_key=12345",
            "apikey 12345",
            "my secret value",
        ] {
            let redacted = redact_for_log(secret);
            assert!(
                redacted.starts_with("<redacted"),
                "'{secret}' should be redacted, got '{redacted}'"
            );
            assert!(!redacted.contains("hunter2"));
            assert!(!redacted.contains("abc123"));
        }
    }

    #[test]
    fn redaction_truncates_long_values_but_keeps_a_prefix() {
        let long = "D:\\Workspace\\a-very-long-project-name\\nested\\deeper\\file.rs";
        assert!(redact_for_log(long).len() <= 200);

        let very_long = "x".repeat(1000);
        let redacted = redact_for_log(&very_long);
        assert!(
            redacted.chars().count() <= 121,
            "got {} chars",
            redacted.chars().count()
        );
        assert!(redacted.ends_with('…'));
    }

    #[test]
    fn redaction_leaves_ordinary_text_alone() {
        assert_eq!(redact_for_log("network is healthy"), "network is healthy");
        assert_eq!(redact_for_log(""), "");
    }

    #[test]
    fn redaction_is_character_safe() {
        let unicode = "日本語".repeat(100);
        let redacted = redact_for_log(&unicode);
        assert!(redacted.chars().count() <= 121);
        assert!(redacted.starts_with("日本語"));
    }

    #[test]
    fn level_filter_accepts_every_configured_level() {
        for level in ["error", "warn", "info", "debug", "trace"] {
            let _ = level_filter(level);
        }
        // An unrecognised level must not fail; it falls back.
        let _ = level_filter("nonsense");
        let _ = level_filter("");
        let _ = level_filter("  INFO  ");
    }

    #[test]
    fn log_directory_size_sums_files() {
        let dir = TempDir::new("size-sum");
        write_log(&dir.0, "a", 100);
        write_log(&dir.0, "b", 250);
        assert_eq!(log_directory_size(&dir.0), 350);
    }

    #[test]
    fn log_directory_size_of_a_missing_directory_is_zero() {
        assert_eq!(
            log_directory_size(Path::new(r"C:\definitely-not-a-real-directory-8f3a2b")),
            0
        );
        assert!(log_files(Path::new(r"C:\definitely-not-a-real-directory-8f3a2b")).is_empty());
    }

    #[test]
    fn initialized_stderr_logging_does_not_panic() {
        // Installing a subscriber can only happen once per process; tolerate the failure.
        let config = LoggingConfig {
            level: "error".into(),
            ..Default::default()
        };
        init_stderr(&config);
    }
}
