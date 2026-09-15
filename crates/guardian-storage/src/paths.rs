//! Canonical filesystem locations.
//!
//! Machine state lives under `%ProgramData%\WorkstationGuardian` so the LocalSystem
//! service, elevated tooling and a future installer all agree on one location. Per-user
//! settings live in the user's own profile, where a standard user can write them without
//! needing an administrator.

use std::path::{Path, PathBuf};

/// Directory name under `%ProgramData%`.
pub const PROGRAM_DATA_DIR: &str = "WorkstationGuardian";

/// Resolved paths for machine state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardianPaths {
    root: PathBuf,
}

impl GuardianPaths {
    /// Default production location: `%ProgramData%\WorkstationGuardian`.
    ///
    /// Falls back to `C:\ProgramData` when the environment variable is missing, which
    /// happens in some service contexts. If even that is unavailable we still return a
    /// path rather than failing: the caller decides whether that is fatal, and update
    /// protection must not depend on being able to write a log file.
    pub fn default_root() -> PathBuf {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join(PROGRAM_DATA_DIR)
    }

    pub fn production() -> Self {
        GuardianPaths {
            root: Self::default_root(),
        }
    }

    /// A path set rooted anywhere, used by tests and by `--data-dir` on the CLI.
    pub fn for_test_dir(dir: impl Into<PathBuf>) -> Self {
        GuardianPaths { root: dir.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Create the directories Guardian writes to.
    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.logs_dir())?;
        Ok(())
    }

    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.json")
    }

    pub fn state_file(&self) -> PathBuf {
        self.root.join("state.json")
    }

    pub fn incidents_file(&self) -> PathBuf {
        self.root.join("incidents.json")
    }

    /// Discovered agent-like candidates awaiting promotion.
    pub fn candidates_file(&self) -> PathBuf {
        self.root.join("candidates.json")
    }

    pub fn journal_file(&self) -> PathBuf {
        self.root.join("journal.log")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// Per-user settings, kept out of ProgramData so a non-elevated UI can save them.
    ///
    /// Returns `None` when no user profile can be determined (for example inside a service
    /// with a stripped environment), in which case the caller falls back to machine config.
    pub fn user_settings_dir() -> Option<PathBuf> {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.join(PROGRAM_DATA_DIR))
    }
}

impl Default for GuardianPaths {
    fn default() -> Self {
        Self::production()
    }
}

impl std::fmt::Display for GuardianPaths {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.root.display())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_root_ends_with_our_directory() {
        let p = GuardianPaths::production();
        assert!(p.root().ends_with(PROGRAM_DATA_DIR));
        assert!(p.config_file().ends_with("config.json"));
        assert!(p.journal_file().ends_with("journal.log"));
        assert!(p.logs_dir().ends_with("logs"));
    }

    #[test]
    fn all_files_are_distinct() {
        let p = GuardianPaths::production();
        let files = [
            p.config_file(),
            p.state_file(),
            p.incidents_file(),
            p.candidates_file(),
            p.journal_file(),
        ];
        for (i, a) in files.iter().enumerate() {
            for b in files.iter().skip(i + 1) {
                assert_ne!(a, b, "paths must not collide: {a:?} vs {b:?}");
            }
        }
    }

    #[test]
    fn ensure_dirs_is_idempotent() {
        let mut d = std::env::temp_dir();
        d.push(format!("guardian-paths-{}", std::process::id()));
        let p = GuardianPaths::for_test_dir(d.clone());
        p.ensure_dirs().unwrap();
        p.ensure_dirs().unwrap();
        assert!(p.logs_dir().is_dir());
        let _ = std::fs::remove_dir_all(&d);
    }
}
