//! Generic, data-driven AI coding agent detection.
//!
//! # The problem this solves
//!
//! There is no Windows flag meaning "this process is an AI coding agent". Agents ship as
//! native binaries, as Node packages, as Python packages, as Rust binaries, and as shell
//! wrappers around all of those. A detector that pattern-matches one executable name is
//! wrong the moment the user installs a different agent, and a detector that calls every
//! `node.exe` an agent is worse than useless because it blocks shutdown forever.
//!
//! # The approach
//!
//! Layered evidence with explicit confidence, driven by a **data** database rather than
//! code. A signature is a set of regex rules over fields of a process snapshot, each rule
//! contributing a weight. The engine adds the weights, applies veto rules, and maps the
//! total onto a confidence level.
//!
//! Because the database is data, adding an agent — or correcting a false positive —
//! requires no code change and no recompilation. That is what makes this maintainable as the
//! ecosystem moves.
//!
//! ```text
//!   process snapshot ──▶ rule matching ──▶ weighted score ──▶ confidence
//!         │                    │                                  │
//!         │              veto rules                             │
//!         │                    │                                  ▼
//!         └──▶ process graph ──┴──▶ session grouping ──▶ AgentInstance
//! ```
//!
//! # What is deliberately not done
//!
//! * No PEB scraping for another process's working directory. It is undocumented,
//!   version-fragile, and would break on a Windows update. Project directories come from
//!   each agent's own local state instead (see [`adapters`]).
//! * No network calls. Process inventories never leave the machine.
//! * No guessing. An agent whose evidence is weak is reported `Possible`, and `Possible`
//!   never blocks shutdown.

pub mod adapters;
pub mod builtins;
pub mod engine;
pub mod graph;

pub use engine::{Detection, DetectionEngine, EngineConfig, RejectionReason};
pub use graph::ProcessGraph;

/// Convenience: build the default engine from built-in signatures plus user configuration.
pub fn default_engine(config: &guardian_proto::model::AgentConfig) -> DetectionEngine {
    DetectionEngine::new(EngineConfig::from_agent_config(config))
}

#[cfg(test)]
mod tests;
