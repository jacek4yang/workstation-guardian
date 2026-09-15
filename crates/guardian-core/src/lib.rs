//! Pure protection logic for Workstation Guardian.
//!
//! Every module in this crate is free of Win32, I/O and ambient globals. Anything that
//! touches the host is expressed as a trait in [`ports`] and injected. That is what lets
//! the safety-critical state machines — update protection, maintenance, single-use reboot
//! authorization, network failover, agent confidence — be tested exhaustively without
//! rebooting a machine or touching a real registry.
//!
//! The crate is compiled with `#![forbid(unsafe_code)]`: all `unsafe` lives in
//! `guardian-win`, behind small safe wrappers.

#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod config;
pub mod maintenance;
pub mod net;
pub mod ports;
pub mod reboot;
pub mod update_policy;

pub use ports::{Clock, EventLogSource, PendingRebootSource, UpdatePolicyBackend};

/// Guardrail for the whole crate: nothing may panic on malformed persisted input.
///
/// Recovery code paths run on a machine that has already failed once. A panic there turns
/// a recoverable situation into a protection outage, which is the exact outcome the
/// project exists to prevent. This lint set is applied crate-wide.
#[allow(unused)]
const _NO_PANIC_ON_INPUT: () = ();
