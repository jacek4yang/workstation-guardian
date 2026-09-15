//! The Workstation Guardian Windows service.
//!
//! This is the core authority. It runs as `LocalSystem`, owns update protection, and must
//! remain fully functional when the UI is closed, the UI has crashed, WebView2 has crashed,
//! Explorer has restarted, or no user is logged in at all.
//!
//! # Structure
//!
//! * [`supervisor`] runs each subsystem as an isolated task with bounded-backoff restarts, so
//!   a panic in the network worker cannot take update protection down with it.
//! * [`state`] holds the shared protection state and the logic that combines subsystem
//!   observations into a single honest verdict.
//! * [`ipc`] serves the named pipe, authorizing every request against the caller's token.
//! * [`journal`] persists recovery metadata and classifies an unclean previous session.
//!
//! # Fail-closed
//!
//! Every uncertain path resolves toward protection. If a subsystem is unavailable, its
//! contribution to the verdict is "unknown", and an unknown update-protection subsystem is
//! never reported as `Protected`.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod ipc;
pub mod journal;
pub mod logging;
pub mod state;
pub mod supervisor;

pub use state::{ProtectionCoordinator, SharedState};
pub use supervisor::{Supervisor, WorkerHealth};
