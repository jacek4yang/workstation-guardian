//! Connectivity probes and RAS/Wi-Fi orchestration for Workstation Guardian.
//!
//! The *decisions* live in `guardian-core::net`, which is pure and exhaustively tested. This
//! crate supplies the observations and performs the actions:
//!
//! * [`probes`] measures connectivity with a quorum of independent checks.
//! * [`backend`] talks to RAS and the Native Wi-Fi API.
//! * [`worker`] runs the loop that ties observation, decision and action together.
//!
//! # The policy this implements
//!
//! Broadband is always the preferred uplink. Wi-Fi exists only to preserve connectivity
//! while broadband is unavailable, and broadband is restored as preferred only after it has
//! proven stable. Broadband repair happens *in parallel* with Wi-Fi continuity, never by
//! tearing down the only working path.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod backend;
pub mod probes;
pub mod worker;

pub use backend::{NetworkBackend, RasBackend};
pub use probes::ProbeRunner;
