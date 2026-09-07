//! `unidpp-cli`: the UniDPP command-line verifier — what a customs
//! officer's terminal runs offline.
//!
//! The library backs the `unidpp` binary (see `src/main.rs`). It wires
//! the real crates together into passport lifecycle operations:
//!
//! - [`passport`]: the on-disk passport document (core skeleton + event
//!   log + event signatures) that `create`/`event`/`pack` share;
//! - [`packfile`]: Tier-A pack minting concerns — the carrier budget
//!   grammar and the canonical *signing body* a pack signature covers;
//! - [`carrier`]: the carrier adapter translating scanned GS1 Digital
//!   Link / GB/T 33993 / EAN-13 / URN forms into the core's
//!   [`unidpp_model::ProductIdentifier`];
//! - [`commands`]: one module per subcommand, each returning the
//!   process exit code (see [`exit`]);
//! - [`report`]: the findings/readings tables the verifier prints.
//!
//! Exit-code contract (scripts and customs terminals depend on it):
//! [`exit::PASS`] 0, [`exit::DEGRADED`] 1, [`exit::FAIL`] 2,
//! [`exit::USAGE`] 3.

#![warn(missing_docs)]

pub mod carrier;
pub mod commands;
pub mod encoding;
pub mod packfile;
pub mod passport;
pub mod report;

/// Process exit codes: the contract with calling scripts and officer
/// terminals. The three verdict codes mirror the core's degradation
/// ladder (I9/I13: pass / degraded-with-reason / fail — never a bare
/// boolean).
pub mod exit {
    /// Verdict Pass.
    pub const PASS: u8 = 0;
    /// Verdict Degraded (explicit reason always printed).
    pub const DEGRADED: u8 = 1;
    /// Verdict Fail, or an operational failure of a non-verify command.
    pub const FAIL: u8 = 2;
    /// Usage error: bad invocation or unreadable input.
    pub const USAGE: u8 = 3;
}
