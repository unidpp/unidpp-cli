//! Subcommand dispatch and shared argument plumbing.
//!
//! Argument parsing is hand-rolled (a flag/value cursor per command) to
//! keep the CLI's dependency surface at `serde_json`; the grammar is
//! strict — unknown flags and missing values are usage errors (exit 3).

pub mod create;
pub mod demo;
pub mod dossier;
pub mod event;
pub mod frozen;
pub mod grid;

/// `unidpp grid` — the G-GRID demo: one subject, two sovereignty
/// segments (one sealed), the spine — assurance without access.
pub const GRID_USAGE: &str = "unidpp grid [--dossier <path>] — the grid demo";
/// Usage line for `unidpp dossier`.
pub const DOSSIER_USAGE: &str = "unidpp dossier <path> — verify a dossier offline (XB-5)";
/// Usage line for `unidpp frozen`.
pub const FROZEN_USAGE: &str = "unidpp frozen <path> — verify a frozen view air-gapped (SI-1)";
pub mod pack;
pub mod resolve;
pub mod verify;

use crate::exit;

/// The top-level usage text (`unidpp help`).
pub const USAGE: &str = "\
unidpp - the UniDPP command-line verifier (what an officer's terminal runs)

USAGE:
    unidpp <COMMAND> [OPTIONS]

COMMANDS:
    create    mint a passport document (core skeleton + empty log) as JSON
    event     append a typed event to a passport's log (optionally Ed25519-signed)
    pack      mint the Tier-A offline pack from a passport (optionally signed)
    verify    unpack a pack, check it, and print the graded verdict
    resolve   normalize a scanned carrier (GS1 DL / GB/T 33993 / EAN-13 / URN)
    demo      run a narrated demonstration scenario
    help      print this help

EXIT CODES:
    0  verdict Pass
    1  verdict Degraded (reason always printed)
    2  verdict Fail (or an operational failure of a non-verify command)
    3  usage error

SEE:
    unidpp help <command> for per-command options and payload examples";

/// Per-command usage texts (`unidpp help <command>`).
pub fn command_usage(command: &str) -> Option<&'static str> {
    Some(match command {
        "create" => create::USAGE,
        "event" => event::USAGE,
        "pack" => pack::USAGE,
        "verify" => verify::USAGE,
        "resolve" => resolve::USAGE,
        "demo" => demo::USAGE,
        "grid" => GRID_USAGE,
        "dossier" => DOSSIER_USAGE,
        "frozen" => FROZEN_USAGE,
        _ => return None,
    })
}

/// A command-level failure: usage errors exit 3; operational failures
/// of non-verify commands exit 2 (the Fail code — verdict codes belong
/// to `verify`, operational failure reuses it and says so in stderr).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandError {
    /// Bad invocation or unreadable input (exit 3).
    Usage(String),
    /// The command could not complete (exit 2).
    Failure(String),
}

impl CommandError {
    /// The exit code this error maps to.
    pub fn exit_code(&self) -> u8 {
        match self {
            CommandError::Usage(_) => exit::USAGE,
            CommandError::Failure(_) => exit::FAIL,
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommandError::Usage(m) => write!(f, "usage error: {m}"),
            CommandError::Failure(m) => write!(f, "failure: {m}"),
        }
    }
}

impl std::error::Error for CommandError {}

/// Dispatch `argv[1..]` to a command; `Ok(code)` is the process exit
/// code.
pub fn dispatch(args: &[String]) -> Result<u8, CommandError> {
    let Some(first) = args.first() else {
        return Err(CommandError::Usage("missing command".to_string()));
    };
    let rest = &args[1..];
    match first.as_str() {
        "create" => create::run(rest),
        "event" => event::run(rest),
        "pack" => pack::run(rest),
        "verify" => verify::run(rest),
        "resolve" => resolve::run(rest),
        "demo" => demo::run(rest),
        "grid" => grid::run(rest),
        "dossier" => dossier::run(rest),
        "frozen" => frozen::run(rest),
        "help" | "--help" | "-h" => {
            if let Some(sub) = rest.first() {
                let usage = command_usage(sub).ok_or_else(|| {
                    CommandError::Usage(format!("no help for `{sub}` (not a command)"))
                })?;
                println!("{usage}");
            } else {
                println!("{USAGE}");
            }
            Ok(exit::PASS)
        }
        "--version" | "-V" => {
            println!("unidpp {}", env!("CARGO_PKG_VERSION"));
            Ok(exit::PASS)
        }
        other => Err(CommandError::Usage(format!(
            "unknown command `{other}` (see `unidpp help`)"
        ))),
    }
}

/// Consume the value following the flag at position `i` (which the
/// caller advances past first).
pub(crate) fn take_value(
    args: &[String],
    i: &mut usize,
    flag: &str,
) -> Result<String, CommandError> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| CommandError::Usage(format!("`{flag}` requires a value")))
}

/// Parse an ISO 8601 / RFC 3339 timestamp option value.
pub(crate) fn parse_timestamp(
    value: &str,
    flag: &str,
) -> Result<unidpp_model::Timestamp, CommandError> {
    unidpp_model::Timestamp::parse(value).map_err(|e| CommandError::Usage(format!("`{flag}`: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn dispatch_routes_and_rejects() {
        assert_eq!(dispatch(&args(&["--version"])).unwrap(), 0);
        assert!(matches!(dispatch(&args(&["help", "verify"])), Ok(0)));
        assert!(matches!(dispatch(&args(&[])), Err(CommandError::Usage(_))));
        assert!(matches!(
            dispatch(&args(&["nope"])),
            Err(CommandError::Usage(m)) if m.contains("unknown command")
        ));
        assert!(matches!(
            dispatch(&args(&["help", "nope"])),
            Err(CommandError::Usage(_))
        ));
    }

    #[test]
    fn every_command_has_help() {
        for command in [
            "create", "event", "pack", "verify", "resolve", "demo", "grid", "dossier", "frozen",
        ] {
            assert!(
                command_usage(command).is_some(),
                "missing usage text for {command}"
            );
        }
    }

    #[test]
    fn error_codes() {
        assert_eq!(CommandError::Usage("x".into()).exit_code(), 3);
        assert_eq!(CommandError::Failure("x".into()).exit_code(), 2);
    }
}
