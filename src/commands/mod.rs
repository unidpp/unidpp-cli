//! Subcommand dispatch and shared argument plumbing.
//!
//! Argument parsing is hand-rolled (a flag/value cursor per command) to
//! keep the CLI's dependency surface at `serde_json`; the grammar is
//! strict — unknown flags and missing values are usage errors (exit 3).

pub mod conform;
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
/// Usage line for `unidpp conform`.
pub const CONFORM_USAGE: &str =
    "unidpp conform <class> <material> — run a federation class claim test (FW-3)

CLASSES (Clause 11; every class's material is public):
  f1 <frozen-view.json> [anchors.json]   publishes verifiable frozen views
  f2 <signed-exchange.json>              S13 protocol participant
  f3 <mapping-chain.json>                mapping-capable
  f4 <view-a.json> <view-b.json> [anchors.json]  shared-profile adopter
  f5 [family-dir]                        full core (the golden-vector sweep)";
pub mod pack;
pub mod resolve;
pub mod verify;

use crate::exit;

/// The top-level usage text (`unidpp help`).
/// One command: its name, its one-line help and its run function —
/// the single table the dispatcher, the help text and the exported
/// contract (`commands.json`) all read from. Adding a command is
/// adding one row.
pub struct CommandSpec {
    /// The command name (`unidpp <name>`).
    pub name: &'static str,
    /// The one-line help, rendered in the top-level usage.
    pub summary: &'static str,
    /// The command's entry point.
    pub run: fn(&[String]) -> Result<u8, CommandError>,
}

/// The command table: one row per command. The dispatcher, the
/// top-level help and the exported contract () all
/// read from this table; adding a command is adding one row.
pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "create",
        summary: "mint a passport document (core skeleton + empty log) as JSON",
        run: create::run,
    },
    CommandSpec {
        name: "event",
        summary: "append a typed event to a passport's log (optionally Ed25519-signed)",
        run: event::run,
    },
    CommandSpec {
        name: "pack",
        summary: "mint the Tier-A offline pack from a passport (optionally signed)",
        run: pack::run,
    },
    CommandSpec {
        name: "verify",
        summary: "unpack a pack, check it, and print the graded verdict",
        run: verify::run,
    },
    CommandSpec {
        name: "resolve",
        summary: "normalize a scanned carrier (GS1 DL / GB/T 33993 / EAN-13 / URN)",
        run: resolve::run,
    },
    CommandSpec {
        name: "grid",
        summary: "run the two-segment grid demonstration (spine, route, coverage)",
        run: grid::run,
    },
    CommandSpec {
        name: "dossier",
        summary: "verify a dossier offline, with zero calls to foreign systems",
        run: dossier::run,
    },
    CommandSpec {
        name: "frozen",
        summary: "verify a frozen view air-gapped (SI-1)",
        run: frozen::run,
    },
    CommandSpec {
        name: "conform",
        summary: "run a conformance-class claim test on public material",
        run: conform::run,
    },
    CommandSpec {
        name: "demo",
        summary: "run a narrated demonstration scenario",
        run: demo::run,
    },
];

/// Look a command up in the table.
pub fn command(name: &str) -> Option<&'static CommandSpec> {
    COMMANDS.iter().find(|c| c.name == name)
}

/// The top-level help, rendered from the command table.
pub fn usage_text() -> String {
    use std::fmt::Write as _;
    let mut out = String::from(
        "unidpp - the UniDPP command-line verifier (what an officer's terminal runs)\n\nUSAGE:\n    unidpp <COMMAND> [OPTIONS]\n\nCOMMANDS:\n",
    );
    for spec in COMMANDS {
        let _ = writeln!(out, "    {:<9} {}", spec.name, spec.summary);
    }
    let _ = write!(out, "    help      print this help\n\nEXIT CODES:\n    0  verdict Pass\n    1  verdict Degraded (reason always printed)\n    2  verdict Fail (or an operational failure of a non-verify command)\n    3  usage error\n\nSEE:\n    unidpp help <command> for per-command options and payload examples");
    out
}

/// The exported command table (`commands.json`): the machine-readable
/// form of the same single source, locked to it by a golden test.
pub fn commands_json() -> String {
    let commands: Vec<serde_json::Value> = COMMANDS
        .iter()
        .map(|spec| serde_json::json!({"name": spec.name, "summary": spec.summary}))
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "commands": commands,
    }))
    .expect("command table serializes")
}

#[cfg(test)]
mod command_table_tests {
    use super::*;

    #[test]
    fn the_golden_matches_the_committed_command_table() {
        assert_eq!(commands_json(), include_str!("../../commands.json"));
    }

    #[test]
    #[ignore = "regenerates commands.json after a table change: cargo test -- --ignored export"]
    fn export_golden() {
        std::fs::write(
            concat!(env!("CARGO_MANIFEST_DIR"), "/commands.json"),
            commands_json(),
        )
        .expect("golden written");
    }

    #[test]
    fn the_help_lists_every_command() {
        let help = usage_text();
        for spec in COMMANDS {
            assert!(help.contains(spec.name), "help omits {}", spec.name);
        }
    }

    #[test]
    fn every_command_has_a_per_command_usage() {
        for spec in COMMANDS {
            assert!(
                command_usage(spec.name).is_some(),
                "no `unidpp help {}` text",
                spec.name
            );
        }
    }
}


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
        "conform" => CONFORM_USAGE,
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
    if let Some(spec) = command(first) {
        return (spec.run)(rest);
    }
    match first.as_str() {
        "help" | "--help" | "-h" => {
            if let Some(sub) = rest.first() {
                let usage = command_usage(sub).ok_or_else(|| {
                    CommandError::Usage(format!("no help for `{sub}` (not a command)"))
                })?;
                println!("{usage}");
            } else {
                println!("{}", usage_text());
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
            "conform",
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
