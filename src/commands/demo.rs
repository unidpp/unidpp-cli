//! `unidpp demo`: delegate to the narrated demonstration scenarios of
//! `unidpp-demo` (battery-loop / car / laptop).

use std::io::Write;

use crate::commands::{take_value, CommandError};
use crate::exit;

/// The `demo` usage text.
pub const USAGE: &str = "\
unidpp demo - run a narrated demonstration scenario

USAGE:
    unidpp demo [<SCENARIO>] [--seed <HEX>] [--list]

SCENARIOS:
    battery-loop  cells -> pack (combine) -> split harvest -> blind install
                  -> theft taint -> end-of-waste -> Tier A -> graded verdicts
    car           parent car + battery child passports, blind install edge,
                  predicate-based recall, as-of verification readings
    laptop        one neutral core, EU + JP profiles, custody, firmware
                  update, part replace, per-lens coverage verdicts

OPTIONS:
    --seed <HEX>  64-bit hex seed driving deterministic salts
                  (default 0x756e69647070)
    --list        list scenarios and exit

Output is deterministic for a given seed.";

/// The default demo seed (same as `unidpp-demo`'s).
const DEFAULT_SEED: u64 = 0x756e_6964_7070;

fn parse_seed(s: &str) -> Result<u64, CommandError> {
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(body, 16)
        .map_err(|_| CommandError::Usage(format!("--seed: `{s}` is not a hexadecimal u64")))
}

/// Run the command.
pub fn run(args: &[String]) -> Result<u8, CommandError> {
    let mut scenario: Option<String> = None;
    let mut seed = DEFAULT_SEED;
    let mut list = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => seed = parse_seed(&take_value(args, &mut i, "--seed")?)?,
            "--list" => list = true,
            other if other.starts_with("--") => {
                return Err(CommandError::Usage(format!(
                    "demo: unknown option `{other}` (see `unidpp help demo`)"
                )))
            }
            positional => {
                if scenario.is_some() {
                    return Err(CommandError::Usage(format!(
                        "demo: unexpected second argument `{positional}`"
                    )));
                }
                scenario = Some(positional.to_string());
            }
        }
        i += 1;
    }

    if list {
        for (name, blurb) in unidpp_demo::SCENARIO_BLURBS {
            println!("{name:<14} {blurb}");
        }
        return Ok(exit::PASS);
    }
    let scenario = scenario.unwrap_or_else(|| "battery-loop".to_string());
    if !unidpp_demo::SCENARIOS.contains(&scenario.as_str()) {
        return Err(CommandError::Usage(format!(
            "unknown scenario `{scenario}` (available: {})",
            unidpp_demo::SCENARIOS.join(", ")
        )));
    }

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    match unidpp_demo::run(&scenario, &mut out, seed) {
        Ok(()) => {}
        // A consumer that closed the pipe (`... | head`) is not a failure.
        Err(e) if e.is_broken_pipe() => return Ok(exit::PASS),
        Err(e) => return Err(CommandError::Failure(e.to_string())),
    }
    out.flush()
        .map_err(|e| CommandError::Failure(e.to_string()))
        .map(|()| exit::PASS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn list_exits_zero() {
        assert_eq!(run(&args(&["--list"])).unwrap(), 0);
    }

    #[test]
    fn unknown_scenario_is_usage() {
        assert!(matches!(
            run(&args(&["nope"])),
            Err(CommandError::Usage(m)) if m.contains("unknown scenario")
        ));
    }

    #[test]
    fn seeds_parse() {
        assert_eq!(parse_seed("0x1").unwrap(), 1);
        assert_eq!(parse_seed("ff").unwrap(), 255);
        assert!(parse_seed("zz").is_err());
    }

    #[test]
    fn every_scenario_runs() {
        for name in unidpp_demo::SCENARIOS {
            let mut buffer: Vec<u8> = Vec::new();
            unidpp_demo::run(name, &mut buffer, DEFAULT_SEED)
                .unwrap_or_else(|e| panic!("scenario {name} failed: {e}"));
            assert!(!buffer.is_empty());
        }
    }
}
