//! `unidpp`: the UniDPP command-line verifier — what a customs
//! officer's terminal runs offline.
//!
//! Exit codes: 0 Pass, 1 Degraded, 2 Fail, 3 usage error. See
//! `unidpp help` for the full grammar.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match unidpp_cli::commands::dispatch(&args) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            let code = err.exit_code();
            eprintln!("unidpp: {err}");
            if code == unidpp_cli::exit::USAGE {
                eprintln!("try `unidpp help`");
            }
            ExitCode::from(code)
        }
    }
}
