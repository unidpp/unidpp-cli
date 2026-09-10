//! `unidpp conform <class> <path>` — the federation class claim
//! tests (FW-3): machine-checkable, third-party runnable against
//! any deployment's exported artifacts.
//!
//! F1 is the minimal adopter's claim — publishes verifiable frozen
//! views — and its test is the air-gapped verification of a
//! published frozen view under the runner's OWN anchors: bundle
//! verifies, inputs spine-proved, lens re-execution byte-identical.
//! The higher classes' test material lands with the implementation
//! phases that carry them (F2 with the S13 harness, F3 with the
//! mapping registry); the classes and claims are stated in
//! Clause 11.

use unidpp_signatif::frozen::{example::battery_lens, FrozenView};

use crate::commands::dossier::verifier_graph;
use crate::commands::CommandError;
use crate::exit;

/// Run a federation class claim test (exit PASS when the claim holds).
pub fn run(rest: &[String]) -> Result<u8, CommandError> {
    let (Some(class), Some(path)) = (rest.first(), rest.get(1)) else {
        return Err(CommandError::Usage(
            "usage: unidpp conform <f1> <frozen-view.json>".to_string(),
        ));
    };
    match class.as_str() {
        "f1" => run_f1(path),
        other => Err(CommandError::Usage(format!(
            "class `{other}` is defined in Clause 11; its test material lands with the \
             implementation phase that carries it (F2 with the S13 harness, F3 with the \
             mapping registry, F4 with shared profiles, F5 with the core suite)"
        ))),
    }
}

/// The F1 claim test: a published frozen view verifies under the
/// runner's own anchors, air-gapped.
fn run_f1(path: &str) -> Result<u8, CommandError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| CommandError::Failure(format!("read {path}: {e}")))?;
    let view: FrozenView = serde_json::from_str(&json)
        .map_err(|e| CommandError::Failure(format!("frozen view parse: {e}")))?;
    let anchors = verifier_graph();
    let check = view
        .verify(&anchors)
        .map_err(|e| CommandError::Failure(format!("bundle: {e}")))?;
    let re_executed = view.re_executes(battery_lens);
    println!("F1 claim test — frozen view {}", short(&view.subject));
    println!(
        "  bundle verified: policies {}, proofs {}, attestations {}",
        check.policies_ok, check.proofs_ok, check.attestations_ok
    );
    println!("  inputs spine-proved: {}", view.inputs.len());
    println!(
        "  lens re-execution: {}",
        if re_executed {
            "byte-identical"
        } else {
            "MISMATCH"
        }
    );
    if re_executed {
        println!("F1: PASS — the view is verifiable by a third party with its own anchors");
        Ok(exit::PASS)
    } else {
        println!("F1: FAIL");
        Ok(exit::FAIL)
    }
}

fn short(id: &str) -> String {
    id.rsplit('/').next().unwrap_or(id).to_string()
}
