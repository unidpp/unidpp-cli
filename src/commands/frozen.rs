//! `unidpp frozen <path>` — the air-gapped foreign-verifier path
//! (SI-1): read one frozen view, verify it under the verifier's OWN
//! anchors, re-execute the lens over the committed inputs, and
//! compare with the issuer-side render — byte for byte, offline.

use unidpp_signatif::frozen::{example::battery_lens, FrozenView};

use crate::commands::dossier::verifier_graph;
use crate::commands::CommandError;
use crate::exit;

/// Run the air-gapped frozen-view verification (exit PASS when
/// re-execution matches).
pub fn run(rest: &[String]) -> Result<u8, CommandError> {
    let Some(path) = rest.first() else {
        return Err(CommandError::Usage(
            "usage: unidpp frozen <path>".to_string(),
        ));
    };
    let json = std::fs::read_to_string(path)
        .map_err(|e| CommandError::Failure(format!("read {path}: {e}")))?;
    let view: FrozenView = serde_json::from_str(&json)
        .map_err(|e| CommandError::Failure(format!("frozen view parse: {e}")))?;

    // The verifier's own anchors — never anything from the view.
    let graph = verifier_graph();
    let check = view
        .verify(&graph)
        .map_err(|e| CommandError::Failure(format!("frozen view verification: {e}")))?;

    // Re-execution: the lens over the committed inputs must
    // reproduce the issuer's payload byte for byte.
    let re_executed = view.re_executes(battery_lens);

    println!(
        "offline frozen view — subject {} (descriptor {})",
        view.subject,
        view.descriptor.token()
    );
    println!(
        "  bundle: policies {} · proofs {} · attestations {} · journal decisions {}",
        check.policies_ok,
        check.proofs_ok,
        check.attestations_ok,
        check.journal_decisions.len()
    );
    println!("  inputs spine-proved: {}", view.inputs.len());
    println!(
        "  re-execution {} the issuer-side render",
        if re_executed { "MATCHES" } else { "FAILS" }
    );
    println!("  reader instructions:");
    for (i, step) in view.instructions.iter().enumerate() {
        println!("    {}. {step}", i + 1);
    }
    if re_executed {
        Ok(exit::PASS)
    } else {
        Ok(exit::FAIL)
    }
}
