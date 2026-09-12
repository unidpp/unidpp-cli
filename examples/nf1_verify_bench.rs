//! NF-1's first number: Tier-A offline verification latency.
//!
//! The requirement: verification of a Tier-A carrier shall complete
//! in the order of milliseconds. This bench mints a population of
//! signed packs deterministically (same seeds, same bytes every
//! run), then times the officer's terminal's own verify pipeline
//! over them — decode, schema, signature, freshness — in process,
//! excluding process startup and file I/O, which are not the
//! verifier's work.
//!
//! Run: cargo run --release --example nf1_verify_bench [-- <packs> <rounds>]
//! Prints per-verification p50/p95/max; the structural check (every
//! verdict passes) and the stated bar (p95 under 50 ms — two orders
//! of headroom over "the order of milliseconds") gate the exit code.

use std::time::Instant;

use unidpp_cli::commands::verify::verify_pack;
use unidpp_cli::packfile::{sign_pack, DEFAULT_BUDGET};
use unidpp_cli::passport::{MintOptions, Passport};
use unidpp_cli::report::Grade;
use unidpp_model::time::Timestamp;
use unidpp_tier_a::{TierAPacker, TierAPayload};

/// The bar: p95 under 50 ms per verification (the requirement says
/// "the order of milliseconds"; two orders of headroom keeps the
/// gate meaningful on slow machines without ever hiding a
/// millisecond-order regression into seconds).
const P95_BAR_MS: u128 = 50;

fn mint_pack(index: usize) -> (Vec<u8>, unidpp_signatif::keyring::PublicKey) {
    let mut passport = Passport::mint(MintOptions {
        id: format!("sgtin:4006381333931+21+NF1{index:06}"),
        granularity: None,
        type_ref: Some("https://example.org/types/battery-pack".into()),
        capability: "S1".into(),
        eo_id: Some(format!("eo-nf1-{index:04}")),
        resolver_uri: None,
        passport_id: None,
        valid_from: None,
        valid_to: None,
    })
    .expect("mint");
    // One issuance event, so the pack carries a log-head commitment
    // (an empty log degrades the log-head finding — the bench must
    // measure the passing pipeline).
    let event = unidpp_event::TypedEvent::new(
        0,
        Timestamp::now(),
        "issuing authority",
        &passport.eo_id,
        unidpp_event::EventType::Issuance,
        unidpp_event::EventPayload::Issuance {
            derived: false,
            inputs: vec![],
        },
        unidpp_model::TrustMarker::Unsigned,
    )
    .expect("event");
    passport.log.append(event, None, None).expect("append");
    let payload = TierAPayload::from_log(
        &passport.log,
        passport.product_id.clone(),
        &passport.resolver_uri,
        &passport.eo_id,
        passport.validity,
        Vec::new(),
    );
    let (payload, anchor, _key_id) = sign_pack(&payload, b"nf1-verify-bench-seed").expect("sign");
    let packed = TierAPacker::new(DEFAULT_BUDGET.0, DEFAULT_BUDGET.1)
        .pack(&payload)
        .expect("pack");
    (packed.as_slice().to_vec(), anchor)
}

fn main() {
    let packs: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(64);
    let rounds: usize = std::env::args()
        .nth(2)
        .and_then(|a| a.parse().ok())
        .unwrap_or(20);

    let mut population = Vec::with_capacity(packs);
    for index in 0..packs {
        population.push(mint_pack(index));
    }

    // Warm the pipeline (first ECDSA verification initializes
    // lazily-built tables on some platforms).
    for (bytes, anchor) in population.iter().take(4) {
        let outcome = verify_pack(bytes, Some(anchor), Timestamp::now(), 0);
        assert!(
            matches!(outcome.grade, Grade::Pass),
            "warm-up verdict: {:?} — findings: {:?}",
            outcome.grade,
            outcome.findings
        );
    }

    let mut samples: Vec<u128> = Vec::with_capacity(packs * rounds);
    let now = Timestamp::now();
    for _ in 0..rounds {
        for (bytes, anchor) in &population {
            let start = Instant::now();
            let outcome = verify_pack(bytes, Some(anchor), now, 0);
            let elapsed = start.elapsed().as_micros();
            assert!(
                matches!(outcome.grade, Grade::Pass),
                "verdict regressed to {:?}: a bench over failing verifications \
                 measures the failure path, not the requirement",
                outcome.grade
            );
            samples.push(elapsed);
        }
    }
    samples.sort_unstable();

    let at = |fraction: f64| samples[((samples.len() as f64 - 1.0) * fraction) as usize];
    let p50 = at(0.50);
    let p95 = at(0.95);
    let max = samples[samples.len() - 1];

    println!("NF-1 Tier-A offline verification (in-process, {packs} packs x {rounds} rounds)");
    println!("  p50  {p50:>6} µs");
    println!("  p95  {p95:>6} µs");
    println!("  max  {max:>6} µs");
    println!(
        "  bar  p95 < {P95_BAR_MS} ms — {}",
        if p95 < P95_BAR_MS * 1000 {
            "HOLDS"
        } else {
            "EXCEEDED"
        }
    );

    if p95 >= P95_BAR_MS * 1000 {
        eprintln!("nf1-verify-bench: p95 {p95} µs exceeds the {P95_BAR_MS} ms bar");
        std::process::exit(1);
    }
}
