//! `unidpp grid` — the grid demo (G-GRID): Phase 1's beat.
//!
//! One subject, two sovereignty segments (one open, one sealed), the
//! spine over both — and a verifier who proves the sealed segment's
//! EXISTENCE and CURRENCY from the spine alone, verifies the open
//! segment under its policy, and watches tamper and stale cases fail
//! loudly. The sealed plaintext is never printed (the demo asserts
//! it): sovereignty means assurance without access.

use std::collections::BTreeMap;

use unidpp_grid::{PolicyObject, PolicyRef, RevealClass, Segment, Spine};
use unidpp_signatif::graph::{DelegationNode, NodeId, NodeKind, RegisteredKey, TrustGraph};
use unidpp_signatif::grid::{SignedPolicy, SignedSpine};
use unidpp_signatif::keyring::{KeyId, KeyPair};
use unidpp_signatif::sign::Suite;

use crate::commands::CommandError;
use crate::exit;

/// The sealed segment's plaintext (NEVER printed — the point).
const SEALED_STATE: &[u8] = b"cycle_count=412,voltage=3.71,temp=28.4";

/// Run the grid demo (G-GRID): the whole Phase-1 pipeline, verdicts
/// printed; exit PASS only when every check holds.
pub fn run() -> Result<u8, CommandError> {
    let mut ok = 0usize;
    let mut total = 0usize;
    let mut check = |label: &str, passed: bool, detail: &str| {
        total += 1;
        if passed {
            ok += 1;
            println!("  [ok]   {label} — {detail}");
        } else {
            println!("  [FAIL] {label} — {detail}");
        }
    };

    println!("G-GRID — one subject, two sovereignty segments, one spine");
    println!();

    // -- The cast: the CN regulator (segment authority) and the pack
    //    maker (the spine custodian), keys registered on the graph.
    let samr_key = KeyPair::seeded(Suite::Ed25519, b"ggrid/cn-samr").map_err(fail)?;
    let custodian_key = KeyPair::seeded(Suite::Ed25519, b"ggrid/weilian").map_err(fail)?;
    let mut graph = TrustGraph::new();
    for (id, key) in [("cn-samr", &samr_key), ("weilian-shenzhen", &custodian_key)] {
        let mut node = DelegationNode::new(NodeId::new(id).map_err(fail)?, NodeKind::Delegated);
        node.register(RegisteredKey {
            key_id: KeyId::of(key.public()),
            public: *key.public(),
        });
        graph.add_node(node);
    }
    check(
        "authorities registered",
        graph.node(&NodeId::new("cn-samr").unwrap()).is_some(),
        "cn-samr (segment authority), weilian-shenzhen (custodian)",
    );

    // -- The policies: the constitution of each segment, signed by
    //    the authority. One open (EU static data), one sealed.
    let open_policy = SignedPolicy::issue(
        PolicyObject {
            policy_id: "eu-static-open".into(),
            version: 1,
            authority: "cn-samr".into(),
            readers: vec!["any-verifier".into()],
            verifiers: vec!["any-verifier".into()],
            writers: vec!["weilian-shenzhen".into()],
            reveal: RevealClass::Open,
            suites: vec!["ecdsa-p256".into()],
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_to: None,
            superseded_by: None,
        },
        &samr_key,
    )
    .map_err(fail)?;
    let sealed_policy = SignedPolicy::issue(
        PolicyObject {
            policy_id: "cn-dynamic-bms".into(),
            version: 1,
            authority: "cn-samr".into(),
            readers: vec!["cn-customs".into()],
            verifiers: vec!["cn-customs".into()],
            writers: vec!["weilian-shenzhen".into()],
            reveal: RevealClass::OriginSealed,
            suites: vec!["sm2".into()],
            valid_from: "2027-01-01T00:00:00Z".into(),
            valid_to: None,
            superseded_by: None,
        },
        &samr_key,
    )
    .map_err(fail)?;
    check(
        "policies signed by the authority",
        open_policy.verify(&graph).is_ok() && sealed_policy.verify(&graph).is_ok(),
        "eu-static-open (reveal: open) · cn-dynamic-bms (reveal: origin-sealed)",
    );

    // -- The segments: commitments only. The open segment's state is
    //    printable; the sealed one's never leaves this process.
    let open_state = b"cell_model=H-2231,capacity_Ah=52,chemistry=LFP";
    let eu_segment = Segment {
        segment_id: "eu-static".into(),
        subject: "urn:unidpp:passport:pack-0001".into(),
        policy: PolicyRef {
            policy_id: "eu-static-open".into(),
            version: 1,
        },
        state_commitment: Segment::commit_state(open_state),
        sequence: 3,
    };
    let cn_segment = Segment {
        segment_id: "cn-dynamic".into(),
        subject: "urn:unidpp:passport:pack-0001".into(),
        policy: PolicyRef {
            policy_id: "cn-dynamic-bms".into(),
            version: 1,
        },
        state_commitment: Segment::commit_state(SEALED_STATE),
        sequence: 118,
    };
    println!(
        "  segment eu-static:  open      commit {}…",
        hex_prefix(&eu_segment.state_commitment)
    );
    println!(
        "  segment cn-dynamic: sealed    commit {}… (contents never leave the custodian)",
        hex_prefix(&cn_segment.state_commitment)
    );

    // -- The spine over both; the custodian signs it.
    let mut commitments = BTreeMap::new();
    commitments.insert(eu_segment.segment_id.clone(), eu_segment.state_commitment);
    commitments.insert(cn_segment.segment_id.clone(), cn_segment.state_commitment);
    let spine = Spine::over(1, commitments);
    let signed_spine =
        SignedSpine::issue(spine, "weilian-shenzhen", &custodian_key).map_err(fail)?;
    check(
        "spine signed by the custodian",
        signed_spine.verify(&graph).is_ok(),
        &format!(
            "root {}… over 2 segments",
            hex_prefix(&signed_spine.spine.root)
        ),
    );

    // -- The verifier's view: the sealed segment from the SPINE alone.
    let proof = signed_spine
        .spine
        .proof("cn-dynamic")
        .ok_or_else(|| CommandError::Failure("no spine proof".into()))?;
    check(
        "sealed segment: existence + currency from the spine alone",
        proof.verifies_against(&signed_spine.spine.root),
        "the proof carries hashes only — no other segment opened",
    );
    // SG-1: the proof contains nothing about the EU segment.
    let proof_json = serde_json::to_string(&proof)
        .map_err(|e| CommandError::Failure(format!("proof serialization: {e}")))?;
    check(
        "the proof opens no other segment",
        !proof_json.contains("eu-static") && !proof_json.contains("cycle_count"),
        "sibling hashes only, no names, no facts",
    );

    // -- The open segment verifies under its policy (class grades it).
    let open_check = open_policy.verify(&graph).map_err(fail)?;
    check(
        "open segment: policy current and graded",
        open_check.fresh.is_current()
            && open_policy.policy.reveal == RevealClass::Open
            && open_policy
                .policy
                .status_for(&eu_segment.policy)
                .is_current(),
        &format!(
            "policy {} v{}, ceiling {}",
            open_policy.policy.policy_id,
            open_policy.policy.version,
            open_policy
                .policy
                .suites
                .first()
                .map(|s| s.as_str())
                .unwrap_or("?")
        ),
    );

    // -- Growth: the spine gains the owner's private segment; the
    //    prior spine is a provable prefix (segments never rewind).
    let mut grown = signed_spine.spine.commitments.clone();
    grown.insert(
        "owner-private".to_string(),
        Segment::commit_state(b"owner_notes"),
    );
    let spine_v2 = Spine::over(2, grown);
    check(
        "append-only growth provable",
        spine_v2.proves_prefix(&signed_spine.spine),
        "spine v2 proves v1 — segments never rewind",
    );

    // -- The loud failures.
    let mut forged = proof.clone();
    forged.commitment = [9u8; 32];
    check(
        "forged segment state fails the spine",
        !forged.verifies_against(&signed_spine.spine.root),
        "a fabricated commitment cannot splice in",
    );
    let mut superseded_sealed = sealed_policy.policy.clone();
    superseded_sealed.superseded_by = Some(2);
    let superseded = SignedPolicy::issue(superseded_sealed, &samr_key).map_err(fail)?;
    let stale = superseded.verify_with_freshness(&graph).map_err(fail)?;
    check(
        "stale policy detected at verification",
        !stale.fresh.is_current(),
        &format!("graded {} (v1 superseded by v2)", stale.fresh.label()),
    );

    println!();
    println!(
        "grid verdict: {}/{} — the sealed segment is PROVEN without being SEEN",
        ok, total
    );
    if ok == total {
        Ok(exit::PASS)
    } else {
        Ok(exit::FAIL)
    }
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn fail(e: unidpp_signatif::SignatifError) -> CommandError {
    CommandError::Failure(format!("grid demo: {e}"))
}
