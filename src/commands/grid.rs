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
pub fn run(rest: &[String]) -> Result<u8, CommandError> {
    let dossier_path = parse_value_flag(rest, "--dossier");
    let frozen_path = parse_value_flag(rest, "--frozen");
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

    // The verifier's own key (its S13 requests carry its signature).
    let de_zoll_key = KeyPair::seeded(Suite::Ed25519, b"ggrid/de-zoll").map_err(fail)?;
    {
        let mut node =
            DelegationNode::new(NodeId::new("de-zoll").map_err(fail)?, NodeKind::Delegated);
        node.register(RegisteredKey {
            key_id: KeyId::of(de_zoll_key.public()),
            public: *de_zoll_key.public(),
        });
        graph.add_node(node);
    }

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
            verifiers: vec!["cn-customs".into(), "de-zoll".into()],
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

    // -- The cross-border moment (Phase 2): the EU verifier asks;
    //    the policy offers substitution; the verdict is
    //    coverage-graded (XB-1..3).
    use unidpp_s13::{S13Outcome, S13Request, S13Response};
    let request = S13Request {
        verifier: "de-zoll".into(),
        subject: "urn:unidpp:passport:pack-0001".into(),
        profile: "urn:unidpp:profile:eu-battery".into(),
        segment: "cn-dynamic".into(),
        at: "2030-06-01T08:00:00Z".into(),
    };
    let response = S13Response::evaluate(&request, &sealed_policy.policy, "weilian-shenzhen");
    check(
        "S13: the sealed policy offers ATTESTATION, not data",
        matches!(response.outcome, S13Outcome::AttestationOffer { .. }),
        &format!(
            "governing policy {} v{} (outcome cited by name)",
            response.governing_policy, response.governing_policy_version
        ),
    );
    let unlisted = S13Request {
        verifier: "random-party".into(),
        ..request.clone()
    };
    let denied = S13Response::evaluate(&unlisted, &sealed_policy.policy, "weilian-shenzhen");
    check(
        "S13: an unlisted verifier is DENIED, stated",
        matches!(denied.outcome, S13Outcome::Deny { .. }),
        "never silent",
    );

    // The sovereign attestation substitutes (XB-2): the CN service
    // attests ABOUT the sealed commitment; the EU verifier accepts
    // under its own anchors.
    use unidpp_signatif::sovereign::{
        AttestationStatement, ClaimClass, CoverageGrade, SovereignAttestation,
    };
    let attestation_service = KeyPair::seeded(Suite::Ed25519, b"ggrid/cn-attest").map_err(fail)?;
    let quorum_a = KeyPair::seeded(Suite::Ed25519, b"ggrid/quorum-a").map_err(fail)?;
    let quorum_b = KeyPair::seeded(Suite::Ed25519, b"ggrid/quorum-b").map_err(fail)?;
    for (id, key) in [
        ("cn-attestation-service", &attestation_service),
        ("cn-quorum-a", &quorum_a),
        ("cn-quorum-b", &quorum_b),
    ] {
        let mut node = DelegationNode::new(NodeId::new(id).map_err(fail)?, NodeKind::Delegated);
        node.register(RegisteredKey {
            key_id: KeyId::of(key.public()),
            public: *key.public(),
        });
        graph.add_node(node);
    }
    let statement = AttestationStatement {
        segment: "cn-dynamic".into(),
        state_commitment: cn_segment.state_commitment,
        claim: ClaimClass::Conformity,
        value: "pass".into(),
        as_of: "2030-06-01T08:00:00Z".into(),
        governing_policy: sealed_policy.policy.policy_id.clone(),
        governing_policy_version: sealed_policy.policy.version,
        subject: "urn:unidpp:passport:pack-0001".into(),
    };
    let quorum_id = NodeId::new("cn-attestation-quorum").map_err(fail)?;
    let attestation = SovereignAttestation::issue(
        statement,
        "cn-attestation-service",
        &attestation_service,
        Some((&quorum_id, 2, &[&quorum_a, &quorum_b])),
    )
    .map_err(fail)?;
    let grade = attestation
        .verify(&graph)
        .map_err(|e| CommandError::Failure(format!("sovereign attestation verification: {e}")))?;
    check(
        "substitution: the attestation verifies under the verifier's own anchors",
        grade == CoverageGrade::AttestedByAuthority,
        "high-stakes conformity, 2-of-3 quorum co-signed",
    );
    check(
        "the attestation binds the governing policy (XB-3 names it)",
        attestation.binds_policy(&sealed_policy.policy),
        "cn-dynamic-bms v1 — the verdict will cite it",
    );

    // XB-4: acceptance — the RECEIVING profile decides whether the
    // attestation is evidence AT ALL. Same attestation, two profiles.
    use unidpp_signatif::acceptance::AcceptancePolicy;
    let accepting_policy = AcceptancePolicy {
        profile: "urn:unidpp:profile:eu-battery".into(),
        attestation_services: vec!["cn-attestation-service".into()],
        accepted_claims: vec![ClaimClass::Conformity],
        minimum_quorum: 2,
        max_age_secs: Some(3600),
        element_modes: Default::default(),
    };
    let mut strict_policy = accepting_policy.clone();
    strict_policy.profile = "urn:unidpp:profile:eu-battery-strict".into();
    strict_policy.attestation_services = vec![];
    let at_now = "2030-06-01T08:30:00Z";
    check(
        "acceptance: the receiving profile decides (XB-4)",
        accepting_policy.grade(&attestation, "cn-dynamic", at_now)
            == CoverageGrade::AttestedByAuthority
            && strict_policy.grade(&attestation, "cn-dynamic", at_now)
                == CoverageGrade::ExplicitlyUnavailable,
        "same attestation — evidence under eu-battery, refused under a non-anchoring profile",
    );

    // The coverage-graded verdict (XB-3+XB-8): a first-class report
    // object — static verified-direct, dynamic attested (the grade
    // the RECEIVING profile accepted) — rendered from the object.
    use unidpp_s13::coverage::{CoverageEntry, CoverageReport, EvidenceKind};
    fn evidence_of(grade: CoverageGrade) -> EvidenceKind {
        match grade {
            CoverageGrade::VerifiedDirect => EvidenceKind::VerifiedDirect,
            CoverageGrade::AttestedByAuthority => EvidenceKind::AttestedByAuthority,
            CoverageGrade::ExplicitlyUnavailable => EvidenceKind::ExplicitlyUnavailable,
        }
    }
    let sealed_grade = accepting_policy.grade(&attestation, "cn-dynamic", at_now);
    let mut report = CoverageReport::new(
        "urn:unidpp:passport:pack-0001",
        "urn:unidpp:profile:eu-battery",
        at_now,
    );
    let static_entry = CoverageEntry {
        class: "eu-static".into(),
        element_set: "urn:unidpp:elements:battery-static".into(),
        evidence: EvidenceKind::VerifiedDirect,
        governing_policy: "eu-static-open".into(),
        governing_policy_version: 1,
        reading: "conformant".into(),
        as_of: at_now.into(),
    };
    let dynamic_entry = CoverageEntry {
        class: "cn-dynamic".into(),
        element_set: "urn:unidpp:elements:bms-dynamic".into(),
        evidence: evidence_of(sealed_grade),
        governing_policy: attestation.statement.governing_policy.clone(),
        governing_policy_version: attestation.statement.governing_policy_version,
        reading: attestation.statement.value.clone(),
        as_of: attestation.statement.as_of.clone(),
    };
    report
        .entry(static_entry.clone())
        .entry(dynamic_entry.clone());
    // SI-11: the recorded verification route — the report's
    // replayable trace. Re-running the route reproduces the verdict
    // byte-identically (the acceptance bar's route clause).
    use unidpp_s13::route::{RouteStep, VerificationRoute};
    let mut route = VerificationRoute::new();
    route
        .step(RouteStep::Resolve {
            subject: "urn:unidpp:passport:pack-0001".into(),
        })
        .step(RouteStep::Transport {
            mode: "document".into(),
            counterpart: "de-zoll".into(),
        })
        .step(RouteStep::Document {
            kind: "frozen-view".into(),
            digest: report_digest_of(&report),
        })
        .step(RouteStep::Substitution {
            data_class: "cn-dynamic".into(),
            service: "cn-attestation-service".into(),
        })
        .step(RouteStep::Classify {
            entry: static_entry.clone(),
        })
        .step(RouteStep::Classify {
            entry: dynamic_entry.clone(),
        });
    report.route = Some(route.clone());
    let replayed = route.replay(
        "urn:unidpp:passport:pack-0001",
        "urn:unidpp:profile:eu-battery",
        at_now,
    );
    let coverage = report.summary();
    check(
        "the verdict is a coverage report object, naming the governing policy",
        coverage.contains("verified-direct") && coverage.contains("attested-by-authority"),
        &coverage,
    );
    check(
        "the recorded route replays the verdict byte-identically (SI-11)",
        replayed.digest() == report.digest(),
        &format!("route {} steps, replay digest matches", route.steps.len()),
    );

    // XB-5: the dossier — everything the foreign verifier needs, as
    // signed documents. The offline path (`unidpp dossier <path>`)
    // re-derives this verdict with zero calls to any live system.
    if let Some(path) = dossier_path {
        use unidpp_signatif::dossier::Dossier;
        use unidpp_signatif::s13::{
            S13Journal, S13JournalEntry, S13Side, SignedS13Request, SignedS13Response,
        };
        let signed_request =
            SignedS13Request::issue(request.clone(), "de-zoll", &de_zoll_key).map_err(fail)?;
        let signed_response =
            SignedS13Response::issue(response.clone(), &custodian_key).map_err(fail)?;
        let mut journal = S13Journal::new(S13Side::Custodian);
        journal.append(S13JournalEntry::Request(signed_request));
        journal.append(S13JournalEntry::Response(signed_response));
        let eu_proof = signed_spine
            .spine
            .proof("eu-static")
            .ok_or_else(|| CommandError::Failure("no eu proof".into()))?;
        let mut dossier = Dossier {
            subject: "urn:unidpp:passport:pack-0001".into(),
            policies: vec![open_policy, sealed_policy],
            spine: signed_spine.clone(),
            proofs: vec![eu_proof, proof.clone()],
            attestations: vec![attestation.clone()],
            journal,
            receipt: None,
        };
        // CN-4: the spine anchors in the transparency log — one
        // anchoring chain — and the re-servable receipt rides the
        // dossier.
        let operator = KeyPair::seeded(Suite::Ed25519, b"ggrid/log-operator").map_err(fail)?;
        let mut log = unidpp_signatif::anchor::TransparencyLog::new("unidpp-main");
        let seq = unidpp_signatif::spine_anchor::anchor_spine(&mut log, &signed_spine);
        let at = unidpp_model::time::Timestamp::from_secs(1_900_000_000);
        dossier.receipt = Some(
            unidpp_signatif::spine_anchor::SpineReceipt::serve(&log, seq, at, &operator)
                .map_err(fail)?,
        );
        std::fs::write(&path, dossier.to_json().map_err(fail)?)
            .map_err(|e| CommandError::Failure(format!("dossier write {path}: {e}")))?;
        println!("  dossier written: {path} — documents, not API calls (XB-5); spine anchored in the log (CN-4)");

        // SI-1: the frozen view — the self-describing publication
        // (payload + descriptor + lens + spine-proved inputs + the
        // bundle). `unidpp frozen <path>` re-derives it air-gapped.
        if let Some(frozen) = frozen_path {
            use unidpp_signatif::frozen::{
                example::battery_lens, FrozenInput, FrozenView, LensMetadata, TransformStep,
            };
            let inputs = vec![FrozenInput {
                name: "static".into(),
                segment: "eu-static".into(),
                bytes: open_state.to_vec(),
            }];
            let lens = LensMetadata {
                profile: "urn:unidpp:profile:eu-battery".into(),
                transforms: vec![TransformStep {
                    reference: "urn:unidpp:transform:battery-view".into(),
                    version: 1,
                }],
                input_segments: vec![("static".into(), "eu-static".into())],
            };
            let view = FrozenView::freeze(
                "urn:unidpp:passport:pack-0001",
                battery_lens(&inputs),
                unidpp_model::BATTERY_FROZEN,
                lens,
                inputs,
                dossier,
                vec![
                    "verify the bundle under your own anchors".into(),
                    "check each input against its spine commitment".into(),
                    "re-execute the lens over the inputs".into(),
                ],
                "2030-06-01T08:00:00Z",
            )
            .map_err(fail)?;
            std::fs::write(
                &frozen,
                serde_json::to_vec_pretty(&view).map_err(|e| {
                    CommandError::Failure(format!("frozen view serialization: {e}"))
                })?,
            )
            .map_err(|e| CommandError::Failure(format!("frozen view write {frozen}: {e}")))?;
            println!("  frozen view written: {frozen} — the F1 publication act (SI-1)");
        }
    }

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

fn report_digest_of(report: &unidpp_s13::coverage::CoverageReport) -> [u8; 32] {
    report.digest()
}

fn parse_value_flag(rest: &[String], flag: &str) -> Option<String> {
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        if arg == flag {
            return it.next().cloned();
        }
    }
    None
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    bytes.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

fn fail(e: unidpp_signatif::SignatifError) -> CommandError {
    CommandError::Failure(format!("grid demo: {e}"))
}
