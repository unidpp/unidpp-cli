//! `unidpp dossier <path>` — the OFFLINE verifier path (XB-5).
//!
//! Reads one dossier file — the exchanged signed objects — and
//! re-derives the foreign verdict under the VERIFIER's own anchors
//! and acceptance policy. No network, no live system: the file and
//! the verifier's local trust graph are the only inputs. Document
//! orientation: the paper trail IS the protocol.

use unidpp_s13::coverage::{CoverageEntry, CoverageReport, EvidenceKind};
use unidpp_signatif::acceptance::AcceptancePolicy;
use unidpp_signatif::dossier::Dossier;
use unidpp_signatif::graph::{DelegationNode, NodeId, NodeKind, RegisteredKey, TrustGraph};
use unidpp_signatif::keyring::{KeyId, KeyPair};
use unidpp_signatif::sign::Suite;
use unidpp_signatif::sovereign::{ClaimClass, CoverageGrade};

use crate::commands::CommandError;
use crate::exit;

/// Run the offline dossier verification (exit PASS when the
/// report carries both evidence tiers).
pub fn run(rest: &[String]) -> Result<u8, CommandError> {
    let Some(path) = rest.first() else {
        return Err(CommandError::Usage(
            "usage: unidpp dossier <path>".to_string(),
        ));
    };
    let json = std::fs::read_to_string(path)
        .map_err(|e| CommandError::Failure(format!("read {path}: {e}")))?;
    let dossier = Dossier::from_json(&json).map_err(|e| CommandError::Failure(format!("{e}")))?;

    // The verifier's OWN anchors (here: the reference verifier's
    // seeded graph — a real deployment loads its own key directory).
    let verifier_anchors = verifier_graph();
    let check = dossier
        .verify(&verifier_anchors)
        .map_err(|e| CommandError::Failure(format!("offline verification: {e}")))?;

    // The receiving profile's acceptance policy — local, not in the
    // dossier.
    let acceptance = AcceptancePolicy {
        profile: "urn:unidpp:profile:eu-battery".into(),
        attestation_services: vec!["cn-attestation-service".into()],
        accepted_claims: vec![ClaimClass::Conformity],
        minimum_quorum: 2,
        max_age_secs: None,
        element_modes: Default::default(),
    };
    let at_now = "2030-06-01T08:30:00Z";

    // The coverage report, rebuilt OFFLINE from the dossier alone:
    // open classes verified-direct via their spine proofs, sealed
    // classes graded under the acceptance policy.
    let mut report = CoverageReport::new(&dossier.subject, &acceptance.profile, at_now);
    for proof in &dossier.proofs {
        let open = dossier.policies.iter().any(|p| {
            p.policy.reveal == unidpp_grid::RevealClass::Open
                && dossier
                    .attestations
                    .iter()
                    .all(|a| a.statement.segment != proof.segment_id)
        });
        if open {
            report.entry(CoverageEntry {
                class: proof.segment_id.clone(),
                element_set: "urn:unidpp:elements:battery-static".into(),
                evidence: EvidenceKind::VerifiedDirect,
                governing_policy: "eu-static-open".into(),
                governing_policy_version: 1,
                reading: "existence+currency proven from the spine".into(),
                as_of: at_now.into(),
            });
        }
    }
    for attestation in &dossier.attestations {
        let grade = acceptance.grade(attestation, &attestation.statement.segment, at_now);
        let evidence = match grade {
            CoverageGrade::VerifiedDirect => EvidenceKind::VerifiedDirect,
            CoverageGrade::AttestedByAuthority => EvidenceKind::AttestedByAuthority,
            CoverageGrade::ExplicitlyUnavailable => EvidenceKind::ExplicitlyUnavailable,
        };
        report.entry(CoverageEntry {
            class: attestation.statement.segment.clone(),
            element_set: "urn:unidpp:elements:bms-dynamic".into(),
            evidence,
            governing_policy: attestation.statement.governing_policy.clone(),
            governing_policy_version: attestation.statement.governing_policy_version,
            reading: attestation.statement.value.clone(),
            as_of: attestation.statement.as_of.clone(),
        });
    }

    println!("offline dossier verification — subject {}", dossier.subject);
    println!(
        "  policies {} · proofs {} · attestations {} · journal decisions {}",
        check.policies_ok,
        check.proofs_ok,
        check.attestations_ok,
        check.journal_decisions.len()
    );
    // CN-4: the spine's log receipt, when carried, verifies offline
    // and binds THIS dossier's spine (checked in Dossier::verify).
    if let Some(receipt) = &dossier.receipt {
        let operator = KeyPair::seeded(Suite::Ed25519, b"ggrid/log-operator")
            .map_err(|e| CommandError::Failure(format!("operator key: {e}")))?;
        receipt
            .verify(operator.public())
            .map_err(|e| CommandError::Failure(format!("log receipt: {e}")))?;
        println!(
            "  log receipt verified: spine committed in log {} at seq {} (CN-4)",
            receipt.log_id, receipt.seq
        );
    }
    println!("  zero calls to foreign synchronous APIs — the dossier is the protocol");
    println!("  {}", report.summary());
    if report
        .entries
        .iter()
        .any(|e| e.evidence == EvidenceKind::VerifiedDirect)
        && report
            .entries
            .iter()
            .any(|e| e.evidence == EvidenceKind::AttestedByAuthority)
    {
        Ok(exit::PASS)
    } else {
        Ok(exit::FAIL)
    }
}

/// The reference verifier's anchors (seeded — a deployment loads its
/// own key directory; the graph never comes from the dossier).
fn verifier_graph() -> TrustGraph {
    let anchors: Vec<(&str, KeyPair)> = [
        ("cn-samr", b"ggrid/cn-samr" as &[u8]),
        ("weilian-shenzhen", b"ggrid/weilian"),
        ("de-zoll", b"ggrid/de-zoll"),
        ("cn-attestation-service", b"ggrid/cn-attest"),
        ("cn-quorum-a", b"ggrid/quorum-a"),
        ("cn-quorum-b", b"ggrid/quorum-b"),
    ]
    .into_iter()
    .map(|(id, seed)| (id, KeyPair::seeded(Suite::Ed25519, seed).unwrap()))
    .collect();
    let mut graph = TrustGraph::new();
    for (id, key) in &anchors {
        let mut node = DelegationNode::new(NodeId::new(id).unwrap(), NodeKind::Delegated);
        node.register(RegisteredKey {
            key_id: KeyId::of(key.public()),
            public: *key.public(),
        });
        graph.add_node(node);
    }
    graph
}
