//! FW-7: the no-orphan adversarial audit.
//!
//! The rule under audit: no capability shall degrade when its
//! counterpart is not UniDPP — adopted parts federate with the
//! non-adopted remainder through frozen views, the inter-scheme
//! protocol and mapping items.
//!
//! The audit's method: the partial adopter is this crate's world —
//! the libraries the verify-only binary links, files on disk, and
//! nothing else. No registry, no issuer, no trust service, no log,
//! no projector, no network. For each capability the full host
//! serves, the audit constructs the capability at the partial
//! adopter's scope and asserts it holds at the SAME class level:
//! the frozen view verifies and re-executes air-gapped after a
//! document round-trip; the verification route composes, digests
//! deterministically, and replays byte-identically; the mapping
//! items apply as data, refusing the tier confusions by rule. What
//! the full host computes through its services, the partial adopter
//! computes from the same bytes — the digests are the proof.

use unidpp_s13::coverage::{CoverageEntry, EvidenceKind};
use unidpp_s13::route::{compose, LayerVector, LinkState, RouteStep, VerificationRoute};
use unidpp_semantics::mapping::{MappingChain, MappingItem, MappingKind};
use unidpp_signatif::frozen::example::{battery_lens, battery_view};
use unidpp_signatif::frozen::{FrozenInput, FrozenView};

// -------------------------------------------------------------------------
// Capability 1 — frozen views (SI-1/F1): the full host freezes a
// projection behind its projector and trust services; the partial
// adopter receives the frozen view as a DOCUMENT and verifies it
// air-gapped, re-executing the render from the committed inputs.
// -------------------------------------------------------------------------

#[test]
fn frozen_views_verify_and_re_execute_air_gapped_at_full_class_level() {
    let (view, graph) = battery_view();

    // The full host's own verify clause, run at the partial
    // adopter's scope: the dossier checks, every input's commitment
    // present in the spine.
    view.verify(&graph)
        .expect("the frozen view verifies at partial-adopter scope");

    // The air-gapped re-execution (F1): re-derive the payload from
    // the committed inputs alone — no services consulted.
    assert!(
        view.re_executes(battery_lens),
        "the render re-derives from the committed inputs, air-gapped"
    );

    // The document form: what actually travels to a partial adopter.
    // A serde round-trip changes nothing — canonical bytes and the
    // verify outcome are identical.
    let doc = serde_json::to_string(&view).expect("serializes");
    let back: FrozenView = serde_json::from_str(&doc).expect("parses");
    assert_eq!(back.canonical_bytes(), view.canonical_bytes());
    back.verify(&graph)
        .expect("the round-tripped view still verifies");
    assert!(back.re_executes(battery_lens));

    // A tampered payload no longer re-executes — the air-gapped
    // reader catches the edit with nothing to ask.
    let mut tampered = view.clone();
    tampered.payload[0] ^= 0xff;
    assert!(!tampered.re_executes(battery_lens));

    // The inputs are spine-provable commitments, not claims: an
    // input naming a segment the spine does not carry is refused.
    let mut orphan = view.clone();
    orphan.inputs.push(FrozenInput {
        name: "ghost".into(),
        segment: "not-in-the-spine".into(),
        bytes: vec![0],
    });
    assert!(orphan.verify(&graph).is_err());
}

// -------------------------------------------------------------------------
// Capability 2 — the inter-scheme protocol (SI-9/10/11): the full
// host derives layer vectors, composes them under policy, and
// records verification routes with replayable traces. All three are
// pure computations over data — the partial adopter runs the same
// laws from recorded state, no registry or declarations service
// involved.
// -------------------------------------------------------------------------

fn bridged_vector() -> LayerVector {
    LayerVector {
        transport: LinkState::Same,
        protocol: LinkState::Same,
        structure: LinkState::BridgedBy("urn:unidpp:mapping:eu-cn".into()),
        semantics: LinkState::BridgedBy("urn:unidpp:mapping:eu-cn".into()),
        identity: LinkState::Same,
        trust: LinkState::Same,
    }
}

#[test]
fn the_composition_law_binds_the_partial_adopter_identically() {
    // A fully bridged vector composes to the policy cap — bridges do
    // not lift a policy, and the composition says so.
    let composed = compose(&bridged_vector(), 3);
    assert_eq!(composed.level, 3);
    assert!(composed.policy_bound);

    // A gap in one layer drops the level to that layer and NAMES the
    // bottleneck — the same law the full host's verdict runs.
    let mut gapped = bridged_vector();
    gapped.trust = LinkState::Gap;
    let composed = compose(&gapped, 3);
    assert_eq!(composed.level, 0);
    assert_eq!(composed.bottleneck.as_deref(), Some("trust"));
    assert!(!composed.policy_bound);
}

#[test]
fn verification_routes_digest_deterministically_and_replay_byte_identically() {
    let route = || {
        let mut r = VerificationRoute::new();
        r.step(RouteStep::Resolve {
            subject: "urn:unidpp:passport:pack-0001".into(),
        });
        r.step(RouteStep::Transport {
            mode: "document".into(),
            counterpart: "de-zoll".into(),
        });
        r.step(RouteStep::Document {
            kind: "frozen-view".into(),
            digest: [7u8; 32],
        });
        r.step(RouteStep::Classify {
            entry: CoverageEntry {
                class: "battery.carbon-footprint".into(),
                element_set: "urn:untded:battery".into(),
                evidence: EvidenceKind::VerifiedDirect,
                governing_policy: "eu-battery-2027".into(),
                governing_policy_version: 2,
                reading: "42 kgCO2e declared, verified".into(),
                as_of: "2027-03-01T00:00:00Z".into(),
            },
        });
        r.clone()
    };

    // Two independent constructions digest identically — the trace is
    // a function of the steps, nothing else. This is the equality
    // between the full host's recorded route and the partial
    // adopter's reconstructed one.
    assert_eq!(route().digest(), route().digest());

    // Replay reproduces the coverage report byte-identically — the
    // verdict re-derives from the recorded trace alone (SI-11).
    let first = route().replay("s", "p", "2027-03-01T00:00:00Z");
    let second = route().replay("s", "p", "2027-03-01T00:00:00Z");
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap()
    );
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].class, "battery.carbon-footprint");

    // The document form round-trips: the trace a partial adopter
    // receives drives the same replay.
    let doc = serde_json::to_string(&route()).unwrap();
    let back: VerificationRoute = serde_json::from_str(&doc).unwrap();
    assert_eq!(back.digest(), route().digest());
    let replayed = back.replay("s", "p", "2027-03-01T00:00:00Z");
    assert_eq!(
        serde_json::to_string(&replayed).unwrap(),
        serde_json::to_string(&first).unwrap()
    );
}

// -------------------------------------------------------------------------
// Capability 3 — mapping items (SI-12): the full host serves
// cross-register mappings from its registry; a partial adopter holds
// the same items as DATA (a registry export, a mirror-federation
// pull) and applies them under the same tier discipline.
// -------------------------------------------------------------------------

fn deterministic_hop() -> MappingItem {
    MappingItem {
        source: "register:eu-battery@3".into(),
        target: "register:cn-battery@2".into(),
        version: 1,
        kind: MappingKind::Deterministic {
            transform: "urn:unidpp:transform:eu-cn-mass@4".into(),
        },
    }
}

#[test]
fn mapping_items_apply_as_data_under_the_tier_discipline() {
    // The registry's item, held as data: construction is
    // deterministic (the same item digests the same — what the
    // registry committed is what the adopter holds).
    assert_eq!(deterministic_hop().digest(), deterministic_hop().digest());

    // Application at partial-adopter scope: the transform function
    // is local code; the item names it by reference.
    let chain = MappingChain::single(deterministic_hop()).expect("single hop");
    let applied = chain
        .apply_deterministic("12.5 kg", &|value, transform| {
            assert_eq!(transform, "urn:unidpp:transform:eu-cn-mass@4");
            Ok(format!("{value} (mapped via {transform})"))
        })
        .expect("applies");
    assert_eq!(
        applied,
        "12.5 kg (mapped via urn:unidpp:transform:eu-cn-mass@4)"
    );
    assert_eq!(
        chain.versions(),
        vec![("register:eu-battery@3→register:cn-battery@2".into(), 1)]
    );

    // A tier-2 hop in a deterministic application is REFUSED by
    // rule — correspondences are not transforms, and the refusal
    // names the hop (the registry enforces the same law at intake;
    // the adopter enforces it at application).
    let correspondence = MappingItem {
        source: "register:cn-battery@2".into(),
        target: "register:jp-battery@1".into(),
        version: 1,
        kind: MappingKind::Correspondence {
            scope: vec!["carbon-footprint".into()],
            residual: "recycled-content shares are not covered".into(),
            attester: "jp-meti".into(),
        },
    };
    let mixed = MappingChain::single(deterministic_hop())
        .expect("single")
        .then(correspondence, 8)
        .expect("composes as a chain");
    let refused = mixed.apply_deterministic("12.5 kg", &|value, _t| Ok(value.into()));
    assert!(refused.is_err(), "a correspondence is not a transform");

    // The tier-3 record exists to state divergence — its canonical
    // bytes commit the note, not a reconciliation.
    let no_mapping = MappingItem {
        source: "register:eu-battery@3".into(),
        target: "register:us-battery@1".into(),
        version: 1,
        kind: MappingKind::NoMapping {
            note: "divergent legal bases recorded, not reconciled".into(),
        },
    };
    assert!(!no_mapping.canonical_bytes().is_empty());
    assert_eq!(no_mapping.digest(), {
        let again = no_mapping.clone();
        again.digest()
    });

    // The document form: items travel as JSON (what a registry
    // export or mirror pull delivers) and parse back to the same
    // committed bytes.
    let doc = serde_json::to_string(&deterministic_hop()).unwrap();
    let back: MappingItem = serde_json::from_str(&doc).unwrap();
    assert_eq!(back.digest(), deterministic_hop().digest());
}
