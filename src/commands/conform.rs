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

use unidpp_semantics::mapping::{MappingChain, MappingItem};
use unidpp_signatif::frozen::{example::battery_lens, FrozenView};

use crate::commands::dossier::verifier_graph;
use crate::commands::CommandError;
use crate::exit;

/// Run a federation class claim test (exit PASS when the claim
/// holds). Every class's material is public (Clause 11): a frozen
/// view for F1, the signed exchange for F2, the mapping chain for
/// F3, two views under one shared profile for F4, and the family's
/// golden vectors for F5.
pub fn run(rest: &[String]) -> Result<u8, CommandError> {
    let Some(class) = rest.first() else {
        return Err(CommandError::Usage(USAGE.to_string()));
    };
    let failed = match class.as_str() {
        "f1" => {
            let Some(path) = rest.get(1) else {
                return Err(CommandError::Usage(USAGE.to_string()));
            };
            run_f1_with(path, rest.get(2).map(String::as_str))?
        }
        "f2" => {
            let Some(path) = rest.get(1) else {
                return Err(CommandError::Usage(USAGE.to_string()));
            };
            run_f2(path)?
        }
        "f3" => {
            let Some(path) = rest.get(1) else {
                return Err(CommandError::Usage(USAGE.to_string()));
            };
            run_f3(path)?
        }
        "f4" => {
            let (Some(a), Some(b)) = (rest.get(1), rest.get(2)) else {
                return Err(CommandError::Usage(USAGE.to_string()));
            };
            run_f4(a, b, rest.get(3).map(String::as_str))?
        }
        "f5" => run_f5(rest.get(1).map(String::as_str))?,
        other => {
            return Err(CommandError::Usage(format!(
                "unknown class `{other}` — {USAGE}"
            )))
        }
    };
    Ok(if failed { exit::FAIL } else { exit::PASS })
}

const USAGE: &str = "usage: unidpp conform <class> <material> \
    (f1 <frozen-view.json> [anchors.json] | f2 <signed-exchange.json> | \
     f3 <mapping-chain.json> | f4 <view-a.json> <view-b.json> [anchors.json] | \
     f5 [family-dir])";

/// The trust graph for a claim test: the runner's own anchors when a
/// file is given (the third-party form — never anything from the
/// view), the reference graph otherwise (the demo's anchors).
fn claim_graph(
    anchors_path: Option<&str>,
) -> Result<unidpp_signatif::graph::TrustGraph, CommandError> {
    let Some(path) = anchors_path else {
        return Ok(verifier_graph());
    };
    let doc = load_json(path)?;
    let mut graph = unidpp_signatif::graph::TrustGraph::new();
    for (node, keys) in doc.as_object().into_iter().flatten() {
        let mut delegation = unidpp_signatif::graph::DelegationNode::new(
            unidpp_signatif::graph::NodeId::new(node)
                .map_err(|e| CommandError::Failure(format!("anchor id: {e}")))?,
            unidpp_signatif::graph::NodeKind::Delegated,
        );
        // The anchors form: node -> its registered keys (public hex +
        // suite each — a node may hold several).
        for key in keys.as_array().into_iter().flatten() {
            let public_hex = key
                .get("public_hex")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CommandError::Failure(format!("anchor `{node}` has a key with no public_hex"))
                })?;
            let public = unidpp_signatif::keyring::PublicKey::from_bytes(&decode_hex(public_hex)?)
                .map_err(|e| CommandError::Failure(format!("anchor `{node}`: {e}")))?;
            delegation.register(unidpp_signatif::graph::RegisteredKey {
                key_id: unidpp_signatif::keyring::KeyId::of(&public),
                public,
            });
        }
        graph.add_node(delegation);
    }
    Ok(graph)
}

/// The F1 claim test: a published frozen view verifies under the
/// runner's own anchors, air-gapped.
fn run_f1_with(path: &str, anchors_path: Option<&str>) -> Result<bool, CommandError> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| CommandError::Failure(format!("read {path}: {e}")))?;
    let view: FrozenView = serde_json::from_str(&json)
        .map_err(|e| CommandError::Failure(format!("frozen view parse: {e}")))?;
    let anchors = claim_graph(anchors_path)?;
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
        Ok(false)
    } else {
        println!("F1: FAIL");
        Ok(true)
    }
}

fn short(id: &str) -> String {
    id.rsplit('/').next().unwrap_or(id).to_string()
}

fn load_json(path: &str) -> Result<serde_json::Value, CommandError> {
    std::fs::read_to_string(path)
        .map_err(|e| CommandError::Failure(format!("read {path}: {e}")))
        .and_then(|text| {
            serde_json::from_str(&text)
                .map_err(|e| CommandError::Failure(format!("{path} parse: {e}")))
        })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fact(label: &str, detail: &str) {
    println!("  {label}: {detail}");
}

// --- F2: the S13 protocol participant -----------------------------------

fn run_f2(path: &str) -> Result<bool, CommandError> {
    let doc = load_json(path)?;
    let request: unidpp_s13::S13Request = serde_json::from_value(
        doc.pointer("/signed_request/request")
            .cloned()
            .ok_or_else(|| CommandError::Failure("no signed_request.request".into()))?,
    )
    .map_err(|e| CommandError::Failure(format!("request parse: {e}")))?;
    let response: unidpp_s13::S13Response = serde_json::from_value(
        doc.pointer("/signed_response/response")
            .cloned()
            .ok_or_else(|| CommandError::Failure("no signed_response.response".into()))?,
    )
    .map_err(|e| CommandError::Failure(format!("response parse: {e}")))?;
    let request_sig: unidpp_signatif::sign::SignatureSlot = serde_json::from_value(
        doc.pointer("/signed_request/signature")
            .cloned()
            .ok_or_else(|| CommandError::Failure("no request signature".into()))?,
    )
    .map_err(|e| CommandError::Failure(format!("request signature parse: {e}")))?;
    let response_sig: unidpp_signatif::sign::SignatureSlot = serde_json::from_value(
        doc.pointer("/signed_response/signature")
            .cloned()
            .ok_or_else(|| CommandError::Failure("no response signature".into()))?,
    )
    .map_err(|e| CommandError::Failure(format!("response signature parse: {e}")))?;
    let requester_hex = doc
        .pointer("/requester_public_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::Failure("no requester_public_hex".into()))?;
    let responder_hex = doc
        .pointer("/responder_public_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CommandError::Failure("no responder_public_hex".into()))?;

    let domain = unidpp_signatif::sign::SigningDomain::S13Message;
    let requester_key =
        unidpp_signatif::keyring::PublicKey::from_bytes(&decode_hex(requester_hex)?)
            .map_err(|e| CommandError::Failure(format!("requester key: {e}")))?;
    let responder_key =
        unidpp_signatif::keyring::PublicKey::from_bytes(&decode_hex(responder_hex)?)
            .map_err(|e| CommandError::Failure(format!("responder key: {e}")))?;

    println!("F2 claim test — the S13 exchange {path}");
    let request_ok = request_sig
        .verify(domain, &request.canonical_bytes(), &requester_key)
        .is_ok();
    let response_ok = response_sig
        .verify(domain, &response.canonical_bytes(), &responder_key)
        .is_ok();
    let cites_policy = !response.governing_policy.is_empty();
    fact(
        "verifier's signed request",
        if request_ok {
            "verifies (S13-MESSAGE domain)"
        } else {
            "DOES NOT VERIFY"
        },
    );
    fact(
        "custodian's signed response",
        if response_ok {
            "verifies (S13-MESSAGE domain)"
        } else {
            "DOES NOT VERIFY"
        },
    );
    fact(
        "governing policy cited",
        &format!(
            "{} v{}",
            response.governing_policy, response.governing_policy_version
        ),
    );
    println!(
        "F2: {}",
        if request_ok && response_ok && cites_policy {
            "PASS — the exchange completes end to end for a third party"
        } else {
            "FAIL"
        }
    );
    Ok(!(request_ok && response_ok && cites_policy))
}

fn decode_hex(text: &str) -> Result<Vec<u8>, CommandError> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16);
        let lo = pair.get(1).and_then(|b| (*b as char).to_digit(16));
        match (hi, lo) {
            (Some(hi), Some(lo)) => out.push(((hi << 4) | lo) as u8),
            _ => return Err(CommandError::Failure(format!("not hex: `{text}`"))),
        }
    }
    Ok(out)
}

// --- F3: mapping-capable -------------------------------------------------

fn run_f3(path: &str) -> Result<bool, CommandError> {
    let doc = load_json(path)?;
    let chain: MappingChain = serde_json::from_value(
        doc.get("chain")
            .cloned()
            .ok_or_else(|| CommandError::Failure("no chain".into()))?,
    )
    .map_err(|e| CommandError::Failure(format!("chain parse: {e}")))?;
    let pinned: Vec<(String, String)> = [
        doc.get("hop_a_canonical_hex"),
        doc.get("hop_b_canonical_hex"),
    ]
    .into_iter()
    .filter_map(|v| v.and_then(|v| v.as_str()))
    .map(str::to_string)
    .zip(chain.hops.iter().map(|h| hex(&h.canonical_bytes())))
    .collect();
    let correspondence: MappingItem = serde_json::from_value(
        doc.get("correspondence")
            .cloned()
            .ok_or_else(|| CommandError::Failure("no correspondence".into()))?,
    )
    .map_err(|e| CommandError::Failure(format!("correspondence parse: {e}")))?;
    let divergence: MappingItem = serde_json::from_value(
        doc.get("divergence")
            .cloned()
            .ok_or_else(|| CommandError::Failure("no divergence".into()))?,
    )
    .map_err(|e| CommandError::Failure(format!("divergence parse: {e}")))?;

    println!("F3 claim test — the mapping chain {path}");
    let vectors_ok = pinned.iter().all(|(want, got)| want == got)
        && hex(&correspondence.canonical_bytes())
            == doc
                .get("correspondence_canonical_hex")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
        && hex(&divergence.canonical_bytes())
            == doc
                .get("divergence_canonical_hex")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
    let applied = chain.apply_deterministic("12.5 kg", &|value, transform| {
        Ok(format!("{value} (via {transform})"))
    });
    let applies = applied.is_ok();
    // The mixed chain: the fixture's correspondence re-sourced to
    // continue the chain (composition is legal; it is the
    // DETERMINISTIC APPLICATION that must refuse).
    let let_in = MappingItem {
        source: chain.hops[0].target.clone(),
        target: correspondence.target.clone(),
        version: correspondence.version,
        kind: correspondence.kind.clone(),
    };
    let mixed = MappingChain::single(chain.hops[0].clone())
        .ok()
        .and_then(|c| c.then(let_in, 8).ok());
    let refuses_correspondence = matches!(
        mixed.map(|c| c.apply_deterministic("12.5 kg", &|v, _t| Ok(v.to_string()))),
        Some(Err(_))
    );
    let refuses_divergence = matches!(
        MappingChain::single(divergence.clone())
            .ok()
            .map(|c| c.apply_deterministic("12.5 kg", &|v, _t| Ok(v.to_string()))),
        Some(Err(_))
    );
    fact(
        "vectors reproduce",
        if vectors_ok {
            "canonical bytes match the pins"
        } else {
            "DIVERGED"
        },
    );
    fact(
        "tier-1 applies deterministically",
        if let Ok(value) = &applied {
            value
        } else {
            "REFUSED"
        },
    );
    fact(
        "tier-2 in a deterministic application",
        if refuses_correspondence {
            "refused (correspondences are not transforms)"
        } else {
            "ACCEPTED"
        },
    );
    fact(
        "tier-3 renders distinct",
        if refuses_divergence {
            "no correspondence asserted"
        } else {
            "ASSERTED"
        },
    );
    println!(
        "F3: {}",
        if vectors_ok && applies && refuses_correspondence && refuses_divergence {
            "PASS — mapping items flow in and out for a third party"
        } else {
            "FAIL"
        }
    );
    Ok(!(vectors_ok && applies && refuses_correspondence && refuses_divergence))
}

// --- F4: shared-profile adopter -------------------------------------------

fn run_f4(a: &str, b: &str, anchors_path: Option<&str>) -> Result<bool, CommandError> {
    let view_a: FrozenView = serde_json::from_str(
        &std::fs::read_to_string(a).map_err(|e| CommandError::Failure(format!("read {a}: {e}")))?,
    )
    .map_err(|e| CommandError::Failure(format!("{a} parse: {e}")))?;
    let view_b: FrozenView = serde_json::from_str(
        &std::fs::read_to_string(b).map_err(|e| CommandError::Failure(format!("read {b}: {e}")))?,
    )
    .map_err(|e| CommandError::Failure(format!("{b} parse: {e}")))?;
    let anchors = claim_graph(anchors_path)?;

    println!("F4 claim test — {a} vs {b}");
    let shared = view_a.lens.profile == view_b.lens.profile
        && view_a.lens.transforms == view_b.lens.transforms
        && view_a.lens.input_segments == view_b.lens.input_segments;
    let a_ok = view_a.verify(&anchors).is_ok() && view_a.re_executes(battery_lens);
    let b_ok = view_b.verify(&anchors).is_ok() && view_b.re_executes(battery_lens);
    fact(
        "shared profile",
        &format!(
            "{} ({} transform(s), {} input channel(s))",
            view_a.lens.profile,
            view_a.lens.transforms.len(),
            view_a.lens.input_segments.len()
        ),
    );
    fact(
        "each view self-consistent",
        &format!(
            "a: {}, b: {}",
            if a_ok {
                "verifies + re-executes"
            } else {
                "FAILS"
            },
            if b_ok {
                "verifies + re-executes"
            } else {
                "FAILS"
            }
        ),
    );
    println!(
        "F4: {}",
        if shared && a_ok && b_ok {
            "PASS — one profile version honored by both views, each independently verifiable"
        } else {
            "FAIL"
        }
    );
    Ok(!(shared && a_ok && b_ok))
}

// --- F5: full core implementer (the vector sweep) -------------------------

/// The vector sweep's counters.
struct Tally {
    failed: usize,
    total: usize,
}

fn run_f5(family_dir: Option<&str>) -> Result<bool, CommandError> {
    // The family layout the whole suite assumes: <root>/unidpp-core,
    // <root>/unidpp-signatif beside this binary's repo. Probe the
    // given root, the cwd, and the cwd's parent.
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    if let Some(given) = family_dir {
        roots.push(given.into());
    }
    if let Ok(from_env) = std::env::var("UNIDPP_FAMILY") {
        roots.push(from_env.into());
    }
    roots.push(".".into());
    roots.push("..".into());
    let root = roots
        .into_iter()
        .find(|r| r.join("unidpp-core/crates/s13/fixtures/canonical").is_dir())
        .ok_or_else(|| {
            CommandError::Failure(
                "the family checkout was not found (run from a family root, or pass \
                 the root, or set UNIDPP_FAMILY)"
                    .into(),
            )
        })?;

    let mut tally = Tally {
        failed: 0,
        total: 0,
    };
    let check = |tally: &mut Tally, name: &str, want: &str, got: String| {
        tally.total += 1;
        if want == got {
            println!("  [ok]   {name}");
        } else {
            tally.failed += 1;
            println!("  [FAIL] {name}: pinned {want} got {got}");
        }
    };

    println!(
        "F5 claim test — the family's golden vectors (root {})",
        root.display()
    );

    // The sweep's table: one row per fixture — where the object
    // rides in the JSON, the field the pin lives in, and how to
    // re-derive the bytes. A new fixture family is a row here, not
    // a copied branch.
    let rows: Vec<(&str, &str, &str, &str, Derive)> = vec![
        // S13 messages
        (
            "unidpp-core/crates/s13/fixtures/canonical/request.json",
            "request",
            "canonical_hex",
            "",
            Derive::S13Request,
        ),
        (
            "unidpp-core/crates/s13/fixtures/canonical/response.json",
            "response",
            "canonical_hex",
            "",
            Derive::S13Response,
        ),
        (
            "unidpp-core/crates/s13/fixtures/canonical/verification-route.json",
            "route",
            "digest_hex",
            "",
            Derive::RouteDigest,
        ),
        // SIGNATIF objects
        (
            "unidpp-signatif/fixtures/canonical/interop-declaration.json",
            "declaration",
            "canonical_hex",
            "",
            Derive::Declaration,
        ),
        (
            "unidpp-signatif/fixtures/canonical/frozen-view.json",
            "view",
            "canonical_hex",
            "",
            Derive::FrozenView,
        ),
        // The grid
        (
            "unidpp-core/crates/grid/fixtures/canonical/policy.json",
            "policy",
            "canonical_hex",
            "",
            Derive::Policy,
        ),
        // The mapping discipline
        (
            "unidpp-core/crates/semantics/fixtures/canonical/mapping-chain.json",
            "correspondence",
            "correspondence_canonical_hex",
            "",
            Derive::MappingItem,
        ),
        // Segment commitment: a raw-hex state, not a nested object
        (
            "unidpp-core/crates/grid/fixtures/canonical/segment-commitment.json",
            "",
            "commitment_hex",
            "state_hex",
            Derive::SegmentCommitment,
        ),
    ];

    for (rel, object_key, pin_key, raw_key, derive) in rows {
        let path = root.join(rel);
        let name = std::path::Path::new(rel)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(rel);
        let Some(doc) = load_json(path.to_str().unwrap_or_default()).ok() else {
            tally.total += 1;
            tally.failed += 1;
            println!("  [FAIL] {name}: fixture unreadable");
            continue;
        };
        let got = match derive {
            Derive::S13Request => serde_json::from_value::<unidpp_s13::S13Request>(
                doc.get(object_key).cloned().unwrap_or_default(),
            )
            .ok()
            .map(|r| hex(&r.canonical_bytes())),
            Derive::S13Response => serde_json::from_value::<unidpp_s13::S13Response>(
                doc.get(object_key).cloned().unwrap_or_default(),
            )
            .ok()
            .map(|r| hex(&r.canonical_bytes())),
            Derive::RouteDigest => serde_json::from_value::<unidpp_s13::route::VerificationRoute>(
                doc.get(object_key).cloned().unwrap_or_default(),
            )
            .ok()
            .map(|r| hex(&r.digest())),
            Derive::Declaration => serde_json::from_value::<
                unidpp_signatif::declaration::InteropDeclaration,
            >(doc.get(object_key).cloned().unwrap_or_default())
            .ok()
            .map(|d| hex(&d.canonical_bytes())),
            Derive::FrozenView => serde_json::from_value::<FrozenView>(
                doc.get(object_key).cloned().unwrap_or_default(),
            )
            .ok()
            .map(|v| hex(&v.canonical_bytes())),
            Derive::Policy => serde_json::from_value::<unidpp_grid::PolicyObject>(
                doc.get(object_key).cloned().unwrap_or_default(),
            )
            .ok()
            .map(|p| hex(&p.canonical_bytes())),
            Derive::MappingItem => serde_json::from_value::<MappingItem>(
                doc.get(object_key).cloned().unwrap_or_default(),
            )
            .ok()
            .map(|m| hex(&m.canonical_bytes())),
            Derive::SegmentCommitment => {
                // The state rides as raw hex; the commitment is
                // derived from the bytes directly.
                doc.get(raw_key)
                    .and_then(|v| v.as_str())
                    .and_then(|h| decode_hex(h).ok())
                    .map(|state| hex(&unidpp_grid::Segment::commit_state(&state)))
            }
        }
        .unwrap_or_default();
        check(
            &mut tally,
            name,
            doc.get(pin_key)
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            got,
        );
    }

    // The signed exchange pins no digests of its own; its objects
    // must parse and the canonical form stay stable across a
    // serialization round trip.
    let exchange = root.join("unidpp-signatif/fixtures/canonical/s13-signed-exchange.json");
    if let Ok(doc) = load_json(exchange.to_str().unwrap_or_default()) {
        let parsed = serde_json::from_value::<unidpp_s13::S13Response>(
            doc.pointer("/signed_response/response")
                .cloned()
                .unwrap_or_default(),
        )
        .ok();
        let round_trips = parsed.as_ref().is_some_and(|r| {
            serde_json::to_value(r)
                .ok()
                .and_then(|v| serde_json::from_value::<unidpp_s13::S13Response>(v).ok())
                .is_some_and(|again| again.canonical_bytes() == r.canonical_bytes())
        });
        tally.total += 1;
        if round_trips {
            println!("  [ok]   s13-signed-exchange.json (objects parse, canonical form stable)");
        } else {
            tally.failed += 1;
            println!("  [FAIL] s13-signed-exchange.json");
        }
    }

    println!(
        "F5: {} — {}/{} golden vectors reproduce in this binary",
        if tally.failed == 0 { "PASS" } else { "FAIL" },
        tally.total - tally.failed,
        tally.total
    );
    Ok(tally.failed != 0)
}

/// How one fixture's canonical bytes are re-derived.
enum Derive {
    S13Request,
    S13Response,
    RouteDigest,
    Declaration,
    FrozenView,
    Policy,
    MappingItem,
    SegmentCommitment,
}
