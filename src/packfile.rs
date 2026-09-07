//! Tier-A pack minting concerns: the carrier budget grammar and the
//! canonical *signing body* a pack's signature slots cover.

use unidpp_model::{SigSlot, SignatureSuite};
use unidpp_signatif::keyring::{KeyId, KeyPair, PublicKey};
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};
use unidpp_tier_a::{EcLevel, TierAError, TierAPacker, TierAPayload};

/// The default carrier budget: QR version <= 40, EC level M — the
/// core packer's own default (largest carrier; constrain with
/// `--budget` for production carriers).
pub const DEFAULT_BUDGET: (EcLevel, u8) = (EcLevel::M, 40);

/// Parse a budget token: `qr-v<version>-<ec>` with version 1..=40 and
/// ec one of `L|M|Q|H` (case-insensitive), e.g. `qr-v15-M`.
pub fn parse_budget(token: &str) -> Result<(EcLevel, u8), String> {
    let token = token.trim().to_ascii_lowercase();
    let body = token
        .strip_prefix("qr-")
        .ok_or_else(|| format!("bad budget `{token}` (expected `qr-v15-M` form)"))?;
    let body = body
        .strip_prefix('v')
        .ok_or_else(|| format!("bad budget `{token}`: expected `v<version>` after `qr-`"))?;
    let (version, ec) = body
        .rsplit_once('-')
        .ok_or_else(|| format!("bad budget `{token}`: expected `-<ec>` suffix (L/M/Q/H)"))?;
    let version: u8 = version
        .parse()
        .map_err(|_| format!("bad budget `{token}`: version is not a number"))?;
    if !(1..=40).contains(&version) {
        return Err(format!("bad budget `{token}`: QR version must be 1..=40"));
    }
    let ec: EcLevel = ec
        .parse()
        .map_err(|_| format!("bad budget `{token}`: unknown EC level `{ec}` (L/M/Q/H)"))?;
    Ok((ec, version))
}

/// The canonical bytes a Tier-A pack signature covers: the pack's own
/// encoding with the signature slots cleared. This is a fixpoint —
/// clearing the slots of an already-unsigned payload changes nothing —
/// so the packer and the verifier always agree on the signed body
/// without shipping it alongside the pack.
pub fn signing_body(payload: &TierAPayload) -> Result<Vec<u8>, TierAError> {
    let mut bare = payload.clone();
    bare.signatures = Vec::new();
    let (bytes, _projected) = TierAPacker::encode(&bare)?;
    Ok(bytes)
}

/// Fill the payload's signature slots with a real ECDSA-P256
/// (deterministic RFC 6979) signature over its signing body, using a
/// key seeded from `seed`.
///
/// Suite choice is not free: the core's Tier-A carrier frames
/// `ecdsa-p256 | sm2 | ml-dsa-*` only — Ed25519, SIGNATIF's
/// infrastructure suite, deliberately has no carrier slot (see the
/// deviation note in `unidpp-signatif/src/sign.rs`). ECDSA-P256 is the
/// one computed suite that rides the carrier, so packs sign with it.
/// The returned public key hex is the anchor a verifier pins.
pub fn sign_pack(
    payload: &TierAPayload,
    seed: &[u8],
) -> Result<(TierAPayload, PublicKey, KeyId), String> {
    let (signed, mut anchors) = sign_pack_suites(payload, seed, &[Suite::EcdsaP256])?;
    let (public, key_id) = anchors.remove(0);
    Ok((signed, public, key_id))
}

/// Derive the signing seed for one pack suite from a base seed.
///
/// ECDSA-P256 consumes the base seed verbatim (the historical
/// behaviour — existing anchors keep verifying). Every other suite
/// gets suite-separated material (`H("UNIDPP/PACK-SUITE|" + suite +
/// "|" + seed)`), so one base seed never yields a shared scalar
/// across curves.
pub fn pack_suite_seed(seed: &[u8], suite: Suite) -> Vec<u8> {
    match suite {
        Suite::EcdsaP256 => seed.to_vec(),
        other => {
            unidpp_model::sha256(&[b"UNIDPP/PACK-SUITE|", other.as_str().as_bytes(), b"|", seed])
                .0
                .to_vec()
        }
    }
}

/// Fill the payload's signature slots with one real signature per
/// requested suite over the same signing body — the co-signature
/// model (one pack body, many sovereign suites, e.g. P-256 for the
/// EU anchor and SM2 for the CN anchor).
///
/// Every requested suite must compute in this build and map onto the
/// core carrier table; anything else is refused rather than framed.
pub fn sign_pack_suites(
    payload: &TierAPayload,
    seed: &[u8],
    suites: &[Suite],
) -> Result<(TierAPayload, Vec<(PublicKey, KeyId)>), String> {
    if suites.is_empty() {
        return Err("no signing suites requested".to_string());
    }
    let body = signing_body(payload).map_err(|e| e.to_string())?;
    let mut slots = Vec::with_capacity(suites.len());
    let mut anchors = Vec::with_capacity(suites.len());
    for &suite in suites {
        if suite.to_core().is_none() {
            return Err(format!(
                "suite {suite} has no core carrier slot (packs ride ecdsa-p256/sm2/ml-dsa-*)"
            ));
        }
        let key = KeyPair::seeded(suite, &pack_suite_seed(seed, suite))
            .map_err(|e| format!("cannot derive the {suite} pack signing key: {e}"))?;
        let slot = SignatureSlot::sign(&key, SigningDomain::ArtifactEvent, &body)
            .map_err(|e| format!("pack signing failed for {suite}: {e}"))?;
        anchors.push((*key.public(), key.key_id().clone()));
        slots.push(
            slot.to_sig_slot()
                .expect("carrier-capable suites map onto the core table"),
        );
    }
    let mut signed = payload.clone();
    signed.signatures = slots;
    Ok((signed, anchors))
}

/// Verify one decoded carrier slot against an anchor public key.
///
/// Grading (the pack-verdict ladder):
/// - key id mismatch — the anchor does not pin this signing key:
///   **degraded**, the verifier's trust configuration simply does not
///   cover the signer (this is how a wrong anchor surfaces);
/// - signature invalid under the pinned key: **fail** — tampering;
/// - deferred suite: **degraded** (framing-only, honestly reported).
#[derive(Debug)]
pub enum SlotCheck {
    /// Signature verified against the anchor.
    Verified {
        /// Suite token.
        suite: String,
        /// Key id that verified.
        key_id: String,
    },
    /// The anchor does not pin the slot's signing key.
    UnknownKey {
        /// Key id the slot names.
        key_id: String,
        /// Key id the anchor pins.
        anchor_key_id: String,
    },
    /// The signature failed real verification (or the slot is
    /// framed-only / wrongly typed).
    Invalid {
        /// Suite token.
        suite: String,
        /// Why.
        why: String,
    },
    /// The suite is framing-only in this build.
    Deferred {
        /// Suite token.
        suite: String,
        /// Documented deferral.
        detail: String,
    },
}

impl SlotCheck {
    /// Human-facing detail line.
    pub fn detail(&self) -> String {
        match self {
            SlotCheck::Verified { suite, key_id } => {
                format!("signature verified ({suite}, {key_id}) against the anchor")
            }
            SlotCheck::UnknownKey {
                key_id,
                anchor_key_id,
            } => format!(
                "slot names key {key_id} but the anchor pins {anchor_key_id}: \
                 the anchor's trust configuration does not cover this signer"
            ),
            SlotCheck::Invalid { suite, why } => format!("{suite} signature check failed: {why}"),
            SlotCheck::Deferred { suite, detail } => {
                format!("{suite} suite is framing-only: {detail}")
            }
        }
    }
}

/// Run [`SlotCheck`] for one core carrier slot against `anchor`.
///
/// Grading order: a deferred suite (SM2 / ML-DSA, framing-only in this
/// build) is reported first — no anchor could verify it here; then the
/// key-id pin (a mismatch degrades: the verifier's trust configuration
/// does not cover the signer — this is how a wrong anchor surfaces);
/// only a signature that fails under the pinned key fails outright.
pub fn check_slot(slot: &SigSlot, anchor: &PublicKey, body: &[u8]) -> SlotCheck {
    check_slot_in(slot, std::slice::from_ref(anchor), body)
}

/// Check one carrier slot against a set of pinned anchors (the
/// multi-suite co-signature form): the slot is verified against the
/// anchor whose key id it names; an unlisted key id is `UnknownKey`
/// (degraded — the verifier's trust configuration does not cover that
/// suite's signer), never a global failure.
pub fn check_slot_in(slot: &SigSlot, anchors: &[PublicKey], body: &[u8]) -> SlotCheck {
    let suite = Suite::from_core(slot.suite);
    if !suite.is_computed() {
        return SlotCheck::Deferred {
            suite: suite.to_string(),
            detail: suite
                .deferral()
                .unwrap_or("computation deferred to a binding crate")
                .to_string(),
        };
    }
    let Ok(key_id) = KeyId::new(&slot.key_id) else {
        return SlotCheck::Invalid {
            suite: slot.suite.to_string(),
            why: format!("malformed key id `{}`", slot.key_id),
        };
    };
    let Some(anchor) = anchors.iter().find(|a| KeyId::of(a) == key_id) else {
        return SlotCheck::UnknownKey {
            key_id: slot.key_id.clone(),
            anchor_key_id: anchors
                .iter()
                .map(|a| KeyId::of(a).to_string())
                .collect::<Vec<_>>()
                .join(","),
        };
    };
    check_slot_against(slot, anchor, body)
}

fn check_slot_against(slot: &SigSlot, anchor: &PublicKey, body: &[u8]) -> SlotCheck {
    let Ok(signatif_slot) = SignatureSlot::from_sig_slot(slot) else {
        return SlotCheck::Invalid {
            suite: slot.suite.to_string(),
            why: "slot does not map onto the SIGNATIF suite table".to_string(),
        };
    };
    match signatif_slot.verify(SigningDomain::ArtifactEvent, body, anchor) {
        Ok(()) => SlotCheck::Verified {
            suite: signatif_suite_string(slot),
            key_id: slot.key_id.clone(),
        },
        Err(unidpp_signatif::SignatifError::SuiteDeferred { detail, .. }) => SlotCheck::Deferred {
            suite: signatif_suite_string(slot),
            detail,
        },
        Err(e) => SlotCheck::Invalid {
            suite: signatif_suite_string(slot),
            why: e.to_string(),
        },
    }
}

/// The SIGNATIF suite token of a core carrier slot.
fn signatif_suite_string(slot: &SigSlot) -> String {
    Suite::from_core(slot.suite).to_string()
}

/// Whether the core carrier suite has real computation here (used to
/// phrase findings honestly for framing-only slots without an anchor).
pub fn suite_is_computed(suite: SignatureSuite) -> bool {
    Suite::from_core(suite).is_computed()
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_event::{EventLog, SafetyFlag, Status};
    use unidpp_model::{Interval, PassportId, Timestamp};
    use unidpp_tier_a::TierAPacker;

    fn sample() -> TierAPayload {
        let subject = PassportId::new("urn:unidpp:passport:test-1").unwrap();
        let mut log = EventLog::new(subject.clone());
        let event = unidpp_event::TypedEvent::new(
            0,
            Timestamp::from_secs(1_800_000_000),
            "issuing authority",
            "eo-1",
            unidpp_event::EventType::Issuance,
            unidpp_event::EventPayload::Issuance {
                derived: false,
                inputs: vec![],
            },
            unidpp_model::TrustMarker::Attested,
        )
        .unwrap();
        log.append(event, None, None).unwrap();
        TierAPayload::from_log(
            &log,
            unidpp_model::ProductIdentifier::parse("gtin:4006381333931").unwrap(),
            "https://resolver.unidpp.org/r/test-1",
            "eo-1",
            Interval::starting(Timestamp::from_secs(1_800_000_000)),
            vec![],
        )
    }

    #[test]
    fn budget_grammar() {
        assert_eq!(parse_budget("qr-v15-M").unwrap(), (EcLevel::M, 15));
        assert_eq!(parse_budget("QR-V3-h").unwrap(), (EcLevel::H, 3));
        assert_eq!(DEFAULT_BUDGET, (EcLevel::M, 40));
        assert!(parse_budget("qr-v0-M").is_err());
        assert!(parse_budget("qr-v41-M").is_err());
        assert!(parse_budget("qr-v15-X").is_err());
        assert!(parse_budget("qr-vX-M").is_err());
        assert!(parse_budget("qr-v15").is_err());
        assert!(parse_budget("v15-M").is_err());
    }

    #[test]
    fn signing_body_is_a_fixpoint() {
        let payload = sample();
        let bare = signing_body(&payload).unwrap();
        let (bytes, _) = TierAPacker::encode(&payload).unwrap();
        assert_eq!(
            bare, bytes,
            "unsigned payload: clearing slots changes nothing"
        );

        let (signed, _public, key_id) = sign_pack(&payload, b"seed-a").unwrap();
        assert_eq!(signed.signatures.len(), 1);
        assert_eq!(signed.signatures[0].key_id, key_id.to_string());
        assert!(signed.signatures[0].signature.is_some());
        // The signed body is invariant to the slots that were added.
        assert_eq!(signing_body(&signed).unwrap(), bare);
    }

    #[test]
    fn signed_pack_verifies_and_tampering_fails() {
        let payload = sample();
        let (signed, public, _) = sign_pack(&payload, b"seed-a").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let decoded = TierAPacker::decode(packed.as_slice()).unwrap();
        let body = signing_body(&decoded).unwrap();
        assert!(matches!(
            check_slot(&decoded.signatures[0], &public, &body),
            SlotCheck::Verified { .. }
        ));

        // Tamper the product identity and re-encode with the original
        // signature: the check must fail.
        let mut tampered = decoded.clone();
        tampered.product_id = unidpp_model::ProductIdentifier::parse("gtin:4006381333930").unwrap();
        let tampered_body = signing_body(&tampered).unwrap();
        assert!(matches!(
            check_slot(&decoded.signatures[0], &public, &tampered_body),
            SlotCheck::Invalid { .. }
        ));

        // Wrong anchor: degraded unknown-key, never a crypto failure.
        let other = KeyPair::seeded(Suite::EcdsaP256, b"seed-b").unwrap();
        assert!(matches!(
            check_slot(&decoded.signatures[0], other.public(), &body),
            SlotCheck::UnknownKey { .. }
        ));

        // Deferred suite honesty: a suite that never computes here
        // (ML-DSA-44) framed with a fake value reports Deferred, not
        // Invalid. (SM2/ML-DSA-65 compute in this build — the
        // multi-suite test below covers them.)
        let mut framed = unidpp_model::SigSlot::placeholder(SignatureSuite::MlDsa44, "k-framed");
        framed.signature = Some(vec![0u8; 2420]);
        assert!(matches!(
            check_slot(&framed, &public, &body),
            SlotCheck::Deferred { .. }
        ));
    }

    #[test]
    fn multi_suite_pack_cosigns_one_body() {
        let payload = sample();
        let suites = [Suite::EcdsaP256, Suite::Sm2, Suite::MlDsa65];
        let (signed, anchors) = sign_pack_suites(&payload, b"seed-a", &suites).unwrap();
        assert_eq!(signed.signatures.len(), 3);
        // One signing body, three sovereign suites: every slot verifies
        // against its own anchor.
        let body = signing_body(&signed).unwrap();
        for (slot, (public, key_id)) in signed.signatures.iter().zip(&anchors) {
            assert_eq!(slot.key_id, key_id.to_string());
            assert!(matches!(
                check_slot_in(
                    &signed.signatures[0],
                    &anchors.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
                    &body
                ),
                SlotCheck::Verified { .. }
            ));
            assert!(matches!(
                check_slot(slot, public, &body),
                SlotCheck::Verified { .. }
            ));
        }
        // Suite-separated seeds: the same base seed yields distinct
        // key ids per suite (no shared scalar across curves).
        let ids: Vec<_> = anchors.iter().map(|(_, k)| k.to_string()).collect();
        let set: std::collections::BTreeSet<_> = ids.iter().collect();
        assert_eq!(set.len(), 3);
        // Tampered body fails in every computed suite.
        let mut tampered = signed.clone();
        tampered.product_id = unidpp_model::ProductIdentifier::parse("gtin:4006381333930").unwrap();
        let tampered_body = signing_body(&tampered).unwrap();
        for slot in &signed.signatures {
            assert!(matches!(
                check_slot_in(
                    slot,
                    &anchors.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
                    &tampered_body
                ),
                SlotCheck::Invalid { .. }
            ));
        }
    }

    #[test]
    fn multi_suite_pack_carries_both_classical_suites_on_the_qr() {
        // P-256 + SM2 slots (64 + 64 signature bytes) fit the QR
        // carrier; the pair rides one pack body (the co-signature
        // model). ML-DSA-65's 3309-byte slot exceeds any QR budget —
        // it rides Tier-B/NFC carriers, not Tier-A QR.
        let payload = sample();
        let (signed, anchors) =
            sign_pack_suites(&payload, b"seed-a", &[Suite::EcdsaP256, Suite::Sm2]).unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let decoded = TierAPacker::decode(packed.as_slice()).unwrap();
        assert_eq!(decoded.signatures.len(), 2);
        let body = signing_body(&decoded).unwrap();
        let pinned: Vec<_> = anchors.iter().map(|(p, _)| *p).collect();
        for slot in &decoded.signatures {
            assert!(matches!(
                check_slot_in(slot, &pinned, &body),
                SlotCheck::Verified { .. }
            ));
        }
        // Wrong-anchor subset (verifier pins only the P-256 anchor):
        // the SM2 slot degrades per suite, the P-256 slot still
        // verifies — degradation is scoped, never global.
        let p256_only: Vec<_> = pinned[..1].to_vec();
        let mut seen_verified = false;
        let mut seen_unknown = false;
        for slot in &decoded.signatures {
            match check_slot_in(slot, &p256_only, &body) {
                SlotCheck::Verified { .. } => seen_verified = true,
                SlotCheck::UnknownKey { .. } => seen_unknown = true,
                other => panic!("expected Verified or UnknownKey, got {other:?}"),
            }
        }
        assert!(seen_verified && seen_unknown);
    }

    #[test]
    fn suite_seed_separation_keeps_p256_compatible() {
        // The P-256 seed is consumed verbatim: existing anchors keep
        // verifying packs minted before the multi-suite era.
        assert_eq!(pack_suite_seed(b"seed-a", Suite::EcdsaP256), b"seed-a");
        let sm2 = pack_suite_seed(b"seed-a", Suite::Sm2);
        assert_ne!(sm2, b"seed-a".to_vec());
        assert_eq!(sm2.len(), 32);
        assert_ne!(sm2, pack_suite_seed(b"seed-a", Suite::MlDsa65));
    }

    #[test]
    fn sample_pack_round_trips_with_status_and_safety() {
        let payload = sample();
        let (signed, _, _) = sign_pack(&payload, b"seed-a").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let decoded = TierAPacker::decode(packed.as_slice()).unwrap();
        assert_eq!(decoded.status, Status::Issued);
        assert_eq!(decoded.safety, SafetyFlag::None);
        assert!(decoded.log_head.is_some());
    }
}
