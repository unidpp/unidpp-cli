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
    let key = KeyPair::seeded(Suite::EcdsaP256, seed)
        .map_err(|e| format!("cannot derive the pack signing key: {e}"))?;
    let body = signing_body(payload).map_err(|e| e.to_string())?;
    let slot = SignatureSlot::sign(&key, SigningDomain::ArtifactEvent, &body)
        .map_err(|e| format!("pack signing failed: {e}"))?;
    let slot: SigSlot = slot
        .to_sig_slot()
        .expect("ecdsa-p256 maps onto the core carrier table");
    let mut signed = payload.clone();
    signed.signatures = vec![slot];
    Ok((signed, *key.public(), key.key_id().clone()))
}

/// Verify one decoded carrier slot against an anchor public key.
///
/// Grading (the pack-verdict ladder):
/// - key id mismatch — the anchor does not pin this signing key:
///   **degraded**, the verifier's trust configuration simply does not
///   cover the signer (this is how a wrong anchor surfaces);
/// - signature invalid under the pinned key: **fail** — tampering;
/// - deferred suite: **degraded** (framing-only, honestly reported).
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
    let anchor_key_id = KeyId::of(anchor);
    let Ok(key_id) = KeyId::new(&slot.key_id) else {
        return SlotCheck::Invalid {
            suite: slot.suite.to_string(),
            why: format!("malformed key id `{}`", slot.key_id),
        };
    };
    if key_id != anchor_key_id {
        return SlotCheck::UnknownKey {
            key_id: slot.key_id.clone(),
            anchor_key_id: anchor_key_id.to_string(),
        };
    }
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

        // Deferred suite honesty: an SM2 slot framed with a fake value
        // reports Deferred, not Invalid.
        let mut sm2 = unidpp_model::SigSlot::placeholder(SignatureSuite::Sm2, "k-sm2");
        sm2.signature = Some(vec![0u8; 64]);
        assert!(matches!(
            check_slot(&sm2, &public, &body),
            SlotCheck::Deferred { .. }
        ));
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
