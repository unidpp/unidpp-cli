//! `unidpp event`: append a typed event to a passport's log.

use std::collections::BTreeMap;
use std::path::PathBuf;

use unidpp_event::{EventPayload, EventType, TypedEvent};
use unidpp_model::Timestamp;
use unidpp_signatif::keyring::KeyPair;
use unidpp_signatif::sign::{SignatureSlot, SigningDomain, Suite};

use crate::commands::{parse_timestamp, take_value, CommandError};
use crate::encoding::hex_encode;
use crate::exit;
use crate::passport::{EventSignature, Passport};

/// The `event` usage text.
pub const USAGE: &str = "\
unidpp event - append a typed event to a passport's log

USAGE:
    unidpp event --passport <FILE> --type <TYPE> [OPTIONS]

OPTIONS:
    --passport <FILE>   the passport document to append to (updated in place)
    --type <TYPE>       event class token, e.g. custody.transfer, issuance,
                        correction, status.change, recall.campaign, split,
                        software.update, inspection.stamp, ... (casing and
                        separators are free: CustodyTransfer parses too)
    --data <JSON>       the typed payload, as the variant's JSON object:
                          {\"CustodyTransfer\":{\"from\":\"mfg\",\"to\":\"dist\",
                                             \"counterparty_signed\":true}}
                        The wrapper key may be omitted when --type is given.
                        Common payloads:
                          issuance:      {\"derived\":false,\"inputs\":[]}
                          custody.transfer: from,to,counterparty_signed
                          correction:    field,prior_value,new_value,reason
                          status.change: from,to,authority
                          software.update: versions{},unlocked_features[]
    --key <SEED>        sign the event's canonical body with a seeded
                        Ed25519 key (deterministic; the signature is
                        recorded in the document; the event is marked
                        attested). Without a key the event is unsigned.
    --actor <ID>        acting operator id (default: the passport's EO id)
    --actor-role <ROLE> acting role (default: the class's appending role)
    --at <TIMESTAMP>    event time (default: now)
    --out <FILE>        write the updated passport here instead of in place

The append is unsalted (the CLI keeps owner-side salt ceremonies out of
scope), so the chain fully recomputes on every later verification.";

/// Options parsed from the command line.
#[derive(Debug, Clone, Default)]
struct EventArgs {
    passport: Option<PathBuf>,
    event_type: Option<String>,
    data: Option<String>,
    key: Option<String>,
    actor: Option<String>,
    actor_role: Option<String>,
    at: Option<String>,
    out: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<EventArgs, CommandError> {
    let mut parsed = EventArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--passport" | "-p" => {
                parsed.passport = Some(PathBuf::from(take_value(args, &mut i, "--passport")?))
            }
            "--type" | "-t" => parsed.event_type = Some(take_value(args, &mut i, "--type")?),
            "--data" | "-d" => parsed.data = Some(take_value(args, &mut i, "--data")?),
            "--key" | "-k" => parsed.key = Some(take_value(args, &mut i, "--key")?),
            "--actor" => parsed.actor = Some(take_value(args, &mut i, "--actor")?),
            "--actor-role" => parsed.actor_role = Some(take_value(args, &mut i, "--actor-role")?),
            "--at" => parsed.at = Some(take_value(args, &mut i, "--at")?),
            "--out" => parsed.out = Some(PathBuf::from(take_value(args, &mut i, "--out")?)),
            other => {
                return Err(CommandError::Usage(format!(
                    "event: unknown option `{other}` (see `unidpp help event`)"
                )))
            }
        }
        i += 1;
    }
    Ok(parsed)
}

/// The serde variant name of each event class (the externally-tagged
/// JSON key of its payload variant).
fn variant_name(event_type: EventType) -> &'static str {
    use EventType::*;
    match event_type {
        CustodyTransfer => "CustodyTransfer",
        PartReplace => "PartReplace",
        RepairPerform => "RepairPerform",
        ProductModify => "ProductModify",
        SoftwareUpdate => "SoftwareUpdate",
        UpgradeInstall => "UpgradeInstall",
        RefurbishRemanufacture => "RefurbishRemanufacture",
        ConsumableReplace => "ConsumableReplace",
        RecallCampaign => "RecallCampaign",
        Correction => "Correction",
        StatusChange => "StatusChange",
        FlagSecurity => "FlagSecurity",
        Decompose => "Decompose",
        InspectionStamp => "InspectionStamp",
        MilestoneRecord => "MilestoneRecord",
        Split => "Split",
        Combine => "Combine",
        EndOfWaste => "EndOfWaste",
        Install => "Install",
        Uninstall => "Uninstall",
        Issuance => "Issuance",
        EdgeVisibilityChange => "EdgeVisibilityChange",
        EscrowDisclosure => "EscrowDisclosure",
    }
}

/// The default appending role for each class (cleaned from the
/// taxonomy's descriptive appender notes).
fn default_role(event_type: EventType) -> &'static str {
    use EventType::*;
    match event_type {
        CustodyTransfer | Split | Combine | ConsumableReplace => "custodian",
        Issuance => "issuing authority",
        PartReplace | RepairPerform | Install | Uninstall | UpgradeInstall => "installer",
        ProductModify => "accredited modifier",
        SoftwareUpdate => "economic operator",
        RefurbishRemanufacture => "refurbisher",
        RecallCampaign | StatusChange => "regulator",
        Correction => "economic operator",
        FlagSecurity => "authority",
        Decompose => "recycler",
        EndOfWaste => "accredited actor",
        InspectionStamp => "verifier",
        MilestoneRecord => "device",
        EdgeVisibilityChange | EscrowDisclosure => "edge owner",
    }
}

/// The payload used when `--data` is omitted: only the classes whose
/// payloads have no operator-supplied content.
fn default_payload(event_type: EventType) -> Option<EventPayload> {
    match event_type {
        EventType::Issuance => Some(EventPayload::Issuance {
            derived: false,
            inputs: vec![],
        }),
        EventType::MilestoneRecord => Some(EventPayload::MilestoneRecord {
            counters: BTreeMap::new(),
        }),
        _ => None,
    }
}

/// Build the typed payload from `--data`: either an already-wrapped
/// single-variant object (`{"CustodyTransfer":{...}}`) or the bare
/// variant body, wrapped using `--type`. Type agreement with `--type`
/// is enforced either way.
fn payload_from_data(event_type: EventType, data: &str) -> Result<EventPayload, CommandError> {
    let value: serde_json::Value = serde_json::from_str(data)
        .map_err(|e| CommandError::Usage(format!("--data is not JSON: {e}")))?;
    let is_wrapped = value
        .as_object()
        .map(|m| {
            m.len() == 1
                && EventType::ALL
                    .iter()
                    .any(|t| m.contains_key(variant_name(*t)))
        })
        .unwrap_or(false);
    let wrapped = if is_wrapped {
        value
    } else {
        serde_json::json!({ variant_name(event_type): value })
    };
    let payload: EventPayload = serde_json::from_value(wrapped).map_err(|e| {
        CommandError::Usage(format!(
            "--data does not match the `{event_type}` payload shape: {e}"
        ))
    })?;
    if payload.event_type() != event_type {
        return Err(CommandError::Usage(format!(
            "--data carries a {} payload but --type is {event_type}",
            payload.event_type()
        )));
    }
    Ok(payload)
}

/// Run the command.
pub fn run(args: &[String]) -> Result<u8, CommandError> {
    let parsed = parse(args)?;
    let path = parsed
        .passport
        .clone()
        .ok_or_else(|| CommandError::Usage("event: `--passport <FILE>` is required".to_string()))?;
    let token = parsed
        .event_type
        .clone()
        .ok_or_else(|| CommandError::Usage("event: `--type <TYPE>` is required".to_string()))?;
    let event_type =
        EventType::parse_token(&token).map_err(|e| CommandError::Usage(format!("--type: {e}")))?;
    let payload = match (&parsed.data, default_payload(event_type)) {
        (Some(data), _) => payload_from_data(event_type, data)?,
        (None, Some(payload)) => payload,
        (None, None) => {
            return Err(CommandError::Usage(format!(
                "event: `--data` is required for {event_type} (payload has \
                 operator-supplied fields; see `unidpp help event`)"
            )))
        }
    };

    let mut passport = Passport::load(&path).map_err(CommandError::Usage)?;
    let occurred_at = match &parsed.at {
        Some(v) => parse_timestamp(v, "--at")?,
        None => Timestamp::now(),
    };
    let seq = passport.log.len() as u64;
    let actor_role = parsed
        .actor_role
        .clone()
        .unwrap_or_else(|| default_role(event_type).to_string());
    let actor_id = parsed
        .actor
        .clone()
        .unwrap_or_else(|| passport.eo_id.clone());
    let trust = if parsed.key.is_some() {
        unidpp_model::TrustMarker::Attested
    } else {
        unidpp_model::TrustMarker::Unsigned
    };
    let event = TypedEvent::new(
        seq,
        occurred_at,
        &actor_role,
        &actor_id,
        event_type,
        payload,
        trust,
    )
    .map_err(|e| CommandError::Usage(format!("event rejected: {e}")))?;
    let body = event
        .canonical_body()
        .map_err(|e| CommandError::Failure(e.to_string()))?;
    let head = passport
        .log
        .append(event, None, None)
        .map_err(|e| CommandError::Failure(e.to_string()))?;

    if let Some(seed) = &parsed.key {
        let key = KeyPair::seeded(Suite::Ed25519, seed.as_bytes())
            .map_err(|e| CommandError::Failure(format!("cannot derive the signing key: {e}")))?;
        let slot = SignatureSlot::sign(&key, SigningDomain::ArtifactEvent, &body)
            .map_err(|e| CommandError::Failure(format!("event signing failed: {e}")))?;
        passport.event_signatures.push(EventSignature {
            seq,
            suite: slot.suite.to_string(),
            key_id: slot.key_id.to_string(),
            signature: hex_encode(
                slot.signature
                    .as_deref()
                    .expect("SignatureSlot::sign fills the value"),
            ),
        });
        eprintln!(
            "signed event #{seq} with {} key {} (public key, hex): {}",
            slot.suite,
            slot.key_id,
            hex_encode(key.public().as_bytes())
        );
    }

    let destination = parsed.out.clone().unwrap_or_else(|| path.clone());
    passport.save(&destination).map_err(CommandError::Failure)?;
    println!(
        "event #{seq} {} appended by {actor_id} ({actor_role}); log head {}..; \
         status {}; safety {}",
        event_type,
        &head.hex()[..16],
        passport.log.current_status(),
        passport.log.safety_flag()
    );
    Ok(exit::PASS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_names_are_unique_and_total() {
        let mut seen = std::collections::BTreeSet::new();
        for event_type in EventType::ALL {
            let name = variant_name(*event_type);
            assert!(!name.is_empty());
            assert!(seen.insert(name), "duplicate variant name `{name}`");
        }
        assert_eq!(seen.len(), EventType::ALL.len());
    }

    #[test]
    fn default_payloads_round_trip_through_the_wrapped_form() {
        for event_type in [EventType::Issuance, EventType::MilestoneRecord] {
            let payload = default_payload(event_type).unwrap();
            let json = serde_json::to_value(&payload).unwrap();
            let text = json.to_string();
            assert_eq!(payload_from_data(event_type, &text).unwrap(), payload);
        }
    }

    #[test]
    fn bare_body_and_wrapped_forms_agree() {
        let bare = payload_from_data(
            EventType::CustodyTransfer,
            r#"{"from":"a","to":"b","counterparty_signed":true}"#,
        )
        .unwrap();
        let wrapped = payload_from_data(
            EventType::CustodyTransfer,
            r#"{"CustodyTransfer":{"from":"a","to":"b","counterparty_signed":true}}"#,
        )
        .unwrap();
        assert_eq!(bare, wrapped);
    }

    #[test]
    fn type_mismatch_and_bad_shapes_are_usage_errors() {
        assert!(payload_from_data(
            EventType::Issuance,
            r#"{"from":"a","to":"b","counterparty_signed":true}"#
        )
        .is_err());
        assert!(payload_from_data(EventType::Correction, "not json").is_err());
        assert!(
            payload_from_data(EventType::Correction, r#"{"Correction":{"field":"f"}}"#).is_err()
        );
    }

    #[test]
    fn default_roles_and_payloads_exist() {
        for event_type in EventType::ALL {
            assert!(!default_role(*event_type).is_empty());
        }
        assert!(default_payload(EventType::Issuance).is_some());
        assert!(default_payload(EventType::MilestoneRecord).is_some());
        assert!(default_payload(EventType::Correction).is_none());
    }
}
