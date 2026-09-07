//! `unidpp verify` — the flagship: unpack a Tier-A pack, check it, and
//! print the graded verdict.
//!
//! Pipeline (each stage is a finding, never a silent skip):
//!
//! 1. **unpack + schema** — canonical Tier-A decode; a broken frame is
//!    an outright Fail;
//! 2. **signature check** — every slot's real cryptographic
//!    verification against the supplied anchor (an unknown signing key
//!    *degrades* — the verifier's trust configuration does not cover
//!    the signer — while a signature that fails under the pinned key
//!    *fails* — tampering);
//! 3. **freshness** — the as-of stamp against the window
//!    (`--max-age`, default 24 h; `0` selects static/archival
//!    semantics);
//! 4. **evidence** — log-head commitment, validity window;
//! 5. **current state** — replayed status and the critical safety /
//!    recall flag.
//!
//! The three readings (cryptographic / evidentiary / current-state) are
//! printed alongside a coverage report and the findings table; the
//! verdict states which reading it answers (`current-state`: a Tier-A
//! pack is the current-state projection an officer decides on).
//!
//! What a Tier-A carrier *cannot* assess offline is reported honestly
//! instead of guessed: the retroactive-taint cascade needs registry /
//! revocation state (Tier B), so the current-state reading carries that
//! caveat rather than fabricating a pass.

use std::collections::BTreeSet;
use std::path::PathBuf;

use unidpp_event::{SafetyFlag, Status};
use unidpp_model::{FreshnessRequirement, Timestamp, TrustMarker};
use unidpp_signatif::keyring::PublicKey;
use unidpp_tier_a::{TierAPacker, TierAPayload};
use unidpp_verdict::{evaluate_freshness, CoverageReport, FreshnessVerdict};

use crate::commands::{parse_timestamp, take_value, CommandError};
use crate::encoding::{auto_decode, hex_decode, Encoding};
use crate::packfile::{check_slot_in, signing_body, SlotCheck};
use crate::report::{render_table, Finding, Grade};

/// The default freshness window of an offline pack (24 h). The Primmel
/// doctrine: unbounded staleness becomes bounded `fresh_within`.
pub const DEFAULT_MAX_AGE_SECS: i64 = 86_400;

/// Which reading the pack verdict answers.
pub const READING_ANSWERED: &str = "current-state";

/// The `verify` usage text.
pub const USAGE: &str = "\
unidpp verify - unpack a Tier-A pack and print the graded verdict

USAGE:
    unidpp verify <PACK-FILE-OR-ENCODED> [OPTIONS]

ARGUMENT:
    PACK-FILE-OR-ENCODED   a path to a file containing the pack, or the
                           pack itself as hex/base64 text

OPTIONS:
    --anchor <PUBKEY>       the verifier's pinned issuer public key:
                           raw hex (65 bytes 04||X||Y for ECDSA-P256,
                           32 bytes Ed25519, 1952 bytes ML-DSA-65) or
                           suite:hex for the ambiguous SM2 form (e.g.
                           sm2:04ab...). With no anchor, signature
                           slots cannot be verified and the verdict
                           degrades.
    --as-of <TIMESTAMP>    verification moment (default: now)
    --max-age <SECONDS>    freshness window (default 86400; 0 = static /
                           archival semantics: never stale)
    --image <FILE>         decode a QR carrier from a still photo (PNG)
                           and verify the pack it carries; a QR holding a
                           resolver URI is surfaced explicitly
    --camera               live camera capture (not linked in this build:
                           photograph the carrier and use --image)
    --encoding <ENC>       force hex or base64 (default: auto-detect)
    --json                 machine-readable report on stdout

EXIT CODES: 0 pass, 1 degraded, 2 fail.";

/// One reading row of the verdict.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Reading {
    /// Reading name (cryptographic / evidentiary / current-state).
    pub name: &'static str,
    /// Grade of this reading.
    pub grade: Grade,
    /// Officer-facing detail.
    pub detail: String,
}

/// The full verification outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyOutcome {
    /// Overall grade (worst finding).
    pub grade: Grade,
    /// The decoded payload (`None` when unpacking failed).
    pub payload: Option<TierAPayload>,
    /// Per-check findings, in pipeline order.
    pub findings: Vec<Finding>,
    /// The three readings.
    pub readings: Vec<Reading>,
    /// Which reading the verdict answers.
    pub reading_answered: &'static str,
    /// Derived trust marker (`None` when unpacking failed).
    pub trust_marker: Option<TrustMarker>,
    /// Tier-A field coverage (`None` when unpacking failed).
    pub coverage: Option<CoverageReport>,
    /// Freshness verdict (`None` when unpacking failed).
    pub freshness: Option<FreshnessVerdict>,
}

/// Current-state grade of a replayed status.
fn status_grade(status: Status) -> Grade {
    match status {
        Status::Issued => Grade::Pass,
        Status::Suspended
        | Status::Consumed
        | Status::Transformed
        | Status::EndOfWaste
        | Status::Archived => Grade::Degraded,
        Status::Invalidated | Status::NonConformant => Grade::Fail,
    }
}

fn status_detail(status: Status) -> String {
    match status {
        Status::Issued => "issued: in active circulation".to_string(),
        Status::Suspended => "suspended: circulation paused pending resolution".to_string(),
        Status::Consumed => {
            "consumed: input of a transformation, no longer in circulation".to_string()
        }
        Status::Transformed => "transformed: superseded by derived passports".to_string(),
        Status::EndOfWaste => "end-of-waste status: waste regime re-entry".to_string(),
        Status::Archived => "archived: lifecycle ended".to_string(),
        Status::Invalidated => "invalidated: not valid for circulation".to_string(),
        Status::NonConformant => "non-conformant: failed evaluation".to_string(),
    }
}

fn safety_grade(safety: SafetyFlag) -> Grade {
    match safety {
        SafetyFlag::None => Grade::Pass,
        SafetyFlag::RecallActive | SafetyFlag::SecurityFlagged => Grade::Fail,
    }
}

fn safety_detail(safety: SafetyFlag) -> String {
    match safety {
        SafetyFlag::None => "no recall or security flag".to_string(),
        SafetyFlag::RecallActive => "RECALL ACTIVE: do not release".to_string(),
        SafetyFlag::SecurityFlagged => "SECURITY FLAGGED: do not release".to_string(),
    }
}

fn worst_of(findings: &[Finding]) -> Grade {
    findings
        .iter()
        .map(|f| f.grade)
        .fold(Grade::Pass, |acc, g| acc.worst(g))
}

/// Tier-A required-field coverage: the eight mandatory carrier fields
/// (always present in a decoded pack) plus the two optional pieces of
/// evidence (log-head commitment, real signature).
fn coverage_of(payload: &TierAPayload) -> CoverageReport {
    let required: Vec<String> = [
        "product_id",
        "resolver_uri",
        "passport_id",
        "eo_id",
        "status",
        "safety",
        "validity",
        "as_of",
        "log_head",
        "signature",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let mut present: Vec<String> = required[..8].to_vec();
    if payload.log_head.is_some() {
        present.push("log_head".to_string());
    }
    if payload.signatures.iter().any(|s| s.signature.is_some()) {
        present.push("signature".to_string());
    }
    CoverageReport { required, present }
}

/// Run the verification pipeline over decoded pack bytes.
pub fn verify_pack(
    bytes: &[u8],
    anchor: Option<&PublicKey>,
    now: Timestamp,
    max_age_secs: i64,
) -> VerifyOutcome {
    let anchors: Vec<PublicKey> = anchor.copied().into_iter().collect();
    verify_pack_with_anchors(bytes, &anchors, now, max_age_secs)
}

/// Verify a pack against a **set** of pinned anchors — one per
/// co-signing suite (the sovereign co-signature model). Each filled
/// slot is checked against the anchor whose key id it names; an
/// unpinned key id degrades *that slot only* (`UnknownKey`), so a
/// verifier that pins just the EU P-256 anchor reads the pack as
/// degraded on the CN SM2 slot, never as globally failed.
pub fn verify_pack_with_anchors(
    bytes: &[u8],
    anchors: &[PublicKey],
    now: Timestamp,
    max_age_secs: i64,
) -> VerifyOutcome {
    let mut findings: Vec<Finding> = Vec::new();

    // Stage 1: unpack + schema.
    let payload = match TierAPacker::decode(bytes) {
        Ok(payload) => payload,
        Err(e) => {
            findings.push(Finding::new(
                "schema/decode",
                Grade::Fail,
                format!("Tier-A decode failed: {e}"),
            ));
            return VerifyOutcome {
                grade: Grade::Fail,
                payload: None,
                findings,
                readings: vec![Reading {
                    name: "cryptographic",
                    grade: Grade::Fail,
                    detail: "carrier does not decode: nothing to verify".to_string(),
                }],
                reading_answered: READING_ANSWERED,
                trust_marker: None,
                coverage: None,
                freshness: None,
            };
        }
    };
    findings.push(Finding::new(
        "schema/decode",
        Grade::Pass,
        format!(
            "canonical Tier-A framing intact ({} signature {})",
            payload.signatures.len(),
            if payload.signatures.len() == 1 {
                "slot"
            } else {
                "slots"
            }
        ),
    ));

    // Stage 2: signature check against the anchor.
    let body = match signing_body(&payload) {
        Ok(body) => body,
        Err(e) => {
            findings.push(Finding::new(
                "signature/body",
                Grade::Fail,
                format!("cannot rebuild the canonical signing body: {e}"),
            ));
            Vec::new()
        }
    };
    let mut signature_findings: Vec<Finding> = Vec::new();
    let mut verified = 0usize;
    let mut present = 0usize;
    let mut distinct_suites: BTreeSet<unidpp_model::SignatureSuite> = BTreeSet::new();
    if payload.signatures.is_empty() {
        signature_findings.push(Finding::new(
            "signature/none",
            Grade::Degraded,
            "pack carries no signature slots (trust marker unsigned)",
        ));
    } else {
        for (i, slot) in payload.signatures.iter().enumerate() {
            let name = format!("signature/{}/slot-{}", slot.suite, i + 1);
            if slot.signature.is_none() {
                signature_findings.push(Finding::new(
                    name,
                    Grade::Degraded,
                    "slot is framed-only: framing present, no signature value".to_string(),
                ));
                continue;
            }
            present += 1;
            distinct_suites.insert(slot.suite);
            if anchors.is_empty() {
                signature_findings.push(Finding::new(
                    name,
                    Grade::Degraded,
                    "no anchor supplied: signature present but unverifiable \
                     (verifier without trust configuration)"
                        .to_string(),
                ));
            } else {
                let check = check_slot_in(slot, anchors, &body);
                let grade = match &check {
                    SlotCheck::Verified { .. } => {
                        verified += 1;
                        Grade::Pass
                    }
                    SlotCheck::UnknownKey { .. } | SlotCheck::Deferred { .. } => Grade::Degraded,
                    SlotCheck::Invalid { .. } => Grade::Fail,
                };
                signature_findings.push(Finding::new(name, grade, check.detail()));
            }
        }
    }
    findings.extend(signature_findings.iter().cloned());

    // Stage 3: freshness.
    let requirement = if max_age_secs <= 0 {
        FreshnessRequirement::Static
    } else {
        FreshnessRequirement::FreshWithin { max_age_secs }
    };
    let freshness = evaluate_freshness(now, Some(payload.as_of), requirement);
    let age = now.signed_secs_since(payload.as_of).max(0);
    let freshness_finding = match freshness {
        FreshnessVerdict::Fresh { .. } => Finding::new(
            "freshness",
            Grade::Pass,
            format!("fresh: as-of stamp is {age}s old (window {max_age_secs}s)"),
        ),
        FreshnessVerdict::Stale { .. } => Finding::new(
            "freshness",
            Grade::Degraded,
            format!("stale: as-of stamp is {age}s old, window {max_age_secs}s"),
        ),
        FreshnessVerdict::Indeterminate => Finding::new(
            "freshness",
            Grade::Degraded,
            "no as-of evidence (cannot happen in a decoded Tier-A pack)".to_string(),
        ),
    };
    findings.push(freshness_finding.clone());

    // Stage 4: evidence — log-head commitment and validity window.
    let log_head_finding = match payload.log_head {
        Some(head) => Finding::new(
            "evidence/log-head",
            Grade::Pass,
            format!(
                "log-head commitment {}.. pins the event-log chain head",
                &head.hex()[..16]
            ),
        ),
        None => Finding::new(
            "evidence/log-head",
            Grade::Degraded,
            "no log-head commitment: the pack cannot anchor the passport's event log".to_string(),
        ),
    };
    findings.push(log_head_finding.clone());
    let validity_finding = if payload.validity.contains(now) {
        Finding::new(
            "evidence/validity",
            Grade::Pass,
            format!(
                "verification moment inside the validity window {}",
                payload.validity
            ),
        )
    } else {
        Finding::new(
            "evidence/validity",
            Grade::Degraded,
            format!(
                "verification moment outside the validity window {}",
                payload.validity
            ),
        )
    };
    findings.push(validity_finding.clone());

    // Stage 5: current state — status and the critical safety flag.
    let status_finding = Finding::new(
        "status",
        status_grade(payload.status),
        status_detail(payload.status),
    );
    findings.push(status_finding.clone());
    let safety_finding = Finding::new(
        "safety",
        safety_grade(payload.safety),
        safety_detail(payload.safety),
    );
    findings.push(safety_finding.clone());

    let coverage = coverage_of(&payload);
    let trust_marker = TrustMarker::of(present, distinct_suites.len(), verified > 0, false);

    let cryptographic = Reading {
        name: "cryptographic",
        grade: worst_of(&signature_findings),
        detail: format!(
            "{verified}/{} slots verified against the anchor; trust marker {}",
            payload.signatures.len(),
            trust_marker.as_str()
        ),
    };
    let evidentiary = Reading {
        name: "evidentiary",
        grade: worst_of(&[freshness_finding, log_head_finding, validity_finding]),
        detail: format!(
            "as-of {}; freshness {}; coverage {}/{}",
            payload.as_of,
            freshness.label(),
            coverage.present.len(),
            coverage.required.len()
        ),
    };
    let current_state = Reading {
        name: "current-state",
        grade: worst_of(&[status_finding, safety_finding]),
        detail: format!(
            "status {}; safety {}; retroactive taints not assessable from a \
             Tier-A carrier (needs registry/revocation state)",
            payload.status, payload.safety
        ),
    };

    let grade = worst_of(&findings);
    VerifyOutcome {
        grade,
        payload: Some(payload),
        findings,
        readings: vec![cryptographic, evidentiary, current_state],
        reading_answered: READING_ANSWERED,
        trust_marker: Some(trust_marker),
        coverage: Some(coverage),
        freshness: Some(freshness),
    }
}

/// Options parsed from the command line.
#[derive(Debug, Clone, Default)]
struct VerifyArgs {
    pack: Option<String>,
    image: Option<String>,
    camera: bool,
    anchor: Option<String>,
    as_of: Option<String>,
    max_age: Option<i64>,
    encoding: Option<Encoding>,
    json: bool,
}

fn parse(args: &[String]) -> Result<VerifyArgs, CommandError> {
    let mut parsed = VerifyArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--anchor" | "-a" => parsed.anchor = Some(take_value(args, &mut i, "--anchor")?),
            "--image" => parsed.image = Some(take_value(args, &mut i, "--image")?),
            "--camera" => parsed.camera = true,
            "--as-of" => parsed.as_of = Some(take_value(args, &mut i, "--as-of")?),
            "--max-age" => {
                let token = take_value(args, &mut i, "--max-age")?;
                parsed.max_age = Some(token.parse().map_err(|_| {
                    CommandError::Usage(format!("--max-age: `{token}` is not a number"))
                })?);
            }
            "--encoding" => {
                let token = take_value(args, &mut i, "--encoding")?;
                parsed.encoding = Some(
                    Encoding::parse(&token)
                        .map_err(|e| CommandError::Usage(format!("--encoding: {e}")))?,
                );
            }
            "--json" => parsed.json = true,
            other if other.starts_with("--") => {
                return Err(CommandError::Usage(format!(
                    "verify: unknown option `{other}` (see `unidpp help verify`)"
                )))
            }
            positional => {
                if parsed.pack.is_some() {
                    return Err(CommandError::Usage(format!(
                        "verify: unexpected second argument `{positional}`"
                    )));
                }
                parsed.pack = Some(positional.to_string());
            }
        }
        i += 1;
    }
    Ok(parsed)
}

/// Load the pack bytes: from a file when the argument names one, else
/// from the argument text itself (hex or base64, auto-detected unless
/// forced).
fn load_pack_bytes(
    spec: &str,
    forced: Option<Encoding>,
) -> Result<(Vec<u8>, Encoding), CommandError> {
    let path = PathBuf::from(spec);
    let text = if path.is_file() {
        std::fs::read_to_string(&path).map_err(|e| {
            CommandError::Usage(format!("cannot read pack `{}`: {e}", path.display()))
        })?
    } else {
        spec.to_string()
    };
    let decoded = match forced {
        Some(encoding) => encoding.decode(&text).map(|bytes| (bytes, encoding)),
        None => auto_decode(&text),
    };
    decoded.map_err(|e| {
        // A path-looking argument that neither names a file nor decodes
        // is almost certainly a missing file — say that first.
        if spec.contains('/') {
            CommandError::Usage(format!(
                "cannot read pack `{spec}`: no such file, and the argument does not \
                 decode as hex/base64 ({e})"
            ))
        } else {
            CommandError::Usage(format!("pack decode: {e}"))
        }
    })
}

fn parse_anchor(token: &str) -> Result<PublicKey, CommandError> {
    // Two grammars: raw hex (length-inferred suite — the historical
    // form) or `suite:hex` (needed for SM2, whose 65-byte SEC1 point
    // is indistinguishable from P-256 by encoding alone).
    if let Some((suite_token, hex)) = token.trim().split_once(':') {
        let suite = unidpp_signatif::sign::Suite::parse_token(suite_token).map_err(|e| {
            CommandError::Usage(format!("--anchor: unknown suite `{suite_token}`: {e}"))
        })?;
        let bytes = hex_decode(hex).map_err(|e| CommandError::Usage(format!("--anchor: {e}")))?;
        return unidpp_signatif::keyring::PublicKey::from_bytes_in(suite, &bytes)
            .map_err(|e| CommandError::Usage(format!("--anchor: {e}")));
    }
    let hex = token;
    let bytes = hex_decode(hex).map_err(|e| CommandError::Usage(format!("--anchor: {e}")))?;
    PublicKey::from_bytes(&bytes).map_err(|e| {
        CommandError::Usage(format!(
            "--anchor: not a public key (raw hex: 65-byte SEC1, 32-byte \
             Ed25519, or 1952-byte ML-DSA-65; or suite:hex, e.g. sm2:<hex>): {e}"
        ))
    })
}

/// Render the human-facing report.
fn render(outcome: &VerifyOutcome, encoded_len: usize, encoding: Encoding) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "UniDPP Tier-A verification");
    let _ = writeln!(
        out,
        "  carrier       {encoded_len} bytes ({})",
        encoding.as_str()
    );
    if let Some(p) = &outcome.payload {
        let _ = writeln!(out, "  passport      {}", p.passport_id);
        let _ = writeln!(
            out,
            "  product       {} ({})",
            p.product_id, p.product_id.granularity
        );
        let _ = writeln!(out, "  resolver      {}", p.resolver_uri);
        let _ = writeln!(out, "  economic op.  {}", p.eo_id);
        let _ = writeln!(out, "  as-of         {}", p.as_of);
        match p.log_head {
            Some(head) => {
                let _ = writeln!(out, "  log head      {}..", &head.hex()[..16]);
            }
            None => {
                let _ = writeln!(out, "  log head      absent");
            }
        }
        let _ = writeln!(out, "  status        {}", p.status);
        let _ = writeln!(out, "  safety        {}", p.safety);
    }
    out.push('\n');
    out.push_str("Findings\n");
    out.push_str(&render_table(
        &["CHECK", "GRADE", "DETAIL"],
        &outcome
            .findings
            .iter()
            .map(|f| {
                vec![
                    f.check.clone(),
                    f.grade.label().to_string(),
                    f.detail.clone(),
                ]
            })
            .collect::<Vec<_>>(),
    ));
    out.push('\n');
    out.push_str("Readings\n");
    out.push_str(&render_table(
        &["READING", "GRADE", "DETAIL"],
        &outcome
            .readings
            .iter()
            .map(|r| {
                vec![
                    r.name.to_string(),
                    r.grade.label().to_string(),
                    r.detail.clone(),
                ]
            })
            .collect::<Vec<_>>(),
    ));
    if let Some(coverage) = &outcome.coverage {
        out.push('\n');
        let missing = coverage.missing();
        if missing.is_empty() {
            let _ = writeln!(
                out,
                "Coverage  {}/{} Tier-A fields present",
                coverage.present.len(),
                coverage.required.len()
            );
        } else {
            let _ = writeln!(
                out,
                "Coverage  {}/{} Tier-A fields present (missing: {})",
                coverage.present.len(),
                coverage.required.len(),
                missing.join(", ")
            );
        }
    }
    let reason = outcome
        .findings
        .iter()
        .find(|f| f.grade == outcome.grade)
        .map(|f| f.detail.clone())
        .unwrap_or_default();
    let _ = writeln!(
        out,
        "Verdict: {} — {} (reading answered: {})",
        outcome.grade.label(),
        if outcome.grade == Grade::Pass {
            "all checks passed".to_string()
        } else {
            reason
        },
        outcome.reading_answered
    );
    out
}

/// Render the machine-facing report.
fn render_json(
    outcome: &VerifyOutcome,
    encoded_len: usize,
    encoding: Encoding,
    now: Timestamp,
) -> String {
    let json = serde_json::json!({
        "verdict": outcome.grade.token(),
        "exit_code": outcome.grade.exit_code(),
        "reading_answered": outcome.reading_answered,
        "carrier": { "bytes": encoded_len, "encoding": encoding.as_str() },
        "passport_id": outcome.payload.as_ref().map(|p| p.passport_id.to_string()),
        "product_id": outcome.payload.as_ref().map(|p| p.product_id.to_string()),
        "granularity": outcome.payload.as_ref().map(|p| p.product_id.granularity.to_string()),
        "status": outcome.payload.as_ref().map(|p| p.status.to_string()),
        "safety": outcome.payload.as_ref().map(|p| p.safety.to_string()),
        "as_of": outcome.payload.as_ref().map(|p| p.as_of.to_string()),
        "verified_at": now.to_string(),
        "freshness": outcome.freshness.map(|f| f.label().to_string()),
        "trust_marker": outcome.trust_marker.map(|t| t.as_str().to_string()),
        "coverage": outcome.coverage,
        "findings": outcome.findings,
        "readings": outcome.readings,
    });
    serde_json::to_string_pretty(&json).expect("the report is plain data")
}

/// Run the command.
pub fn run(args: &[String]) -> Result<u8, CommandError> {
    let parsed = parse(args)?;
    if parsed.camera {
        // Live capture drags platform media stacks into the binary;
        // this build links none. State the working path instead of
        // silently pretending.
        return Err(CommandError::Usage(
            "--camera: live capture is not linked in this build — photograph the carrier and \
             use `unidpp verify --image <photo.png>`"
                .to_string(),
        ));
    }
    let (bytes, encoding) = match &parsed.image {
        Some(image) => {
            let content = crate::qr::decode_png(std::path::Path::new(image))
                .map_err(|e| CommandError::Usage(format!("--image: {e}")))?;
            match content {
                crate::qr::QrContent::Pack(bytes, encoding) => {
                    if parsed.pack.is_some() {
                        return Err(CommandError::Usage(
                            "verify: pass either a pack argument or --image, not both".to_string(),
                        ));
                    }
                    (bytes, encoding)
                }
                crate::qr::QrContent::Uri(uri) => {
                    return Err(CommandError::Usage(format!(
                        "--image: the QR carries a resolver URI, not the pack: {uri} — resolve \
                         it (`unidpp resolve`) and verify what comes back"
                    )));
                }
            }
        }
        None => {
            let pack = parsed.pack.clone().ok_or_else(|| {
                CommandError::Usage(
                    "verify: a pack file, an encoded pack, or --image <photo.png> is required"
                        .to_string(),
                )
            })?;
            load_pack_bytes(&pack, parsed.encoding)?
        }
    };
    let anchor = match &parsed.anchor {
        Some(hex) => Some(parse_anchor(hex)?),
        None => None,
    };
    let now = match &parsed.as_of {
        Some(v) => parse_timestamp(v, "--as-of")?,
        None => Timestamp::now(),
    };
    let max_age = parsed.max_age.unwrap_or(DEFAULT_MAX_AGE_SECS);
    let outcome = verify_pack(&bytes, anchor.as_ref(), now, max_age);

    if parsed.json {
        println!("{}", render_json(&outcome, bytes.len(), encoding, now));
    } else {
        print!("{}", render(&outcome, bytes.len(), encoding));
    }
    Ok(outcome.grade.exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packfile::sign_pack;
    use unidpp_event::{EventLog, EventPayload, EventType, TypedEvent};
    use unidpp_model::{Interval, PassportId, ProductIdentifier, TrustMarker};
    use unidpp_signatif::keyring::KeyPair;
    use unidpp_signatif::sign::Suite;
    use unidpp_tier_a::EcLevel;

    fn t(secs: i64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn log_with(events: Vec<(EventType, EventPayload)>, at: i64) -> EventLog {
        let mut log = EventLog::new(PassportId::new("urn:unidpp:passport:vtest").unwrap());
        for (i, (event_type, payload)) in events.into_iter().enumerate() {
            let event = TypedEvent::new(
                i as u64,
                t(at + i as i64),
                "custodian",
                "eo-v",
                event_type,
                payload,
                TrustMarker::Attested,
            )
            .unwrap();
            log.append(event, None, None).unwrap();
        }
        log
    }

    fn basic_log() -> EventLog {
        log_with(
            vec![(
                EventType::Issuance,
                EventPayload::Issuance {
                    derived: false,
                    inputs: vec![],
                },
            )],
            1_800_000_000,
        )
    }

    fn payload_for(log: &EventLog) -> TierAPayload {
        TierAPayload::from_log(
            log,
            ProductIdentifier::parse("gtin:4006381333931").unwrap(),
            "https://resolver.unidpp.org/r/vtest",
            "eo-v",
            Interval::starting(t(1_700_000_000)),
            vec![],
        )
    }

    fn now() -> Timestamp {
        t(1_800_000_600)
    }

    #[test]
    fn round_trip_passes_with_matching_anchor() {
        let payload = payload_for(&basic_log());
        let (signed, public, _) = sign_pack(&payload, b"seed-v").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let outcome = verify_pack(
            packed.as_slice(),
            Some(&public),
            now(),
            DEFAULT_MAX_AGE_SECS,
        );
        assert_eq!(outcome.grade, Grade::Pass, "{:#?}", outcome.findings);
        assert_eq!(outcome.grade.exit_code(), 0);
        assert_eq!(outcome.trust_marker, Some(TrustMarker::Attested));
        assert_eq!(outcome.reading_answered, "current-state");
        assert!(outcome.coverage.as_ref().unwrap().is_complete());
    }

    #[test]
    fn garbage_bytes_fail_the_schema_check() {
        let outcome = verify_pack(&[0xff, 0x00, 0x11], None, now(), DEFAULT_MAX_AGE_SECS);
        assert_eq!(outcome.grade, Grade::Fail);
        assert_eq!(outcome.grade.exit_code(), 2);
        assert!(outcome.payload.is_none());
        assert!(outcome.findings[0].check == "schema/decode");
    }

    #[test]
    fn tampered_payload_fails_the_signature_check() {
        let payload = payload_for(&basic_log());
        let (signed, public, _) = sign_pack(&payload, b"seed-v").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        // Flip a byte inside the encoded data region.
        let mut bytes = packed.into_bytes();
        let idx = bytes.len() / 2;
        bytes[idx] ^= 0x01;
        let outcome = verify_pack(&bytes, Some(&public), now(), DEFAULT_MAX_AGE_SECS);
        // Either the frame breaks (schema Fail) or the signature fails —
        // both are Fail.
        assert_eq!(outcome.grade, Grade::Fail);
        assert_eq!(outcome.grade.exit_code(), 2);
    }

    #[test]
    fn substituted_identity_fails_while_decoding_fine() {
        let payload = payload_for(&basic_log());
        let (signed, public, _) = sign_pack(&payload, b"seed-v").unwrap();
        let decoded = TierAPacker::decode(
            TierAPacker::new(EcLevel::M, 40)
                .pack(&signed)
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        // Re-encode the pack with a different EO id but the original
        // signature: decodes fine, fails real verification.
        let mut forged = decoded.clone();
        forged.eo_id = "eo-mallorca".to_string();
        let forged_pack = TierAPacker::new(EcLevel::M, 40).pack(&forged).unwrap();
        let outcome = verify_pack(
            forged_pack.as_slice(),
            Some(&public),
            now(),
            DEFAULT_MAX_AGE_SECS,
        );
        assert_eq!(outcome.grade, Grade::Fail);
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.check.starts_with("signature/") && f.grade == Grade::Fail));
    }

    #[test]
    fn wrong_anchor_degrades_not_fails() {
        let payload = payload_for(&basic_log());
        let (signed, _, _) = sign_pack(&payload, b"seed-v").unwrap();
        let other = KeyPair::seeded(Suite::EcdsaP256, b"seed-w").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let outcome = verify_pack(
            packed.as_slice(),
            Some(other.public()),
            now(),
            DEFAULT_MAX_AGE_SECS,
        );
        assert_eq!(outcome.grade, Grade::Degraded);
        assert_eq!(outcome.grade.exit_code(), 1);
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.detail.contains("does not cover this signer")));
    }

    #[test]
    fn missing_anchor_and_unsigned_packs_degrade() {
        let payload = payload_for(&basic_log());
        let (signed, _, _) = sign_pack(&payload, b"seed-v").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let outcome = verify_pack(packed.as_slice(), None, now(), DEFAULT_MAX_AGE_SECS);
        assert_eq!(outcome.grade, Grade::Degraded);
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.detail.contains("no anchor supplied")));

        let unsigned = TierAPacker::new(EcLevel::M, 40).pack(&payload).unwrap();
        let outcome = verify_pack(unsigned.as_slice(), None, now(), DEFAULT_MAX_AGE_SECS);
        assert_eq!(outcome.grade, Grade::Degraded);
        assert_eq!(outcome.trust_marker, Some(TrustMarker::Unsigned));
    }

    #[test]
    fn stale_pack_degrades_and_static_semantics_never_go_stale() {
        let payload = payload_for(&basic_log());
        let (signed, public, _) = sign_pack(&payload, b"seed-v").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let late = t(1_800_000_000 + 10 * DEFAULT_MAX_AGE_SECS);
        let outcome = verify_pack(packed.as_slice(), Some(&public), late, DEFAULT_MAX_AGE_SECS);
        assert_eq!(outcome.grade, Grade::Degraded);
        assert!(matches!(
            outcome.freshness,
            Some(FreshnessVerdict::Stale { .. })
        ));

        let archival = verify_pack(packed.as_slice(), Some(&public), late, 0);
        assert!(archival.freshness.unwrap().is_fresh());
    }

    #[test]
    fn recall_and_invalid_status_drive_current_state() {
        let mut log = basic_log();
        let recall = TypedEvent::new(
            1,
            t(1_800_000_010),
            "regulator",
            "reg-1",
            EventType::RecallCampaign,
            EventPayload::RecallCampaign {
                campaign: "R-9".into(),
                predicate: unidpp_model::TriggerPredicate::Any,
            },
            TrustMarker::Attested,
        )
        .unwrap();
        log.append(recall, None, None).unwrap();
        let payload = payload_for(&log);
        let (signed, public, _) = sign_pack(&payload, b"seed-v").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let outcome = verify_pack(
            packed.as_slice(),
            Some(&public),
            now(),
            DEFAULT_MAX_AGE_SECS,
        );
        assert_eq!(outcome.grade, Grade::Fail);
        assert!(outcome.readings[2].detail.contains("recall-active"));

        let suspended = log_with(
            vec![
                (
                    EventType::Issuance,
                    EventPayload::Issuance {
                        derived: false,
                        inputs: vec![],
                    },
                ),
                (
                    EventType::StatusChange,
                    EventPayload::StatusChange {
                        from: Status::Issued,
                        to: Status::Suspended,
                        authority: "reg".into(),
                    },
                ),
            ],
            1_800_000_000,
        );
        let payload = payload_for(&suspended);
        let (signed, public, _) = sign_pack(&payload, b"seed-v").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let outcome = verify_pack(
            packed.as_slice(),
            Some(&public),
            now(),
            DEFAULT_MAX_AGE_SECS,
        );
        assert_eq!(outcome.grade, Grade::Degraded);
        assert!(outcome.readings[2].detail.contains("suspended"));
    }

    #[test]
    fn deferred_suites_degrade_honestly() {
        let mut payload = payload_for(&basic_log());
        payload.signatures = vec![unidpp_model::SigSlot::placeholder(
            unidpp_model::SignatureSuite::Sm2,
            "k-sm2",
        )];
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&payload).unwrap();
        let key = KeyPair::seeded(Suite::EcdsaP256, b"anchor").unwrap();
        let outcome = verify_pack(
            packed.as_slice(),
            Some(key.public()),
            now(),
            DEFAULT_MAX_AGE_SECS,
        );
        assert_eq!(outcome.grade, Grade::Degraded);
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.detail.contains("framed-only")));
    }

    #[test]
    fn expired_validity_degrades() {
        let log = basic_log();
        let mut payload = payload_for(&log);
        payload.validity = Interval::between(t(1_700_000_000), t(1_750_000_000)).unwrap();
        let (signed, public, _) = sign_pack(&payload, b"seed-v").unwrap();
        let packed = TierAPacker::new(EcLevel::M, 40).pack(&signed).unwrap();
        let outcome = verify_pack(
            packed.as_slice(),
            Some(&public),
            now(),
            DEFAULT_MAX_AGE_SECS,
        );
        assert_eq!(outcome.grade, Grade::Degraded);
        assert!(outcome
            .findings
            .iter()
            .any(|f| f.check == "evidence/validity" && f.grade == Grade::Degraded));
    }
}
