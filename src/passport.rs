//! The on-disk passport document: the core skeleton (identity, type
//! ref, capability class, validity) plus the authoritative event log
//! and the Ed25519 event signatures `unidpp event --key` records.
//!
//! This is the CLI-side *full* passport (Tier-B document). The Tier-A
//! pack `unidpp pack` mints from it is a projection; the log stays here
//! with its owner. Everything is plain JSON, serde-derived from the
//! core types — no hand-rolled field mapping.

use std::fs;
use std::path::Path;

use unidpp_event::EventLog;
use unidpp_model::{
    CapabilityClass, Granularity, Interval, PassportId, ProductIdentifier, Timestamp,
};

/// Document schema tag (versioned for forward detection).
pub const SCHEMA: &str = "unidpp/passport@1";

/// One signature over an appended event's canonical body, recorded in
/// the passport document. Suite and key id follow SIGNATIF's framing;
/// the signature value is hex.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EventSignature {
    /// Sequence number of the sealed event covered.
    pub seq: u64,
    /// SIGNATIF suite token (`ed25519`).
    pub suite: String,
    /// Content-derived key id of the signer.
    pub key_id: String,
    /// Signature value, hex-encoded.
    pub signature: String,
}

/// The passport document.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Passport {
    /// Document schema tag.
    pub schema: String,
    /// The passport identifier (location-free URN slug, invariant I14).
    pub passport_id: PassportId,
    /// The subject identity (scheme-agnostic product identifier).
    pub product_id: ProductIdentifier,
    /// Optional product-type reference (profile applicability input).
    #[serde(default)]
    pub type_ref: Option<String>,
    /// Subject capability class (S0-S3).
    pub capability: CapabilityClass,
    /// Economic-operator identifier.
    pub eo_id: String,
    /// Resolver URI for Tier-B serving.
    pub resolver_uri: String,
    /// Passport validity interval.
    pub validity: Interval,
    /// When this passport was created.
    pub created_at: Timestamp,
    /// The authoritative append-only event log.
    pub log: EventLog,
    /// Signatures over appended events (empty while events are unsigned).
    #[serde(default)]
    pub event_signatures: Vec<EventSignature>,
}

/// Options for [`Passport::mint`].
#[derive(Debug, Clone)]
pub struct MintOptions {
    /// Scheme-prefixed / element-string / bare product identifier.
    pub id: String,
    /// Granularity the operator declared; must match the identifier's
    /// derived granularity (invariant I3: identity is recorded at the
    /// finest granularity the identifier itself carries — you cannot
    /// claim `item` for a bare GTIN, nor `model` for an SGTIN).
    pub granularity: Option<Granularity>,
    /// Product-type reference.
    pub type_ref: Option<String>,
    /// Capability class token (`S0`-`S3` or the canonical names).
    pub capability: String,
    /// Economic-operator id.
    pub eo_id: Option<String>,
    /// Resolver URI override.
    pub resolver_uri: Option<String>,
    /// Passport id override (else derived from identity + time).
    pub passport_id: Option<String>,
    /// Validity start (default: now).
    pub valid_from: Option<Timestamp>,
    /// Validity end (default: open).
    pub valid_to: Option<Timestamp>,
}

impl Passport {
    /// Mint a new passport: skeleton plus an empty log (identity never
    /// re-minted — the same `--id` mints an equivalent document, and
    /// the passport id is content/time-derived unless overridden).
    pub fn mint(opts: MintOptions) -> Result<Passport, String> {
        let product_id = ProductIdentifier::parse(&opts.id).map_err(|e| format!("--id: {e}"))?;
        if let Some(wanted) = &opts.granularity {
            if *wanted != product_id.granularity {
                return Err(format!(
                    "--granularity {} contradicts the identifier `{}` (derived {}): \
                     record identity at the granularity the identifier carries",
                    wanted, product_id, product_id.granularity
                ));
            }
        }
        let capability = parse_capability(&opts.capability)?;
        let created_at = Timestamp::now();
        let passport_id = match &opts.passport_id {
            Some(raw) => PassportId::new(raw).map_err(|e| format!("--passport-id: {e}"))?,
            None => derive_passport_id(&product_id, created_at),
        };
        let resolver_uri = opts
            .resolver_uri
            .unwrap_or_else(|| format!("https://resolver.unidpp.org/{}", passport_id.as_str()));
        let validity = Interval {
            from: opts.valid_from.unwrap_or(created_at),
            to: opts.valid_to,
        };
        if let Some(to) = validity.to {
            if to < validity.from {
                return Err(format!("validity end {to} before start {}", validity.from));
            }
        }
        let eo_id = opts.eo_id.unwrap_or_else(|| "eo-local".to_string());
        Ok(Passport {
            schema: SCHEMA.to_string(),
            passport_id: passport_id.clone(),
            product_id,
            type_ref: opts.type_ref,
            capability,
            eo_id,
            resolver_uri,
            validity,
            created_at,
            log: EventLog::new(passport_id),
            event_signatures: Vec::new(),
        })
    }

    /// Parse a JSON passport document.
    pub fn from_json(text: &str) -> Result<Passport, String> {
        let passport: Passport =
            serde_json::from_str(text).map_err(|e| format!("not a passport document: {e}"))?;
        if passport.schema != SCHEMA {
            return Err(format!(
                "unsupported passport schema `{}` (expected `{SCHEMA}`)",
                passport.schema
            ));
        }
        Ok(passport)
    }

    /// Serialize (pretty, newline-terminated — diff- and human-friendly).
    pub fn to_json(&self) -> Result<String, String> {
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|e| format!("passport serialization failed: {e}"))?;
        text.push('\n');
        Ok(text)
    }

    /// Load from a file.
    pub fn load(path: &Path) -> Result<Passport, String> {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("cannot read passport `{}`: {e}", path.display()))?;
        Passport::from_json(&text)
    }

    /// Save to a file (pretty JSON).
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let text = self.to_json()?;
        fs::write(path, text)
            .map_err(|e| format!("cannot write passport `{}`: {e}", path.display()))
    }
}

/// Passport id for a freshly minted document: content- and
/// time-derived slug (I1: one subject, one identity — deterministic
/// for the same input and minting moment).
fn derive_passport_id(product_id: &ProductIdentifier, at: Timestamp) -> PassportId {
    let material = format!("unidpp-cli/mint|{}|{}|{}", product_id, at.secs, at.nanos);
    let digest = unidpp_model::sha256(&[material.as_bytes()]);
    PassportId::new(&format!("urn:unidpp:passport:cli-{}", &digest.hex()[..12]))
        .expect("derived passport id is well-formed")
}

/// Parse a capability class: `S0`-`S3` codes or canonical tokens.
fn parse_capability(s: &str) -> Result<CapabilityClass, String> {
    let token = s.trim();
    for class in CapabilityClass::ALL {
        if token.eq_ignore_ascii_case(class.code()) || token.eq_ignore_ascii_case(class.as_str()) {
            return Ok(*class);
        }
    }
    Err(format!(
        "unknown capability `{s}` (expected S0-S3 or {})",
        CapabilityClass::ALL
            .iter()
            .map(|c| c.as_str())
            .collect::<Vec<_>>()
            .join("/")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(id: &str) -> MintOptions {
        MintOptions {
            id: id.to_string(),
            granularity: None,
            type_ref: None,
            capability: "S1".to_string(),
            eo_id: Some("eo-test".to_string()),
            resolver_uri: None,
            passport_id: None,
            valid_from: None,
            valid_to: None,
        }
    }

    #[test]
    fn mint_makes_skeleton_with_empty_log() {
        let p = Passport::mint(opts("gtin:4006381333931")).unwrap();
        assert_eq!(p.schema, SCHEMA);
        assert_eq!(p.capability, CapabilityClass::PassiveAuth);
        assert!(p.log.is_empty());
        assert!(p.log.subject() == &p.passport_id);
        assert!(p
            .passport_id
            .as_str()
            .starts_with("urn:unidpp:passport:cli-"));
        assert!(p.resolver_uri.contains(p.passport_id.as_str()));
        assert!(p.validity.is_open());
    }

    #[test]
    fn granularity_must_match_the_identifier() {
        let mut o = opts("gtin:4006381333931");
        o.granularity = Some(Granularity::Item);
        let err = Passport::mint(o).unwrap_err();
        assert!(err.contains("contradicts"), "{err}");

        let mut ok = opts("sgtin:4006381333931+21+SN7");
        ok.granularity = Some(Granularity::Item);
        assert!(Passport::mint(ok).is_ok());
    }

    #[test]
    fn capability_tokens_both_ways() {
        assert_eq!(parse_capability("S3").unwrap(), CapabilityClass::Connected);
        assert_eq!(
            parse_capability("Passive-Auth").unwrap(),
            CapabilityClass::PassiveAuth
        );
        assert!(parse_capability("S4").is_err());
    }

    #[test]
    fn json_round_trip_and_schema_guard() {
        let p = Passport::mint(opts("01+4006381333931+10+LOT9")).unwrap();
        let text = p.to_json().unwrap();
        assert!(text.ends_with('\n'));
        let back = Passport::from_json(&text).unwrap();
        assert_eq!(back, p);
        assert!(Passport::from_json("{\"schema\": \"nope\"}").is_err());
    }
}
