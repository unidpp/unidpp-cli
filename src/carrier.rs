//! The carrier adapter (S1 seam, CLI side): translate whatever an
//! officer scanned into the core's normalized identifier.
//!
//! The core identifier module (`unidpp_model::identifier`) already
//! understands scheme-prefixed forms (`gtin:…`), GS1 element strings
//! (`01+K[+10+L][+21+S]`), bare 8–14 digit GTINs, http(s) URIs, and
//! issuer-local keys. This adapter adds the *carrier* shapes that never
//! reach the core directly, mirroring the semantics of the federated
//! resolver (`unidpp-resolver/src/carrier.rs`, `gs1dl.rs`,
//! `gbt33993.rs`) without depending on its HTTP stack:
//!
//! - **GS1 Digital Link** — `https://id.example.com/01/09506000134352/21/S`,
//!   with AI 10/21 also accepted as query parameters;
//! - **GB/T 33993-2017** — GDS-style `https://gds.example.cn/g/<EAN-13>[/qualifier]`
//!   (an alphabetic qualifier is a serial, a numeric one a lot — the
//!   documented national default) and legacy 1D EAN-13 scans;
//! - **parenthesized element strings** — `(01)K(10)L(21)S`;
//! - **URNs** — carried as the core's `uri:` scheme (ISO/IEC 15459 URNs
//!   pass through verbatim).
//!
//! GS1 check digits are *enforced* here (the core keeps them advisory):
//! a correctly shaped carrier with a bad check digit is a syntax error,
//! not an unknown identity.

use unidpp_model::{IdScheme, ProductIdentifier};

/// A scanned carrier, resolved to the core's normalized identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierResolution {
    /// Which carrier shape was recognized (reported to the officer).
    pub kind: &'static str,
    /// The normalized identity.
    pub identifier: ProductIdentifier,
    /// URL origin when the carrier itself was a resolver entry point.
    pub resolver_base: Option<String>,
}

/// Recognized carrier kinds (stable tokens for `--json` output).
pub mod kind {
    /// GS1 Digital Link URI (`/01/…` AI path).
    pub const GS1_DL: &str = "gs1-digital-link";
    /// GS1 AI key path without a scheme (`01/09506000134352/21/X`).
    pub const GS1_KEY_PATH: &str = "gs1-key-path";
    /// GB/T 33993 GDS-style `/g/<EAN-13>[/qualifier]` path.
    pub const GBT_GDS: &str = "gbt-33993-gds";
    /// GB/T 33993 enterprise custom code (an http(s) URL of any other shape).
    pub const GBT_CUSTOM: &str = "gbt-33993-custom";
    /// Legacy 1D EAN-13 / GTIN-14 scan.
    pub const LEGACY_EAN: &str = "legacy-ean13";
    /// An `urn:` carrier (ISO/IEC 15459 URNs included).
    pub const URN: &str = "urn";
    /// An ISO/IEC 15459 URN, specifically.
    pub const ISO_15459_URN: &str = "iso-15459-urn";
    /// Any other http(s) URL.
    pub const WEB_URI: &str = "web-uri";
    /// A form the core parses natively (`gtin:…`, `sgtin:…`, `local:…`).
    pub const CORE_FORM: &str = "core-form";
}

/// Resolve a scanned carrier string to the normalized identifier.
///
/// Errors carry the officer-facing reason (unrecognized shape, or a
/// carrier shape with an invalid value).
pub fn resolve_carrier(input: &str) -> Result<CarrierResolution, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty carrier".to_string());
    }

    if let Some(res) = parse_paren_element_string(trimmed)? {
        return Ok(res);
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return parse_url_carrier(trimmed);
    }
    if let Some(res) = parse_gs1_key_path(trimmed) {
        return Ok(res);
    }
    if trimmed.starts_with("urn:") {
        let kind = if is_iso15459_urn(trimmed) {
            kind::ISO_15459_URN
        } else {
            kind::URN
        };
        let identifier =
            ProductIdentifier::new(IdScheme::Uri, trimmed).map_err(|e| e.to_string())?;
        return Ok(CarrierResolution {
            kind,
            identifier,
            resolver_base: None,
        });
    }
    let is_bare_gtin =
        trimmed.bytes().all(|b| b.is_ascii_digit()) && (8..=14).contains(&trimmed.len());
    if is_bare_gtin {
        let identifier = ProductIdentifier::parse(trimmed).map_err(|e| e.to_string())?;
        enforce_check_digit(&identifier)?;
        return Ok(CarrierResolution {
            kind: kind::LEGACY_EAN,
            identifier,
            resolver_base: None,
        });
    }

    // Fall through to the core's native forms (gtin:, sgtin:, gsrn:,
    // local:<tag>:<key>, http(s) URI literals, element strings).
    let identifier =
        ProductIdentifier::parse(trimmed).map_err(|e| format!("unrecognized carrier: {e}"))?;
    enforce_check_digit(&identifier)?;
    Ok(CarrierResolution {
        kind: kind::CORE_FORM,
        identifier,
        resolver_base: None,
    })
}

/// ISO/IEC 15459 / EN 18219 URN carriers (the neutral primary scheme).
fn is_iso15459_urn(s: &str) -> bool {
    const PREFIX: &str = "urn:iso:std:iso-iec:15459";
    match s.strip_prefix(PREFIX) {
        Some(rest) => matches!(rest.as_bytes().first(), Some(b':') | Some(b'#')) && rest.len() > 1,
        None => false,
    }
}

/// Parse a parenthesized element string `(01)K[(10)L][(21)S]` into the
/// core's `+`-separated wire form.
fn parse_paren_element_string(s: &str) -> Result<Option<CarrierResolution>, String> {
    if !s.starts_with("(01)") {
        return Ok(None);
    }
    let err = |m: &str| format!("malformed element string `{s}`: {m}");
    let mut tail = &s[4..];
    let key_len = tail.find('(').unwrap_or(tail.len());
    let (key, rest) = tail.split_at(key_len);
    if key.is_empty() || !key.bytes().all(|b| b.is_ascii_digit()) {
        return Err(err("expected digits after (01)"));
    }
    let mut wire = format!("01+{key}");
    tail = rest;
    while !tail.is_empty() {
        let (ai, after) = tail
            .strip_prefix("(10)")
            .map(|r| ("+10+", r))
            .or_else(|| tail.strip_prefix("(21)").map(|r| ("+21+", r)))
            .ok_or_else(|| err("expected (10)/(21) qualifiers"))?;
        let val_len = after.find('(').unwrap_or(after.len());
        let (val, next) = after.split_at(val_len);
        if val.is_empty() {
            return Err(err("empty qualifier value"));
        }
        wire.push_str(ai);
        wire.push_str(val);
        tail = next;
    }
    let identifier = ProductIdentifier::parse(&wire).map_err(|e| e.to_string())?;
    enforce_check_digit(&identifier)?;
    Ok(Some(CarrierResolution {
        kind: kind::GS1_DL,
        identifier,
        resolver_base: None,
    }))
}

/// A minimal URL split: origin, percent-raw path segments, query pairs.
struct UrlParts {
    origin: String,
    path_segments: Vec<String>,
    query_pairs: Vec<(String, String)>,
}

fn split_url(uri: &str) -> Option<UrlParts> {
    let (scheme, rest) = uri.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let (authority, tail) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return None;
    }
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, q),
        None => (tail, ""),
    };
    let path_segments = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    let query_pairs = query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            pair.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    Some(UrlParts {
        origin: format!("{scheme}://{authority}"),
        path_segments,
        query_pairs,
    })
}

fn parse_url_carrier(uri: &str) -> Result<CarrierResolution, String> {
    let url = split_url(uri).ok_or_else(|| format!("malformed URL `{uri}`"))?;
    let base = Some(url.origin.clone());

    // GS1 Digital Link: AI pairs on the path (01 key, 10/21 qualifiers).
    if let Some(el) = assemble_gs1_from_pairs(&url.path_segments, &url.query_pairs) {
        let identifier = ProductIdentifier::parse(&el).map_err(|e| e.to_string())?;
        enforce_check_digit(&identifier)?;
        return Ok(CarrierResolution {
            kind: kind::GS1_DL,
            identifier,
            resolver_base: base,
        });
    }

    // GB/T 33993 GDS path: /g/<13-digit GTIN>[/<qualifier>].
    if url.path_segments.first().map(String::as_str) == Some("g") {
        if let Some(identifier) = parse_gds_gtin(&url.path_segments) {
            enforce_check_digit(&identifier)?;
            return Ok(CarrierResolution {
                kind: kind::GBT_GDS,
                identifier,
                resolver_base: base,
            });
        }
        if url
            .path_segments
            .get(1)
            .is_some_and(|s| s.len() == 13 && s.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(format!(
                "invalid carrier `{uri}`: bad EAN-13 check digit in the /g/ path"
            ));
        }
        return Err(format!("invalid carrier `{uri}`: malformed /g/ path"));
    }

    // Any other http(s) URL: GB/T enterprise custom code or a plain web
    // URI — both normalize to the core's uri scheme.
    let identifier = ProductIdentifier::parse(uri).map_err(|e| e.to_string())?;
    Ok(CarrierResolution {
        kind: kind::GBT_CUSTOM,
        identifier,
        resolver_base: base,
    })
}

/// GS1 AI key path without scheme/authority: `01/09506000134352/21/X`.
fn parse_gs1_key_path(s: &str) -> Option<CarrierResolution> {
    if s.contains("://") || !s.contains('/') {
        return None;
    }
    let (path, query) = match s.split_once('?') {
        Some((p, q)) => (p, q),
        None => (s, ""),
    };
    let segments: Vec<String> = path
        .split('/')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect();
    let pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|pair| {
            pair.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    let el = assemble_gs1_from_pairs(&segments, &pairs)?;
    let identifier = ProductIdentifier::parse(&el).ok()?;
    enforce_check_digit(&identifier).ok()?;
    Some(CarrierResolution {
        kind: kind::GS1_KEY_PATH,
        identifier,
        resolver_base: None,
    })
}

/// Assemble `01+K[+10+L][+21+S]` from AI/value path pairs (query pairs
/// as fallback for qualifiers). Returns `None` when no AI 01 is present.
fn assemble_gs1_from_pairs(path: &[String], query: &[(String, String)]) -> Option<String> {
    let supported = |ai: &str| {
        ai.len() == 2 && ai.bytes().all(|b| b.is_ascii_digit()) && matches!(ai, "01" | "10" | "21")
    };
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    let mut i = 0;
    while i + 1 < path.len() {
        if supported(&path[i]) {
            pairs.push((&path[i], &path[i + 1]));
        }
        i += 2;
    }
    let gtin = pairs
        .iter()
        .find(|(k, _)| *k == "01")
        .map(|(_, v)| v.to_string())?;
    let qualifier = |ai: &str| -> Option<String> {
        pairs
            .iter()
            .find(|(k, _)| *k == ai)
            .map(|(_, v)| v.to_string())
            .or_else(|| query.iter().find(|(k, _)| k == ai).map(|(_, v)| v.clone()))
    };
    let mut wire = format!("01+{gtin}");
    if let Some(lot) = qualifier("10") {
        wire.push_str(&format!("+10+{lot}"));
    }
    if let Some(serial) = qualifier("21") {
        wire.push_str(&format!("+21+{serial}"));
    }
    Some(wire)
}

/// GB/T GDS `/g/<13 digits>[/<qualifier>]`: zero-pad to GTIN-14; an
/// alphabetic qualifier is a serial (canonicalizing the scheme to
/// SGTIN, as the core does for GTIN+serial), a numeric one a lot.
fn parse_gds_gtin(segments: &[String]) -> Option<ProductIdentifier> {
    let gtin13 = segments.get(1)?;
    if gtin13.len() != 13 || !gtin13.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if segments.len() > 3 {
        return None;
    }
    let gtin14 = format!("0{gtin13}");
    let has_serial = segments
        .get(2)
        .is_some_and(|q| is_gbt_qualifier(q) && q.chars().any(|c| c.is_ascii_alphabetic()));
    let mut identifier = ProductIdentifier::new(
        if has_serial {
            IdScheme::Sgtin
        } else {
            IdScheme::Gtin
        },
        &gtin14,
    )
    .ok()?;
    match segments.get(2) {
        None => {}
        Some(q) if is_gbt_qualifier(q) => {
            if has_serial {
                identifier = identifier.with_serial(q).ok()?;
            } else {
                identifier = identifier.with_lot(q).ok()?;
            }
        }
        Some(_) => return None,
    }
    Some(identifier)
}

/// GDS qualifier charset (`[\w.-]{1,20}`).
fn is_gbt_qualifier(q: &str) -> bool {
    (1..=20).contains(&q.len())
        && q.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

/// GS1 check digits are enforced at the carrier seam (the core keeps
/// them advisory: a parseable key with a bad check digit is a syntax
/// error here, matching the federated resolver's 400 classification).
fn enforce_check_digit(identifier: &ProductIdentifier) -> Result<(), String> {
    if identifier.gs1_check_digit_ok() == Some(false) {
        return Err(format!(
            "invalid carrier: GS1 check digit of `{identifier}` is wrong"
        ));
    }
    Ok(())
}

/// One-line rendering for terminal output.
pub fn describe(res: &CarrierResolution) -> String {
    let mut out = format!(
        "carrier        {}\nnormalized id  {}\nscheme         {}\ngranularity    {}",
        res.kind,
        res.identifier,
        res.identifier.scheme,
        res.identifier.granularity.as_str(),
    );
    if let Some(base) = &res.resolver_base {
        out.push_str(&format!("\nresolver base  {base}"));
    }
    if let Some(true) = res.identifier.gs1_check_digit_ok() {
        out.push_str("\ncheck digit    valid");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use unidpp_model::Granularity;

    fn resolve(s: &str) -> CarrierResolution {
        resolve_carrier(s).unwrap_or_else(|e| panic!("`{s}` should resolve: {e}"))
    }

    #[test]
    fn gs1_digital_link_path_and_query_ais() {
        let r = resolve("https://id.example.com/01/09506000134352/21/BP52-000841");
        assert_eq!(r.kind, kind::GS1_DL);
        assert_eq!(r.identifier.to_string(), "01+09506000134352+21+BP52-000841");
        assert_eq!(r.identifier.granularity, Granularity::Item);
        assert_eq!(r.resolver_base.as_deref(), Some("https://id.example.com"));

        let q = resolve("https://id.example.com/01/09506000134352?10=LOT2026Q3");
        assert_eq!(q.identifier.to_string(), "01+09506000134352+10+LOT2026Q3");
        assert_eq!(q.identifier.granularity, Granularity::Batch);
    }

    #[test]
    fn gs1_key_path_without_scheme() {
        let r = resolve("01/09506000134352/21/X");
        assert_eq!(r.kind, kind::GS1_KEY_PATH);
        assert_eq!(r.identifier.to_string(), "01+09506000134352+21+X");
    }

    #[test]
    fn parenthesized_element_string() {
        let r = resolve("(01)09506000134352(10)LOT42(21)SN7");
        assert_eq!(r.kind, kind::GS1_DL);
        assert_eq!(
            r.identifier.to_string(),
            "01+09506000134352+10+LOT42+21+SN7"
        );
        assert!(resolve_carrier("(01)09506000134352(30)X").is_err());
    }

    #[test]
    fn gbt_gds_paths() {
        let serial = resolve("https://gds.example.cn/g/6901234567892/AB2026111");
        assert_eq!(serial.kind, kind::GBT_GDS);
        assert_eq!(
            serial.identifier.to_string(),
            "01+06901234567892+21+AB2026111"
        );
        // A serial qualifier canonicalizes the scheme to SGTIN, as the
        // core does for GTIN+serial.
        assert_eq!(serial.identifier.scheme, IdScheme::Sgtin);
        assert_eq!(serial.identifier.granularity, Granularity::Item);

        let lot = resolve("https://gds.example.cn/g/6901234567892/20260901");
        assert_eq!(lot.identifier.to_string(), "01+06901234567892+10+20260901");
        assert_eq!(lot.identifier.scheme, IdScheme::Gtin);
        assert_eq!(lot.identifier.granularity, Granularity::Batch);

        let bare = resolve("https://gds.example.cn/g/6901234567892");
        assert_eq!(bare.identifier.to_string(), "01+06901234567892");
        assert_eq!(bare.identifier.granularity, Granularity::Model);
    }

    #[test]
    fn bad_check_digits_are_syntax_errors() {
        assert!(resolve_carrier("https://gds.example.cn/g/6901234567893").is_err());
        assert!(resolve_carrier("6901234567893").is_err());
        assert!(resolve_carrier("(01)09506000134353(21)X").is_err());
        assert!(resolve_carrier("gtin:4006381333932").is_err());
    }

    #[test]
    fn legacy_ean13_and_urns() {
        let ean = resolve("6901234567892");
        assert_eq!(ean.kind, kind::LEGACY_EAN);
        assert_eq!(ean.identifier.scheme, IdScheme::Gtin);

        let urn = resolve("urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345");
        assert_eq!(urn.kind, kind::ISO_15459_URN);
        assert_eq!(urn.identifier.scheme, IdScheme::Uri);
        assert_eq!(
            urn.identifier.to_string(),
            "uri:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345"
        );
        assert_eq!(resolve("urn:unidpp:thing:1").kind, kind::URN);
    }

    #[test]
    fn custom_codes_and_web_uris_normalize_to_uri_scheme() {
        let r = resolve("https://qr.enterprise.cn/x/MA-2026-8841");
        assert_eq!(r.kind, kind::GBT_CUSTOM);
        assert_eq!(r.identifier.scheme, IdScheme::Uri);
    }

    #[test]
    fn core_forms_pass_through() {
        let r = resolve("sgtin:4006381333931+21+SN7");
        assert_eq!(r.kind, kind::CORE_FORM);
        assert_eq!(r.identifier.scheme, IdScheme::Sgtin);
        assert!(resolve_carrier("hello world").is_err());
        assert!(resolve_carrier("").is_err());
    }
}
