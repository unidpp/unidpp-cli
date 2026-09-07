//! `unidpp pack`: mint the Tier-A offline pack from a passport.

use std::path::PathBuf;

use unidpp_tier_a::{TierAPacker, TierAPayload};

use crate::commands::{take_value, CommandError};
use crate::encoding::{hex_encode, Encoding};
use crate::exit;
use crate::packfile::{parse_budget, sign_pack, DEFAULT_BUDGET};
use crate::passport::Passport;

/// The `pack` usage text.
pub const USAGE: &str = "\
unidpp pack - mint the Tier-A offline pack from a passport

USAGE:
    unidpp pack --passport <FILE> [OPTIONS]

OPTIONS:
    --passport <FILE>    the passport document to project
    --budget <TOKEN>     carrier budget `qr-v<version>-<ec>`, e.g. qr-v15-M
                         (default qr-v40-M; ec one of L/M/Q/H)
    --key <SEED>         sign the pack with a seeded key: fills the real
                         ECDSA-P256 signature slot over the pack's canonical
                         body. The derived public key (hex) is printed on
                         stderr — that is the anchor a verifier pins.
    --encoding <ENC>     hex (default) or base64
    --out <FILE>         write the pack here (default: stdout)

The pack is the carrier-embedded minimum viable passport: product id,
resolver URI, passport id, EO id, status, safety flag, validity, as-of
stamp, log head, and the signature slots. Projected length (signature
reserves at canonical suite lengths) is budgeted against the QR
capacity tables — an oversized pack fails loudly, never truncates.

Suite note: the core's Tier-A carrier frames ecdsa-p256 / sm2 /
ml-dsa-*; ECDSA-P256 (deterministic RFC 6979) is the computed suite
that rides it, so packs sign with it. Ed25519 — SIGNATIF's
infrastructure suite — has no carrier slot (see the deviation note in
unidpp-signatif) and is used for event signing instead.";

/// Options parsed from the command line.
#[derive(Debug, Clone, Default)]
struct PackArgs {
    passport: Option<PathBuf>,
    budget: Option<String>,
    key: Option<String>,
    encoding: Option<Encoding>,
    out: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<PackArgs, CommandError> {
    let mut parsed = PackArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--passport" | "-p" => {
                parsed.passport = Some(PathBuf::from(take_value(args, &mut i, "--passport")?))
            }
            "--budget" | "-b" => parsed.budget = Some(take_value(args, &mut i, "--budget")?),
            "--key" | "-k" => parsed.key = Some(take_value(args, &mut i, "--key")?),
            "--encoding" => {
                let token = take_value(args, &mut i, "--encoding")?;
                parsed.encoding = Some(
                    Encoding::parse(&token)
                        .map_err(|e| CommandError::Usage(format!("--encoding: {e}")))?,
                );
            }
            "--out" => parsed.out = Some(PathBuf::from(take_value(args, &mut i, "--out")?)),
            other => {
                return Err(CommandError::Usage(format!(
                    "pack: unknown option `{other}` (see `unidpp help pack`)"
                )))
            }
        }
        i += 1;
    }
    Ok(parsed)
}

/// Run the command.
pub fn run(args: &[String]) -> Result<u8, CommandError> {
    let parsed = parse(args)?;
    let path = parsed
        .passport
        .clone()
        .ok_or_else(|| CommandError::Usage("pack: `--passport <FILE>` is required".to_string()))?;
    let (ec, max_version) = match &parsed.budget {
        Some(token) => {
            parse_budget(token).map_err(|e| CommandError::Usage(format!("--budget: {e}")))?
        }
        None => DEFAULT_BUDGET,
    };
    let encoding = parsed.encoding.unwrap_or(Encoding::Hex);
    let passport = Passport::load(&path).map_err(CommandError::Usage)?;

    let payload = TierAPayload::from_log(
        &passport.log,
        passport.product_id.clone(),
        &passport.resolver_uri,
        &passport.eo_id,
        passport.validity,
        vec![],
    );
    let (payload, anchor, key_id) = match &parsed.key {
        Some(seed) => {
            let (payload, public, key_id) =
                sign_pack(&payload, seed.as_bytes()).map_err(CommandError::Failure)?;
            (payload, Some(public), Some(key_id))
        }
        None => (payload, None, None),
    };

    let packer = TierAPacker::new(ec, max_version);
    let packed = packer
        .pack(&payload)
        .map_err(|e| CommandError::Failure(format!("cannot pack: {e}")))?;
    let text = encoding.encode(packed.as_slice());
    match &parsed.out {
        Some(out) => std::fs::write(out, format!("{text}\n"))
            .map_err(|e| CommandError::Failure(format!("cannot write `{}`: {e}", out.display())))?,
        None => println!("{text}"),
    }

    eprintln!(
        "packed {} bytes (projected {}) into QR v{} EC {} with margin {} bytes",
        packed.used,
        packed.projected,
        packed.version,
        ec,
        packed.margin()
    );
    if let (Some(anchor), Some(key_id)) = (anchor, key_id) {
        eprintln!(
            "signed with ecdsa-p256 key {key_id}; anchor (public key, hex): {}",
            hex_encode(anchor.as_bytes())
        );
    } else {
        eprintln!("unsigned pack (no --key): signature slots are absent");
    }
    Ok(exit::PASS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn passport_required() {
        assert!(matches!(
            run(&args(&[])),
            Err(CommandError::Usage(m)) if m.contains("--passport")
        ));
    }

    #[test]
    fn unknown_option_rejected() {
        assert!(matches!(
            run(&args(&["--passport", "x.json", "--frobnicate"])),
            Err(CommandError::Usage(m)) if m.contains("--frobnicate")
        ));
    }
}
