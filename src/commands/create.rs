//! `unidpp create`: mint a passport document (core skeleton + empty
//! log) as JSON.

use std::path::PathBuf;

use crate::commands::{parse_timestamp, take_value, CommandError};
use crate::exit;
use crate::passport::{MintOptions, Passport};

/// The `create` usage text.
pub const USAGE: &str = "\
unidpp create - mint a passport document (core skeleton + empty log)

USAGE:
    unidpp create --id <scheme:key> [OPTIONS]

OPTIONS:
    --id <IDENTIFIER>       product identity: `gtin:4006381333931`,
                            `sgtin:4006381333931+21+SN7`,
                            `01+4006381333931+10+LOT42`, bare EAN/GTIN,
                            `local:<tag>:<key>`, http(s) URI
    --granularity <G>       model | batch | item — must match what the
                            identifier itself carries (default: derived)
    --type <REF>            product-type reference (profile applicability)
    --capability <CLASS>    S0 silent | S1 passive-auth | S2 logged-contact
                            | S3 connected (codes or names; default S0)
    --eo <ID>               economic-operator id (default eo-local)
    --resolver <URI>        resolver URI override
    --passport-id <URN>     passport id override
    --valid-from <TS>       validity start (default: now)
    --valid-to <TS>         validity end (default: open)
    --out <FILE>            write the passport here (default: stdout)

The document is `unidpp/passport@1` JSON: identity, type ref, capability
class, resolver URI, validity, and an empty hash-chained event log.";

/// Options parsed from the command line.
#[derive(Debug, Clone, Default)]
pub struct CreateArgs {
    id: Option<String>,
    granularity: Option<String>,
    type_ref: Option<String>,
    capability: Option<String>,
    eo_id: Option<String>,
    resolver_uri: Option<String>,
    passport_id: Option<String>,
    valid_from: Option<String>,
    valid_to: Option<String>,
    out: Option<PathBuf>,
}

fn parse(args: &[String]) -> Result<CreateArgs, CommandError> {
    let mut parsed = CreateArgs::default();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--id" => parsed.id = Some(take_value(args, &mut i, "--id")?),
            "--granularity" => {
                parsed.granularity = Some(take_value(args, &mut i, "--granularity")?)
            }
            "--type" | "--type-ref" => parsed.type_ref = Some(take_value(args, &mut i, "--type")?),
            "--capability" => parsed.capability = Some(take_value(args, &mut i, "--capability")?),
            "--eo" | "--eo-id" => parsed.eo_id = Some(take_value(args, &mut i, "--eo")?),
            "--resolver" => parsed.resolver_uri = Some(take_value(args, &mut i, "--resolver")?),
            "--passport-id" => {
                parsed.passport_id = Some(take_value(args, &mut i, "--passport-id")?)
            }
            "--valid-from" => parsed.valid_from = Some(take_value(args, &mut i, "--valid-from")?),
            "--valid-to" => parsed.valid_to = Some(take_value(args, &mut i, "--valid-to")?),
            "--out" => parsed.out = Some(PathBuf::from(take_value(args, &mut i, "--out")?)),
            other => {
                return Err(CommandError::Usage(format!(
                    "create: unknown option `{other}` (see `unidpp help create`)"
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
    let id = parsed.id.clone().ok_or_else(|| {
        CommandError::Usage("create: `--id <scheme:key>` is required".to_string())
    })?;
    let granularity = match &parsed.granularity {
        Some(token) => Some(
            unidpp_model::Granularity::parse_token(token)
                .map_err(|e| CommandError::Usage(format!("--granularity: {e}")))?,
        ),
        None => None,
    };
    let opts = MintOptions {
        id,
        granularity,
        type_ref: parsed.type_ref,
        capability: parsed.capability.unwrap_or_else(|| "S0".to_string()),
        eo_id: parsed.eo_id,
        resolver_uri: parsed.resolver_uri,
        passport_id: parsed.passport_id,
        valid_from: parsed
            .valid_from
            .as_deref()
            .map(|v| parse_timestamp(v, "--valid-from"))
            .transpose()?,
        valid_to: parsed
            .valid_to
            .as_deref()
            .map(|v| parse_timestamp(v, "--valid-to"))
            .transpose()?,
    };
    let passport = Passport::mint(opts).map_err(CommandError::Usage)?;
    match &parsed.out {
        Some(path) => passport.save(path).map_err(CommandError::Failure)?,
        None => {
            println!("{}", passport.to_json().map_err(CommandError::Failure)?);
        }
    }
    eprintln!(
        "created passport {} for {} (capability {}, empty log)",
        passport.passport_id,
        passport.product_id,
        passport.capability.code()
    );
    Ok(exit::PASS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn id_is_required() {
        assert!(matches!(
            run(&args(&[])),
            Err(CommandError::Usage(m)) if m.contains("--id")
        ));
    }

    #[test]
    fn unknown_option_rejected() {
        assert!(matches!(
            run(&args(&["--id", "gtin:4006381333931", "--bogus"])),
            Err(CommandError::Usage(m)) if m.contains("--bogus")
        ));
    }

    #[test]
    fn missing_option_value_rejected() {
        assert!(matches!(
            run(&args(&["--id"])),
            Err(CommandError::Usage(m)) if m.contains("requires a value")
        ));
    }
}
