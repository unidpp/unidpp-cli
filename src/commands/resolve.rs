//! `unidpp resolve`: normalize a scanned carrier into the core's
//! product identifier.

use crate::carrier::{resolve_carrier, CarrierResolution};
use crate::commands::CommandError;
use crate::exit;

/// The `resolve` usage text.
pub const USAGE: &str = "\
unidpp resolve - normalize a scanned carrier to the product identifier

USAGE:
    unidpp resolve <CARRIER> [--json]

ARGUMENT:
    CARRIER   a GS1 Digital Link URI (https://…/01/<GTIN>/21/<serial>,
              qualifiers as ?10=…&21=…), a GB/T 33993 code
              (https://…/g/<EAN-13>[/qualifier], or an enterprise custom
              code URL), an AI key path (01/<GTIN>/21/<serial>), a bare
              EAN-13/GTIN, an ISO/IEC 15459 URN, or any core form
              (gtin:…, sgtin:…, local:<tag>:<key>, 01+<GTIN>+…)

OPTIONS:
    --json    machine-readable output

GS1 check digits are enforced at this seam: a correctly shaped carrier
with a bad check digit is a syntax error (exit 3), matching the
federated resolver's classification.";

/// Options parsed from the command line.
#[derive(Debug, Clone, Default)]
struct ResolveArgs {
    carrier: Option<String>,
    json: bool,
}

fn parse(args: &[String]) -> Result<ResolveArgs, CommandError> {
    let mut parsed = ResolveArgs::default();
    for arg in args {
        match arg.as_str() {
            "--json" => parsed.json = true,
            other if other.starts_with("--") => {
                return Err(CommandError::Usage(format!(
                    "resolve: unknown option `{other}` (see `unidpp help resolve`)"
                )))
            }
            positional => {
                if parsed.carrier.is_some() {
                    return Err(CommandError::Usage(format!(
                        "resolve: unexpected second argument `{positional}`"
                    )));
                }
                parsed.carrier = Some(positional.to_string());
            }
        }
    }
    Ok(parsed)
}

/// Run the command.
pub fn run(args: &[String]) -> Result<u8, CommandError> {
    let parsed = parse(args)?;
    let carrier = parsed.carrier.clone().ok_or_else(|| {
        CommandError::Usage("resolve: a carrier URI or code is required".to_string())
    })?;
    let resolution = resolve_carrier(&carrier).map_err(CommandError::Usage)?;
    if parsed.json {
        println!("{}", render_json(&resolution));
    } else {
        println!("{}", crate::carrier::describe(&resolution));
    }
    Ok(exit::PASS)
}

/// Machine-readable rendering.
fn render_json(res: &CarrierResolution) -> String {
    let json = serde_json::json!({
        "kind": res.kind,
        "identifier": res.identifier.to_string(),
        "scheme": res.identifier.scheme.to_string(),
        "key": res.identifier.key,
        "lot": res.identifier.lot,
        "serial": res.identifier.serial,
        "granularity": res.identifier.granularity.to_string(),
        "check_digit": res.identifier.gs1_check_digit_ok(),
        "resolver_base": res.resolver_base,
    });
    serde_json::to_string_pretty(&json).expect("the resolution is plain data")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn carrier_required() {
        assert!(matches!(
            run(&args(&[])),
            Err(CommandError::Usage(m)) if m.contains("carrier")
        ));
        assert!(matches!(
            run(&args(&["a", "b"])),
            Err(CommandError::Usage(m)) if m.contains("second argument")
        ));
    }
}
