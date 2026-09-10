//! End-to-end integration tests: drive the real `unidpp` binary
//! through the full officer workflow and assert the exit-code
//! contract.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use unidpp_signatif::keyring::{KeyPair, PublicKey};
use unidpp_signatif::sign::Suite;

/// The built `unidpp` binary.
fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_unidpp"))
}

fn run(cmd: &mut Command) -> Output {
    cmd.output().expect("the unidpp binary runs")
}

/// A scratch directory per test (no tempfile dependency).
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("unidpp-cli-it-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// The deterministic anchor for a pack signing seed (ECDSA-P256, the
/// computed suite that rides the Tier-A carrier).
fn anchor_for(seed: &str) -> String {
    let key = KeyPair::seeded(Suite::EcdsaP256, seed.as_bytes()).unwrap();
    hex(key.public())
}

fn hex(public: &PublicKey) -> String {
    let mut out = String::with_capacity(public.as_bytes().len() * 2);
    for b in public.as_bytes() {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn assert_exit(expected: i32, output: &Output, context: &str) {
    let code = output.status.code().unwrap_or(-1);
    assert_eq!(
        code,
        expected,
        "{context}: expected exit {expected}, got {code}\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn mint_passport(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    let out = run(bin()
        .args([
            "create",
            "--id",
            "gtin:4006381333931",
            "--capability",
            "S1",
            "--eo",
            "eo-test",
            "--type",
            "urn:unidpp:type:battery-pack",
            "--out",
        ])
        .arg(&path));
    assert_exit(0, &out, "create");
    path
}

fn append_custody_event(passport: &Path) {
    let out = run(bin().args(["event", "--passport"]).arg(passport).args([
        "--type",
        "custody.transfer",
        "--data",
        r#"{"from":"manufacturer","to":"distributor","counterparty_signed":true}"#,
        "--key",
        "issuer-seed",
    ]));
    assert_exit(0, &out, "event");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("custody.transfer"),
        "event summary printed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

fn pack_with_key(passport: &Path, out_file: &Path, seed: &str) {
    let out = run(bin()
        .args(["pack", "--passport"])
        .arg(passport)
        .arg("--out")
        .arg(out_file)
        .args(["--key", seed]));
    assert_exit(0, &out, "pack");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("anchor"),
        "pack prints the anchor: {stderr}"
    );
}

#[test]
fn full_round_trip_passes_with_matching_anchor() {
    let dir = scratch("roundtrip");
    let passport = mint_passport(&dir, "passport.json");
    append_custody_event(&passport);

    // The event signature is recorded in the document.
    let document = std::fs::read_to_string(&passport).unwrap();
    assert!(
        document.contains("\"ed25519\""),
        "Ed25519 event signature recorded"
    );
    assert!(document.contains("custody.transfer"));

    let pack = dir.join("pack.hex");
    pack_with_key(&passport, &pack, "pack-seed");
    let encoded = std::fs::read_to_string(&pack).unwrap().trim().to_string();
    assert!(!encoded.is_empty());

    // Verify the pack file with the matching anchor: exit 0 (Pass).
    let out = run(bin()
        .arg("verify")
        .arg(&pack)
        .args(["--anchor", &anchor_for("pack-seed")]));
    assert_exit(0, &out, "verify (file, matching anchor)");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Verdict: PASS"), "{stdout}");
    assert!(stdout.contains("cryptographic"), "readings table: {stdout}");
    assert!(stdout.contains("current-state"), "readings table: {stdout}");

    // Verify the raw hex argument directly (no file): same verdict.
    let out = run(bin()
        .arg("verify")
        .arg(&encoded)
        .args(["--anchor", &anchor_for("pack-seed")]));
    assert_exit(0, &out, "verify (hex argument)");

    // JSON output agrees with the human report.
    let out = run(bin().arg("verify").arg(&encoded).args([
        "--anchor",
        &anchor_for("pack-seed"),
        "--json",
    ]));
    assert_exit(0, &out, "verify --json");
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(json["verdict"], "pass");
    assert_eq!(json["exit_code"], 0);
}

#[test]
fn tampered_pack_fails() {
    let dir = scratch("tamper");
    let passport = mint_passport(&dir, "passport.json");
    append_custody_event(&passport);
    let pack = dir.join("pack.hex");
    pack_with_key(&passport, &pack, "pack-seed");
    let encoded = std::fs::read_to_string(&pack).unwrap().trim().to_string();

    // Flip one hex digit in the middle of the pack.
    let mut tampered = encoded.clone();
    let mid = (tampered.len() / 2) & !1; // keep hex alignment
    let flipped = if tampered.as_bytes()[mid] == b'0' {
        '1'
    } else {
        '0'
    };
    replace_at(&mut tampered, mid, flipped);

    let out = run(bin()
        .arg("verify")
        .arg(&tampered)
        .args(["--anchor", &anchor_for("pack-seed")]));
    assert_exit(2, &out, "verify tampered");
}

/// Replace the byte at `idx` with `c` (test helper).
fn replace_at(s: &mut String, idx: usize, c: char) {
    s.replace_range(idx..idx + 1, &c.to_string());
}

#[test]
fn wrong_anchor_degrades() {
    let dir = scratch("wrong-anchor");
    let passport = mint_passport(&dir, "passport.json");
    append_custody_event(&passport);
    let pack = dir.join("pack.hex");
    pack_with_key(&passport, &pack, "pack-seed");

    let out = run(bin()
        .arg("verify")
        .arg(&pack)
        .args(["--anchor", &anchor_for("some-other-seed")]));
    assert_exit(1, &out, "verify wrong anchor");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Verdict: DEGRADED"), "{stdout}");
    assert!(
        stdout.contains("does not cover this signer"),
        "wrong anchor phrased as trust-coverage, not tampering: {stdout}"
    );
}

#[test]
fn stale_pack_and_missing_anchor_degrade() {
    let dir = scratch("degrade");
    let passport = mint_passport(&dir, "passport.json");
    append_custody_event(&passport);
    let pack = dir.join("pack.hex");
    pack_with_key(&passport, &pack, "pack-seed");

    // No anchor at all: degraded.
    let out = run(bin().arg("verify").arg(&pack));
    assert_exit(1, &out, "verify without anchor");

    // Far-future as-of: stale, degraded.
    let out = run(bin()
        .arg("verify")
        .arg(&pack)
        .args(["--anchor", &anchor_for("pack-seed")])
        .args(["--as-of", "2036-01-01T00:00:00Z"]));
    assert_exit(1, &out, "verify stale");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("stale"), "{stdout}");

    // Static semantics (--max-age 0): never stale.
    let out = run(bin()
        .arg("verify")
        .arg(&pack)
        .args(["--anchor", &anchor_for("pack-seed")])
        .args(["--as-of", "2036-01-01T00:00:00Z", "--max-age", "0"]));
    assert_exit(0, &out, "verify archival");
}

#[test]
fn unsigned_pack_degrades() {
    let dir = scratch("unsigned");
    let passport = mint_passport(&dir, "passport.json");
    append_custody_event(&passport);
    let pack = dir.join("pack-unsigned.hex");
    let out = run(bin()
        .args(["pack", "--passport"])
        .arg(&passport)
        .arg("--out")
        .arg(&pack));
    assert_exit(0, &out, "pack unsigned");
    let out = run(bin()
        .arg("verify")
        .arg(&pack)
        .args(["--anchor", &anchor_for("pack-seed")]));
    assert_exit(1, &out, "verify unsigned pack");
}

#[test]
fn usage_errors_exit_three() {
    assert_exit(3, &run(&mut bin()), "no command");
    assert_exit(3, &run(bin().arg("bogus")), "unknown command");
    assert_exit(3, &run(bin().args(["create"])), "create without --id");
    assert_exit(
        3,
        &run(bin().args(["verify", "--anchor", "zz"])),
        "verify without pack",
    );
    assert_exit(
        3,
        &run(bin().args(["resolve", "6901234567893"])),
        "bad check digit",
    );
    assert_exit(
        3,
        &run(bin().args(["event", "--type", "issuance"])),
        "event without --passport",
    );
    assert_exit(
        3,
        &run(bin().args(["pack", "--passport", "/nonexistent.json"])),
        "pack missing file",
    );
}

#[test]
fn create_writes_valid_document_to_stdout() {
    let out = run(bin().args([
        "create",
        "--id",
        "sgtin:4006381333931+21+SN7",
        "--granularity",
        "item",
        "--capability",
        "S3",
    ]));
    assert_exit(0, &out, "create stdout");
    let document: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(document["schema"], "unidpp/passport@1");
    assert_eq!(document["capability"], "connected");
    assert_eq!(document["product_id"], "01+4006381333931+21+SN7");
    assert_eq!(
        document["log"]["sealed"]
            .as_array()
            .map(Vec::len)
            .unwrap_or(1),
        0,
        "freshly created passports carry an empty log"
    );
}

#[test]
fn create_rejects_granularity_contradictions() {
    let out = run(bin().args([
        "create",
        "--id",
        "gtin:4006381333931",
        "--granularity",
        "item",
    ]));
    assert_exit(3, &out, "granularity contradiction");
}

#[test]
fn event_appends_and_state_advances() {
    let dir = scratch("events");
    let passport = mint_passport(&dir, "passport.json");

    let out = run(bin()
        .args(["event", "--passport"])
        .arg(&passport)
        .args(["--type", "issuance"]));
    assert_exit(0, &out, "issuance with default payload");

    let out = run(bin().args(["event", "--passport"]).arg(&passport).args([
        "--type",
        "status.change",
        "--data",
        r#"{"from":"issued","to":"suspended","authority":"reg-1"}"#,
    ]));
    assert_exit(0, &out, "status change");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("suspended"), "{stdout}");

    // Legal under spec table 2: suspended -> archived.
    let out = run(bin().args(["event", "--passport"]).arg(&passport).args([
        "--type",
        "status.change",
        "--data",
        r#"{"from":"suspended","to":"archived","authority":"reg-1"}"#,
    ]));
    assert_exit(0, &out, "suspended -> archived is legal (spec table 2)");

    // Illegal transitions are rejected as usage errors (I6): archived
    // is terminal — nothing leaves it.
    let out = run(bin().args(["event", "--passport"]).arg(&passport).args([
        "--type",
        "status.change",
        "--data",
        r#"{"from":"archived","to":"issued","authority":"reg-1"}"#,
    ]));
    assert_exit(3, &out, "illegal transition (archived is terminal)");

    // A recall event flips the safety flag and the pack fails outright.
    let out = run(bin().args(["event", "--passport"]).arg(&passport).args([
        "--type",
        "recall.campaign",
        "--data",
        r#"{"campaign":"R-9","predicate":"Any"}"#,
    ]));
    assert_exit(0, &out, "recall");
    let pack = dir.join("pack.hex");
    pack_with_key(&passport, &pack, "pack-seed");
    let out = run(bin()
        .arg("verify")
        .arg(&pack)
        .args(["--anchor", &anchor_for("pack-seed")]));
    assert_exit(2, &out, "recalled pack");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("RECALL ACTIVE"), "{stdout}");
}

#[test]
fn pack_budget_is_enforced() {
    let dir = scratch("budget");
    let passport = mint_passport(&dir, "passport.json");
    append_custody_event(&passport);
    // A tiny carrier cannot hold a signed pack.
    let out = run(bin().args(["pack", "--passport"]).arg(&passport).args([
        "--budget",
        "qr-v3-M",
        "--key",
        "pack-seed",
    ]));
    assert_exit(2, &out, "over budget");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot pack"), "{stderr}");
}

#[test]
fn pack_supports_base64() {
    let dir = scratch("base64");
    let passport = mint_passport(&dir, "passport.json");
    append_custody_event(&passport);
    let pack = dir.join("pack.b64");
    let out = run(bin()
        .args(["pack", "--passport"])
        .arg(&passport)
        .arg("--out")
        .arg(&pack)
        .args(["--key", "pack-seed", "--encoding", "base64"]));
    assert_exit(0, &out, "pack base64");
    let text = std::fs::read_to_string(&pack).unwrap();
    assert!(!text.trim().is_empty());
    assert!(
        !text.trim().chars().all(|c| c.is_ascii_hexdigit()),
        "output is base64, not hex"
    );
    let out = run(bin()
        .arg("verify")
        .arg(&pack)
        .args(["--anchor", &anchor_for("pack-seed")]));
    assert_exit(0, &out, "verify base64 file (auto-detected)");
}

#[test]
fn resolve_normalizes_all_carrier_families() {
    let cases = [
        (
            "https://id.example.com/01/09506000134352/21/BP52-000841",
            "01+09506000134352+21+BP52-000841",
            "item",
        ),
        (
            "https://gds.example.cn/g/6901234567892/AB2026111",
            "01+06901234567892+21+AB2026111",
            "item",
        ),
        ("6901234567892", "01+6901234567892", "model"),
        (
            "urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
            "uri:urn:iso:std:iso-iec:15459:unidpp:inst:84120099012345",
            "model",
        ),
    ];
    for (carrier, identifier, granularity) in cases {
        let out = run(bin().arg("resolve").arg(carrier));
        assert_exit(0, &out, "resolve {carrier}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains(&format!("normalized id  {identifier}")),
            "{carrier} -> {identifier}:\n{stdout}"
        );
        assert!(stdout.contains(granularity), "{stdout}");

        let json_out = run(bin().arg("resolve").arg(carrier).arg("--json"));
        assert_exit(0, &json_out, "resolve --json {carrier}");
        let json: serde_json::Value =
            serde_json::from_str(&String::from_utf8_lossy(&json_out.stdout)).unwrap();
        assert_eq!(json["identifier"], identifier);
        assert_eq!(json["granularity"], granularity);
    }
}

#[test]
fn demo_scenarios_run_through_the_cli() {
    for scenario in ["battery-loop", "car", "laptop"] {
        let out = run(bin().arg("demo").arg(scenario));
        assert_exit(0, &out, "demo {scenario}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(!stdout.is_empty(), "demo {scenario} narrates");
    }
    let out = run(bin().args(["demo", "--list"]));
    assert_exit(0, &out, "demo --list");
}

#[test]
fn help_and_version_work() {
    assert_exit(0, &run(bin().arg("help")), "help");
    assert_exit(0, &run(bin().arg("--version")), "--version");
    for command in ["create", "event", "pack", "verify", "resolve", "demo"] {
        let out = run(bin().args(["help", command]));
        assert_exit(0, &out, "help {command}");
        assert!(String::from_utf8_lossy(&out.stdout).contains("USAGE"));
    }
}

// ---------------------------------------------------------------------------
// QR capture (--image): the carrier as a photographed label
// ---------------------------------------------------------------------------

/// Render text as a QR PNG (the label printer's output shape).
fn qr_png(content: &str, path: &Path) {
    let code = qrcode::QrCode::new(content.as_bytes()).expect("qr encode");
    let modules = code.width();
    let scale = 8usize;
    let quiet = 4usize;
    let size = (modules + 2 * quiet) * scale;
    let mut pixels = vec![255u8; size * size];
    for row in 0..modules {
        for column in 0..modules {
            if code[(column, row)] == qrcode::Color::Dark {
                for dy in 0..scale {
                    for dx in 0..scale {
                        let x = (quiet + column) * scale + dx;
                        let y = (quiet + row) * scale + dy;
                        pixels[y * size + x] = 0;
                    }
                }
            }
        }
    }
    let file = std::fs::File::create(path).unwrap();
    let mut encoder = png::Encoder::new(std::io::BufWriter::new(file), size as u32, size as u32);
    encoder.set_color(png::ColorType::Grayscale);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .unwrap()
        .write_image_data(&pixels)
        .unwrap();
}

#[test]
fn verify_from_a_photographed_qr_label() {
    let dir = scratch("qr");
    let passport = mint_passport(&dir, "passport.json");
    append_custody_event(&passport);
    let pack = dir.join("pack.hex");
    pack_with_key(&passport, &pack, "pack-seed");
    let encoded = std::fs::read_to_string(&pack).unwrap().trim().to_string();

    // The printed label: the pack's QR code.
    let label = dir.join("label.png");
    qr_png(&encoded, &label);

    // The officer photographs it and verifies: the full pipeline from
    // the decoded pixels.
    let out = run(bin()
        .arg("verify")
        .arg("--image")
        .arg(&label)
        .args(["--anchor", &anchor_for("pack-seed")]));
    assert_exit(0, &out, "verify --image");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Verdict: PASS"), "{stdout}");

    // The JSON report names the carrier.
    let out = run(bin().arg("verify").arg("--image").arg(&label).args([
        "--anchor",
        &anchor_for("pack-seed"),
        "--json",
    ]));
    assert_exit(0, &out, "verify --image --json");
    let report: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(report["passport_id"].as_str().is_some());

    // A QR carrying a resolver URI (not the pack) is surfaced
    // explicitly, never guessed at.
    let uri_label = dir.join("uri-label.png");
    qr_png(
        "https://resolver.unidpp.org/r/urn:unidpp:passport:qr-1",
        &uri_label,
    );
    let out = run(bin()
        .arg("verify")
        .arg("--image")
        .arg(&uri_label)
        .args(["--anchor", &anchor_for("pack-seed")]));
    assert_exit(3, &out, "verify --image (uri)");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("resolver URI"), "{stderr}");

    // --camera states its path instead of pretending.
    let out = run(bin().arg("verify").arg("--camera"));
    assert_exit(3, &out, "verify --camera");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--image"), "{stderr}");

    // Both a pack argument and --image is refused.
    let out = run(bin().arg("verify").arg(&pack).arg("--image").arg(&label));
    assert_exit(3, &out, "verify pack + --image");
}
