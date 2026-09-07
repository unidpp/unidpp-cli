# unidpp-cli

The UniDPP command-line verifier — what a customs officer's terminal
runs offline.

`unidpp` mints passport documents, appends typed events, packs the
Tier-A offline carrier, and — the flagship — verifies a scanned pack
end-to-end: unpack, schema check, **real signature verification**,
freshness, and a graded verdict with the three readings, a coverage
report, and a findings table.

Licensed under [Apache-2.0](LICENSE).

## Build and install

```sh
cargo build # debug
cargo test # 50 unit + 14 integration tests
cargo install --path . # installs the `unidpp` binary
```

The crate is standalone with path dependencies into the sibling
repositories (`../unidpp-core/crates/*`, `../unidpp-signatif`); clone
the family side by side, or adjust the paths in `Cargo.toml`.

## Commands

```text
unidpp create --id <scheme:key> --granularity <model|batch|item>
 [--type <ref>] [--capability S0-S3] [--eo <id>]
 [--resolver <uri>] [--passport-id <urn>]
 [--valid-from <ts>] [--valid-to <ts>] [--out <file>]

unidpp event --passport <file> --type <EventType> [--data <json>]
 [--key <seed>] [--actor <id>] [--actor-role <role>]
 [--at <ts>] [--out <file>]

unidpp pack --passport <file> [--budget qr-v15-M] [--key <seed>]
 [--encoding hex|base64] [--out <file>]

unidpp verify <pack-file-or-hex> [--anchor <pubkey-hex>]
 [--as-of <timestamp>] [--max-age <secs>] [--encoding <enc>]
 [--json]

unidpp resolve <carrier-uri-or-code> [--json]

unidpp demo <battery-loop|car|laptop> [--seed <hex>] [--list]
```

`unidpp help` and `unidpp help <command>` print the same grammar with
payload examples.

### The officer workflow

```sh
# Issuer side.
unidpp create --id gtin:4006381333931 --capability S2 --eo eo-mfg-42 --out p.json
unidpp event --passport p.json --type custody.transfer \
 --data '{"from":"manufacturer","to":"distributor","counterparty_signed":true}' \
 --key issuer-seed
unidpp pack --passport p.json --key pack-seed --out pack.hex
# stderr: "… anchor (public key, hex): 04…" <- pin this on the verifier

# Verifier side (offline; the pack file may be replaced by raw hex).
unidpp verify pack.hex --anchor 04…
```

## Exit codes

| Code | Meaning |
|------|----------------------------------------------------------------------|
| 0 | Verdict **Pass** |
| 1 | Verdict **Degraded** — the reason is always printed |
| 2 | Verdict **Fail** (or an operational failure of a non-verify command) |
| 3 | Usage error (bad invocation or unreadable input) |

The three verdict codes mirror the core's degradation ladder
(I9/I13: pass / degraded-with-reason / fail — never a bare boolean).

## How `verify` grades a pack

Every stage is a finding; the verdict is the worst of them.

- **schema/decode** — canonical Tier-A unpacking; a broken frame fails
 outright.
- **signature/&lt;suite&gt;/slot-N** — real cryptographic verification
 of each slot against the anchor:
 - signature invalid under the pinned key → **Fail** (tampering),
 - the anchor does not pin the slot's signing key → **Degraded**
 (that is how a *wrong anchor* surfaces: trust configuration not
 covering the signer, not a forgery),
 - framing-only or deferred suites (SM2 / ML-DSA) → **Degraded**,
 honestly reported,
 - no anchor supplied → **Degraded** (unverifiable offline);
- **freshness** — as-of stamp vs the window (`--max-age`, default
 86400 s; `0` selects static/archival semantics);
- **evidence/log-head**, **evidence/validity** — the chain-head
 commitment and the validity window;
- **status**, **safety** — the replayed current state. A recall or
 security flag **fails** ("do not release"); suspended / consumed /
 transformed / end-of-waste / archived **degrade**; outside the
 validity window **degrades**.

The three readings (cryptographic, evidentiary, current-state) are
printed with a coverage report (10 Tier-A fields) and the verdict names
the reading it answers: `current-state` — a Tier-A pack is the
current-state projection an officer decides on. The retroactive-taint
cascade needs registry/revocation state (Tier B); the current-state
reading carries that caveat instead of fabricating a pass.

## Design choices and deviations (documented)

- **Argument parsing is hand-rolled**, not clap. The family doctrine is
 dependency-light: the only non-path dependency is `serde_json`
 (documents and event payloads). The grammar is strict — unknown flags
 and missing values are usage errors. Hex and base64 codecs are also
 hand-rolled (~60 lines each, tested against the RFC 4648 vectors).
- **Pack signature slots are ECDSA-P256, not Ed25519.** The core's
 Tier-A carrier frames `ecdsa-p256 | sm2 | ml-dsa-*` only — Ed25519 is
 SIGNATIF's *infrastructure* suite and deliberately has no carrier
 slot (see the deviation note in `unidpp-signatif/src/sign.rs`).
 ECDSA-P256 (deterministic RFC 6979 via the `p256` crate) is the one
 computed suite that rides the carrier, so packs sign with it.
 `--key` on `event` signs with Ed25519, as specified; `verify
 --anchor` accepts either key type (65-byte P-256 SEC1 or 32-byte
 Ed25519, raw hex) and runs real verification in whichever suite the
 anchor carries.
- **What a pack signature covers**: the pack's own canonical encoding
 with the signature slots cleared (`packfile::signing_body` — a
 fixpoint), signed in SIGNATIF's `ArtifactEvent` domain. The verifier
 rebuilds the identical bytes from the decoded pack, so the signed
 body never ships alongside it.
- **Seeded keys are for tests and ceremonies.** `--key <seed>` derives
 a deterministic key (`KeyPair::seeded`); production keys come from a
 CSPRNG/HSM (see the signatif keyring docs). Signing material is only
 ever printed to stderr, never into the pack or passport document —
 only key ids and signature values are recorded.
- **Events append unsalted**: the owner-side salt ceremony is out of
 scope for a CLI, so the chain fully recomputes on verification.
- **`--granularity` is a check, not data**: the identifier itself
 carries its granularity (invariant I3), so `create` rejects a
 `--granularity` that contradicts it (you cannot claim `item` for a
 bare GTIN) and stores nothing redundant.
- **Carrier resolution mirrors the federated resolver's semantics**
 (GS1 Digital Link, GB/T 33993 GDS paths and custom codes, legacy
 EAN-13, ISO/IEC 15459 URNs) without depending on its HTTP stack; GS1
 check digits are enforced at this seam — the core keeps them
 advisory.
- **The passport document** (`unidpp/passport@1` JSON) is serde-derived
 from the core types: skeleton (identity, type ref, capability,
 resolver, validity) + the authoritative event log + recorded event
 signatures. No hand-rolled field mapping anywhere.

## Repository layout

```text
src/main.rs thin binary: dispatch + exit codes
src/lib.rs library root and the exit-code contract
src/passport.rs the passport document (mint/load/save)
src/packfile.rs budget grammar, signing body, slot checks
src/carrier.rs carrier adapter (GS1 DL / GB/T 33993 / EAN-13 / URN)
src/encoding.rs hex + base64 codecs
src/report.rs grades, findings, tables
src/commands/ one module per subcommand
tests/cli.rs end-to-end tests against the built binary
```
