# PQ Enclave Binding

Bind a **post-quantum root keypair** to a **specific AWS Nitro Enclave** at a
**verifiable pre-Q-Day date** — and let anyone check it, offline, years later.

The artifact is a small JSON **bundle** proving:

> *These ML-DSA-65 and SLH-DSA-SHAKE-128f public keys were generated inside this
> attested enclave, before a given Bitcoin block.*

It is a one-time key **burn-in ceremony**, not a live attestation service.

## Why

A Nitro attestation quote is signed with AWS's **ECDSA P-384** PKI — classical
crypto that a quantum computer breaks. So a quote alone is worthless after Q-Day.
This design chains three independently-sound primitives so the proof survives:

1. **NSM quote** binds the enclave identity (PCR0/1/2) to the PQ keys, by
   embedding `SHA-256(canonical_payload)` in the attestation's `user_data`.
2. **OpenTimestamps** anchors the bundle in a Bitcoin block — a SHA-256 /
   proof-of-work timestamp with no signatures, so Shor gives no advantage. This
   proves the bundle (and thus the quote) existed *before* a block whose time is
   pre-Q-Day, when the ECDSA was still sound.
3. **Dual PQ self-signatures** (lattice **and** hash-based) prove possession of
   the private keys and hedge a future break of either family.

See [`demo-spec.md`](demo-spec.md) for the full cryptographic soundness analysis.

## How it works

```
[Nitro Enclave: pq-ceremony]            (one shot, on startup)
  generate ML-DSA-65 + SLH-DSA-128f keypair
  payload = canonical_payload(ml_pk, slh_pk)   # length-prefixed concat
  dual-sign payload
  NSM attest with user_data = "pq-keyfork-v1:" || SHA-256(payload)
  read own PCR0/1/2  +  SHA-256(baked-in AWS root CA)
  → serve bundle.json over HTTP  (enclave has no other egress)

[Host / CI]
  curl https://<enclave>/bundle.json > bundle.json
  pq stamp  → bundle.json.ots         # submit digest to OTS calendars

[Verifier: anywhere, any time]
  pq verify  →  OTS anchor + Nitro quote (as of block time) + PCR pinning
                + debug-mode rejection + key binding + dual PQ signature
```

## Workspace layout

| Crate | Role |
|-------|------|
| `pq-core` | ML-DSA + SLH-DSA keygen, dual-sign/verify, `canonical_payload` / `user_data_commitment` |
| `pq-enclave` | NSM attestation behind an `Nsm` trait (`MockNsm` / real `nitro`) |
| `pq-ceremony` | **The enclave binary**: run the burn-in, serve `bundle.json` over HTTP |
| `pq-bundle` | `PqRootBundle` schema + the `verify()` security checks |
| `pq-quote` | Parse + verify the NSM COSE quote against a pinned AWS root, as of an instant |
| `pq-ots` | OpenTimestamps stamping + Bitcoin-anchored proof verification |
| `pq-cli` | `pq` binary: host-side `inspect` / `verify` / `stamp` |

## Build & test

```bash
cargo build --workspace
cargo test  --workspace
bash demo/run_demo.sh     # local loop with MockNsm (no hardware needed)
```

The local demo produces a structurally valid but **mock-attested** bundle — fine
for exercising the plumbing, but `pq verify` only passes on a bundle from a real
enclave.

## Using the `pq` CLI

```bash
# Summarize a bundle (no verification).
pq inspect --bundle bundle.json

# Timestamp it: submit SHA-256(bundle.json) to OTS calendars, write a proof.
pq stamp --bundle bundle.json --out bundle.json.ots
#   wait ~a few hours, then upgrade the .ots once anchored in a Bitcoin block.

# Full verification — ALL checks must pass.
pq verify \
  --bundle  bundle.json \
  --ots     bundle.json.ots \
  --root    aws_nitro_root.der \           # pinned out-of-band; cross-checked vs bundle
  --headers headers.json                   # { "<height>": { "merkle_root": "<hex>", "time": <unix> } }
# or, instead of --headers, hit a live explorer:
#   --esplora https://blockstream.info/api --quote-time-unix <secs>
```

`verify` enforces, and fails on the first miss: OTS Bitcoin anchor → NSM ES384
signature chains to the **pinned** root → **debug-mode rejection** (PCR0/1/2 not
all-zero) → **PCR pinning** (quote PCRs == `expected_pcrs`) → key binding
(`user_data` == commitment) → both PQ signatures. The Nitro chain is checked **as
of the OTS anchor block time**, when AWS's cert was valid and its ECDSA sound.

`merkle_root` in the header file is **internal byte order** — reverse the
big-endian hex that explorers display.

## Deploy on Caution

The ceremony runs as a Caution enclave app. Two files at the repo root drive it:
[`Containerfile`](Containerfile) (reproducible StageX build) and
[`Procfile`](Procfile) (run config).

### 1. Prerequisites

- Add the **AWS Nitro root CA** (DER) to the repo root as `aws_nitro_root.der`.
  It is baked into the image and its SHA-256 is archived into every bundle, so the
  *same* file must be used at verification time (`pq verify --root`). It is a
  public cert — commit it. AWS publishes the long-lived **Root-G1** certificate as
  a PEM in a zip, and documents its **SHA-256 fingerprint** (the authoritative
  check) on the
  [verify-the-root-of-trust](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html)
  page. Download, convert PEM → DER, and confirm the fingerprint matches:

  ```bash
  curl -sO https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
  unzip -o AWS_NitroEnclaves_Root-G1.zip          # -> root.pem
  openssl x509 -in root.pem -outform der -out aws_nitro_root.der
  # AWS-documented fingerprint (on the verify-root page) — must equal:
  #   64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
  openssl x509 -in aws_nitro_root.der -inform der -noout -fingerprint -sha256
  ```
- The `Containerfile` pins the `stagex/pallet-rust` image by digest. It is set to
  a verified value from StageX's published digests; refresh it when you move to a
  newer StageX release and confirm it against the authoritative list:

  ```bash
  curl -s https://codeberg.org/stagex/stagex/raw/branch/main/digests/pallet.txt \
    | awk '$2 == "pallet-rust" { print $1 }'
  ```

- Set a real `domain` (and `app_sources`) in `Procfile`.

### 2. (Optional) inspect the build locally

```bash
caution apps build      # build the EIF to inspect / QEMU-debug — does NOT deploy
```

Note: a real NSM quote requires production Nitro hardware; under QEMU the
attestation step fails by design (no NSM device).

### 3. Deploy

```bash
caution login           # FIDO2/WebAuthn (or `register` first)
caution init            # initialize the deployment (writes .caution/)
caution apps create     # build + deploy
```

Caution deploys a **specific git branch** and needs `Procfile` + `Containerfile`
at the root of *that* branch.

### 4. Harvest and timestamp the bundle

```bash
curl -fsS https://<your-domain>/bundle.json > bundle.json
pq stamp --bundle bundle.json --out bundle.json.ots
```

### 5. Verify the deployment and the bundle

```bash
# Reproduce the enclave build and compare PCRs against the live attestation.
caution verify --attestation-url https://<your-domain>/attestation

# Then verify the bundle itself (after the .ots is anchored, ~hours later).
pq verify --bundle bundle.json --ots bundle.json.ots \
  --root aws_nitro_root.der --esplora https://blockstream.info/api \
  --quote-time-unix <anchor-block-time>
```

`caution verify` independently re-derives the PCR0/1/2 that `pq verify` pins
against, closing the loop: the reproducible build *is* the published
`expected_pcrs`.

> Do not deploy with `debug: true` — it zeroes the PCRs, which `pq verify`
> rejects (debug-mode check) and `caution verify` cannot reproduce.

## Status

Pre-1.0. The PQ crates (`fips204`/`fips205`) are young and SLH-DSA-class
implementations are unaudited — pin versions and track RUSTSEC. This proves a
root-key burn-in; it is **not** a solution for live RA-TLS.
