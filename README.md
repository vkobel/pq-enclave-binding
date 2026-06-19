# PQ Enclave Binding

Bind a **post-quantum root keypair** to a **specific AWS Nitro Enclave** at a
**verifiable pre-Q-Day date** — and let anyone check it, offline, years later.

The artifact is a small JSON **bundle** proving:

> *These ML-DSA-65 and SLH-DSA-SHAKE-128f public keys were generated inside this
> attested enclave, before a given Bitcoin block.*

It is a one-time key **burn-in ceremony**, not a live attestation service.

---

## Walkthrough: the full loop against a live enclave

This walks the whole lifecycle — **fetch → inspect → stamp → upgrade → verify** —
against a real ceremony deployed on Caution (`pq-ceremony.kobl.one`), and shows
what each step prints. To stand up your own enclave first, see
[Deploy on Caution](#deploy-on-caution); to exercise the plumbing with no
hardware, see [Local mock loop](#local-mock-loop).

Build the host CLI once:

```bash
cargo build -p pq-cli      # produces ./target/debug/pq
```

### 1. Fetch the bundle from the live enclave

The enclave serves its one immutable bundle over HTTP:

```console
$ curl https://pq-ceremony.kobl.one/bundle.json > bundle.json
  % Total    % Received % Xferd  Average Speed   Time
100 51346  100 51346    0     0  84907      0 --:--:--

$ jq '. | keys' bundle.json
[
  "aws_root_ca_sha256",
  "expected_pcrs",
  "ml_dsa_pk",
  "ml_dsa_sig",
  "nsm_quote",
  "slh_dsa_pk",
  "slh_dsa_sig",
  "version"
]
```

### 2. Inspect it

```console
$ ./target/debug/pq inspect --bundle bundle.json
bundle version:      1
ml-dsa-65 pk:        1952 bytes
slh-dsa-128f pk:     32 bytes
nsm quote:           4509 bytes (COSE_Sign1)
aws root ca sha256:  641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b
expected PCR0:       7712469de74e5f322f34095a9d080206aaf196e42822c43ea84cfecde21b21958abd471746dd29ad64c6aa12708f5a4c
expected PCR1:       7712469de74e5f322f34095a9d080206aaf196e42822c43ea84cfecde21b21958abd471746dd29ad64c6aa12708f5a4c
expected PCR2:       21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a
digest (sha256):     d2839421d6cc74e7a96ae6b37a9d168019c18ae4edd393a7b2a0656f854fda1c
```

`inspect` does **no** verification — it just decodes the fields. Note
`aws root ca sha256` matches the AWS-documented Root-G1 fingerprint, and PCR0/1/2
are real measurements (not all-zero, so not debug mode).

### 3. Timestamp the bundle

```console
$ ./target/debug/pq stamp --bundle bundle.json --out bundle.json.ots
✓ stamped via https://alice.btc.calendar.opentimestamps.org; wrote bundle.json.ots (272 bytes)
  upgrade the proof in ~a few hours once anchored in Bitcoin
```

`stamp` submits `SHA-256(bundle.json)` to OpenTimestamps calendars and writes a
`.ots` proof. At this point the proof holds only **pending** calendar
attestations — the digest hasn't made it into a Bitcoin block yet.

### 4. Upgrade the proof once it's anchored

Until the timestamp is in a block, `pq verify` fails with:

```
Caused by:
    proof is not anchored in Bitcoin yet (only pending attestations); upgrade it first
```

This CLI does **not** upgrade for you. Wait ~a few hours for the digest to be
mined, then upgrade the `.ots` in place with the reference OpenTimestamps client:

```console
$ uv tool install opentimestamps-client      # one-time

$ ots upgrade bundle.json.ots
Got 1 attestation(s) from https://alice.btc.calendar.opentimestamps.org
Success! Timestamp complete
```

`ots upgrade` walks the pending calendar URIs in the proof, fetches the
Bitcoin-anchored version, and rewrites `bundle.json.ots` (leaving a `.bak`) — the
proof now carries a real **Bitcoin block attestation** instead of only pending
calendar entries. If it reports still-pending, the digest isn't in a block yet —
wait and retry. `ots` needs network for this; `pq verify` itself stays offline.

> `pq verify` against the live chain requires this **upgraded** proof — a
> pending-only `.ots` is what triggers the "not anchored in Bitcoin yet" error.

### 5. Verify the *live* enclave — `caution verify`

Run this from the deployment directory. It is the only step that talks to the
running enclave: it sends a **fresh challenge nonce**, pulls the live PCRs,
reproduces the enclave image from the published manifest, and confirms everything
matches. This proves the enclave is *alive right now and is exactly the code you
expect* — the freshness property `pq verify` deliberately does not provide.

```console
$ caution verify
Verifying enclave attestation...

Challenge nonce (sent): d4d48e057377e931f5936a06be615ce5dfdf876da821813e9bed2a209829ab43
Requesting attestation...

Remote PCR values (from deployed enclave):
  PCR0: 7712469de74e5f322f34095a9d080206aaf196e42822c43ea84cfecde21b21958abd471746dd29ad64c6aa12708f5a4c
  PCR1: 7712469de74e5f322f34095a9d080206aaf196e42822c43ea84cfecde21b21958abd471746dd29ad64c6aa12708f5a4c
  PCR2: 21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a
...
Reproducing build from remote manifest...
Expected PCR values:
  PCR0: 7712469de74e5f322f34095a9d080206aaf196e42822c43ea84cfecde21b21958abd471746dd29ad64c6aa12708f5a4c
  PCR1: 7712469de74e5f322f34095a9d080206aaf196e42822c43ea84cfecde21b21958abd471746dd29ad64c6aa12708f5a4c
  PCR2: 21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a

Verifying attestation with bootproof-sdk...
✓ Certificate chain verified against AWS Nitro root CA
✓ All certificates are within validity period
✓ COSE signature verified
✓ Nonce verified (prevents replay attacks)
✓ PCR values match expected

✓ Attestation verification PASSED
```

Note these remote/reproduced PCRs are **identical** to the `expected_pcrs` shown
by `pq inspect` in step 2 (`7712469d…` / `21b9efbc…`). That is the loop closing:
the reproducible build *is* the measurement the bundle pins against.

### 6. Verify the *bundle* — `pq verify` (offline, durable)

No timestamps to look up by hand: `pq verify` reads the anchor block out of the
proof and fetches that block's time itself.

```console
$ ./target/debug/pq verify \
    --bundle  bundle.json \
    --ots     bundle.json.ots \
    --root    aws_nitro_root.der \
    --esplora https://blockstream.info/api
✓ OTS: bundle anchored in Bitcoin block 954272
✓ NSM quote verified against pinned AWS root (as of unix 1781799289)
✓ PCR0/1/2 pinning, debug-mode rejection, key binding, dual PQ signatures

VERIFIED: these PQ keys were generated in the attested enclave before Bitcoin block 954272
```

`pq verify` is **fully offline with respect to the enclave** — it reads only the
bundle, the `.ots`, the pinned root CA, and a Bitcoin header source, and never
calls the enclave or uses a nonce. It checks the quote *embedded in the bundle*
as of the OTS anchor block time, not a live endpoint.

What it enforces, failing on the first miss:

1. **OTS anchor** — the proof commits to `SHA-256(bundle)` and every Bitcoin
   attestation's Merkle root matches the block header from the source.
2. **Pinned root CA** — `SHA-256(--root)` equals the bundle's `aws_root_ca_sha256`.
3. **NSM quote** — `COSE_Sign1` parses, the ES384 signature verifies, and the cert
   chain validates **to the pinned root as of the anchor block's time**.
4. **Debug-mode rejection** — PCR0/1/2 are not all-zero.
5. **PCR pinning** — quote PCR0/1/2 equal the bundle's `expected_pcrs`.
6. **Key binding** — `quote.user_data == "pq-keyfork-v1:" || SHA-256(canonical_payload)`.
7. **Dual PQ signatures** — ML-DSA-65 **and** SLH-DSA-SHAKE-128f over the payload.

Get `aws_nitro_root.der` once, out of band (see
[Prerequisites](#1-prerequisites)); check (2) ties it to the bundle.

#### Verification time: the anchor block, not now

A Nitro leaf certificate lives only a few hours, and AWS signs it with
quantum-breakable ECDSA P-384. So verifying the chain against the **current** clock
is both broken (the cert expired long ago) and meaningless after Q-Day. `pq verify`
instead checks the chain **as of the instant the bundle was timestamped into
Bitcoin** — when the cert was valid and its signature still sound (see the
`as of unix 1781799289` line above).

That instant is derived from the **proven anchor block itself**, not supplied by
you: `pq verify` takes the earliest Bitcoin block in the upgraded proof and looks
up its timestamp (from `--esplora`, or the `"time"` field of a `--headers` file).
This is deliberate — deriving the time from the anchor removes any chance of
verifying against an attacker-chosen instant where a stale or forged certificate
would validate.

`--quote-time-unix <secs>` exists only as a manual **override**, and is needed in
just one case: a `--headers` file that omits `"time"` for the anchor block. The
offline, self-contained header form is otherwise complete:

```json
{ "954272": { "merkle_root": "<internal-byte-order-hex>", "time": 1781799289 } }
```

```bash
pq verify --bundle bundle.json --ots bundle.json.ots \
  --root aws_nitro_root.der --headers headers.json     # time taken from the file
```

(`merkle_root` is **internal byte order** — reverse the big-endian hex explorers
show.)

### The two checks are complementary

| | `caution verify` (step 5) | `pq verify` (step 6) |
|---|---|---|
| Talks to the enclave | **Yes** — live, over the network | No — reads files only |
| Freshness | **Nonce-challenged** (anti-replay, proves liveness *now*) | None — proves existence *before a Bitcoin block* instead |
| Proves | the running enclave is the expected code, right now | the keys were bound to that enclave pre-Q-Day, checkable forever |
| Post-Q-Day / after teardown | no longer meaningful | still sound |
| Shared anchor | produces the PCRs … | … that the bundle pins against |

You want both: `caution verify` for live assurance at deploy time, `pq verify` for
the durable, offline, quantum-safe artifact anyone can re-check years later.

### Local mock loop

To exercise the pipeline with **no Nitro hardware**:

```bash
bash demo/run_demo.sh
```

This runs `pq-ceremony` with `MockNsm`, serves the bundle, fetches it, and runs
`pq inspect`. The result is **structurally** valid but **mock-attested**: the
quote is a fake COSE doc and the PCRs are placeholders, so `pq verify` will *not*
pass on it. Useful for checking keygen, dual-signing, bundle assembly, HTTP
serving, and `inspect` without deploying.

---

## How it works

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

`verify` enforces these checks and fails on the first miss: OTS Bitcoin anchor →
NSM ES384 signature chains to the **pinned** root → **debug-mode rejection**
(PCR0/1/2 not all-zero) → **PCR pinning** (quote PCRs == `expected_pcrs`) → key
binding (`user_data` == commitment) → both PQ signatures. The Nitro chain is
checked **as of the OTS anchor block time**, when AWS's cert was valid and its
ECDSA sound — that is the whole point of the timestamp.

See [`demo-spec.md`](demo-spec.md) for the full cryptographic soundness analysis.

### Workspace layout

| Crate | Role |
|-------|------|
| `pq-core` | ML-DSA + SLH-DSA keygen, dual-sign/verify, `canonical_payload` / `user_data_commitment` |
| `pq-enclave` | NSM attestation behind an `Nsm` trait (`MockNsm` / real `nitro`) |
| `pq-ceremony` | **The enclave binary**: run the burn-in, serve `bundle.json` over HTTP |
| `pq-bundle` | `PqRootBundle` schema + the `verify()` security checks |
| `pq-quote` | Parse + verify the NSM COSE quote against a pinned AWS root, as of an instant |
| `pq-ots` | OpenTimestamps stamping + Bitcoin-anchored proof verification |
| `pq-cli` | `pq` binary: host-side `inspect` / `verify` / `stamp` |

---

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
# ~a few hours later, once anchored in a Bitcoin block:
ots upgrade bundle.json.ots          # reference OTS client; pq does not auto-upgrade
```

### 5. Verify the deployment and the bundle

Two independent checks. The first checks the **live** enclave; the second checks
the **artifact**.

```bash
# (a) Live attestation: send a fresh nonce, reproduce the enclave build, and
#     compare PCRs against the running enclave. The ONLY step that hits the
#     enclave. Run from the deployment directory.
caution verify

# (b) The bundle itself — fully offline (after the .ots is anchored, ~hours later).
pq verify --bundle bundle.json --ots bundle.json.ots \
  --root aws_nitro_root.der --esplora https://blockstream.info/api
```

See [the walkthrough](#walkthrough-the-full-loop-against-a-live-enclave) (steps
5–6) for full output of both, and why they're complementary.

`caution verify` independently re-derives the PCR0/1/2 that `pq verify` pins
against, closing the loop: the reproducible build *is* the published
`expected_pcrs`. `pq verify` then trusts only the quote bytes inside the bundle —
it does not re-contact the enclave.

> Do not deploy with `debug: true` — it zeroes the PCRs, which `pq verify`
> rejects (debug-mode check) and `caution verify` cannot reproduce.

---

## `pq` CLI reference

```bash
# Summarize a bundle (no verification).
pq inspect --bundle bundle.json

# Timestamp it: submit SHA-256(bundle.json) to OTS calendars, write a proof.
pq stamp --bundle bundle.json --out bundle.json.ots
#   then wait ~a few hours and upgrade the .ots once anchored in a Bitcoin block.
#   `pq` does NOT upgrade — use the reference client:  ots upgrade bundle.json.ots

# Full verification — ALL checks must pass.
pq verify \
  --bundle  bundle.json \
  --ots     bundle.json.ots \
  --root    aws_nitro_root.der \           # pinned out-of-band; cross-checked vs bundle
  --esplora https://blockstream.info/api   # or --headers headers.json (offline)
```

Flags:
- `--root` — the pinned AWS Nitro root CA (DER), fetched out of band; its SHA-256
  is cross-checked against `aws_root_ca_sha256` in the bundle.
- `--headers` **or** `--esplora` — the Bitcoin header source (mutually exclusive).
  `merkle_root` in a header file is **internal byte order** — reverse the
  big-endian hex explorers display. Header entry shape:
  `{ "<height>": { "merkle_root": "<hex>", "time": <unix> } }`.
- `--quote-time-unix` — **optional override** for the instant the Nitro cert chain
  is verified as of. Normally omitted: the anchor block's own timestamp is used
  (fetched via `--esplora`, or read from a `--headers` `"time"` field). Needed only
  if a header file omits `"time"`. See
  [Verification time](#verification-time-the-anchor-block-not-now).

### Why `pq stamp`, not `ots stamp`?

`pq stamp` is an OTS stamp specialized so the proof is directly checkable by
`pq verify`:

- It commits to `SHA-256(bundle.to_json())` — the **canonical** re-serialization
  the verifier reconstructs — not the raw on-disk bytes, so reformatting the JSON
  can't invalidate the proof.
- It **omits the OTS privacy nonce**. Stock `ots stamp` prepends random bytes so
  the calendar never learns your file's hash; that's pure privacy and irrelevant
  for a *public* bundle. Skipping it keeps `start_digest == SHA-256(bundle)`, which
  is exactly what `pq verify` checks — a nonce-wrapped `ots stamp` proof would fail
  `pq verify`'s digest check. (This privacy nonce is unrelated to the *attestation*
  challenge nonce in `caution verify`.)
- It tries several calendars in order (failover) from the one Rust binary.

It does **not** upgrade — once anchored, that's still `ots upgrade` (step 4).

---

## Status

Pre-1.0. The PQ crates (`fips204`/`fips205`) are young and SLH-DSA-class
implementations are unaudited — pin versions and track RUSTSEC. This proves a
root-key burn-in; it is **not** a solution for live RA-TLS.
