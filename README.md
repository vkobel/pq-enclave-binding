# PQ Enclave Binding

*Prove a post-quantum root keypair was born inside a specific AWS Nitro Enclave,
before Q-Day — and let anyone check it offline, forever.*

## What it is

`pq-enclave-binding` runs a one-time key-generation **ceremony** inside an AWS
Nitro Enclave. It produces a dual post-quantum root keypair (**ML-DSA-65** +
**SLH-DSA-SHAKE-128f**) together with a verifiable record that those keys were
generated in that specific enclave. The output is a small JSON **bundle** — the
public keys, the NSM attestation quote, and the enclave's PCR measurements —
**timestamped into the Bitcoin blockchain** via OpenTimestamps.

Verification is **fully offline**: given the bundle, the `.ots` proof, and the
pinned AWS root CA, anyone can check the claim without contacting the enclave or
any live service. The intended use is as a **provenance anchor for a larger key
hierarchy** — a signing service, a CA, an RA-TLS identity built on these keys
inherits a chain of custody traceable to a hardware attestation made while
classical crypto was still sound. The root public keys are permanent; private
material can be migrated to successor enclaves via PQ-KEM wrapping, as long as the
migration happens before Q-Day.

## How it works

A Nitro attestation quote is signed with AWS's **ECDSA P-384** PKI — which Shor's
algorithm breaks, so a quote alone is worthless after Q-Day. Three independently
sound primitives are chained so the proof survives:

1. **NSM quote** binds the enclave identity (PCR0/1/2) to the keys (and the
   pre-committed subkey set) by embedding
   `SHA-256(canonical_payload_with_subkeys)` in the attestation's `user_data`.
2. **OpenTimestamps** anchors the bundle in a Bitcoin block — a SHA-256 /
   proof-of-work timestamp with *no signatures*, so Shor gives no advantage. It
   proves the bundle existed *before* a block whose time is pre-Q-Day.
3. **Dual PQ self-signatures** (lattice **and** hash-based) prove possession of the
   private keys and hedge a future break of either family.

The key move is in verification: `pq verify` checks the Nitro certificate chain
**as of the Bitcoin anchor block's timestamp** — the moment the OTS proof was
committed and the ECDSA was still valid — not against the current clock. Because
the OpenTimestamps path uses only SHA-256 and proof-of-work, that temporal claim
survives a quantum attacker. (Two PCR checks are load-bearing and non-negotiable:
**debug-mode rejection** and **PCR pinning** — without them, a valid AWS chain plus
a matching `user_data` is satisfied by *any* enclave, including an attacker's.)

## Try it

You can run the whole flow against a **live ceremony** — no deploy needed:
**`https://pq-ceremony.kobl.one`**.

```bash
cargo build -p pq-cli      # builds ./target/debug/pq
```

### 1. Fetch and inspect the bundle

```console
$ curl -s https://pq-ceremony.kobl.one/bundle.json > bundle.json

$ ./target/debug/pq inspect --bundle bundle.json
bundle version:      2
ml-dsa-65 pk:        1952 bytes
slh-dsa-128f pk:     32 bytes
nsm quote:           4508 bytes (COSE_Sign1)
aws root ca sha256:  641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b
expected PCR0:       7dd26d083ec6f58ce4429abe56ac343de5c96fdd191408f1968c0d8faf5e778706e7e279b48e573b357a06533aace897
expected PCR1:       7dd26d083ec6f58ce4429abe56ac343de5c96fdd191408f1968c0d8faf5e778706e7e279b48e573b357a06533aace897
expected PCR2:       21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a
subkey merkle root:  18c03335fe2a0ce20e64ea3c9b459b88a2695fa65cd8832108f3284981868808
subkey count:        4
digest (sha256):     cdca69ba14ef217d40e24d5ed4aa6373ad31a0593edfff689ab165cbab3eed8e
```

### 2. Timestamp it, then upgrade once anchored

```console
$ ./target/debug/pq stamp --bundle bundle.json --out bundle.json.ots
✓ stamped via https://alice.btc.calendar.opentimestamps.org; wrote bundle.json.ots (272 bytes)
  upgrade the proof in ~a few hours once anchored in Bitcoin
```

`pq stamp` submits `SHA-256(bundle)` to OpenTimestamps calendars. The proof starts
**pending**; after ~a few hours the digest lands in a Bitcoin block. `pq` does not
upgrade — use the reference client:

```console
$ uv tool install opentimestamps-client      # one-time

$ ots upgrade bundle.json.ots
Got 1 attestation(s) from https://alice.btc.calendar.opentimestamps.org
Success! Timestamp complete
```

### 3. Verify the bundle — offline

`pq verify` reads the anchor block out of the (upgraded) proof, fetches that
block's time itself, and checks the Nitro chain as of that instant. No
`--quote-time-unix` to look up by hand.

```console
$ ./target/debug/pq verify --bundle bundle.json --ots bundle.json.ots \
    --root aws_nitro_root.der --esplora https://blockstream.info/api
Verifying bundle.json ...

✓ [1/7] OTS timestamp — bundle digest committed to Bitcoin
          digest cdca69ba14ef217d40e24d5ed4aa6373ad31a0593edfff689ab165cbab3eed8e
          anchored in block 954272 (time: unix 1781799289)
✓ [2/7] Pinned AWS root CA matches the bundle
          sha256 641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b
✓ [3/7] NSM quote — COSE_Sign1 ES384 signature + cert chain valid
          to the pinned root, as of unix 1781799289 (anchor block time)
✓ [4/7] Debug-mode rejected — PCR0/1/2 are not all-zero
✓ [5/7] PCR pinning — quote PCR0/1/2 == bundle.expected_pcrs
          PCR0 7dd26d083ec6f58ce4429abe56ac343de5c96fdd191408f1968c0d8faf5e778706e7e279b48e573b357a06533aace897
          PCR1 7dd26d083ec6f58ce4429abe56ac343de5c96fdd191408f1968c0d8faf5e778706e7e279b48e573b357a06533aace897
          PCR2 21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a
✓ [6/7] Key binding — quote.user_data == "pq-keyfork-v1:" || SHA-256(canonical_payload_with_subkeys)
          user_data 70712d6b6579666f726b2d76313aa7f12669896fabff3a24f8eabed87bd5294b5b5afff22eef34b2e128a503c41c
✓ [7/7] Dual PQ signatures valid over canonical_payload_with_subkeys
          ML-DSA-65 pk 1952 B  +  SLH-DSA-SHAKE-128f pk 32 B

VERIFIED — these PQ public keys were generated inside the attested
enclave (PCRs above) and the bundle existed before Bitcoin block 954272.
```

You provide `aws_nitro_root.der` out of band (see [Deploy](#deploy-on-caution));
check `[2/7]` ties it to the bundle. `pq verify` never contacts the enclave and
uses no nonce — it proves the keys existed in that enclave *before a Bitcoin
block*, which is checkable forever. For a **live** liveness/freshness check of a
running enclave, that's `caution verify` (next section), which issues a fresh
challenge nonce. The two are complementary.

### 4. Prove subkey birth-provenance — offline

The `inspect` output shows 4 pre-committed subkeys. To list them all:

```console
$ curl -s https://pq-ceremony.kobl.one/subkeys | python3 -m json.tool | grep index
        "index": 0,
        "index": 1,
        "index": 2,
        "index": 3,
```

Subkeys are Auth lane (purpose tag 1), derived at `m/1'/0'`…`m/1'/3'`. To verify
birth-provenance for one — no live enclave needed:

```console
$ curl -s https://pq-ceremony.kobl.one/subkey/0 > subkey.json

$ ./target/debug/pq verify-subkey --bundle bundle.json --subkey subkey.json
✓ [1/1] Birth-provenance — subkey #0 is committed in the enclave's anchored set

VERIFIED — this subkey was generated inside the attested enclave.
```

### 5. Sign with a subkey — oracle round-trip

`POST /sign` re-derives the subkey in-enclave and signs with **both** ML-DSA-65
and SLH-DSA-SHAKE-128f (the same dual-algorithm approach as the root key). The
private key never leaves the enclave; the response contains both signatures plus
the Merkle membership proof.

```console
$ curl -s -X POST https://pq-ceremony.kobl.one/sign \
    -H 'Content-Type: application/json' \
    -d '{"index":0,"message_hex":"68656c6c6f"}' > signed.json

$ ./target/debug/pq verify-subkey --bundle bundle.json --subkey signed.json \
    --message-hex 68656c6c6f
✓ [1/2] Birth-provenance — subkey #0 is committed in the enclave's anchored set
✓ [2/2] Authenticity — dual signature over the message verifies

VERIFIED — this subkey was generated inside the attested enclave.
```

Once `bundle.json.ots` is upgraded, pass `--ots` / `--root` / `--esplora` to run
all 9 checks (the 7 bundle checks + the 2 subkey checks) in one command.

> Offline header source: pass `--headers headers.json`
> (`{"<height>":{"merkle_root":"<internal-hex>","time":<unix>}}`) instead of
> `--esplora` for a fully air-gapped verify. `merkle_root` is internal byte order —
> reverse the big-endian hex explorers show.

## Deploy on Caution

The ceremony deploys as an app on [**Caution**](https://caution.co), a verifiable
compute platform that reproduces and attests your enclave build. Two files at the
repo root drive it: [`Containerfile`](Containerfile) (reproducible StageX build)
and [`Procfile`](Procfile).

**1. Prerequisites.** Commit the **AWS Nitro root CA** (DER) as `aws_nitro_root.der`
at the repo root — it's baked into the image and its SHA-256 is archived in every
bundle, so verifiers must pin the same file. Download, convert, and confirm the
[AWS-documented fingerprint](https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html):

```bash
curl -sO https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
unzip -o AWS_NitroEnclaves_Root-G1.zip && openssl x509 -in root.pem -outform der -out aws_nitro_root.der
openssl x509 -in aws_nitro_root.der -inform der -noout -fingerprint -sha256
#   must equal 64:1A:03:21:...:5B  (see the verify-root page)
```

The `Containerfile` pins `stagex/pallet-rust` by digest; refresh it when bumping
StageX. Set a real `domain` (and `app_sources`) in `Procfile`. `PQ_SUBKEYS_AUTH`
controls how many Auth subkeys the ceremony generates (default 4; the live demo uses
30 — set in `Procfile` as `PQ_SUBKEYS_AUTH=30 /app/pq-ceremony ...`).

**2. Deploy.**

```bash
caution login           # FIDO2/WebAuthn (or `register` first)
caution init            # writes .caution/
caution apps create     # build + deploy the current git branch
```

**3. Harvest, timestamp, upgrade.**

```bash
curl -fsS https://<your-domain>/bundle.json > bundle.json
pq stamp --bundle bundle.json --out bundle.json.ots
# ~a few hours later, once anchored:
ots upgrade bundle.json.ots
```

**4. Verify — live *and* offline.** Run both: `caution verify` checks the *running*
enclave with a fresh nonce and a reproduced build; `pq verify` checks the durable
*artifact*.

```console
$ caution verify          # run from the deployment directory
Challenge nonce (sent): d4d48e05...
Remote PCR values (from deployed enclave):
  PCR0: 7712469de74e5f322f34095a9d080206aaf196e42822c43ea84cfecde21b21958abd471746dd29ad64c6aa12708f5a4c
  ...
✓ Nonce verified (prevents replay attacks)
✓ PCR values match expected
✓ Attestation verification PASSED
```

Those remote/reproduced PCRs are **identical** to the bundle's `expected_pcrs` (the
`pq inspect` output above) — the reproducible build *is* the measurement
`pq verify` pins against. Then run `pq verify` as in [Try it](#try-it).

> Don't deploy with `debug: true` — it zeroes the PCRs, which `pq verify` rejects
> and `caution verify` can't reproduce.

## Build & test locally

```bash
cargo build --workspace
cargo test  --workspace      # all crates use mocks; no network/hardware needed
bash demo/run_demo.sh        # local ceremony loop with MockNsm (structurally valid,
                             #   but mock-attested — `pq verify` won't pass on it)
```

A real NSM quote requires production Nitro; under QEMU/mock the attestation step is
fake by design.

### Crate layout

`pq-core` (keygen + dual-sign, `canonical_payload`/`canonical_payload_with_subkeys`/`user_data_commitment`) ·
`pq-enclave` (NSM behind an `Nsm` trait; `MockNsm` vs real `nitro`) ·
`pq-merkle` (subkey pre-commitment tree; `subkey_leaf`/`merkle_root`/`merkle_proof`/`verify_membership`) ·
`pq-derive` (mnemonic → HD subkey derivation via keyfork/SLIP-0010) ·
`pq-ceremony` (the enclave binary; serves `bundle.json` + signing oracle) ·
`pq-bundle` (v2 schema + the `verify()` security checks) ·
`pq-quote` (parse/verify the COSE quote as of an instant) ·
`pq-ots` (OpenTimestamps stamp + offline anchor verify) ·
`pq-cli` (the `pq` binary).

### Subkeys

Subkey birth-provenance and the signing oracle are demonstrated in steps 4–5 of
[Try it](#try-it) above.

**How many subkeys.** Set `PQ_SUBKEYS_AUTH` (Auth lane, default 4) before starting
the ceremony. All subkeys are HD-derived from the same in-enclave mnemonic at
`m/1'/0'`…`m/1'/<N-1>'`; their public keys are hashed into a Merkle tree whose root
is folded into `canonical_payload_with_subkeys`, dual-signed, attested, and
OTS-anchored. (`PQ_SUBKEYS_ENC` reserves a second lane at `m/2'/...` for future use;
leave it at 0 for now.)

**Dual signing.** `POST /sign` produces two independent signatures over the same
message — one ML-DSA-65 (lattice) and one SLH-DSA-SHAKE-128f (hash-based). Both are
returned in the response and both are verified by `pq verify-subkey`. This mirrors the
root key design: a break of one algorithm family leaves the other intact.

**Discovering subkey indices.** `GET /subkeys` returns all pre-committed subkeys with
their purpose tag (`1` = Auth), public keys, and Merkle proofs. Use this to enumerate
available indices before calling `/subkey/<i>` or `POST /sign`.

**Deferred export paths** (not built in this POC):
- Shamir backup (`keyfork-shard`) for mnemonic recovery.
- TEE-to-TEE migration (ML-KEM / `fips203` wrapping to a successor enclave).

### Why `pq stamp`, not `ots stamp`?

`pq stamp` commits to `SHA-256(bundle.to_json())` — the canonical form `pq verify`
reconstructs, not raw file bytes — and omits the OTS privacy nonce (irrelevant for a
public artifact) so `start_digest == SHA-256(bundle)`, which `pq verify` checks
directly. A stock `ots stamp` proof (nonce-wrapped) would fail that check. It does
not upgrade — that's still `ots upgrade`.

## Status

Pre-1.0. The PQ crates (`fips204`/`fips205`) are young and SLH-DSA-class
implementations are unaudited — pin versions and track RUSTSEC. This proves a
root-key burn-in; it is **not** a solution for live RA-TLS.
