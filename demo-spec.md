# PQ Enclave Binding: Keyfork + ML-DSA + SPHINCS+ Demo

## Cryptographic Soundness Assessment

Before committing to an implementation path, it is worth verifying that every link in the proposed chain is individually sound.

### Link 1 — AWS Nitro Quote as a Binding Primitive

The AWS Nitro Secure Module (NSM) produces CBOR-encoded attestation documents wrapped in a `COSE_Sign1` structure and signed with **ECDSA P-384 (ES384)** by AWS's Nitro certificate hierarchy. The document exposes three user-controlled fields: `public_key` (intended for key wrapping), `user_data` (up to 512 bytes of arbitrary data), and `nonce`. Crucially, these fields live in the COSE *protected payload*, so they are committed to by the hardware signature (ES384 signs SHA-384 of the COSE `Sig_structure`, which covers the payload). This means placing `SHA-256(PQ_pubkey)` in `user_data` creates a hardware-attested, immutable binding between the enclave identity (PCRs 0–8) and the specific PQ public key, with sub-second overhead.[^1][^2][^3][^4]

**Soundness verdict:** ✅ Architecturally sound *as a binding primitive* — but the binding is only meaningful if the verifier also (a) pins the expected **PCR0–2** measurements and (b) **rejects debug-mode** quotes (all-zero PCRs). A valid signature + matching `user_data` alone proves only "*some* Nitro enclave," not *this* enclave (see Phase 5). The ECDSA vulnerability of the underlying Nitro PKI is the *only* classical weak point — it cannot be eliminated from the silicon, but it can be mitigated temporally via timestamping (see Link 3).

### Link 2 — ML-DSA and SPHINCS+ as the PQ Key Algorithms

Both algorithms are NIST-standardized:

| Algorithm | NIST Standard | Type | Rust Crate (recommended) | Security Notes |
|-----------|--------------|------|--------------------------|----------------|
| ML-DSA-65 | FIPS 204 | Lattice (Module-Lattice) | `ml-dsa` (RustCrypto) | Security Level 3 (≈AES-192); structured lattice, theoretically faster attacks than worst-case lattice[^5][^6] |
| SLH-DSA-SHAKE-128f | FIPS 205 | Hash-based (SPHINCS+) | `slh-dsa` (RustCrypto / Trail of Bits) | Security Level 1; relies *only* on SHA-3 hash security, no lattice assumptions[^7][^8] |

A key observation: `pqcrypto-mldsa` (the PQClean C-binding crate) is now unmaintained as PQClean is being archived post-July 2026. The correct migration target is `ml-dsa` (pure Rust, RustCrypto), and for SPHINCS+, `slh-dsa` authored by Trail of Bits and merged into RustCrypto. Both crates are `no_std`-compatible, meaning they can compile inside an enclave environment without an OS heap.[^6][^7][^8]

**Soundness verdict:** ✅ at the *algorithm* level (both are NIST standards); ⚠️ at the *implementation* level. The RustCrypto crates are the right migration target away from PQClean C-bindings, but they are **immature and pre-1.0**: `slh-dsa` ships an explicit "never independently audited — use at your own risk" warning, and `ml-dsa` has had real verification advisories (e.g. accepting signatures with repeated hint indices). Honest framing: *NIST-standard algorithms, immature Rust implementations*. The conservative architectural choice is to favor SPHINCS+ (SLH-DSA) as the root since its security rests on hash functions alone, not lattice hardness — but pin exact crate versions and track advisories.[^7][^8][^6]

### Link 3 — OpenTimestamps as a Quantum-Safe Temporal Anchor

OpenTimestamps (OTS) embeds a SHA-256 Merkle root into a Bitcoin `OP_RETURN` output. Verification requires only Bitcoin block headers and a SHA-256 implementation — no digital signature verification, no certificate authority. The security guarantee derives from Bitcoin's Proof-of-Work, which accumulates hundreds of exahashes of SHA-256 computation per block.[^9][^10][^11]

The critical question is: does an attacker with a CRQC gain any advantage over the OTS proof chain? No — because:

1. Shor's algorithm attacks discrete logarithm and integer factorization problems. It provides no speedup against SHA-256 preimage or collision resistance.[^9]
2. Grover's algorithm provides a quadratic speedup against hash functions, reducing SHA-256's effective security to 128 bits — still computationally infeasible for preimage attacks.[^12]
3. The Bitcoin ECDSA keys of miners are used to *spend UTXOs*, not to sign the block header Merkle tree. Breaking those keys gives an attacker the ability to steal mining rewards, not to retroactively alter or forge `OP_RETURN` commitments embedded in past blocks.[^10][^9]

A May 2026 IETF Internet-Draft (`draft-fassbender-scitt-time-anchor-02`) formally proposes OTS as the Bitcoin-anchored temporal proof mechanism for SCITT transparency services, explicitly citing its trust-minimized, PoW-rooted design.[^11]

**Soundness verdict:** ✅ Cryptographically sound as a post-quantum-resistant timestamp. The only residual risk is a 51% attack on the Bitcoin network itself, which is economically infeasible and orthogonal to quantum computing.[^9]

### Link 4 — Dual-Signing (ML-DSA + SPHINCS+) Over the Bundle

Signing the attestation bundle with both ML-DSA-65 (lattice) and SLH-DSA-SHAKE-128f (hash-based) provides defense-in-depth: if a future cryptanalytic break weakens lattice assumptions, the hash-based signature survives independently. A recent public timestamping service (SasaSavic Quantum Shield) implemented exactly this dual-signature approach (ECDSA + ML-DSA), anchoring both signatures to OTS. For a TEE root key use case, using two *PQ* algorithms (rather than classical + PQ) is preferable since classical ECDSA provides no long-term security guarantee.[^13][^5][^8]

**Soundness verdict:** ✅ Belt-and-suspenders, sound, with prior art.[^13] **But scope it correctly:** these self-signatures do *not* strengthen the enclave→key *binding* — that rests entirely on the NSM quote + PCR pinning + OTS. They prove *possession* of the private keys at bundle time. The "if lattice breaks, hash survives" benefit applies to *future use of the root key*, not to this bundle's integrity. Worth keeping, but it is not the load-bearing element.

***

## Implementation Path: Demo App

### Scope and Goal

The demo produces a **PQ Root Key Bundle** — an immutable file proving that a PQ keypair was generated inside a specific Nitro Enclave instance at a verifiable pre-Q-Day date. It is a one-time burn-in operation, not a live RA-TLS flow.

```
[Nitro Enclave]
    generate ML-DSA-65 keypair
    generate SLH-DSA-SHAKE-128f keypair
    compose bundle payload
    embed SHA-256(bundle_payload) into NSM user_data
    get NSM quote → quote_doc (CBOR, ECDSA-signed by AWS PKI)
    sign bundle_payload with both PQ keys
→ emit: bundle.json = { ml_dsa_pk, slh_dsa_pk, quote_doc, ml_dsa_sig, slh_dsa_sig }

[Host / CI]
    sha256(bundle.json) → digest
    submit digest to OTS calendar servers → bundle.json.ots

[Verification (any time, anywhere)]
    verify OTS proof against Bitcoin headers
    verify AWS NSM quote signature (ECDSA, valid pre-Q-Day)
    check quote.user_data == SHA-256(bundle_payload)
    verify ml_dsa_sig and slh_dsa_sig over bundle_payload
    → conclude: these PQ keys were generated in this enclave before <BTC block date>
```

### Repository Layout

This is a **standalone project**, not a fork of keyfork. The PQ crates import zero
keyfork code and ride RustCrypto's `signature 2.3.0-pre` train, which is incompatible
with keyfork's stable sequoia/rsa stack — so they cannot share keyfork's lockfile.

**Division of responsibility:** keyfork stays the key *generator/manager* (seed-derived
classical keys today; a future seed-derived PQ generator is the *only* thing that would
justify a keyfork change). Everything that *attests, binds, timestamps, packages, or
verifies* the artifact — including all OTS/Bitcoin code — lives here.

```
pq-enclave-binding/           ← standalone workspace (own Cargo.lock)
├── crates/
│   ├── pq-core/              ← ML-DSA + SLH-DSA key generation + dual-sign   [done]
│   ├── pq-enclave/           ← NSM attestation binding (Nsm trait + nitro)   [done]
│   ├── pq-ots/               ← OTS submission + Bitcoin-header verification   [done]
│   ├── pq-quote/             ← NSM COSE quote parse + verify to pinned root   [done]
│   ├── pq-bundle/            ← bundle serialization + verification library    [done]
│   └── pq-cli/               ← `pq` binary: inspect / verify / stamp          [done]
├── enclave/
│   └── Dockerfile.enclave    ← reproducible build for Nitro EIF              [todo]
├── demo/
│   └── run_demo.sh                                                           [todo]
└── demo-spec.md
```

### Phase 0 — Dependencies and Toolchain

Add to `Cargo.toml`:

> **Implementation note (supersedes the crate choice below):** the build uses
> **`fips204` + `fips205`** (integritychain), *not* the RustCrypto `ml-dsa`/`slh-dsa`
> crates the prose recommends. Reason: `slh-dsa 0.1` hard-requires a prerelease
> `signature` crate that is irreconcilable, in one Cargo lockfile, with the mature
> X.509/COSE stack (`x509-cert`, `nsm-nitro-enclave-utils`) needed to verify the
> Nitro quote — and the verify CLI must use both. `fips204`/`fips205` pull no
> `signature` crate at all, are pure-Rust / `no_std`, more mature (0.4.x), and
> FIPS-validation-focused. Everything below about ML-DSA-65 / SLH-DSA-SHAKE-128f
> parameter sets still holds.

```toml
[dependencies]
# PQ signatures — pure Rust, no_std, no `signature`-crate dependency
fips204      = "0.4"   # FIPS 204 ML-DSA
fips205      = "0.4"   # FIPS 205 SLH-DSA
# (NOT used: ml-dsa / slh-dsa RustCrypto crates — see note above)

# NSM interface
aws-nitro-enclaves-nsm-api = "0.4"
nsm-nitro-enclave-utils    = "0.1"

# OTS
ots_core     = { git = "https://github.com/lvaccaro/rust-opentimestamps-client" }  # async feature

# Serialization
serde        = { version = "1", features = ["derive"] }
serde_json   = "1"
serde_cbor   = "0.11"
sha2         = "0.10"
hex          = "0.4"
zeroize      = "1"
```

> **Note:** `pqcrypto-mldsa` and `pqcrypto-dilithium` are deprecated — do not use them.[^14][^6]

### Phase 1 — `keyfork-pq-core`: PQ Key Generation Inside the Enclave

> **API note:** the snippet below uses the *actual* RustCrypto APIs as of `ml-dsa 0.1` / `slh-dsa 0.x`. Keygen returns key objects (not `(pk, sk)` tuples), public keys come from `verifying_key()`, and signing goes through the `signature::Signer` trait on the key instance.

> **Entropy note:** inside a Nitro enclave do **not** rely on `rand::thread_rng()` blindly. Either (a) run a normal Linux-in-enclave where `/dev/urandom` is seeded from NSM/virtio-rng, or (b) under `no_std`, feed an RNG wrapper backed by the NSM `GetRandom` request. The `R: CryptoRngCore` parameter below makes the entropy source explicit and testable.

```rust
// crates/keyfork-pq-core/src/lib.rs
use ml_dsa::{MlDsa65, KeyGen};
use ml_dsa::signature::{Keypair, Signer};
use slh_dsa::{Shake128f, SigningKey as SlhSigningKey};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

pub struct PqKeyBundle {
    pub ml_dsa_pk:  Vec<u8>,
    pub slh_dsa_pk: Vec<u8>,
    // private key material held in Zeroizing wrappers, never serialized
    ml_dsa_sk:  Zeroizing<Vec<u8>>,
    slh_dsa_sk: Zeroizing<Vec<u8>>,
}

impl PqKeyBundle {
    /// `rng` is supplied by the caller so the enclave can inject an NSM-backed source.
    pub fn generate(rng: &mut impl CryptoRngCore) -> Self {
        // ml-dsa: key_gen returns a KeyPair-like object
        let ml_kp  = MlDsa65::key_gen(rng);
        let ml_vk  = ml_kp.verifying_key();
        // slh-dsa: SigningKey::new(rng); verifying_key() for the public key
        let slh_sk = SlhSigningKey::<Shake128f>::new(rng);
        let slh_vk = slh_sk.verifying_key();

        PqKeyBundle {
            ml_dsa_pk:  ml_vk.encode().to_vec(),
            slh_dsa_pk: slh_vk.to_bytes().to_vec(),
            ml_dsa_sk:  Zeroizing::new(ml_kp.signing_key().encode().to_vec()),
            slh_dsa_sk: Zeroizing::new(slh_sk.to_bytes().to_vec()),
        }
    }

    pub fn sign_payload(&self, payload: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // reconstruct signing keys from stored bytes, then sign via Signer trait
        let ml_sk  = ml_dsa::SigningKey::<MlDsa65>::decode(&self.ml_dsa_sk).expect("ml-dsa sk");
        let slh_sk = SlhSigningKey::<Shake128f>::try_from(self.slh_dsa_sk.as_slice()).expect("slh sk");
        let ml_sig  = ml_sk.sign(payload);
        let slh_sig = slh_sk.sign(payload);
        (ml_sig.encode().to_vec(), slh_sig.to_vec())
    }
}
```

Private keys are `Zeroize`-on-drop and never included in serialized output. (Exact method names — `encode`/`decode` vs `to_bytes`/`try_from` — should be confirmed against the pinned crate versions during implementation; the shape is correct.)

### Phase 2 — `keyfork-enclave`: NSM Attestation Binding

The NSM `user_data` field accepts up to 512 bytes. A SHA-256 digest of the bundle payload (32 bytes) fits comfortably with room for a version tag.[^2][^15]

```rust
// crates/keyfork-enclave/src/lib.rs
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use nsm_nitro_enclave_utils::driver::{Driver, nitro::Nitro};
use sha2::{Sha256, Digest};
use serde_bytes::ByteBuf;

pub fn attest_bundle_payload(payload_bytes: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(payload_bytes);
    // prefix with version tag for future-proofing
    let mut user_data = b"pq-keyfork-v1:".to_vec();
    user_data.extend_from_slice(&digest);

    let nsm = Nitro::init();
    let resp = nsm.process_request(Request::Attestation {
        user_data:  Some(ByteBuf::from(user_data)),
        public_key: None,   // not used; binding is via user_data
        nonce:      None,
    });
    match resp {
        Response::Attestation { document } => document,
        _ => panic!("NSM attestation failed"),
    }
}
```

> **Why `user_data` not `public_key`?** The `public_key` field is a KMS-specific convention for wrapping ephemeral keys. For a static root key burn-in, `user_data` is the semantically correct field and allows embedding a version prefix.[^3][^15][^1]

### Phase 3 — Bundle Serialization

```rust
// crates/keyfork-bundle/src/lib.rs
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PqRootBundle {
    pub version:        String,
    pub ml_dsa_pk:      String,   // hex-encoded
    pub slh_dsa_pk:     String,   // hex-encoded
    pub nsm_quote:      String,   // base64-encoded COSE_Sign1 CBOR (carries cabundle)
    pub aws_root_ca_sha256: String, // hex; pins the root the quote chains to, archived
                                    // into the timestamp so verification stays anchored
    pub expected_pcrs:  ExpectedPcrs, // PCR0/1/2 from the reproducible build, for the record
    pub ml_dsa_sig:     String,   // hex-encoded signature over canonical_payload()
    pub slh_dsa_sig:    String,   // hex-encoded signature over canonical_payload()
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ExpectedPcrs { pub pcr0: String, pub pcr1: String, pub pcr2: String }

impl PqRootBundle {
    /// Canonical payload: the bytes that are signed and also hashed into NSM user_data
    pub fn canonical_payload(ml_dsa_pk: &[u8], slh_dsa_pk: &[u8]) -> Vec<u8> {
        // deterministic: length-prefixed concatenation
        let mut v = Vec::new();
        v.extend_from_slice(&(ml_dsa_pk.len() as u32).to_be_bytes());
        v.extend_from_slice(ml_dsa_pk);
        v.extend_from_slice(&(slh_dsa_pk.len() as u32).to_be_bytes());
        v.extend_from_slice(slh_dsa_pk);
        v
    }
}
```

The canonical payload is signed *before* quoting, so the NSM quote commits to `SHA-256(canonical_payload)`, which itself commits to both public keys deterministically.

### Phase 4 — `keyfork-ots`: Timestamping the Bundle

After the enclave emits `bundle.json`, the *host* (not the enclave) submits it to OTS calendar servers. The enclave has no network access by design.

```rust
// crates/keyfork-ots/src/lib.rs  (async)
use ots_core::{OtsClient, CalendarServer};
use sha2::{Sha256, Digest};
use std::path::Path;

pub async fn stamp_file(bundle_path: &Path) -> anyhow::Result<()> {
    let bundle_bytes = std::fs::read(bundle_path)?;
    let digest = Sha256::digest(&bundle_bytes);

    let calendars = vec![
        "https://alice.btc.calendar.opentimestamps.org",
        "https://bob.btc.calendar.opentimestamps.org",
        "https://finney.calendar.eternitywall.com",
    ];

    let client = OtsClient::new(calendars);
    let ots_proof = client.stamp(&digest).await?;

    let ots_path = bundle_path.with_extension("json.ots");
    std::fs::write(&ots_path, ots_proof.serialize())?;
    println!("OTS receipt written to {:?}", ots_path);
    // Upgrade after ~2h once anchored in a Bitcoin block
    Ok(())
}
```

Three calendar servers are used in parallel — the OTS spec requires only one to succeed, and the proof is self-contained in the `.ots` file.[^16][^17]

### Phase 5 — Verification CLI

> **Implemented as the `pq` binary** (`crates/pq-cli`). Expected PCRs are read
> from the bundle's `expected_pcrs` field (recorded at ceremony time from the
> reproducible build) rather than passed as flags. Bitcoin headers come from a
> local JSON file (`--headers`) or a live esplora API (`--esplora`). The Nitro
> chain is verified *as of* the OTS anchor block time (or `--quote-time-unix`).

```bash
pq verify \
  --bundle bundle.json \
  --ots    bundle.json.ots \
  --root   aws_nitro_root.der \            # pinned out-of-band; cross-checked vs bundle
  --headers headers.json                    # { "<height>": { "merkle_root": "<hex>", "time": <unix> } }
  # or: --esplora https://blockstream.info/api --quote-time-unix <secs>

# Verification steps performed (ALL must pass):
# 1. OTS: SHA-256(bundle.json) → Merkle path → Bitcoin block header (PoW check).
#    Record the anchored block timestamp; assert it is < Q-Day horizon.
# 2. NSM signature: parse COSE_Sign1, verify ES384 signature, verify the embedded
#    cabundle chains to the PINNED AWS Nitro root CA (not just "some chain").
# 3. Debug-mode rejection: assert PCR0/1/2 are NOT all-zero (debug enclaves emit
#    zeroed PCRs); reject if so. [CRITICAL — without this, anyone forges a bundle]
# 4. PCR pinning: assert quote.PCR0 == expected-pcr0 && PCR1 == expected && PCR2 ==
#    expected. [CRITICAL — this is what makes it "THIS enclave", not "an enclave"]
# 5. Binding: quote.user_data == "pq-keyfork-v1:" || SHA-256(canonical_payload).
# 6. ML-DSA: verify ml_dsa_sig over canonical_payload using ml_dsa_pk.
# 7. SLH-DSA: verify slh_dsa_sig over canonical_payload using slh_dsa_pk.
```

> **Steps 3 and 4 are non-negotiable.** Without PCR pinning, a valid cert chain plus a
> matching `user_data` is satisfied by *any* Nitro enclave — including an attacker's own
> enclave running arbitrary code. Without the debug-mode check, an attacker launches a
> `--debug-mode` enclave (all-zero PCRs) and inspects/forges at will. The expected PCR
> values come from the reproducible build in Phase 6 and must be published alongside the
> bundle.
>
> **AWS root CA archival.** Post-Q-Day verification needs the AWS Nitro *root* CA that was
> valid when the quote was made. The attestation document carries its intermediate
> `cabundle`, but the root must be pinned out-of-band — and to keep the bundle
> self-contained, the root cert (or its hash) should itself be included in the timestamped
> `bundle.json`. Otherwise a future verifier has no trustworthy anchor to chain to.

### Phase 6 — Reproducible Enclave Build

The PCR0–2 values in the NSM quote must match a publicly reproducible EIF. Use the existing Keyfork reproducible build infrastructure and lock the Nitro image:

```dockerfile
# enclave/Dockerfile.enclave
FROM scratch
COPY --from=keyfork-pq-core:builder /app/enclave_bin /enclave_bin
CMD ["/enclave_bin"]
```

Build with `nitro-cli build-enclave --docker-uri keyfork-pq:latest` and publish the expected PCR0 hash alongside the bundle for independent verification.

***

## Known Limitations and Open Questions

| Concern | Status | Notes |
|---------|--------|-------|
| **PCR pinning in verifier** | ✅ Required (Phase 5 step 4) | Without it, a valid quote from *any* enclave passes — the binding becomes worthless |
| **Debug-mode quotes** | ✅ Rejected (Phase 5 step 3) | `--debug-mode` enclaves emit all-zero PCRs; must be rejected explicitly |
| **AWS Nitro root CA archival** | ⚠️ Must pin + archive | Root pinned out-of-band; its hash archived into the timestamped bundle |
| **Enclave entropy source** | ⚠️ Must be explicit | Use NSM-seeded `/dev/urandom` or NSM `GetRandom`, not a blind `thread_rng()` |
| **PQ crate maturity** | ⚠️ Pre-1.0 / unaudited | `slh-dsa` unaudited; `ml-dsa` has had verification advisories — pin versions, track RUSTSEC |
| Enclave must stay live for real-time RA-TLS | ❌ Not solved by this design | This is purely a root key burn-in — not a solution for live attestation |
| AWS Nitro ECDSA root is classically signed | ⚠️ Accepted, temporally mitigated | Valid only pre-Q-Day; OTS timestamp is the mitigation |
| ML-DSA lattice assumptions | ⚠️ Monitored | Dual-sign with SLH-DSA as hedge; SLH-DSA relies only on SHA-3[^8] |
| OTS calendar availability | ✅ Mitigated | Three independent calendars; proof is self-contained once anchored[^16] |
| `pqcrypto-mldsa` unmaintained | ✅ Resolved | Migrate to `ml-dsa` (RustCrypto) before Q3 2026[^6] |
| Bitcoin 51% attack | ✅ Negligible | Economically infeasible; orthogonal to quantum[^9] |
| SLH-DSA signature size | ⚠️ Large | SLH-DSA-SHAKE-128f signatures are ~17KB; acceptable for a one-shot root key ceremony |

***

## Recommended Algorithm Parameter Sets

For the demo, prioritize conservatism over performance:

- **ML-DSA-65** — NIST Level 3 (≈192-bit classical / ≈128-bit post-quantum)[^5]
- **SLH-DSA-SHAKE-128f** — NIST Level 1, fast variant, hash-based (SHA-3 only)[^8][^7]

For production, upgrade to **ML-DSA-87** (Level 5) and **SLH-DSA-SHAKE-256f** (Level 5) if key ceremony performance is acceptable.

---

## References

1. [Enum RequestCopy item path](https://docs.rs/nsm-nitro-enclave-utils/0.1.0/x86_64-apple-darwin/nsm_nitro_enclave_utils/api/nsm/enum.Request.html) - Operations that a NitroSecureModule should implement. Assumes 64K registers will be enough for every...

2. [Remote Attestations | Welcome to the Marlin docs!](https://docs.marlin.org/oyster/core-concepts/remote-attestations) - How do you know what is running in a TEE?

3. [Get the NitroTPM Attestation Document](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/attestation-get-doc.html) - The Attestation Document is a key component of the NitroTPM attestation process. It contains a serie...

4. [nsm_nitro_enclave_utils/driver/nitro.rs](https://docs.rs/nsm-nitro-enclave-utils/0.1.0/i686-unknown-linux-gnu/src/nsm_nitro_enclave_utils/driver/nitro.rs.html) - Source of the Rust file `src/driver/nitro.rs`.

5. [draft-ietf-pquip-pqc-engineers-07.xml](https://www.ietf.org/archive/id/draft-ietf-pquip-pqc-engineers-07.xml)

6. [RUSTSEC-2026-0166: pqcrypto-mldsa](https://rustsec.org/advisories/RUSTSEC-2026-0166.html) - This crate provides Rust bindings to ML-DSA (FIPS 204) via C implementations from PQClean. The PQCle...

7. [slh_dsa - Rust](https://docs.rs/slh-dsa/latest/slh_dsa/) - RustCrypto: SLH-DSA

8. [We wrote the code, and the code won - The Trail of Bits Blog](https://blog.trailofbits.com/2024/08/15/we-wrote-the-code-and-the-code-won/) - Earlier this week, NIST officially announced three standards specifying FIPS-approved algorithms for...

9. [Paradigm Researcher Proposes PACTs to Shield Dormant Bitcoin ...](https://news.bitcoin.com/paradigm-researcher-proposes-pacts-to-shield-dormant-bitcoin-from-quantum-computing-risk/) - Paradigm's Dan Robinson proposes PACTs, a free, private Bitcoin timestamping tool to protect $75B in...

10. [I built an open-source app that anchors cryptographic commitments ...](https://fintrac.io/news/i-built-an-open-source-app-that-anchors-cryptographic-commitments-to-the-bitcoin-blockchain-via-opentimestamps.html) - I built PSI-COMMIT, an open-source commitment scheme that uses Bitcoin as its timestamp layer. The i...

11. [Bitcoin-Anchored Temporal Proof for Transparency Services](https://www.ietf.org/archive/id/draft-fassbender-scitt-time-anchor-02.html) - This document defines a mechanism for temporal anchoring of digital artifacts by committing cryptogr...

12. [Future-Proof Digital Timestamping - Nicholas Johnson](https://nicholasjohnson.ch/2021/11/13/future-proof-digital-timestamping/) - Online journal about AI, autism, computing, economics, environmentalism, philosophy, privacy, societ...

13. [Show HN: Free Quantum-Resistant Timestamping API ...](https://news.ycombinator.com/item?id=45819273)

14. [RUSTSEC-2024-0380: pqcrypto-dilithium](https://rustsec.org/advisories/RUSTSEC-2024-0380.html) - Security advisory database for Rust crates published through https://crates.io

15. [nitro package - github.com/virtengine ...](https://pkg.go.dev/github.com/virtengine/virtengine/pkg/enclave_runtime/nitro) - Package nitro provides AWS Nitro Enclave integration for VirtEngine TEE.

16. [OpenTimestamps](https://opentimestamps.org) - OpenTimestamps defines a set of operations for creating provable timestamps and later independently ...

17. [OpenTimestamps Tutorial](https://dgi.io/ots-tutorial/) - The OpenTimestamps protocol step-by-step: calculation of a data file hash value, submission to calen...

