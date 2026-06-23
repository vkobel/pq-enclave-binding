# Subkey Pre-Commitment + Signing Oracle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Pre-commit a bounded set of HD-derived PQ subkeys into the enclave's pre-Q-Day attestation, and let the enclave act as a signing oracle so subkeys are *usable without ever exporting their secrets*.

**Architecture:** The enclave generates a mnemonic in-process, HD-derives the root + N subkeys per purpose (`pq-derive`), builds a Merkle tree over the subkey public keys (`pq-merkle`), and folds the Merkle root into the canonical payload that is dual-PQ-signed, committed in the NSM `user_data`, and OTS-anchored. A subkey is "valid" iff its public key proves membership in that anchored tree (**birth-provenance**). The enclave never exports a secret; instead `POST /sign` re-derives the requested subkey, signs in-process, and returns the signature plus the membership proof. No root or subkey secret ever leaves the enclave.

**Tech Stack:** Rust (edition 2021), `fips204`/`fips205` (PQ), `sha2 0.10`, keyfork library crates (via the distrust registry), std-only HTTP.

## Global Constraints

- **PQ crates:** `fips204`/`fips205` only — never RustCrypto `ml-dsa`/`slh-dsa`, never `pqcrypto-*`.
- **`sha2` stays on `0.10`**; `x509-cert` capped at `0.2`.
- **Clippy:** `clippy::all = deny`, `clippy::pedantic = warn` workspace-wide. Treat pedantic warnings as fixes, not noise. Run `cargo clippy --workspace --all-targets` before every commit.
- **One canonical-payload definition** lives in `pq-core`; the enclave and the verifier must both go through it — never inline a second copy.
- **Non-negotiable verifier checks stay:** debug-mode rejection (PCR0/1/2 not all-zero) and PCR pinning. Do not weaken `pq-bundle::verify`.
- **No export in this POC.** Root and subkey secrets stay in the enclave; the mnemonic is generated in-enclave and never serialized or emitted. (Shamir backup and TEE-to-TEE migration are explicitly deferred — see "Deferred".)
- **keyfork registry:** keep `.cargo/config.toml` (distrust registry); the reproducible build uses `cargo fetch` (network) then `cargo build --frozen --network=none`.
- **Leaf/internal domain separation:** Merkle leaves are prefixed `0x00`, internal nodes `0x01` (second-preimage resistance).
- Tests must pass offline with `MockNsm`; no network/hardware.

## File Structure

- `crates/pq-merkle/` *(new)* — pure Merkle tree over subkey leaves: leaf hashing, root, proofs, membership verification. No PQ deps.
- `crates/pq-core/src/lib.rs` *(modify)* — add `canonical_payload_with_subkeys` (root keys + subkey Merkle root). Leave `canonical_payload` untouched (still used by `pq-subkey::root_binding`).
- `crates/pq-derive/src/lib.rs` *(modify)* — add `subkey_path(account, index)` helper.
- `crates/pq-bundle/src/lib.rs` *(modify)* — bundle schema v2: `subkey_merkle_root` + `subkey_count`; `verify` recomputes the new payload.
- `crates/pq-ceremony/src/lib.rs` *(modify)* — derive subkeys, build tree, commit Merkle root; return a `CeremonyState` for the oracle.
- `crates/pq-ceremony/src/main.rs` *(modify)* — hold `CeremonyState`; add `GET /subkey/<i>` and `POST /sign`; read counts from env.
- `crates/pq-cli/src/main.rs` *(modify)* — `verify-subkey` subcommand; extend `inspect`.
- `Cargo.toml` *(modify)* — register `crates/pq-merkle`.
- `CLAUDE.md`, `README.md` *(modify)* — document the new crates and flow.

**Note on `pq-subkey`:** unchanged and unused in this POC. Membership-proof birth-provenance replaces cert-based delegation here; the crate is retained for the cert path (post-Q-Day delegation), which the deferred work may revisit.

---

### Task 1: `pq-merkle` crate — leaves, root, proofs, membership

**Files:**
- Create: `crates/pq-merkle/Cargo.toml`
- Create: `crates/pq-merkle/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

**Interfaces:**
- Produces:
  - `pq_merkle::subkey_leaf(index: u32, purpose_tag: u8, ml_dsa_pk: &[u8], slh_dsa_pk: &[u8]) -> [u8; 32]`
  - `pq_merkle::merkle_root(leaves: &[[u8; 32]]) -> [u8; 32]`
  - `pq_merkle::merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]>`
  - `pq_merkle::verify_membership(root: &[u8; 32], index: u32, purpose_tag: u8, ml_dsa_pk: &[u8], slh_dsa_pk: &[u8], siblings: &[[u8; 32]]) -> bool`
- An empty `leaves` slice yields `merkle_root == [0u8; 32]`. Odd levels duplicate the last node. `merkle_proof` panics on out-of-range index.

- [ ] **Step 1: Register the crate in the workspace**

In `Cargo.toml`, add to `members` (keep alphabetical-ish grouping with the others):

```toml
    "crates/pq-merkle",
```

- [ ] **Step 2: Create the crate manifest**

`crates/pq-merkle/Cargo.toml`:

```toml
[package]
name = "pq-merkle"
version = "0.1.0"
edition.workspace = true
license.workspace = true

[dependencies]
sha2.workspace = true

[lints]
workspace = true
```

- [ ] **Step 3: Write the failing tests**

`crates/pq-merkle/src/lib.rs` (tests first; the module items are added in Step 5):

```rust
//! Binary Merkle tree over PQ subkey public keys.
//!
//! Used to pre-commit the bounded set of subkeys the enclave derives, so a
//! subkey's *birth-provenance* ("generated in the attested enclave pre-Q-Day")
//! is provable by a membership proof against a root that is dual-PQ-signed,
//! committed in the NSM `user_data`, and OTS-anchored.
//!
//! Domain separation: leaves are hashed under a `0x00` prefix, internal nodes
//! under `0x01`, defeating the classic Merkle second-preimage attack.

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0x00;
const NODE_PREFIX: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(n: u8) -> Vec<u8> {
        vec![n; 16]
    }

    #[test]
    fn empty_tree_root_is_zero() {
        assert_eq!(merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn single_leaf_root_is_the_leaf() {
        let leaf = subkey_leaf(0, 1, &pk(1), &pk(2));
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn membership_proof_verifies_for_every_leaf() {
        let leaves: Vec<[u8; 32]> = (0..5u32)
            .map(|i| subkey_leaf(i, 1, &pk(i as u8), &pk((i + 1) as u8)))
            .collect();
        let root = merkle_root(&leaves);
        for i in 0..5usize {
            let proof = merkle_proof(&leaves, i);
            let idx = i as u32;
            assert!(
                verify_membership(&root, idx, 1, &pk(idx as u8), &pk((idx + 1) as u8), &proof),
                "leaf {i} must verify"
            );
        }
    }

    #[test]
    fn wrong_index_fails() {
        let leaves: Vec<[u8; 32]> = (0..4u32)
            .map(|i| subkey_leaf(i, 1, &pk(i as u8), &pk(9)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 1);
        // Same pubkeys, wrong claimed index.
        assert!(!verify_membership(&root, 2, 1, &pk(1), &pk(9), &proof));
    }

    #[test]
    fn tampered_pubkey_fails() {
        let leaves: Vec<[u8; 32]> = (0..4u32)
            .map(|i| subkey_leaf(i, 1, &pk(i as u8), &pk(9)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 1);
        assert!(!verify_membership(&root, 1, 1, &pk(0xff), &pk(9), &proof));
    }

    #[test]
    fn wrong_purpose_fails() {
        let leaves: Vec<[u8; 32]> = (0..2u32)
            .map(|i| subkey_leaf(i, 1, &pk(i as u8), &pk(9)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0);
        assert!(!verify_membership(&root, 0, 2, &pk(0), &pk(9), &proof));
    }
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `cargo test -p pq-merkle`
Expected: FAIL — `subkey_leaf`, `merkle_root`, `merkle_proof`, `verify_membership` not found.

- [ ] **Step 5: Implement the module**

Insert above the `#[cfg(test)]` block in `crates/pq-merkle/src/lib.rs`:

```rust
/// Hash one subkey leaf: `SHA-256(0x00 || index || purpose || lp(ml) || lp(slh))`.
#[must_use]
pub fn subkey_leaf(index: u32, purpose_tag: u8, ml_dsa_pk: &[u8], slh_dsa_pk: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([LEAF_PREFIX]);
    h.update(index.to_be_bytes());
    h.update([purpose_tag]);
    h.update(u32::try_from(ml_dsa_pk.len()).expect("pk len fits u32").to_be_bytes());
    h.update(ml_dsa_pk);
    h.update(u32::try_from(slh_dsa_pk.len()).expect("pk len fits u32").to_be_bytes());
    h.update(slh_dsa_pk);
    h.finalize().into()
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([NODE_PREFIX]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Compute the Merkle root. Empty input yields all-zero. Odd levels duplicate
/// the last node (Bitcoin-style).
#[must_use]
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(hash_node(&pair[0], right));
        }
        level = next;
    }
    level[0]
}

/// Produce the sibling path (leaf → root) for `index`.
///
/// # Panics
/// Panics if `index >= leaves.len()`.
#[must_use]
pub fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    assert!(index < leaves.len(), "index out of range");
    let mut proof = Vec::new();
    let mut level = leaves.to_vec();
    let mut idx = index;
    while level.len() > 1 {
        let sibling = if idx % 2 == 0 {
            level.get(idx + 1).copied().unwrap_or(level[idx])
        } else {
            level[idx - 1]
        };
        proof.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(hash_node(&pair[0], right));
        }
        level = next;
        idx /= 2;
    }
    proof
}

/// Recompute the root from a leaf + sibling path and compare to `root`.
#[must_use]
pub fn verify_membership(
    root: &[u8; 32],
    index: u32,
    purpose_tag: u8,
    ml_dsa_pk: &[u8],
    slh_dsa_pk: &[u8],
    siblings: &[[u8; 32]],
) -> bool {
    let mut acc = subkey_leaf(index, purpose_tag, ml_dsa_pk, slh_dsa_pk);
    let mut idx = index as usize;
    for sibling in siblings {
        acc = if idx % 2 == 0 {
            hash_node(&acc, sibling)
        } else {
            hash_node(sibling, &acc)
        };
        idx /= 2;
    }
    &acc == root
}
```

- [ ] **Step 6: Run tests and clippy to verify they pass**

Run: `cargo test -p pq-merkle && cargo clippy -p pq-merkle --all-targets`
Expected: all tests PASS, no clippy warnings.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates/pq-merkle
git commit -m "Add pq-merkle: subkey pre-commitment tree

Domain-separated binary Merkle (leaf 0x00 / node 0x01) over
(index, purpose, dual pubkeys), with root/proof/membership verify."
```

---

### Task 2: `pq-core::canonical_payload_with_subkeys`

**Files:**
- Modify: `crates/pq-core/src/lib.rs`

**Interfaces:**
- Consumes: existing `canonical_payload(ml_dsa_pk, slh_dsa_pk) -> Vec<u8>`.
- Produces: `pq_core::canonical_payload_with_subkeys(ml_dsa_pk: &[u8], slh_dsa_pk: &[u8], subkey_merkle_root: &[u8]) -> Vec<u8>` — the root-only payload followed by a length-prefixed Merkle root. This is the message the ceremony dual-signs and commits to `user_data`; `canonical_payload` (root-only) is left intact for `pq-subkey::root_binding`.

- [ ] **Step 1: Write the failing tests**

Add inside `crates/pq-core/src/lib.rs`'s `mod tests`:

```rust
    #[test]
    fn payload_with_subkeys_extends_root_payload() {
        let root = [0x055u8; 32];
        let base = canonical_payload(b"ml", b"slh");
        let full = canonical_payload_with_subkeys(b"ml", b"slh", &root);
        assert!(full.starts_with(&base), "must extend the root-only payload");
        assert!(full.len() > base.len());
    }

    #[test]
    fn payload_with_subkeys_binds_the_root() {
        let a = canonical_payload_with_subkeys(b"ml", b"slh", &[1u8; 32]);
        let b = canonical_payload_with_subkeys(b"ml", b"slh", &[2u8; 32]);
        assert_ne!(a, b, "different Merkle roots must give different payloads");
    }
```

(`0x055` is a typo guard — use `0x55`.)

Replace the literal in the first test with `[0x55u8; 32]`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pq-core payload_with_subkeys`
Expected: FAIL — `canonical_payload_with_subkeys` not found.

- [ ] **Step 3: Implement the function**

Add after `canonical_payload` in `crates/pq-core/src/lib.rs`:

```rust
/// The canonical payload that also commits to the subkey Merkle root:
/// [`canonical_payload`] followed by a length-prefixed `subkey_merkle_root`.
///
/// This is what the enclave dual-signs and hashes into the NSM `user_data`, so
/// the hardware attestation, the OTS anchor, and the PQ signatures all commit to
/// the two root public keys *and* the bounded subkey set in one shot.
///
/// # Panics
/// Panics if `subkey_merkle_root` is longer than `u32::MAX` (never the case: 32 bytes).
#[must_use]
pub fn canonical_payload_with_subkeys(
    ml_dsa_pk: &[u8],
    slh_dsa_pk: &[u8],
    subkey_merkle_root: &[u8],
) -> Vec<u8> {
    let mut v = canonical_payload(ml_dsa_pk, slh_dsa_pk);
    v.extend_from_slice(
        &u32::try_from(subkey_merkle_root.len()).expect("root len fits u32").to_be_bytes(),
    );
    v.extend_from_slice(subkey_merkle_root);
    v
}
```

- [ ] **Step 4: Run tests + clippy**

Run: `cargo test -p pq-core && cargo clippy -p pq-core --all-targets`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/pq-core/src/lib.rs
git commit -m "pq-core: add canonical_payload_with_subkeys

Extends the root payload with a length-prefixed subkey Merkle root so
the attestation/OTS/dual-sig all commit to the bounded subkey set."
```

---

### Task 3: `pq-derive::subkey_path` helper

**Files:**
- Modify: `crates/pq-derive/src/lib.rs`

**Interfaces:**
- Consumes: existing `derive_keypair(mnemonic, &DerivationPath)`.
- Produces: `pq_derive::subkey_path(account: u32, index: u32) -> DerivationPath` returning the hardened path `m/account'/index'`. Callers pass it to `derive_keypair`. (`account` models the purpose lane: `0` = root reserved, `1` = Auth, `2` = Encryption.)

- [ ] **Step 1: Write the failing test**

Add to `crates/pq-derive/src/lib.rs`'s `mod tests`:

```rust
    #[test]
    fn subkey_path_is_hardened_and_distinct() {
        let m = mnemonic();
        let a = derive_keypair(&m, &subkey_path(1, 0)).unwrap();
        let b = derive_keypair(&m, &subkey_path(1, 1)).unwrap();
        let c = derive_keypair(&m, &subkey_path(2, 0)).unwrap();
        assert_ne!(a.ml_dsa_pk(), b.ml_dsa_pk(), "index must matter");
        assert_ne!(a.ml_dsa_pk(), c.ml_dsa_pk(), "account must matter");
        // Reproducible.
        let a2 = derive_keypair(&m, &subkey_path(1, 0)).unwrap();
        assert_eq!(a.ml_dsa_pk(), a2.ml_dsa_pk());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pq-derive subkey_path`
Expected: FAIL — `subkey_path` not found.

- [ ] **Step 3: Implement the helper**

Add after `derive_keypair` in `crates/pq-derive/src/lib.rs` (import `DerivationIndex` if needed — see note):

```rust
/// Build the hardened subkey path `m/account'/index'`.
///
/// `account` is the purpose lane (1 = Auth, 2 = Encryption by convention);
/// `index` enumerates subkeys within that lane.
///
/// # Panics
/// Panics only if keyfork's hardened-index construction rejects the values,
/// which it does not for any `u32` (the hardened bit is set internally).
#[must_use]
pub fn subkey_path(account: u32, index: u32) -> DerivationPath {
    use std::str::FromStr as _;
    DerivationPath::from_str(&format!("m/{account}'/{index}'"))
        .expect("hardened u32 path is always valid")
}
```

- [ ] **Step 4: Run test + clippy**

Run: `cargo test -p pq-derive && cargo clippy -p pq-derive --all-targets`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/pq-derive/src/lib.rs
git commit -m "pq-derive: add subkey_path(account, index) helper"
```

---

### Task 4: bundle schema v2 — commit the subkey Merkle root

**Files:**
- Modify: `crates/pq-bundle/src/lib.rs`

**Interfaces:**
- Consumes: `pq_core::canonical_payload_with_subkeys`.
- Produces: `PqRootBundle` gains `pub subkey_merkle_root: String` (hex, 32 bytes) and `pub subkey_count: u32`. `verify` recomputes the binding and dual-sig over `canonical_payload_with_subkeys(ml, slh, subkey_merkle_root)`; `VerifyReport` gains `pub subkey_merkle_root: Vec<u8>` and `pub subkey_count: u32`.

- [ ] **Step 1: Update the struct, report, and verify logic**

In `crates/pq-bundle/src/lib.rs`:

1. Change the import:

```rust
use pq_core::{canonical_payload_with_subkeys, user_data_commitment, verify_dual, DualSignature};
```

2. Add fields to `PqRootBundle` (after `expected_pcrs`):

```rust
    /// Merkle root over the bounded set of pre-committed subkey public keys,
    /// hex-encoded. Folded into the signed/attested/anchored canonical payload.
    pub subkey_merkle_root: String,
    /// Number of leaves in the subkey Merkle tree.
    pub subkey_count: u32,
```

3. Add fields to `VerifyReport`:

```rust
    /// The subkey Merkle root that was committed (decoded bytes).
    pub subkey_merkle_root: Vec<u8>,
    /// Number of pre-committed subkeys.
    pub subkey_count: u32,
```

4. In `verify`, decode the root and use the new payload. Replace the binding/signature section (the `let payload = canonical_payload(...)` block through `verify_dual(...)`) with:

```rust
    let subkey_root = hex::decode(&bundle.subkey_merkle_root).map_err(|e| Error::HexDecode {
        field: "subkey_merkle_root",
        source: e,
    })?;

    // ── Step 4: Binding check (root keys + subkey set) ───────────────────────
    let payload = canonical_payload_with_subkeys(&ml_pk, &slh_pk, &subkey_root);
    let expected_user_data = user_data_commitment(&payload);
    if quote_data.user_data != expected_user_data {
        return Err(Error::BindingMismatch);
    }

    // ── Step 5: Dual PQ signature ────────────────────────────────────────────
    let dual_sig = DualSignature {
        ml_dsa: ml_sig_bytes,
        slh_dsa: slh_sig_bytes,
    };
    verify_dual(&ml_pk, &slh_pk, &payload, &dual_sig)?;
```

5. Extend the returned `VerifyReport`:

```rust
    Ok(VerifyReport {
        pcr0: quote_data.pcr0,
        pcr1: quote_data.pcr1,
        pcr2: quote_data.pcr2,
        user_data: quote_data.user_data,
        ml_dsa_pk_len: ml_pk.len(),
        slh_dsa_pk_len: slh_pk.len(),
        subkey_merkle_root: subkey_root,
        subkey_count: bundle.subkey_count,
    })
```

- [ ] **Step 2: Update the test helper and add a tamper test**

In `mod tests`, update the import and `make_valid_bundle`:

```rust
    use pq_core::{
        canonical_payload, canonical_payload_with_subkeys, user_data_commitment, PqRootKeypair,
        USER_DATA_PREFIX,
    };
```

In `make_valid_bundle`, compute a real one-leaf tree and sign the new payload. Replace the `payload`/`sig`/`bundle` construction with:

```rust
        let ml_pk = kp.ml_dsa_pk();
        let slh_pk = kp.slh_dsa_pk();

        // A minimal one-subkey tree so the bundle is internally consistent.
        let leaf = pq_merkle::subkey_leaf(0, 1, &ml_pk, &slh_pk);
        let subkey_root = pq_merkle::merkle_root(&[leaf]);

        let payload = canonical_payload_with_subkeys(&ml_pk, &slh_pk, &subkey_root);
        let sig = kp.sign_payload(&payload);

        let pcr0 = sample_pcr(0x11);
        let pcr1 = sample_pcr(0x22);
        let pcr2 = sample_pcr(0x33);

        let bundle = PqRootBundle {
            version: "2".to_owned(),
            ml_dsa_pk: hex::encode(&ml_pk),
            slh_dsa_pk: hex::encode(&slh_pk),
            nsm_quote: BASE64.encode(b"dummy-quote"),
            aws_root_ca_sha256: hex::encode([0u8; 32]),
            expected_pcrs: ExpectedPcrs {
                pcr0: hex::encode(&pcr0),
                pcr1: hex::encode(&pcr1),
                pcr2: hex::encode(&pcr2),
            },
            subkey_merkle_root: hex::encode(subkey_root),
            subkey_count: 1,
            ml_dsa_sig: hex::encode(&sig.ml_dsa),
            slh_dsa_sig: hex::encode(&sig.slh_dsa),
        };
```

Every test that recomputes `user_data` (e.g. `happy_path_passes`, `all_zero_pcrs_rejected`, `wrong_pcr_rejected`, `bad_signature_rejected`) must build it from the new payload. Replace each local `let payload = canonical_payload(&ml_pk, &slh_pk);` with:

```rust
        let subkey_root = hex::decode(&bundle.subkey_merkle_root).unwrap();
        let payload = canonical_payload_with_subkeys(&ml_pk, &slh_pk, &subkey_root);
```

Add a new test:

```rust
    #[test]
    fn tampered_subkey_root_rejected() {
        let (mut bundle, pcr0, pcr1, pcr2) = make_valid_bundle();

        // Flip the committed Merkle root; the recomputed user_data no longer matches.
        bundle.subkey_merkle_root = hex::encode([0xaau8; 32]);

        let ml_pk = hex::decode(&bundle.ml_dsa_pk).unwrap();
        let slh_pk = hex::decode(&bundle.slh_dsa_pk).unwrap();
        // user_data still commits to the *original* root, so binding fails.
        let original_root = pq_merkle::merkle_root(&[pq_merkle::subkey_leaf(0, 1, &ml_pk, &slh_pk)]);
        let payload = canonical_payload_with_subkeys(&ml_pk, &slh_pk, &original_root);
        let user_data = user_data_commitment(&payload);

        let verifier = MockQuoteVerifier::good(pcr0, pcr1, pcr2, user_data);
        let err = verify(&bundle, &verifier, None).unwrap_err();
        assert!(matches!(err, Error::BindingMismatch), "expected BindingMismatch, got: {err}");
    }
```

- [ ] **Step 3: Add the `pq-merkle` dev/normal dependency**

In `crates/pq-bundle/Cargo.toml`, add under `[dependencies]`:

```toml
pq-merkle = { path = "../pq-merkle" }
```

- [ ] **Step 4: Run tests + clippy**

Run: `cargo test -p pq-bundle && cargo clippy -p pq-bundle --all-targets`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/pq-bundle
git commit -m "pq-bundle: v2 schema commits the subkey Merkle root

Binding + dual-sig now cover canonical_payload_with_subkeys, so the
pre-committed subkey set inherits the attestation and OTS anchor."
```

---

### Task 5: ceremony derives subkeys, builds the tree, commits the root

**Files:**
- Modify: `crates/pq-ceremony/src/lib.rs`
- Modify: `crates/pq-ceremony/Cargo.toml`

**Interfaces:**
- Consumes: `pq_derive::{derive_keypair, subkey_path}`, `pq_merkle::{subkey_leaf, merkle_root, merkle_proof}`, `pq_core::canonical_payload_with_subkeys`, `keyfork_mnemonic::Mnemonic`.
- Produces:
  - `pq_ceremony::CeremonyConfig { pub auth_count: u32, pub enc_count: u32 }`
  - `pq_ceremony::SubkeyRecord { pub global_index: u32, pub account: u32, pub account_index: u32, pub purpose_tag: u8, pub ml_dsa_pk: Vec<u8>, pub slh_dsa_pk: Vec<u8> }`
  - `pq_ceremony::CeremonyState { pub bundle: PqRootBundle, mnemonic: Mnemonic, leaves: Vec<[u8;32]>, pub subkeys: Vec<SubkeyRecord> }` with methods `sign_with_subkey(global_index, message) -> Option<(DualSignature, Vec<[u8;32]>)>` and `proof(global_index) -> Option<Vec<[u8;32]>>`.
  - `run_ceremony(nsm: &impl Nsm, root_ca_der: &[u8], config: &CeremonyConfig) -> Result<CeremonyState, CeremonyError>` (signature changed: now takes `config`, returns `CeremonyState`).
- Convention: `account` 1 = Auth (`purpose_tag` 1), 2 = Encryption (`purpose_tag` 2); root is derived at `m/0'/0'`. Global leaf order: all Auth subkeys (index 0..auth_count), then all Encryption subkeys.

- [ ] **Step 1: Add dependencies**

In `crates/pq-ceremony/Cargo.toml` `[dependencies]`:

```toml
pq-derive = { path = "../pq-derive" }
pq-merkle = { path = "../pq-merkle" }
keyfork-mnemonic = { version = "0.3", registry = "distrust", default-features = false }
getrandom = "0.2"
```

(Match the `keyfork-mnemonic` version already resolved in `Cargo.lock` for `pq-derive`; adjust if it differs.)

- [ ] **Step 2: Write the failing tests**

Replace `crates/pq-ceremony/src/lib.rs`'s `mod tests` body with tests that exercise the new shape (keep `distinct_runs_produce_distinct_keys` adapted):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::{canonical_payload_with_subkeys, user_data_commitment, verify_dual, DualSignature};
    use pq_enclave::MockNsm;

    fn config() -> CeremonyConfig {
        CeremonyConfig { auth_count: 3, enc_count: 2 }
    }

    #[test]
    fn ceremony_commits_subkey_tree() {
        let state = run_ceremony(&MockNsm, b"fake-root-ca", &config()).expect("ceremony ok");
        let b = &state.bundle;

        assert_eq!(b.version, "2");
        assert_eq!(b.subkey_count, 5);
        assert_eq!(state.subkeys.len(), 5);

        // The dual signature verifies over the subkey-committing payload.
        let ml_pk = hex::decode(&b.ml_dsa_pk).unwrap();
        let slh_pk = hex::decode(&b.slh_dsa_pk).unwrap();
        let root = hex::decode(&b.subkey_merkle_root).unwrap();
        let payload = canonical_payload_with_subkeys(&ml_pk, &slh_pk, &root);
        let dual = DualSignature {
            ml_dsa: hex::decode(&b.ml_dsa_sig).unwrap(),
            slh_dsa: hex::decode(&b.slh_dsa_sig).unwrap(),
        };
        verify_dual(&ml_pk, &slh_pk, &payload, &dual).expect("dual sig over committing payload");

        // The mock quote commits to that same payload.
        let commitment_hex = hex::encode(user_data_commitment(&payload));
        let quote = BASE64.decode(&b.nsm_quote).unwrap();
        assert!(std::str::from_utf8(&quote).unwrap().contains(&commitment_hex));
    }

    #[test]
    fn every_subkey_is_provable_and_signs() {
        let state = run_ceremony(&MockNsm, b"r", &config()).expect("ceremony ok");
        let root: [u8; 32] = hex::decode(&state.bundle.subkey_merkle_root).unwrap().try_into().unwrap();

        for rec in &state.subkeys {
            // Membership proof checks against the anchored root.
            let proof = state.proof(rec.global_index).expect("proof exists");
            assert!(pq_merkle::verify_membership(
                &root, rec.global_index, rec.purpose_tag, &rec.ml_dsa_pk, &rec.slh_dsa_pk, &proof,
            ));

            // Signing oracle: signature verifies under the subkey's own keys.
            let (sig, _proof) = state.sign_with_subkey(rec.global_index, b"hello").expect("signed");
            verify_dual(&rec.ml_dsa_pk, &rec.slh_dsa_pk, b"hello", &sig).expect("subkey sig valid");
        }
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p pq-ceremony`
Expected: FAIL — `CeremonyConfig`/`CeremonyState`/new `run_ceremony` signature not found.

- [ ] **Step 4: Rewrite `run_ceremony` and add the state types**

Replace the body of `crates/pq-ceremony/src/lib.rs` above `mod tests` (keep the module doc comment) with:

```rust
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use keyfork_mnemonic::Mnemonic;
use pq_bundle::{ExpectedPcrs, PqRootBundle};
use pq_core::{canonical_payload_with_subkeys, DualSignature, PqRootKeypair};
use pq_derive::{derive_keypair, subkey_path};
use pq_enclave::{attest_bundle_payload, Nsm, NsmError};
use sha2::{Digest, Sha256};

/// Errors produced while running the ceremony.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    /// An NSM operation (attestation or `DescribePCR`) failed.
    #[error("NSM operation failed: {0}")]
    Nsm(#[from] NsmError),
    /// Subkey derivation via keyfork failed.
    #[error("subkey derivation failed: {0}")]
    Derive(#[from] pq_derive::Error),
}

/// How many subkeys to pre-commit, per purpose lane.
#[derive(Debug, Clone, Copy)]
pub struct CeremonyConfig {
    /// Number of Auth (`account` 1) subkeys.
    pub auth_count: u32,
    /// Number of Encryption (`account` 2) subkeys.
    pub enc_count: u32,
}

/// One pre-committed subkey's public material and tree position.
#[derive(Debug, Clone)]
pub struct SubkeyRecord {
    /// Position in the flat Merkle leaf order.
    pub global_index: u32,
    /// Derivation account/purpose lane (1 = Auth, 2 = Encryption).
    pub account: u32,
    /// Index within the lane.
    pub account_index: u32,
    /// Purpose tag committed into the leaf (1 = Auth, 2 = Encryption).
    pub purpose_tag: u8,
    /// Subkey ML-DSA-65 public key.
    pub ml_dsa_pk: Vec<u8>,
    /// Subkey SLH-DSA-SHAKE-128f public key.
    pub slh_dsa_pk: Vec<u8>,
}

/// The full in-enclave ceremony result: the public bundle plus the retained
/// secret-side material the signing oracle needs. **Never serialized.**
pub struct CeremonyState {
    /// The public, serializable bundle.
    pub bundle: PqRootBundle,
    /// Public records for each pre-committed subkey.
    pub subkeys: Vec<SubkeyRecord>,
    mnemonic: Mnemonic,
    leaves: Vec<[u8; 32]>,
}

impl CeremonyState {
    /// Re-derive subkey `global_index` and dual-sign `message` with it, returning
    /// the signature and the subkey's Merkle membership proof. Secret never leaves.
    #[must_use]
    pub fn sign_with_subkey(
        &self,
        global_index: u32,
        message: &[u8],
    ) -> Option<(DualSignature, Vec<[u8; 32]>)> {
        let rec = self.subkeys.iter().find(|r| r.global_index == global_index)?;
        let kp = derive_keypair(&self.mnemonic, &subkey_path(rec.account, rec.account_index)).ok()?;
        let sig = kp.sign_payload(message);
        Some((sig, self.proof(global_index)?))
    }

    /// The Merkle membership proof for `global_index`, if it exists.
    #[must_use]
    pub fn proof(&self, global_index: u32) -> Option<Vec<[u8; 32]>> {
        let idx = usize::try_from(global_index).ok()?;
        if idx >= self.leaves.len() {
            return None;
        }
        Some(pq_merkle::merkle_proof(&self.leaves, idx))
    }
}

/// Run the full in-enclave ceremony: generate a mnemonic, HD-derive the root and
/// `config` subkeys, pre-commit the subkeys in a Merkle tree, dual-sign + attest
/// the root-plus-subkey commitment, and self-read PCRs.
///
/// # Errors
/// Returns [`CeremonyError`] if attestation, PCR readout, or subkey derivation fails.
pub fn run_ceremony(
    nsm: &impl Nsm,
    root_ca_der: &[u8],
    config: &CeremonyConfig,
) -> Result<CeremonyState, CeremonyError> {
    // In-enclave entropy → mnemonic. (Inside real Nitro the CSPRNG must be
    // NSM-seeded — see pq-core's entropy note. Never exported.)
    let mut entropy = [0u8; 32];
    getrandom::getrandom(&mut entropy).expect("enclave CSPRNG");
    let mnemonic = Mnemonic::try_from_slice(&entropy).expect("32 bytes is valid entropy");

    // Root at m/0'/0'.
    let root = derive_keypair(&mnemonic, &subkey_path(0, 0))?;
    let ml_pk = root.ml_dsa_pk();
    let slh_pk = root.slh_dsa_pk();

    // Derive subkeys: Auth lane (account 1) then Encryption lane (account 2).
    let mut subkeys = Vec::new();
    let mut leaves = Vec::new();
    let mut global_index = 0u32;
    for (account, purpose_tag, count) in
        [(1u32, 1u8, config.auth_count), (2u32, 2u8, config.enc_count)]
    {
        for account_index in 0..count {
            let kp = derive_keypair(&mnemonic, &subkey_path(account, account_index))?;
            let (sk_ml, sk_slh) = (kp.ml_dsa_pk(), kp.slh_dsa_pk());
            leaves.push(pq_merkle::subkey_leaf(global_index, purpose_tag, &sk_ml, &sk_slh));
            subkeys.push(SubkeyRecord {
                global_index,
                account,
                account_index,
                purpose_tag,
                ml_dsa_pk: sk_ml,
                slh_dsa_pk: sk_slh,
            });
            global_index += 1;
        }
    }
    let subkey_root = pq_merkle::merkle_root(&leaves);

    // Commit root keys + subkey set in one payload.
    let payload = canonical_payload_with_subkeys(&ml_pk, &slh_pk, &subkey_root);
    let sig = root.sign_payload(&payload);
    let quote = attest_bundle_payload(nsm, &payload)?;

    let pcr0 = nsm.describe_pcr(0)?;
    let pcr1 = nsm.describe_pcr(1)?;
    let pcr2 = nsm.describe_pcr(2)?;
    let root_sha256 = Sha256::digest(root_ca_der);

    let bundle = PqRootBundle {
        version: "2".to_owned(),
        ml_dsa_pk: hex::encode(&ml_pk),
        slh_dsa_pk: hex::encode(&slh_pk),
        nsm_quote: BASE64.encode(&quote),
        aws_root_ca_sha256: hex::encode(root_sha256),
        expected_pcrs: ExpectedPcrs {
            pcr0: hex::encode(pcr0),
            pcr1: hex::encode(pcr1),
            pcr2: hex::encode(pcr2),
        },
        subkey_merkle_root: hex::encode(subkey_root),
        subkey_count: global_index,
        ml_dsa_sig: hex::encode(&sig.ml_dsa),
        slh_dsa_sig: hex::encode(&sig.slh_dsa),
    };

    Ok(CeremonyState { bundle, subkeys, mnemonic, leaves })
}
```

- [ ] **Step 5: Run tests + clippy**

Run: `cargo test -p pq-ceremony && cargo clippy -p pq-ceremony --all-targets`
Expected: PASS, no warnings. (If `keyfork-mnemonic`'s `try_from_slice` name differs in the resolved version, adjust to the actual constructor — confirm via `cargo doc -p keyfork-mnemonic`.)

- [ ] **Step 6: Commit**

```bash
git add crates/pq-ceremony/Cargo.toml crates/pq-ceremony/src/lib.rs Cargo.lock
git commit -m "pq-ceremony: pre-commit HD-derived subkeys into the attestation

Derive root + N subkeys from an in-enclave mnemonic, build a Merkle
tree, and fold its root into the signed/attested/anchored payload.
CeremonyState retains the mnemonic for the signing oracle (no export)."
```

---

### Task 6: signing-oracle HTTP endpoints

**Files:**
- Modify: `crates/pq-ceremony/src/main.rs`

**Interfaces:**
- Consumes: `pq_ceremony::{run_ceremony, CeremonyConfig, CeremonyState}`.
- Produces (testable lib fn inside `main.rs`): `fn sign_response(state: &CeremonyState, body: &str) -> (String, String)` returning `(http_status, json_body)`; HTTP glue calls it for `POST /sign`. Request JSON: `{ "index": u32, "message_hex": "<hex>" }`. Response JSON: `{ index, purpose_tag, ml_dsa_pk, slh_dsa_pk, ml_dsa_sig, slh_dsa_sig, merkle_proof: [hex...] }` (all bytes hex).
- Counts come from env: `PQ_SUBKEYS_AUTH` / `PQ_SUBKEYS_ENC` (default 4 / 0).

- [ ] **Step 1: Write the failing test**

Add a `#[cfg(test)] mod tests` to `crates/pq-ceremony/src/main.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pq_ceremony::{run_ceremony, CeremonyConfig};
    use pq_enclave::MockNsm;

    #[test]
    fn sign_response_signs_and_proves() {
        let state =
            run_ceremony(&MockNsm, b"r", &CeremonyConfig { auth_count: 2, enc_count: 0 }).unwrap();
        let body = r#"{"index":1,"message_hex":"68656c6c6f"}"#; // "hello"
        let (status, json) = sign_response(&state, body);
        assert_eq!(status, "200 OK");
        assert!(json.contains("merkle_proof"));
        assert!(json.contains("ml_dsa_sig"));
    }

    #[test]
    fn sign_response_rejects_unknown_index() {
        let state =
            run_ceremony(&MockNsm, b"r", &CeremonyConfig { auth_count: 1, enc_count: 0 }).unwrap();
        let (status, _json) = sign_response(&state, r#"{"index":99,"message_hex":"00"}"#);
        assert_eq!(status, "404 Not Found");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pq-ceremony --bin pq-ceremony`
Expected: FAIL — `sign_response` not found.

- [ ] **Step 3: Implement env-driven config, state, `sign_response`, and routing**

Rewrite `crates/pq-ceremony/src/main.rs`. Key changes: build `CeremonyConfig` from env, hold `CeremonyState`, add `sign_response`, and route `GET /subkey/<i>` + `POST /sign`. Replace `main`, `serve`, `handle` and add helpers:

```rust
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::Parser;
use pq_ceremony::{run_ceremony, CeremonyConfig, CeremonyState};

#[cfg(feature = "nitro")]
use pq_enclave::nitro::NitroNsm;
#[cfg(not(feature = "nitro"))]
use pq_enclave::MockNsm;

#[derive(Parser)]
#[command(name = "pq-ceremony", about = "In-enclave PQ root key burn-in ceremony + signing oracle")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: String,
    #[arg(long, default_value = "/etc/pq/aws_nitro_root.der")]
    root_ca: PathBuf,
}

fn config_from_env() -> CeremonyConfig {
    let parse = |k: &str, d: u32| env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    CeremonyConfig { auth_count: parse("PQ_SUBKEYS_AUTH", 4), enc_count: parse("PQ_SUBKEYS_ENC", 0) }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root_ca = std::fs::read(&cli.root_ca)
        .with_context(|| format!("reading AWS root CA {}", cli.root_ca.display()))?;

    #[cfg(feature = "nitro")]
    let nsm = NitroNsm;
    #[cfg(not(feature = "nitro"))]
    let nsm = MockNsm;

    let config = config_from_env();
    eprintln!(
        "pq-ceremony: generating root + {} auth / {} enc subkeys, attesting...",
        config.auth_count, config.enc_count
    );
    let state = run_ceremony(&nsm, &root_ca, &config).context("ceremony failed")?;
    let bundle_json = state.bundle.to_json().context("serializing bundle")?;
    eprintln!("pq-ceremony: bundle ready ({} bytes); serving on http://{}", bundle_json.len(), cli.bind);

    serve(&cli.bind, &state, &bundle_json).context("HTTP server failed")
}

/// Build the JSON response for `POST /sign`. Returns `(status, body)`.
fn sign_response(state: &CeremonyState, body: &str) -> (String, String) {
    #[derive(serde::Deserialize)]
    struct Req {
        index: u32,
        message_hex: String,
    }
    let Ok(req) = serde_json::from_str::<Req>(body) else {
        return ("400 Bad Request".into(), "{\"error\":\"bad request\"}".into());
    };
    let Ok(message) = hex::decode(&req.message_hex) else {
        return ("400 Bad Request".into(), "{\"error\":\"bad message_hex\"}".into());
    };
    let Some(rec) = state.subkeys.iter().find(|r| r.global_index == req.index) else {
        return ("404 Not Found".into(), "{\"error\":\"unknown subkey index\"}".into());
    };
    let Some((sig, proof)) = state.sign_with_subkey(req.index, &message) else {
        return ("404 Not Found".into(), "{\"error\":\"unknown subkey index\"}".into());
    };
    let proof_hex: Vec<String> = proof.iter().map(hex::encode).collect();
    let json = serde_json::json!({
        "index": rec.global_index,
        "purpose_tag": rec.purpose_tag,
        "ml_dsa_pk": hex::encode(&rec.ml_dsa_pk),
        "slh_dsa_pk": hex::encode(&rec.slh_dsa_pk),
        "ml_dsa_sig": hex::encode(&sig.ml_dsa),
        "slh_dsa_sig": hex::encode(&sig.slh_dsa),
        "merkle_proof": proof_hex,
    });
    ("200 OK".into(), json.to_string())
}

/// Build the JSON for `GET /subkey/<i>` (public material + proof, no signature).
fn subkey_response(state: &CeremonyState, index: u32) -> (String, String) {
    let Some(rec) = state.subkeys.iter().find(|r| r.global_index == index) else {
        return ("404 Not Found".into(), "{\"error\":\"unknown subkey index\"}".into());
    };
    let proof_hex: Vec<String> =
        state.proof(index).unwrap_or_default().iter().map(hex::encode).collect();
    let json = serde_json::json!({
        "index": rec.global_index,
        "purpose_tag": rec.purpose_tag,
        "ml_dsa_pk": hex::encode(&rec.ml_dsa_pk),
        "slh_dsa_pk": hex::encode(&rec.slh_dsa_pk),
        "merkle_proof": proof_hex,
    });
    ("200 OK".into(), json.to_string())
}

fn serve(addr: &str, state: &CeremonyState, bundle_json: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).with_context(|| format!("binding {addr}"))?;
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                if let Err(e) = handle(&mut s, state, bundle_json) {
                    eprintln!("pq-ceremony: request error: {e}");
                }
            }
            Err(e) => eprintln!("pq-ceremony: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(stream: &mut TcpStream, state: &CeremonyState, bundle_json: &str) -> std::io::Result<()> {
    // Read headers, then the body (Content-Length) if present.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break buf.len();
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            // Ensure the full body is read.
            let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
            let len = content_length(&headers);
            let need = pos + 4 + len;
            while buf.len() < need {
                let n = stream.read(&mut tmp)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            break pos;
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let body = String::from_utf8_lossy(&buf[(header_end + 4).min(buf.len())..]).to_string();

    let (status, content_type, body_out): (String, &str, String) = match (method, path) {
        ("GET", "/bundle.json") => ("200 OK".into(), "application/json", bundle_json.to_string()),
        ("GET", "/health") | ("GET", "/") => ("200 OK".into(), "text/plain", "ok\n".to_string()),
        ("POST", "/sign") => {
            let (s, b) = sign_response(state, &body);
            (s, "application/json", b)
        }
        ("GET", p) if p.starts_with("/subkey/") => {
            match p.trim_start_matches("/subkey/").parse::<u32>() {
                Ok(i) => {
                    let (s, b) = subkey_response(state, i);
                    (s, "application/json", b)
                }
                Err(_) => ("400 Bad Request".into(), "text/plain", "bad index\n".to_string()),
            }
        }
        _ => ("404 Not Found".into(), "text/plain", "not found\n".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_out}",
        body_out.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length:").or_else(|| l.strip_prefix("content-length:")))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}
```

Add to `crates/pq-ceremony/Cargo.toml` `[dependencies]` (if not already present): `serde_json.workspace = true`, `serde = { workspace = true }`, `hex.workspace = true`.

- [ ] **Step 4: Run tests + clippy**

Run: `cargo test -p pq-ceremony && cargo clippy -p pq-ceremony --all-targets`
Expected: PASS, no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/pq-ceremony
git commit -m "pq-ceremony: signing-oracle endpoints (POST /sign, GET /subkey/<i>)

Re-derives a subkey in-enclave, signs, and returns the dual signature
plus its Merkle membership proof. Subkey count from env. No export."
```

---

### Task 7: CLI `verify-subkey` + `inspect` extension

**Files:**
- Modify: `crates/pq-cli/src/main.rs`
- Modify: `crates/pq-cli/Cargo.toml`

**Interfaces:**
- Consumes: `pq_merkle::verify_membership`, `pq_core::verify_dual`, `PqRootBundle`.
- Produces: `pq verify-subkey --bundle <bundle.json> --subkey <subkey.json> [--message-hex <hex>]` where `subkey.json` is the `POST /sign` (or `GET /subkey`) response. Verifies (1) Merkle membership against `bundle.subkey_merkle_root` → birth-provenance, and (2) if `--message-hex` and signatures present, the dual signature over the message → authenticity. `inspect` additionally prints `subkey merkle root` and `subkey count`.

- [ ] **Step 1: Add the `pq-merkle` and `pq-core` deps**

In `crates/pq-cli/Cargo.toml` `[dependencies]`: `pq-merkle = { path = "../pq-merkle" }` and (if absent) `pq-core = { path = "../pq-core" }`.

- [ ] **Step 2: Add the subcommand variant and dispatch**

In `crates/pq-cli/src/main.rs`, add to `enum Command`:

```rust
    /// Verify a subkey's birth-provenance (Merkle membership) and, if given a
    /// message, its dual signature.
    VerifySubkey {
        /// Path to bundle.json (provides the anchored subkey Merkle root).
        #[arg(long)]
        bundle: PathBuf,
        /// Path to the subkey JSON (a `/sign` or `/subkey/<i>` response).
        #[arg(long)]
        subkey: PathBuf,
        /// Optional message (hex) the subkey claims to have signed.
        #[arg(long = "message-hex")]
        message_hex: Option<String>,
    },
```

In the `match cli.command` dispatch, add an arm `Command::VerifySubkey { bundle, subkey, message_hex } => verify_subkey(&bundle, &subkey, message_hex.as_deref()),`.

- [ ] **Step 3: Implement `verify_subkey` and extend `inspect`**

Add the function (uses a local deserialization struct):

```rust
#[derive(serde::Deserialize)]
struct SubkeyResponse {
    index: u32,
    purpose_tag: u8,
    ml_dsa_pk: String,
    slh_dsa_pk: String,
    #[serde(default)]
    ml_dsa_sig: Option<String>,
    #[serde(default)]
    slh_dsa_sig: Option<String>,
    merkle_proof: Vec<String>,
}

fn verify_subkey(bundle_path: &Path, subkey_path: &Path, message_hex: Option<&str>) -> Result<()> {
    let bundle = PqRootBundle::from_json(&fs::read_to_string(bundle_path)?)?;
    let sk: SubkeyResponse = serde_json::from_str(&fs::read_to_string(subkey_path)?)?;

    let root: [u8; 32] = hex::decode(&bundle.subkey_merkle_root)
        .context("decoding bundle.subkey_merkle_root")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("subkey_merkle_root is not 32 bytes"))?;
    let ml_pk = hex::decode(&sk.ml_dsa_pk).context("subkey ml_dsa_pk")?;
    let slh_pk = hex::decode(&sk.slh_dsa_pk).context("subkey slh_dsa_pk")?;
    let siblings: Vec<[u8; 32]> = sk
        .merkle_proof
        .iter()
        .map(|h| {
            hex::decode(h)
                .ok()
                .and_then(|b| b.try_into().ok())
                .context("merkle_proof node must be 32-byte hex")
        })
        .collect::<Result<_>>()?;

    if !pq_merkle::verify_membership(&root, sk.index, sk.purpose_tag, &ml_pk, &slh_pk, &siblings) {
        bail!("✗ membership proof FAILED — subkey is not in the anchored set");
    }
    println!("✓ birth-provenance — subkey #{} is committed in the enclave's anchored set", sk.index);

    if let Some(msg_hex) = message_hex {
        let msg = hex::decode(msg_hex).context("--message-hex")?;
        let (Some(ml_sig), Some(slh_sig)) = (&sk.ml_dsa_sig, &sk.slh_dsa_sig) else {
            bail!("--message-hex given but subkey JSON has no signatures");
        };
        let dual = pq_core::DualSignature {
            ml_dsa: hex::decode(ml_sig).context("ml_dsa_sig")?,
            slh_dsa: hex::decode(slh_sig).context("slh_dsa_sig")?,
        };
        pq_core::verify_dual(&ml_pk, &slh_pk, &msg, &dual).context("subkey signature")?;
        println!("✓ authenticity — dual signature over the message verifies");
    }

    println!("\nVERIFIED — this subkey was generated inside the attested enclave.");
    Ok(())
}
```

Extend the existing `inspect` printout — after the PCR lines, add:

```rust
    println!("subkey merkle root:  {}", bundle.subkey_merkle_root);
    println!("subkey count:        {}", bundle.subkey_count);
```

- [ ] **Step 4: Build + clippy + smoke test**

Run: `cargo build -p pq-cli && cargo clippy -p pq-cli --all-targets`
Expected: builds, no warnings.

- [ ] **Step 5: Commit**

```bash
git add crates/pq-cli
git commit -m "pq-cli: add verify-subkey (membership + signature); show subkeys in inspect"
```

---

### Task 8: Documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

**Interfaces:** none (docs).

- [ ] **Step 1: Update `CLAUDE.md`**

In the "Architecture" crate list, add `pq-merkle` (subkey pre-commitment tree), `pq-derive`, `pq-subkey` (note: cert path, unused in the POC). Update the `pq-core` bullet to mention `from_seed` and `canonical_payload_with_subkeys`. Update the `pq-ceremony` bullet: it now HD-derives root + N subkeys, pre-commits them in a Merkle tree folded into the attested payload, and serves a signing oracle (`POST /sign`, `GET /subkey/<i>`). Update "Two load-bearing invariants" #1 to note the subkey Merkle root is part of the committed payload. Add a one-line note under a new "Subkey model" heading: subkeys are pre-committed pre-Q-Day (birth-provenance via Merkle membership) and used via the in-enclave signing oracle — **no secret export**; shamir backup and TEE-to-TEE migration are deferred.

- [ ] **Step 2: Update `README.md`**

Add a "Subkeys" subsection explaining: the enclave pre-commits N subkeys (configurable via `PQ_SUBKEYS_AUTH` / `PQ_SUBKEYS_ENC`), anchors the Merkle root pre-Q-Day, and signs with a subkey on request without ever exporting the secret. Show the `pq verify-subkey` flow. Add the crate `pq-merkle` to the "Crate layout" list. Note the deferred export paths.

- [ ] **Step 3: Verify the workspace builds clean end-to-end**

Run: `cargo test --workspace && cargo clippy --workspace --all-targets`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: subkey pre-commitment + signing oracle"
```

---

## Deferred (explicitly out of scope for this POC)

- **Shamir backup of the root mnemonic** (`keyfork-shard`) — would re-enable post-enclave recovery; safe only because Merkle membership (not a live root signature) is what verifiers trust. Not built; no export.
- **TEE-to-TEE migration** (ML-KEM / `fips203` wrapping to an attested successor enclave) — durability/redundancy without plaintext export. Noted as the real fix for the single-replica risk.
- **Metadata-in-leaf immutability** beyond `purpose_tag` (e.g. validity windows) and **`pq-subkey` cert integration** for post-Q-Day delegation.

## Self-Review Notes

- **Spec coverage:** no-export ✓ (no secret serialized; mnemonic retained in-enclave only), signing-oracle usability ✓ (Task 6), N-per-type from config/env ✓ (Tasks 5–6), Merkle pre-commit folded into attestation+OTS ✓ (Tasks 2,4,5), birth- vs custody-provenance distinction surfaced in docs ✓ (Task 8).
- **Type consistency:** `canonical_payload_with_subkeys`, `subkey_leaf`/`merkle_root`/`merkle_proof`/`verify_membership`, `CeremonyConfig`/`CeremonyState`/`SubkeyRecord`, `sign_response` used identically across tasks.
- **Open verification point:** confirm `keyfork-mnemonic`'s constructor name (`Mnemonic::try_from_slice`) and version against the resolved `Cargo.lock` before Task 5 Step 4 (the test in `pq-derive` already uses `try_from_slice`, so it should match).
