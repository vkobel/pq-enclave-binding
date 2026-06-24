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

/// Hash one subkey leaf: `SHA-256(0x00 || index || purpose || lp(ml) || lp(slh))`.
///
/// # Panics
/// Panics if either public-key slice is longer than `u32::MAX` bytes (unreachable in
/// practice — ML-DSA and SLH-DSA public keys are at most a few kilobytes).
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
        let sibling = if idx.is_multiple_of(2) {
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
///
/// # Panics
/// Never panics in practice: `u32` fits `usize` on all 32-bit and wider targets.
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
    let mut idx = usize::try_from(index).expect("index fits usize");
    for sibling in siblings {
        acc = if idx.is_multiple_of(2) {
            hash_node(&acc, sibling)
        } else {
            hash_node(sibling, &acc)
        };
        idx /= 2;
    }
    &acc == root
}

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
            .map(|i| subkey_leaf(i, 1, &pk(u8::try_from(i).unwrap()), &pk(u8::try_from(i + 1).unwrap())))
            .collect();
        let root = merkle_root(&leaves);
        for i in 0..5usize {
            let proof = merkle_proof(&leaves, i);
            let idx = u32::try_from(i).unwrap();
            assert!(
                verify_membership(&root, idx, 1, &pk(u8::try_from(idx).unwrap()), &pk(u8::try_from(idx + 1).unwrap()), &proof),
                "leaf {i} must verify"
            );
        }
    }

    #[test]
    fn wrong_index_fails() {
        let leaves: Vec<[u8; 32]> = (0..4u32)
            .map(|i| subkey_leaf(i, 1, &pk(u8::try_from(i).unwrap()), &pk(9)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 1);
        // Same pubkeys, wrong claimed index.
        assert!(!verify_membership(&root, 2, 1, &pk(1), &pk(9), &proof));
    }

    #[test]
    fn tampered_pubkey_fails() {
        let leaves: Vec<[u8; 32]> = (0..4u32)
            .map(|i| subkey_leaf(i, 1, &pk(u8::try_from(i).unwrap()), &pk(9)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 1);
        assert!(!verify_membership(&root, 1, 1, &pk(0xff), &pk(9), &proof));
    }

    #[test]
    fn wrong_purpose_fails() {
        let leaves: Vec<[u8; 32]> = (0..2u32)
            .map(|i| subkey_leaf(i, 1, &pk(u8::try_from(i).unwrap()), &pk(9)))
            .collect();
        let root = merkle_root(&leaves);
        let proof = merkle_proof(&leaves, 0);
        assert!(!verify_membership(&root, 0, 2, &pk(0), &pk(9), &proof));
    }
}
