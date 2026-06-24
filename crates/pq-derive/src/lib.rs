//! Deterministic PQ key derivation from a BIP-39 mnemonic.
//!
//! This crate bridges [keyfork](https://git.distrust.co/public/keyfork) to
//! [`pq_core`]. keyfork owns the **secret side** — a mnemonic and its 512-bit
//! seed, and the SLIP-0010 hardened-derivation tree that turns one master seed
//! into an unbounded set of deterministic 32-byte child nodes. `pq_core` owns
//! the **expansion** — turning a 32-byte node into an ML-DSA-65 + SLH-DSA
//! keypair ([`PqRootKeypair::from_seed`]).
//!
//! ## Does keyfork need to be modified?
//!
//! **No.** keyfork's [`PrivateKey`]/[`PublicKey`] traits and its generic
//! [`ExtendedPrivateKey`] machinery are public, so we implement a PQ seed key
//! ([`PqSeed`]) here, in this workspace, without touching keyfork. We pull
//! keyfork with `default-features = false` so neither `k256`/`ed25519-dalek`
//! (which would add a `signature`-crate edge) nor the `smex` binary helper are
//! compiled — only the seed/mnemonic/derivation machinery we need.
//!
//! PQ derivation is **hardened-only** (exactly like keyfork's ed25519 support):
//! ML-DSA/SLH-DSA public keys have no additive group structure, so non-hardened
//! (public-key) derivation is impossible. The 32-byte child node is used as a
//! seed, not as a usable key — the real PQ keypair is produced by `pq_core`.

use keyfork_derive_util::{
    private_key::{PrivateKey, PrivateKeyError},
    public_key::{PublicKey, PublicKeyError},
    DerivationPath, ExtendedPrivateKey, VariableLengthSeed,
};
use keyfork_mnemonic::Mnemonic;
use pq_core::PqRootKeypair;
use sha2::{Digest, Sha256};

/// Errors produced while deriving a PQ key from a mnemonic.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// keyfork's extended-private-key derivation failed (e.g. a non-hardened
    /// index was used, or the maximum depth was exceeded).
    #[error("keyfork derivation failed: {0}")]
    Derivation(#[from] keyfork_derive_util::XPrvError),
}

/// A 32-byte PQ seed node in keyfork's SLIP-0010 tree.
///
/// Implements keyfork's [`PrivateKey`] in the hardened-only style: the child
/// node is the 32-byte HMAC output adopted directly (no curve arithmetic). The
/// node is *seed material*, expanded into a real keypair by [`PqRootKeypair`].
#[derive(Clone)]
pub struct PqSeed {
    node: [u8; 32],
}

/// Fingerprint-only public representation of a [`PqSeed`].
///
/// keyfork's [`PublicKey`] is fixed at 33 bytes, which cannot hold a real
/// ML-DSA-65 public key (~1952 bytes). Since PQ derivation is hardened-only,
/// this value is never consumed in derivation — only in SLIP-0010 fingerprints —
/// so we expose a 33-byte digest of the node. The usable PQ public key comes
/// from `pq_core`, not from here.
#[derive(Clone)]
pub struct PqSeedFingerprint {
    bytes: [u8; 33],
}

impl PublicKey for PqSeedFingerprint {
    type Err = PublicKeyError;

    fn to_bytes(&self) -> [u8; 33] {
        self.bytes
    }

    fn derive_child(&self, _other: [u8; 32]) -> Result<Self, Self::Err> {
        // Public-key (non-hardened) derivation is impossible for PQ keys.
        Err(PublicKeyError::DerivationUnsupported)
    }
}

impl PrivateKey for PqSeed {
    type PublicKey = PqSeedFingerprint;
    type Err = PrivateKeyError;

    fn from_bytes(b: &[u8; 32]) -> Result<Self, Self::Err> {
        Ok(Self { node: *b })
    }

    fn to_bytes(&self) -> [u8; 32] {
        self.node
    }

    fn key() -> &'static str {
        "pq-root seed"
    }

    fn public_key(&self) -> Self::PublicKey {
        let digest = Sha256::digest(self.node);
        let mut bytes = [0u8; 33];
        bytes[1..33].copy_from_slice(&digest);
        PqSeedFingerprint { bytes }
    }

    fn derive_child(&self, other: &[u8; 32]) -> Result<Self, Self::Err> {
        Ok(Self { node: *other })
    }

    fn requires_hardened_derivation() -> bool {
        true
    }
}

/// Derive the deterministic 32-byte node at `path` from `mnemonic`.
///
/// `path` must be fully hardened (PQ derivation is hardened-only).
///
/// # Errors
/// Returns [`Error::Derivation`] if keyfork rejects the path or seed.
pub fn derive_node(mnemonic: &Mnemonic, path: &DerivationPath) -> Result<[u8; 32], Error> {
    let seed = mnemonic.generate_seed(None);
    let master = ExtendedPrivateKey::<PqSeed>::new(VariableLengthSeed::new(&seed))?;
    let child = master.derive_path(path)?;
    Ok(child.private_key().to_bytes())
}

/// Build the hardened subkey path `m/account'/index'`.
///
/// `account` is the purpose lane (1 = Auth; 2 = reserved scaffold for future use);
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

/// Derive a full PQ root/subkey keypair at `path` from `mnemonic`.
///
/// Equivalent to `PqRootKeypair::from_seed(&derive_node(mnemonic, path)?)`.
/// The same `(mnemonic, path)` always yields the same keypair.
///
/// # Errors
/// Returns [`Error::Derivation`] if keyfork rejects the path or seed.
pub fn derive_keypair(
    mnemonic: &Mnemonic,
    path: &DerivationPath,
) -> Result<PqRootKeypair, Error> {
    Ok(PqRootKeypair::from_seed(&derive_node(mnemonic, path)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn mnemonic() -> Mnemonic {
        // 32 bytes of entropy -> a valid 24-word mnemonic.
        Mnemonic::try_from_slice(&[0x24u8; 32]).expect("valid entropy")
    }

    #[test]
    fn derivation_is_deterministic_and_path_dependent() {
        let m = mnemonic();
        let p0 = DerivationPath::from_str("m/44'/0'/0'").unwrap();
        let p1 = DerivationPath::from_str("m/44'/0'/1'").unwrap();

        let a = derive_node(&m, &p0).unwrap();
        let b = derive_node(&m, &p0).unwrap();
        let c = derive_node(&m, &p1).unwrap();
        assert_eq!(a, b, "same mnemonic+path must reproduce the node");
        assert_ne!(a, c, "different path must give a different node");
    }

    #[test]
    fn same_mnemonic_path_reproduces_keypair() {
        let m = mnemonic();
        let path = DerivationPath::from_str("m/7'/1'").unwrap();
        let kp1 = derive_keypair(&m, &path).unwrap();
        let kp2 = derive_keypair(&m, &path).unwrap();
        assert_eq!(kp1.ml_dsa_pk(), kp2.ml_dsa_pk());
        assert_eq!(kp1.slh_dsa_pk(), kp2.slh_dsa_pk());
    }

    #[test]
    fn auth_and_kem_paths_diverge() {
        // Distinct derivation paths model distinct subkey roles.
        let m = mnemonic();
        let auth = derive_keypair(&m, &DerivationPath::from_str("m/0'/0'").unwrap()).unwrap();
        let kem = derive_keypair(&m, &DerivationPath::from_str("m/1'/0'").unwrap()).unwrap();
        assert_ne!(auth.ml_dsa_pk(), kem.ml_dsa_pk());
    }

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
}
