//! Post-quantum root key generation and dual-signing for the PQ enclave-binding
//! demo.
//!
//! Generates an ML-DSA-65 (FIPS 204, lattice) and an SLH-DSA-SHAKE-128f
//! (FIPS 205, hash-based) keypair and signs a caller-supplied payload with both.
//! The two algorithms rest on independent hardness assumptions, so a future
//! break of one does not compromise the other.
//!
//! Backed by the standalone `fips204` / `fips205` crates (no `signature`-crate
//! dependency), which keeps this workspace compatible with the mature
//! X.509 / COSE stack used to verify AWS Nitro attestation quotes.
//!
//! ## Entropy inside an enclave
//!
//! Key generation draws from the platform CSPRNG (`fips20x` use `OsRng`).
//! **Inside a Nitro Enclave you must ensure that CSPRNG is seeded from the NSM
//! hardware RNG** — either via a Linux-in-enclave whose `/dev/urandom` is seeded
//! from NSM/virtio-rng, or by wiring an NSM `GetRandom`-backed RNG into the
//! `*_with_rng` constructors. Do not assume a fresh enclave's RNG is seeded.
//!
//! ## Secret handling
//!
//! Private keys are held inside the live key objects and are **never serialized**
//! by this crate — only public keys and signatures are exported.

use fips204::ml_dsa_65;
use fips205::slh_dsa_shake_128f;
use sha2::{Digest, Sha256};

// Both crates expose same-named traits; import anonymously so the methods are in
// scope without the trait names colliding.
use fips204::traits::{SerDes as _, Signer as _, Verifier as _};
use fips205::traits::{SerDes as _, Signer as _, Verifier as _};

/// Version tag prepended to the NSM `user_data` commitment, for future-proofing.
pub const USER_DATA_PREFIX: &[u8] = b"pq-keyfork-v1:";

/// Errors produced while verifying a bundle's signatures or public keys.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A public key could not be decoded from the provided bytes.
    #[error("invalid {0} public key encoding")]
    PublicKey(&'static str),
    /// A signature could not be decoded from the provided bytes.
    #[error("invalid {0} signature encoding")]
    Signature(&'static str),
    /// A signature failed cryptographic verification.
    #[error("{0} signature verification failed")]
    Verification(&'static str),
}

/// A dual post-quantum signature over a single payload.
#[derive(Clone, Debug)]
pub struct DualSignature {
    /// ML-DSA-65 signature bytes.
    pub ml_dsa: Vec<u8>,
    /// SLH-DSA-SHAKE-128f signature bytes.
    pub slh_dsa: Vec<u8>,
}

/// A freshly generated PQ root keypair. Holds live secret keys (never serialized).
pub struct PqRootKeypair {
    ml_dsa_pk: Vec<u8>,
    slh_dsa_pk: Vec<u8>,
    ml_dsa_sk: ml_dsa_65::PrivateKey,
    slh_dsa_sk: slh_dsa_shake_128f::PrivateKey,
}

impl PqRootKeypair {
    /// Generate a fresh ML-DSA-65 and SLH-DSA-SHAKE-128f keypair from the
    /// platform CSPRNG.
    ///
    /// See the crate-level docs for the enclave entropy requirements.
    ///
    /// # Panics
    /// Panics if the platform RNG fails during key generation.
    #[must_use]
    pub fn generate() -> Self {
        let (ml_pk, ml_dsa_sk) = ml_dsa_65::try_keygen().expect("ML-DSA-65 key generation");
        let (slh_pk, slh_dsa_sk) =
            slh_dsa_shake_128f::try_keygen().expect("SLH-DSA-SHAKE-128f key generation");
        Self {
            ml_dsa_pk: ml_pk.into_bytes().to_vec(),
            slh_dsa_pk: slh_pk.into_bytes().to_vec(),
            ml_dsa_sk,
            slh_dsa_sk,
        }
    }

    /// The ML-DSA-65 public (verifying) key, encoded as bytes.
    #[must_use]
    pub fn ml_dsa_pk(&self) -> Vec<u8> {
        self.ml_dsa_pk.clone()
    }

    /// The SLH-DSA-SHAKE-128f public (verifying) key, encoded as bytes.
    #[must_use]
    pub fn slh_dsa_pk(&self) -> Vec<u8> {
        self.slh_dsa_pk.clone()
    }

    /// Sign `payload` with both keys. The payload should be
    /// [`canonical_payload`] over the two public keys.
    ///
    /// # Panics
    /// Panics if the platform RNG fails during signing.
    #[must_use]
    pub fn sign_payload(&self, payload: &[u8]) -> DualSignature {
        let ml_sig = self
            .ml_dsa_sk
            .try_sign(payload, &[])
            .expect("ML-DSA-65 signing");
        // hedged = true: include fresh randomness in the SLH-DSA signature.
        let slh_sig = self
            .slh_dsa_sk
            .try_sign(payload, &[], true)
            .expect("SLH-DSA-SHAKE-128f signing");
        DualSignature {
            ml_dsa: ml_sig.to_vec(),
            slh_dsa: slh_sig.to_vec(),
        }
    }
}

/// Deterministic, length-prefixed concatenation of both public keys.
///
/// This is the canonical message that is signed by both PQ keys *and* hashed
/// into the NSM `user_data` commitment, so the hardware attestation and the PQ
/// signatures all commit to exactly the same two public keys.
///
/// # Panics
/// Panics if either public key is longer than `u32::MAX` bytes (never the case
/// for ML-DSA/SLH-DSA keys, which are a few KB at most).
#[must_use]
pub fn canonical_payload(ml_dsa_pk: &[u8], slh_dsa_pk: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + ml_dsa_pk.len() + slh_dsa_pk.len());
    v.extend_from_slice(&u32::try_from(ml_dsa_pk.len()).expect("pk len fits u32").to_be_bytes());
    v.extend_from_slice(ml_dsa_pk);
    v.extend_from_slice(&u32::try_from(slh_dsa_pk.len()).expect("pk len fits u32").to_be_bytes());
    v.extend_from_slice(slh_dsa_pk);
    v
}

/// The bytes to embed in the NSM `user_data` field: the version prefix followed
/// by `SHA-256(payload)`. Fits comfortably in NSM's 512-byte limit.
#[must_use]
pub fn user_data_commitment(payload: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(payload);
    let mut user_data = USER_DATA_PREFIX.to_vec();
    user_data.extend_from_slice(&digest);
    user_data
}

/// Verify an ML-DSA-65 signature over `payload`.
///
/// # Errors
/// Returns [`Error`] if the public key or signature cannot be decoded, or if
/// verification fails.
pub fn verify_ml_dsa(pk: &[u8], payload: &[u8], sig: &[u8]) -> Result<(), Error> {
    let pk_arr: [u8; ml_dsa_65::PK_LEN] = pk.try_into().map_err(|_| Error::PublicKey("ml-dsa"))?;
    let vk = ml_dsa_65::PublicKey::try_from_bytes(pk_arr).map_err(|_| Error::PublicKey("ml-dsa"))?;
    let sig_arr: [u8; ml_dsa_65::SIG_LEN] =
        sig.try_into().map_err(|_| Error::Signature("ml-dsa"))?;
    if vk.verify(payload, &sig_arr, &[]) {
        Ok(())
    } else {
        Err(Error::Verification("ml-dsa"))
    }
}

/// Verify an SLH-DSA-SHAKE-128f signature over `payload`.
///
/// # Errors
/// Returns [`Error`] if the public key or signature cannot be decoded, or if
/// verification fails.
pub fn verify_slh_dsa(pk: &[u8], payload: &[u8], sig: &[u8]) -> Result<(), Error> {
    let pk_arr: [u8; slh_dsa_shake_128f::PK_LEN] =
        pk.try_into().map_err(|_| Error::PublicKey("slh-dsa"))?;
    let vk = slh_dsa_shake_128f::PublicKey::try_from_bytes(&pk_arr)
        .map_err(|_| Error::PublicKey("slh-dsa"))?;
    let sig_arr: [u8; slh_dsa_shake_128f::SIG_LEN] =
        sig.try_into().map_err(|_| Error::Signature("slh-dsa"))?;
    if vk.verify(payload, &sig_arr, &[]) {
        Ok(())
    } else {
        Err(Error::Verification("slh-dsa"))
    }
}

/// Verify both signatures in a [`DualSignature`] over `payload`. Both must pass.
///
/// # Errors
/// Returns the first [`Error`] encountered.
pub fn verify_dual(
    ml_dsa_pk: &[u8],
    slh_dsa_pk: &[u8],
    payload: &[u8],
    sig: &DualSignature,
) -> Result<(), Error> {
    verify_ml_dsa(ml_dsa_pk, payload, &sig.ml_dsa)?;
    verify_slh_dsa(slh_dsa_pk, payload, &sig.slh_dsa)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dual_sign_round_trips() {
        let kp = PqRootKeypair::generate();
        let payload = canonical_payload(&kp.ml_dsa_pk(), &kp.slh_dsa_pk());
        let sig = kp.sign_payload(&payload);
        verify_dual(&kp.ml_dsa_pk(), &kp.slh_dsa_pk(), &payload, &sig)
            .expect("dual verification should pass");
    }

    #[test]
    fn rejects_tampered_payload() {
        let kp = PqRootKeypair::generate();
        let payload = canonical_payload(&kp.ml_dsa_pk(), &kp.slh_dsa_pk());
        let sig = kp.sign_payload(&payload);
        let mut bad = payload.clone();
        bad[0] ^= 0xff;
        assert!(verify_dual(&kp.ml_dsa_pk(), &kp.slh_dsa_pk(), &bad, &sig).is_err());
    }

    #[test]
    fn rejects_wrong_key() {
        let kp = PqRootKeypair::generate();
        let other = PqRootKeypair::generate();
        let payload = canonical_payload(&kp.ml_dsa_pk(), &kp.slh_dsa_pk());
        let sig = kp.sign_payload(&payload);
        assert!(verify_ml_dsa(&other.ml_dsa_pk(), &payload, &sig.ml_dsa).is_err());
        assert!(verify_slh_dsa(&other.slh_dsa_pk(), &payload, &sig.slh_dsa).is_err());
    }

    #[test]
    fn canonical_payload_is_unambiguous() {
        let p1 = canonical_payload(b"AB", b"C");
        let p2 = canonical_payload(b"A", b"BC");
        assert_ne!(p1, p2);
    }

    #[test]
    fn user_data_fits_nsm_limit() {
        let ud = user_data_commitment(b"some payload");
        assert!(ud.len() <= 512);
        assert!(ud.starts_with(USER_DATA_PREFIX));
        assert_eq!(ud.len(), USER_DATA_PREFIX.len() + 32);
    }
}
