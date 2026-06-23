//! The PQ root key burn-in **ceremony** — the code that runs *inside* the Nitro
//! Enclave.
//!
//! [`run_ceremony`] performs the one-shot flow from the demo spec:
//!
//! 1. Generate a mnemonic from in-enclave entropy and HD-derive the root keypair
//!    at `m/0'/0'` plus N subkeys across Auth (account 1) and Encryption
//!    (account 2) lanes.
//! 2. Build a Merkle tree over the subkeys and fold the root into the payload.
//! 3. Dual-sign the payload (`canonical_payload_with_subkeys`) with the root key.
//! 4. Request an NSM attestation document whose `user_data` commits to that
//!    payload ([`pq_enclave::attest_bundle_payload`]).
//! 5. Read the enclave's own PCR0/1/2 via NSM `DescribePCR` and record them as
//!    `expected_pcrs` — the enclave measures itself.
//! 6. Record `SHA-256` of the baked-in AWS Nitro root CA.
//!
//! The result is a [`CeremonyState`] holding the public [`PqRootBundle`] plus the
//! private mnemonic (never serialized) so the signing oracle can re-derive subkeys.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use keyfork_mnemonic::Mnemonic;
use pq_bundle::{ExpectedPcrs, PqRootBundle};
use pq_core::{canonical_payload_with_subkeys, DualSignature};
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
///
/// # Panics
/// Panics if the system CSPRNG is unavailable — this is a fatal enclave invariant.
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
