//! The PQ root key burn-in **ceremony** — the code that runs *inside* the Nitro
//! Enclave.
//!
//! [`run_ceremony`] performs the one-shot flow from the demo spec:
//!
//! 1. Generate an ML-DSA-65 + SLH-DSA-SHAKE-128f keypair ([`pq_core`]).
//! 2. Build the [`canonical_payload`] over both public keys and dual-sign it.
//! 3. Request an NSM attestation document whose `user_data` commits to that
//!    payload ([`pq_enclave::attest_bundle_payload`]).
//! 4. Read the enclave's own PCR0/1/2 via NSM `DescribePCR` and record them as
//!    `expected_pcrs` — the enclave measures itself.
//! 5. Record `SHA-256` of the baked-in AWS Nitro root CA, so the timestamped
//!    bundle stays self-anchoring post-Q-Day.
//!
//! The result is a fully-formed [`PqRootBundle`]. The binary ([`crate`]'s
//! `main`) then serves it over HTTP for the host to fetch and timestamp; the
//! enclave itself never touches the network.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use pq_bundle::{ExpectedPcrs, PqRootBundle};
use pq_core::{canonical_payload, PqRootKeypair};
use pq_enclave::{attest_bundle_payload, Nsm, NsmError};
use sha2::{Digest, Sha256};

/// Errors produced while running the ceremony.
#[derive(Debug, thiserror::Error)]
pub enum CeremonyError {
    /// An NSM operation (attestation or `DescribePCR`) failed.
    #[error("NSM operation failed: {0}")]
    Nsm(#[from] NsmError),
}

/// Run the full in-enclave ceremony and return a complete [`PqRootBundle`].
///
/// `root_ca_der` is the DER-encoded AWS Nitro **root** CA baked into the enclave
/// image; its SHA-256 is archived into the bundle so a future verifier can pin
/// the same anchor (cross-checked by `pq verify`).
///
/// # Errors
///
/// Returns [`CeremonyError::Nsm`] if attestation or PCR readout fails (e.g. the
/// NSM device is unavailable, as it is outside a real enclave).
pub fn run_ceremony(nsm: &impl Nsm, root_ca_der: &[u8]) -> Result<PqRootBundle, CeremonyError> {
    let kp = PqRootKeypair::generate();
    let ml_pk = kp.ml_dsa_pk();
    let slh_pk = kp.slh_dsa_pk();

    let payload = canonical_payload(&ml_pk, &slh_pk);
    let sig = kp.sign_payload(&payload);

    let quote = attest_bundle_payload(nsm, &payload)?;

    let pcr0 = nsm.describe_pcr(0)?;
    let pcr1 = nsm.describe_pcr(1)?;
    let pcr2 = nsm.describe_pcr(2)?;

    let root_sha256 = Sha256::digest(root_ca_der);

    Ok(PqRootBundle {
        version: "1".to_owned(),
        ml_dsa_pk: hex::encode(&ml_pk),
        slh_dsa_pk: hex::encode(&slh_pk),
        nsm_quote: BASE64.encode(&quote),
        aws_root_ca_sha256: hex::encode(root_sha256),
        expected_pcrs: ExpectedPcrs {
            pcr0: hex::encode(pcr0),
            pcr1: hex::encode(pcr1),
            pcr2: hex::encode(pcr2),
        },
        ml_dsa_sig: hex::encode(&sig.ml_dsa),
        slh_dsa_sig: hex::encode(&sig.slh_dsa),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::{user_data_commitment, verify_dual, DualSignature};
    use pq_enclave::MockNsm;

    #[test]
    fn ceremony_produces_consistent_bundle() {
        let root_ca = b"fake-root-ca-der";
        let bundle = run_ceremony(&MockNsm, root_ca).expect("ceremony should succeed with MockNsm");

        // Version + root archival.
        assert_eq!(bundle.version, "1");
        assert_eq!(
            bundle.aws_root_ca_sha256,
            hex::encode(Sha256::digest(root_ca))
        );

        // PCRs are populated and non-zero (debug-mode bundles would be all-zero).
        for pcr in [
            &bundle.expected_pcrs.pcr0,
            &bundle.expected_pcrs.pcr1,
            &bundle.expected_pcrs.pcr2,
        ] {
            let bytes = hex::decode(pcr).expect("pcr hex");
            assert_eq!(bytes.len(), 48, "PCRs are SHA-384-sized");
            assert!(bytes.iter().any(|&b| b != 0), "PCR must not be all-zero");
        }

        // The dual signature verifies over the canonical payload of the two keys.
        let ml_pk = hex::decode(&bundle.ml_dsa_pk).unwrap();
        let slh_pk = hex::decode(&bundle.slh_dsa_pk).unwrap();
        let payload = canonical_payload(&ml_pk, &slh_pk);
        let dual = DualSignature {
            ml_dsa: hex::decode(&bundle.ml_dsa_sig).unwrap(),
            slh_dsa: hex::decode(&bundle.slh_dsa_sig).unwrap(),
        };
        verify_dual(&ml_pk, &slh_pk, &payload, &dual).expect("dual signature must verify");

        // The mock quote embeds the same user_data commitment the verifier recomputes.
        let commitment_hex = hex::encode(user_data_commitment(&payload));
        let quote = BASE64.decode(&bundle.nsm_quote).unwrap();
        let quote_str = std::str::from_utf8(&quote).unwrap();
        assert!(
            quote_str.contains(&commitment_hex),
            "quote must commit to the canonical payload"
        );
    }

    #[test]
    fn distinct_runs_produce_distinct_keys() {
        let a = run_ceremony(&MockNsm, b"r").unwrap();
        let b = run_ceremony(&MockNsm, b"r").unwrap();
        assert_ne!(a.ml_dsa_pk, b.ml_dsa_pk, "each ceremony mints a fresh key");
    }
}
