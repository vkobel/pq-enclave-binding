//! AWS Nitro NSM attestation verification for the PQ enclave-binding demo.
//!
//! [`NitroQuoteVerifier`] implements [`pq_bundle::QuoteVerifier`]: it parses an
//! NSM attestation document (a `COSE_Sign1` CBOR object), verifies the ES384
//! signature and the certificate chain against a **pinned root CA**, and extracts
//! PCR0/1/2 and `user_data`. The PCR pinning, debug-mode rejection, and key
//! binding checks are then performed by [`pq_bundle::verify`].
//!
//! ## Why verification time matters
//!
//! A Nitro leaf certificate is short-lived (hours). Verifying an *archived*
//! bundle years later with the current clock would fail on certificate expiry —
//! and would also be meaningless once AWS's ECDSA is quantum-broken. So the
//! verifier checks the chain **as of a caller-supplied instant**. In the demo
//! that instant is the **OTS Bitcoin anchor time**: the timestamp proof shows the
//! bundle existed at block time `T`, and we verify the Nitro chain as of `T`,
//! when the cert was valid and ECDSA was still sound. This is exactly how the
//! quantum-safe timestamp extends the trust of the quantum-breakable quote.

use nsm_nitro_enclave_utils::api::nsm::AttestationDoc;
use nsm_nitro_enclave_utils::time::Time;
use nsm_nitro_enclave_utils::verify::AttestationDocVerifierExt;
use pq_bundle::{QuoteData, QuoteVerifier};
use sha2::{Digest, Sha256};
// Transitive of nsm-nitro-enclave-utils; referenced to keep it an explicit,
// auditable part of the dependency set. Not used directly.
use x509_cert as _;

/// Verifies AWS Nitro NSM attestation documents against a pinned root CA, as of
/// a fixed verification instant.
pub struct NitroQuoteVerifier {
    root_cert_der: Vec<u8>,
    verify_at_ms: u64,
}

impl NitroQuoteVerifier {
    /// Create a verifier pinned to `root_cert_der` (DER-encoded root CA),
    /// checking certificate validity as of `verify_at_unix_ms` (milliseconds
    /// since the Unix epoch).
    ///
    /// For the AWS root, download the DER from AWS's "verify root" documentation.
    #[must_use]
    pub fn new(root_cert_der: Vec<u8>, verify_at_unix_ms: u64) -> Self {
        Self {
            root_cert_der,
            verify_at_ms: verify_at_unix_ms,
        }
    }

    /// Same as [`Self::new`] but takes seconds (e.g. an OTS Bitcoin block time).
    #[must_use]
    pub fn at_unix_secs(root_cert_der: Vec<u8>, verify_at_unix_secs: u64) -> Self {
        Self::new(root_cert_der, verify_at_unix_secs.saturating_mul(1000))
    }

    /// The SHA-256 of the pinned root CA (hex). Cross-check this against a
    /// bundle's `aws_root_ca_sha256` to confirm the expected root was used.
    #[must_use]
    pub fn root_sha256_hex(&self) -> String {
        hex::encode(Sha256::digest(&self.root_cert_der))
    }
}

impl QuoteVerifier for NitroQuoteVerifier {
    fn verify_quote(&self, quote_bytes: &[u8]) -> Result<QuoteData, String> {
        let at = self.verify_at_ms;
        let time = Time::new(Box::new(move || at));

        let doc = AttestationDoc::from_cose(quote_bytes, &self.root_cert_der, time)
            .map_err(|e| format!("nitro attestation verification failed: {e:?}"))?;

        extract_quote_data(&doc)
    }
}

/// Pull PCR0/1/2 and `user_data` out of a (already verified) attestation
/// document into the shape [`pq_bundle::verify`] expects.
///
/// # Errors
/// Returns an error string if PCR0, PCR1, or PCR2 is absent.
pub fn extract_quote_data(doc: &AttestationDoc) -> Result<QuoteData, String> {
    let pcr = |i: usize| -> Result<Vec<u8>, String> {
        doc.pcrs
            .get(&i)
            .map(|b| b.to_vec())
            .ok_or_else(|| format!("attestation document is missing PCR{i}"))
    };

    Ok(QuoteData {
        pcr0: pcr(0)?,
        pcr1: pcr(1)?,
        pcr2: pcr(2)?,
        user_data: doc
            .user_data
            .as_ref()
            .map(|b| b.to_vec())
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nsm_nitro_enclave_utils::api::nsm::Digest;
    use sha2::Digest as _;
    use serde_bytes::ByteBuf;
    use std::collections::BTreeMap;

    fn doc_with(pcrs: BTreeMap<usize, ByteBuf>, user_data: Option<Vec<u8>>) -> AttestationDoc {
        AttestationDoc {
            module_id: "test-module".to_string(),
            digest: Digest::SHA384,
            timestamp: 1_700_000_000_000,
            pcrs,
            certificate: ByteBuf::new(),
            cabundle: vec![],
            public_key: None,
            user_data: user_data.map(ByteBuf::from),
            nonce: None,
        }
    }

    #[test]
    fn extracts_pcrs_and_user_data() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, ByteBuf::from(vec![0xa0; 48]));
        pcrs.insert(1, ByteBuf::from(vec![0xa1; 48]));
        pcrs.insert(2, ByteBuf::from(vec![0xa2; 48]));
        let doc = doc_with(pcrs, Some(b"pq-keyfork-v1:xyz".to_vec()));

        let qd = extract_quote_data(&doc).expect("extract");
        assert_eq!(qd.pcr0, vec![0xa0; 48]);
        assert_eq!(qd.pcr1, vec![0xa1; 48]);
        assert_eq!(qd.pcr2, vec![0xa2; 48]);
        assert_eq!(qd.user_data, b"pq-keyfork-v1:xyz");
    }

    #[test]
    fn missing_pcr_is_an_error() {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0, ByteBuf::from(vec![0xa0; 48]));
        pcrs.insert(1, ByteBuf::from(vec![0xa1; 48]));
        // PCR2 absent
        let doc = doc_with(pcrs, None);
        assert!(extract_quote_data(&doc).is_err());
    }

    #[test]
    fn absent_user_data_is_empty() {
        let mut pcrs = BTreeMap::new();
        for i in 0..3 {
            pcrs.insert(i, ByteBuf::from(vec![0u8; 48]));
        }
        let doc = doc_with(pcrs, None);
        assert!(extract_quote_data(&doc).unwrap().user_data.is_empty());
    }

    #[test]
    fn rejects_garbage_cose_bytes() {
        let v = NitroQuoteVerifier::new(vec![0u8; 64], 1_700_000_000_000);
        assert!(v.verify_quote(b"not a cose document").is_err());
    }

    #[test]
    fn root_hash_is_stable() {
        let v = NitroQuoteVerifier::new(b"fake-root-der".to_vec(), 0);
        assert_eq!(
            v.root_sha256_hex(),
            hex::encode(Sha256::digest(b"fake-root-der"))
        );
    }
}
