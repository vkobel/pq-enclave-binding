//! NSM attestation binding for the Keyfork PQ enclave-binding demo.
//!
//! This crate wraps AWS Nitro Secure Module (NSM) attestation behind a
//! [`Nsm`] trait so that callers can work with either the real hardware
//! implementation (feature `nitro`, Linux/Nitro only) or the
//! default [`MockNsm`] that produces a deterministic fake document usable in
//! tests on any platform.
//!
//! The primary entry point for production use is [`attest_bundle_payload`],
//! which computes the `user_data` commitment via
//! [`pq_core::user_data_commitment`] and calls the NSM.

/// Errors returned by NSM operations.
#[derive(Debug, thiserror::Error)]
pub enum NsmError {
    /// The NSM device returned an unexpected response type.
    #[error("unexpected NSM response")]
    UnexpectedResponse,
    /// The NSM device returned an error response.
    #[error("NSM error: {0}")]
    NsmError(String),
}

/// Interface to a Nitro Secure Module (real or mock).
///
/// Implementors must be able to produce a raw attestation document given the
/// three optional NSM fields.
pub trait Nsm {
    /// Request an attestation document from the NSM.
    ///
    /// # Arguments
    ///
    /// * `user_data` – up to 512 bytes of caller-controlled data to embed in the
    ///   attested document.
    /// * `nonce` – optional nonce (replay-protection field).
    /// * `public_key` – optional public key (KMS key-wrapping convention; pass
    ///   `None` for root-key burn-in use cases).
    ///
    /// # Errors
    ///
    /// Returns [`NsmError`] if the NSM device is unavailable or returns an
    /// error response.
    fn attest(
        &self,
        user_data: Vec<u8>,
        nonce: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, NsmError>;

    /// Read the raw value of a single Platform Configuration Register.
    ///
    /// The ceremony uses this to record its *own* PCR0/1/2 into the bundle's
    /// `expected_pcrs` — the enclave measures itself. These values must equal
    /// the PCRs embedded in the attestation document (same enclave), and a
    /// verifier independently re-derives them from the reproducible build.
    ///
    /// # Errors
    ///
    /// Returns [`NsmError`] if the NSM device is unavailable or returns an
    /// error response.
    fn describe_pcr(&self, index: u16) -> Result<Vec<u8>, NsmError>;
}

/// A mock NSM implementation that returns a deterministic fake document.
///
/// Useful in tests and on platforms without real Nitro hardware. The returned
/// "document" is a JSON object containing the three input fields encoded in
/// hex so callers can locate the commitment bytes inside it.
#[derive(Default, Debug, Clone, Copy)]
pub struct MockNsm;

impl Nsm for MockNsm {
    /// Return a fake attestation document containing the inputs as hex-encoded
    /// JSON fields. The document is **not** cryptographically signed and is
    /// only suitable for testing.
    ///
    /// # Errors
    ///
    /// This implementation never fails; the `Err` variant is unreachable.
    fn attest(
        &self,
        user_data: Vec<u8>,
        nonce: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, NsmError> {
        let ud_hex = hex_encode(&user_data);
        let nonce_hex = nonce.as_deref().map(hex_encode).unwrap_or_default();
        let pk_hex = public_key.as_deref().map(hex_encode).unwrap_or_default();

        let doc = format!(
            r#"{{"mock":true,"user_data":"{ud_hex}","nonce":"{nonce_hex}","public_key":"{pk_hex}"}}"#
        );
        Ok(doc.into_bytes())
    }

    /// Return a deterministic, non-zero, 48-byte (SHA-384-sized) fake PCR so
    /// that local/QEMU ceremonies produce a structurally valid bundle. These
    /// are **not** real measurements and will not pass `caution verify`.
    fn describe_pcr(&self, index: u16) -> Result<Vec<u8>, NsmError> {
        let byte = u8::try_from(index % 251).unwrap_or(0).wrapping_add(1);
        Ok(vec![byte; 48])
    }
}

/// Real AWS NSM implementation backed by `aws-nitro-enclaves-nsm-api`.
///
/// Only compiled when the `nitro` feature is enabled. This implementation does
/// **not** build on macOS — it is intentionally gated behind a feature flag.
#[cfg(feature = "nitro")]
pub mod nitro {
    use super::{Nsm, NsmError};
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver as nsm_driver;
    use serde_bytes::ByteBuf;

    /// NSM implementation that talks to the real Nitro hardware device.
    pub struct NitroNsm;

    impl Nsm for NitroNsm {
        /// Send an attestation request to the real AWS NSM device.
        ///
        /// # Errors
        ///
        /// Returns [`NsmError::UnexpectedResponse`] if the NSM returns a
        /// response other than `Attestation`, or [`NsmError::NsmError`] if the
        /// driver itself returns an error variant.
        fn attest(
            &self,
            user_data: Vec<u8>,
            nonce: Option<Vec<u8>>,
            public_key: Option<Vec<u8>>,
        ) -> Result<Vec<u8>, NsmError> {
            let fd = nsm_driver::nsm_init();
            let request = Request::Attestation {
                user_data: Some(ByteBuf::from(user_data)),
                nonce: nonce.map(ByteBuf::from),
                public_key: public_key.map(ByteBuf::from),
            };
            let response = nsm_driver::nsm_process_request(fd, request);
            nsm_driver::nsm_exit(fd);
            match response {
                Response::Attestation { document } => Ok(document),
                Response::Error(e) => Err(NsmError::NsmError(format!("{e:?}"))),
                _ => Err(NsmError::UnexpectedResponse),
            }
        }

        /// Read a PCR via the real NSM `DescribePCR` request.
        ///
        /// # Errors
        ///
        /// Returns [`NsmError::UnexpectedResponse`] for a non-`DescribePCR`
        /// response, or [`NsmError::NsmError`] if the driver returns an error.
        fn describe_pcr(&self, index: u16) -> Result<Vec<u8>, NsmError> {
            let fd = nsm_driver::nsm_init();
            let request = Request::DescribePCR { index };
            let response = nsm_driver::nsm_process_request(fd, request);
            nsm_driver::nsm_exit(fd);
            match response {
                Response::DescribePCR { lock: _, data } => Ok(data),
                Response::Error(e) => Err(NsmError::NsmError(format!("{e:?}"))),
                _ => Err(NsmError::UnexpectedResponse),
            }
        }
    }
}

/// Compute the `user_data` commitment for `payload_bytes` and request an NSM
/// attestation document.
///
/// The commitment is `USER_DATA_PREFIX || SHA-256(payload_bytes)` (46 bytes
/// total), well within NSM's 512-byte `user_data` limit.
///
/// # Errors
///
/// Propagates any [`NsmError`] returned by `nsm.attest`.
pub fn attest_bundle_payload(nsm: &impl Nsm, payload_bytes: &[u8]) -> Result<Vec<u8>, NsmError> {
    let user_data = pq_core::user_data_commitment(payload_bytes);
    nsm.attest(user_data, None, None)
}

/// Encode bytes as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::USER_DATA_PREFIX;

    /// `MockNsm` returns a document that contains the hex-encoded commitment,
    /// and the commitment itself starts with `USER_DATA_PREFIX`.
    #[test]
    fn mock_nsm_contains_user_data_commitment() {
        let nsm = MockNsm;
        let payload = b"test bundle payload";
        let doc = attest_bundle_payload(&nsm, payload).expect("mock attest should succeed");

        // The commitment bytes embedded in the document must contain the prefix.
        let commitment = pq_core::user_data_commitment(payload);
        assert!(
            commitment.starts_with(USER_DATA_PREFIX),
            "commitment must start with USER_DATA_PREFIX"
        );

        // The document (JSON) must contain the commitment, hex-encoded.
        let doc_str = std::str::from_utf8(&doc).expect("doc is valid UTF-8");
        let commitment_hex = hex_encode(&commitment);
        assert!(
            doc_str.contains(&commitment_hex),
            "document should contain the hex-encoded commitment; doc={doc_str}"
        );
    }

    /// The commitment is exactly `USER_DATA_PREFIX.len() + 32` bytes.
    #[test]
    fn commitment_length() {
        let commitment = pq_core::user_data_commitment(b"anything");
        assert_eq!(commitment.len(), USER_DATA_PREFIX.len() + 32);
        assert!(commitment.len() <= 512, "must fit in NSM user_data field");
    }

    /// `MockNsm` passes through `None` `nonce`/`public_key` without error.
    #[test]
    fn mock_nsm_direct_attest() {
        let nsm = MockNsm;
        let doc = nsm.attest(b"hello".to_vec(), None, None).expect("should succeed");
        let doc_str = std::str::from_utf8(&doc).expect("valid UTF-8");
        assert!(doc_str.contains("mock\":true"));
        assert!(doc_str.contains(&hex_encode(b"hello")));
    }
}
