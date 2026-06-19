//! Serialization and verification of PQ root key bundles.
//!
//! A **bundle** (`PqRootBundle`) is a JSON document produced inside a Nitro
//! Enclave that ties two post-quantum public keys (ML-DSA-65 and
//! SLH-DSA-SHAKE-128f) to a specific enclave identity via an NSM attestation
//! quote. The verification routine in this crate enforces the security checks
//! described in Phase 5 of the demo spec, while abstracting the two external
//! I/O operations — NSM quote parsing and OTS timestamp verification — behind
//! traits that the caller injects.
//!
//! ## Security checks performed by [`verify`]
//!
//! 1. **Debug-mode rejection** — PCR0/1/2 must not all be zero.
//! 2. **PCR pinning** — PCR0/1/2 from the quote must equal the values stored in
//!    the bundle's `expected_pcrs`.
//! 3. **Binding** — `quote.user_data` must equal
//!    `USER_DATA_PREFIX || SHA-256(canonical_payload(ml_dsa_pk, slh_dsa_pk))`.
//! 4. **Dual PQ signature** — both ML-DSA and SLH-DSA signatures over
//!    `canonical_payload` must verify.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use pq_core::{canonical_payload, user_data_commitment, verify_dual, DualSignature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Errors produced during bundle verification.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The NSM quote could not be parsed by the injected [`QuoteVerifier`].
    #[error("NSM quote parsing failed: {0}")]
    QuoteParse(String),

    /// All three PCRs are zero — this is a debug-mode quote; reject it.
    #[error("debug-mode quote rejected: PCR0/1/2 are all-zero")]
    DebugMode,

    /// A PCR value from the quote does not match the bundle's `expected_pcrs`.
    #[error("PCR{index} mismatch: expected {expected}, got {actual}")]
    PcrMismatch {
        /// PCR index (0, 1, or 2).
        index: u8,
        /// Expected hex-encoded PCR value (from the bundle).
        expected: String,
        /// Actual hex-encoded PCR value (from the quote).
        actual: String,
    },

    /// The `user_data` field in the quote does not match the expected commitment.
    #[error("quote user_data binding check failed")]
    BindingMismatch,

    /// A hex string in the bundle could not be decoded.
    #[error("hex decoding failed for field '{field}': {source}")]
    HexDecode {
        /// Name of the bundle field that failed to decode.
        field: &'static str,
        /// Underlying decode error.
        #[source]
        source: hex::FromHexError,
    },

    /// A base64 string in the bundle could not be decoded.
    #[error("base64 decoding failed for field '{field}': {source}")]
    Base64Decode {
        /// Name of the bundle field that failed to decode.
        field: &'static str,
        /// Underlying decode error.
        #[source]
        source: base64::DecodeError,
    },

    /// The dual PQ signature (ML-DSA + SLH-DSA) did not verify.
    #[error("PQ signature verification failed: {0}")]
    Signature(#[from] pq_core::Error),

    /// JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Parsed data extracted from an NSM attestation quote by a [`QuoteVerifier`].
#[derive(Debug, Clone)]
pub struct QuoteData {
    /// PCR0 bytes from the quote (typically 48 bytes for SHA-384).
    pub pcr0: Vec<u8>,
    /// PCR1 bytes from the quote.
    pub pcr1: Vec<u8>,
    /// PCR2 bytes from the quote.
    pub pcr2: Vec<u8>,
    /// The `user_data` field from the NSM attestation document.
    pub user_data: Vec<u8>,
}

/// The facts `verify` confirmed, returned on success so callers can render an
/// explicit, itemised report. Every field is a value that *passed* its check.
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// Quote PCR0 — equal to `bundle.expected_pcrs.pcr0` (pinning checked).
    pub pcr0: Vec<u8>,
    /// Quote PCR1 — equal to `bundle.expected_pcrs.pcr1`.
    pub pcr1: Vec<u8>,
    /// Quote PCR2 — equal to `bundle.expected_pcrs.pcr2`.
    pub pcr2: Vec<u8>,
    /// The quote's `user_data` — equal to `user_data_commitment(canonical_payload)`.
    pub user_data: Vec<u8>,
    /// Length of the ML-DSA-65 public key whose signature verified.
    pub ml_dsa_pk_len: usize,
    /// Length of the SLH-DSA-SHAKE-128f public key whose signature verified.
    pub slh_dsa_pk_len: usize,
}

/// Abstracts NSM quote parsing and signature verification.
///
/// Implement this trait to supply a real AWS Nitro quote verifier (which must
/// parse the `COSE_Sign1` CBOR, verify the ES384 signature, and check that the
/// certificate chain roots at the pinned AWS Nitro root CA) or a test double.
pub trait QuoteVerifier {
    /// Parse and verify `quote_bytes`, returning the fields relevant to bundle
    /// verification on success.
    ///
    /// # Errors
    ///
    /// Return an error message describing why verification failed. The message
    /// is forwarded into [`Error::QuoteParse`].
    fn verify_quote(&self, quote_bytes: &[u8]) -> Result<QuoteData, String>;
}

/// Abstracts OTS timestamp verification.
///
/// Implement this trait to supply a real `OpenTimestamps` verifier (which proves
/// `sha256(bundle_json)` is committed to in a Bitcoin block header) or a test
/// double.
pub trait TimestampVerifier {
    /// Verify that `bundle_digest` (SHA-256 of the raw bundle JSON bytes) is
    /// anchored in the OTS proof supplied as `ots_bytes`.
    ///
    /// # Errors
    ///
    /// Return an error message describing why verification failed.
    fn verify_timestamp(&self, bundle_digest: &[u8], ots_bytes: &[u8]) -> Result<(), String>;
}

// ─── Bundle struct ────────────────────────────────────────────────────────────

/// Expected PCR measurements from the reproducible enclave build.
///
/// These are the SHA-384 digests (hex-encoded) of PCR0 (enclave image),
/// PCR1 (Linux kernel + bootstrap), and PCR2 (application), as published
/// alongside the reproducible build.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPcrs {
    /// Expected PCR0 value (hex-encoded SHA-384).
    pub pcr0: String,
    /// Expected PCR1 value (hex-encoded SHA-384).
    pub pcr1: String,
    /// Expected PCR2 value (hex-encoded SHA-384).
    pub pcr2: String,
}

/// A PQ root key bundle — the output of the key ceremony inside a Nitro Enclave.
///
/// All byte-array fields are encoded as strings:
/// - public keys and PCR/hash values: **hex**
/// - `nsm_quote`: **base64** (`COSE_Sign1` CBOR is binary)
/// - signatures: **hex**
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PqRootBundle {
    /// Schema version (currently `"1"`).
    pub version: String,
    /// ML-DSA-65 public key, hex-encoded.
    pub ml_dsa_pk: String,
    /// SLH-DSA-SHAKE-128f public key, hex-encoded.
    pub slh_dsa_pk: String,
    /// NSM attestation document (`COSE_Sign1` CBOR), base64-encoded.
    pub nsm_quote: String,
    /// SHA-256 of the AWS Nitro root CA DER, hex-encoded, archived for
    /// post-Q-Day verification.
    pub aws_root_ca_sha256: String,
    /// PCR0/1/2 values from the reproducible build, for the record.
    pub expected_pcrs: ExpectedPcrs,
    /// ML-DSA-65 signature over `canonical_payload(ml_dsa_pk, slh_dsa_pk)`, hex-encoded.
    pub ml_dsa_sig: String,
    /// SLH-DSA-SHAKE-128f signature over `canonical_payload(ml_dsa_pk, slh_dsa_pk)`, hex-encoded.
    pub slh_dsa_sig: String,
}

impl PqRootBundle {
    /// Serialize the bundle to a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] if serialization fails (practically infallible
    /// for this struct).
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize a bundle from a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Json`] if the input is not valid JSON or does not match
    /// the expected schema.
    pub fn from_json(s: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(s)?)
    }
}

// ─── Verification ─────────────────────────────────────────────────────────────

/// Verify a `PqRootBundle`, performing all security checks from Phase 5 of
/// the demo spec **except** the OTS Bitcoin timestamp (which is optional and
/// passed as a separate `Option`).
///
/// The checks, in order:
/// 1. Decode the NSM quote (base64) and call `quote_verifier.verify_quote`.
/// 2. **Debug-mode rejection**: fail if PCR0, PCR1, and PCR2 are all-zero.
/// 3. **PCR pinning**: quote PCR0/1/2 must match `bundle.expected_pcrs`.
/// 4. **Binding**: `quote.user_data == USER_DATA_PREFIX || SHA-256(canonical_payload)`.
/// 5. **Dual PQ signature**: ML-DSA + SLH-DSA over `canonical_payload`.
///
/// If `ts_verifier` and `ots_bytes` are both `Some`, step 0 additionally
/// verifies the OTS timestamp proof.
///
/// # Errors
///
/// Returns the first [`Error`] encountered.
pub fn verify(
    bundle: &PqRootBundle,
    quote_verifier: &dyn QuoteVerifier,
    ts_verifier: Option<(&dyn TimestampVerifier, &[u8])>,
) -> Result<VerifyReport, Error> {
    // ── Decode fields ────────────────────────────────────────────────────────
    let ml_pk = hex::decode(&bundle.ml_dsa_pk).map_err(|e| Error::HexDecode {
        field: "ml_dsa_pk",
        source: e,
    })?;
    let slh_pk = hex::decode(&bundle.slh_dsa_pk).map_err(|e| Error::HexDecode {
        field: "slh_dsa_pk",
        source: e,
    })?;
    let ml_sig_bytes = hex::decode(&bundle.ml_dsa_sig).map_err(|e| Error::HexDecode {
        field: "ml_dsa_sig",
        source: e,
    })?;
    let slh_sig_bytes = hex::decode(&bundle.slh_dsa_sig).map_err(|e| Error::HexDecode {
        field: "slh_dsa_sig",
        source: e,
    })?;
    let quote_bytes = BASE64.decode(&bundle.nsm_quote).map_err(|e| Error::Base64Decode {
        field: "nsm_quote",
        source: e,
    })?;

    // ── Optional OTS verification ────────────────────────────────────────────
    if let Some((ts, ots_bytes)) = ts_verifier {
        let bundle_json = bundle.to_json()?;
        let digest = Sha256::digest(bundle_json.as_bytes());
        ts.verify_timestamp(&digest, ots_bytes)
            .map_err(Error::QuoteParse)?;
    }

    // ── NSM quote verification ───────────────────────────────────────────────
    let quote_data =
        quote_verifier.verify_quote(&quote_bytes).map_err(Error::QuoteParse)?;

    // ── Step 2: Debug-mode rejection ─────────────────────────────────────────
    let all_zero = |v: &[u8]| v.iter().all(|&b| b == 0);
    if all_zero(&quote_data.pcr0) && all_zero(&quote_data.pcr1) && all_zero(&quote_data.pcr2) {
        return Err(Error::DebugMode);
    }

    // ── Step 3: PCR pinning ──────────────────────────────────────────────────
    let check_pcr = |index: u8, expected_hex: &str, actual: &[u8]| -> Result<(), Error> {
        let expected_bytes = hex::decode(expected_hex).map_err(|e| Error::HexDecode {
            field: "expected_pcrs",
            source: e,
        })?;
        if actual != expected_bytes.as_slice() {
            return Err(Error::PcrMismatch {
                index,
                expected: expected_hex.to_owned(),
                actual: hex::encode(actual),
            });
        }
        Ok(())
    };

    check_pcr(0, &bundle.expected_pcrs.pcr0, &quote_data.pcr0)?;
    check_pcr(1, &bundle.expected_pcrs.pcr1, &quote_data.pcr1)?;
    check_pcr(2, &bundle.expected_pcrs.pcr2, &quote_data.pcr2)?;

    // ── Step 4: Binding check ────────────────────────────────────────────────
    let payload = canonical_payload(&ml_pk, &slh_pk);
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

    Ok(VerifyReport {
        pcr0: quote_data.pcr0,
        pcr1: quote_data.pcr1,
        pcr2: quote_data.pcr2,
        user_data: quote_data.user_data,
        ml_dsa_pk_len: ml_pk.len(),
        slh_dsa_pk_len: slh_pk.len(),
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pq_core::{canonical_payload, user_data_commitment, PqRootKeypair, USER_DATA_PREFIX};

    // ── Helpers ───────────────────────────────────────────────────────────────

    struct MockQuoteVerifier {
        pcr0: Vec<u8>,
        pcr1: Vec<u8>,
        pcr2: Vec<u8>,
        user_data: Vec<u8>,
        fail: bool,
    }

    impl MockQuoteVerifier {
        fn good(pcr0: Vec<u8>, pcr1: Vec<u8>, pcr2: Vec<u8>, user_data: Vec<u8>) -> Self {
            Self { pcr0, pcr1, pcr2, user_data, fail: false }
        }

        fn failing() -> Self {
            Self {
                pcr0: vec![],
                pcr1: vec![],
                pcr2: vec![],
                user_data: vec![],
                fail: true,
            }
        }
    }

    impl QuoteVerifier for MockQuoteVerifier {
        fn verify_quote(&self, _quote_bytes: &[u8]) -> Result<QuoteData, String> {
            if self.fail {
                return Err("mock quote parse error".to_owned());
            }
            Ok(QuoteData {
                pcr0: self.pcr0.clone(),
                pcr1: self.pcr1.clone(),
                pcr2: self.pcr2.clone(),
                user_data: self.user_data.clone(),
            })
        }
    }

    /// Produce a valid PCR value: 48 bytes, non-zero.
    fn sample_pcr(byte: u8) -> Vec<u8> {
        vec![byte; 48]
    }

    /// Build a fully valid bundle from a freshly generated keypair.
    fn make_valid_bundle() -> (PqRootBundle, Vec<u8>, Vec<u8>, Vec<u8>) {
        let kp = PqRootKeypair::generate();
        let ml_pk = kp.ml_dsa_pk();
        let slh_pk = kp.slh_dsa_pk();
        let payload = canonical_payload(&ml_pk, &slh_pk);
        let sig = kp.sign_payload(&payload);

        let pcr0 = sample_pcr(0x11);
        let pcr1 = sample_pcr(0x22);
        let pcr2 = sample_pcr(0x33);

        let bundle = PqRootBundle {
            version: "1".to_owned(),
            ml_dsa_pk: hex::encode(&ml_pk),
            slh_dsa_pk: hex::encode(&slh_pk),
            nsm_quote: BASE64.encode(b"dummy-quote"),
            aws_root_ca_sha256: hex::encode([0u8; 32]),
            expected_pcrs: ExpectedPcrs {
                pcr0: hex::encode(&pcr0),
                pcr1: hex::encode(&pcr1),
                pcr2: hex::encode(&pcr2),
            },
            ml_dsa_sig: hex::encode(&sig.ml_dsa),
            slh_dsa_sig: hex::encode(&sig.slh_dsa),
        };

        (bundle, pcr0, pcr1, pcr2)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn happy_path_passes() {
        let (bundle, pcr0, pcr1, pcr2) = make_valid_bundle();

        let ml_pk = hex::decode(&bundle.ml_dsa_pk).unwrap();
        let slh_pk = hex::decode(&bundle.slh_dsa_pk).unwrap();
        let payload = canonical_payload(&ml_pk, &slh_pk);
        let user_data = user_data_commitment(&payload);

        let verifier = MockQuoteVerifier::good(pcr0, pcr1, pcr2, user_data);
        verify(&bundle, &verifier, None).expect("happy path must pass");
    }

    #[test]
    fn all_zero_pcrs_rejected() {
        let (bundle, _, _, _) = make_valid_bundle();

        // Override user_data to the correct commitment so only the PCR check triggers.
        let ml_pk = hex::decode(&bundle.ml_dsa_pk).unwrap();
        let slh_pk = hex::decode(&bundle.slh_dsa_pk).unwrap();
        let payload = canonical_payload(&ml_pk, &slh_pk);
        let user_data = user_data_commitment(&payload);

        let verifier =
            MockQuoteVerifier::good(vec![0u8; 48], vec![0u8; 48], vec![0u8; 48], user_data);
        let err = verify(&bundle, &verifier, None).unwrap_err();
        assert!(
            matches!(err, Error::DebugMode),
            "expected DebugMode error, got: {err}"
        );
    }

    #[test]
    fn wrong_pcr_rejected() {
        let (bundle, pcr0, pcr1, _pcr2) = make_valid_bundle();

        let ml_pk = hex::decode(&bundle.ml_dsa_pk).unwrap();
        let slh_pk = hex::decode(&bundle.slh_dsa_pk).unwrap();
        let payload = canonical_payload(&ml_pk, &slh_pk);
        let user_data = user_data_commitment(&payload);

        // Provide a wrong PCR2
        let wrong_pcr2 = sample_pcr(0xff);
        let verifier =
            MockQuoteVerifier::good(pcr0, pcr1, wrong_pcr2, user_data);
        let err = verify(&bundle, &verifier, None).unwrap_err();
        assert!(
            matches!(err, Error::PcrMismatch { index: 2, .. }),
            "expected PcrMismatch for PCR2, got: {err}"
        );
    }

    #[test]
    fn tampered_user_data_rejected() {
        let (bundle, pcr0, pcr1, pcr2) = make_valid_bundle();

        // Supply an incorrect user_data (e.g. wrong prefix only).
        let bad_user_data = b"wrong-prefix:xxxxxxxxxxxxxxxxxxxxxxxxxxxx".to_vec();
        let verifier = MockQuoteVerifier::good(pcr0, pcr1, pcr2, bad_user_data);
        let err = verify(&bundle, &verifier, None).unwrap_err();
        assert!(
            matches!(err, Error::BindingMismatch),
            "expected BindingMismatch, got: {err}"
        );
    }

    #[test]
    fn bad_signature_rejected() {
        let (mut bundle, pcr0, pcr1, pcr2) = make_valid_bundle();

        // Corrupt the ML-DSA signature.
        let mut sig_bytes = hex::decode(&bundle.ml_dsa_sig).unwrap();
        sig_bytes[0] ^= 0xff;
        bundle.ml_dsa_sig = hex::encode(&sig_bytes);

        let ml_pk = hex::decode(&bundle.ml_dsa_pk).unwrap();
        let slh_pk = hex::decode(&bundle.slh_dsa_pk).unwrap();
        let payload = canonical_payload(&ml_pk, &slh_pk);
        let user_data = user_data_commitment(&payload);

        let verifier = MockQuoteVerifier::good(pcr0, pcr1, pcr2, user_data);
        let err = verify(&bundle, &verifier, None).unwrap_err();
        assert!(
            matches!(err, Error::Signature(_)),
            "expected Signature error, got: {err}"
        );
    }

    #[test]
    fn json_round_trip() {
        let (bundle, _, _, _) = make_valid_bundle();
        let json = bundle.to_json().expect("serialization must succeed");
        let restored = PqRootBundle::from_json(&json).expect("deserialization must succeed");
        assert_eq!(bundle, restored);
    }

    #[test]
    fn user_data_prefix_is_embedded() {
        // Confirm that user_data_commitment starts with the expected prefix —
        // sanity check that the binding formula matches the enclave-side code.
        let payload = canonical_payload(b"ml-pk", b"slh-pk");
        let ud = user_data_commitment(&payload);
        assert!(ud.starts_with(USER_DATA_PREFIX));
        assert_eq!(ud.len(), USER_DATA_PREFIX.len() + 32);
    }

    #[test]
    fn quote_parse_error_propagates() {
        let (bundle, _, _, _) = make_valid_bundle();
        let verifier = MockQuoteVerifier::failing();
        let err = verify(&bundle, &verifier, None).unwrap_err();
        assert!(
            matches!(err, Error::QuoteParse(_)),
            "expected QuoteParse error, got: {err}"
        );
    }
}
