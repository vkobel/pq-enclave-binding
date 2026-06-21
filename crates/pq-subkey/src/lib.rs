//! Root-certified post-quantum subkey delegation ("Approach A").
//!
//! The two PQ root keys (ML-DSA-65 + SLH-DSA-SHAKE-128f) established by the
//! one-time, OTS-anchored enclave ceremony act as a quantum-durable trust
//! anchor. This crate lets the root **certify** an arbitrary number of subkeys
//! by dual-PQ-signing a small [`SubkeyCert`] that binds a subkey to *that
//! specific root*.
//!
//! ## Why this is post-Q-Day safe
//!
//! A subkey cert is signed with ML-DSA **and** SLH-DSA — independent hardness
//! assumptions, neither broken by quantum. Forging a subkey therefore requires
//! breaking both signatures or stealing the root secret; quantum does neither.
//! The one-time OTS stamp already carried the (quantum-breakable) AWS quote
//! across Q-Day, so no further timestamping is needed: a cert issued *after*
//! Q-Day is still unforgeable. The residual risk is purely operational —
//! protecting the root secret — not cryptographic.
//!
//! A post-Q-Day cert proves *"authorized by the genuine attested root"*, not
//! *"this subkey predates Q-Day"*. (The latter needs a Merkle pre-commitment,
//! a separate, later phase.)
//!
//! ## Trust chain
//!
//! `OTS (once) → root bundle/attestation → SubkeyCert → subkey`. This crate
//! covers the last link: given root public keys already validated via
//! `pq-bundle`, [`verify`] confirms the cert was issued by that root.

use pq_core::{canonical_payload, verify_dual, DualSignature, PqRootKeypair};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema version for [`SubkeyCert`].
pub const CERT_VERSION: &str = "1";

/// Domain-separation prefix for the bytes the root signs.
const SIGNING_DOMAIN: &[u8] = b"pq-subkey-cert-v1";

/// Errors produced while issuing or verifying a [`SubkeyCert`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A hex field in the cert could not be decoded.
    #[error("hex decoding failed for field '{field}': {source}")]
    HexDecode {
        /// Name of the field that failed to decode.
        field: &'static str,
        /// Underlying decode error.
        #[source]
        source: hex::FromHexError,
    },

    /// The cert's `root_binding` does not match the provided root public keys —
    /// the cert was issued for a *different* root.
    #[error("root binding mismatch: cert is not bound to the provided root keys")]
    RootBindingMismatch,

    /// The root's dual signature over the cert failed verification.
    #[error("subkey certificate signature verification failed: {0}")]
    Signature(#[from] pq_core::Error),

    /// The cert is not yet valid at the supplied `as_of` time.
    #[error("certificate not yet valid: not_before {not_before} > as_of {as_of}")]
    NotYetValid {
        /// The cert's `not_before` (unix seconds).
        not_before: u64,
        /// The verification time (unix seconds).
        as_of: u64,
    },

    /// The cert has expired at the supplied `as_of` time.
    #[error("certificate expired: not_after {not_after} <= as_of {as_of}")]
    Expired {
        /// The cert's `not_after` (unix seconds).
        not_after: u64,
        /// The verification time (unix seconds).
        as_of: u64,
    },

    /// JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// The intended use of a subkey. Carried as metadata; it does not change the
/// (dual-PQ-signature) trust mechanism.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubkeyPurpose {
    /// Authentication / signing subkey.
    Auth,
    /// Encryption / key-agreement subkey (e.g. a future ML-KEM key).
    Encryption,
}

impl SubkeyPurpose {
    /// One-byte tag used in the canonical signing bytes.
    const fn tag(self) -> u8 {
        match self {
            Self::Auth => 1,
            Self::Encryption => 2,
        }
    }
}

/// Metadata supplied when issuing a subkey certificate.
#[derive(Debug, Clone, Copy)]
pub struct SubkeyMeta {
    /// Monotonic serial number, unique per root (for revocation / audit).
    pub serial: u64,
    /// Intended use of the subkey.
    pub purpose: SubkeyPurpose,
    /// Validity start (unix seconds); `0` means no lower bound.
    pub not_before: u64,
    /// Validity end (unix seconds); `0` means no expiry.
    pub not_after: u64,
}

/// The validated public keys returned by [`verify`].
#[derive(Debug, Clone)]
pub struct SubkeyPublicKeys {
    /// The subkey's ML-DSA-65 public key.
    pub ml_dsa_pk: Vec<u8>,
    /// The subkey's SLH-DSA-SHAKE-128f public key.
    pub slh_dsa_pk: Vec<u8>,
    /// The subkey's declared purpose.
    pub purpose: SubkeyPurpose,
    /// The subkey's serial number.
    pub serial: u64,
}

/// A root-issued certificate delegating trust to a subkey.
///
/// All byte fields are hex-encoded. The root's dual signature covers every
/// other field via [`SubkeyCert::signing_bytes`].
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SubkeyCert {
    /// Schema version (currently [`CERT_VERSION`]).
    pub version: String,
    /// `SHA-256(canonical_payload(root_ml_dsa_pk, root_slh_dsa_pk))`, hex.
    /// Binds this cert to one specific attested root.
    pub root_binding: String,
    /// Subkey ML-DSA-65 public key, hex.
    pub ml_dsa_pk: String,
    /// Subkey SLH-DSA-SHAKE-128f public key, hex.
    pub slh_dsa_pk: String,
    /// Serial number.
    pub serial: u64,
    /// Subkey purpose.
    pub purpose: SubkeyPurpose,
    /// Validity start (unix seconds); `0` = no lower bound.
    pub not_before: u64,
    /// Validity end (unix seconds); `0` = no expiry.
    pub not_after: u64,
    /// Root's ML-DSA-65 signature over [`SubkeyCert::signing_bytes`], hex.
    pub ml_dsa_sig: String,
    /// Root's SLH-DSA-SHAKE-128f signature over [`SubkeyCert::signing_bytes`], hex.
    pub slh_dsa_sig: String,
}

/// Compute the binding digest that ties a cert to a specific root keypair:
/// `SHA-256(canonical_payload(root_ml_dsa_pk, root_slh_dsa_pk))`.
#[must_use]
pub fn root_binding(root_ml_dsa_pk: &[u8], root_slh_dsa_pk: &[u8]) -> [u8; 32] {
    let payload = canonical_payload(root_ml_dsa_pk, root_slh_dsa_pk);
    Sha256::digest(&payload).into()
}

impl SubkeyCert {
    /// The exact, deterministic bytes the root signs. Length-prefixes every
    /// variable field and fixes the width of scalars, under a domain prefix, so
    /// no two distinct certs can share a signing message.
    #[must_use]
    pub fn signing_bytes(
        root_binding: &[u8; 32],
        ml_dsa_pk: &[u8],
        slh_dsa_pk: &[u8],
        meta: &SubkeyMeta,
    ) -> Vec<u8> {
        fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
            let len = u32::try_from(bytes.len()).expect("field len fits u32");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(bytes);
        }

        let mut v = Vec::new();
        lp(&mut v, SIGNING_DOMAIN);
        lp(&mut v, CERT_VERSION.as_bytes());
        lp(&mut v, root_binding);
        lp(&mut v, ml_dsa_pk);
        lp(&mut v, slh_dsa_pk);
        v.extend_from_slice(&meta.serial.to_be_bytes());
        v.push(meta.purpose.tag());
        v.extend_from_slice(&meta.not_before.to_be_bytes());
        v.extend_from_slice(&meta.not_after.to_be_bytes());
        v
    }

    /// Serialize to pretty JSON.
    ///
    /// # Errors
    /// Returns [`Error::Json`] if serialization fails.
    pub fn to_json(&self) -> Result<String, Error> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Deserialize from JSON.
    ///
    /// # Errors
    /// Returns [`Error::Json`] if the input is not a valid cert.
    pub fn from_json(s: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(s)?)
    }
}

/// Issue a subkey certificate: the `root` dual-PQ-signs a binding from itself to
/// the given subkey public keys.
///
/// The caller holds the root secret (e.g. reconstructed inside an enclave). This
/// is the only operation that needs the root secret; verification never does.
#[must_use]
pub fn issue(
    root: &PqRootKeypair,
    subkey_ml_dsa_pk: &[u8],
    subkey_slh_dsa_pk: &[u8],
    meta: &SubkeyMeta,
) -> SubkeyCert {
    let binding = root_binding(&root.ml_dsa_pk(), &root.slh_dsa_pk());
    let msg = SubkeyCert::signing_bytes(&binding, subkey_ml_dsa_pk, subkey_slh_dsa_pk, meta);
    let sig = root.sign_payload(&msg);
    SubkeyCert {
        version: CERT_VERSION.to_owned(),
        root_binding: hex::encode(binding),
        ml_dsa_pk: hex::encode(subkey_ml_dsa_pk),
        slh_dsa_pk: hex::encode(subkey_slh_dsa_pk),
        serial: meta.serial,
        purpose: meta.purpose,
        not_before: meta.not_before,
        not_after: meta.not_after,
        ml_dsa_sig: hex::encode(sig.ml_dsa),
        slh_dsa_sig: hex::encode(sig.slh_dsa),
    }
}

/// Verify a subkey certificate against the root public keys (which the caller
/// must have already validated via `pq-bundle`).
///
/// Checks, in order: (1) `root_binding` matches the provided root keys, (2) the
/// root's dual signature over the canonical bytes, (3) the validity window at
/// `as_of` (unix seconds) when supplied.
///
/// # Errors
/// Returns the first [`Error`] encountered.
pub fn verify(
    cert: &SubkeyCert,
    root_ml_dsa_pk: &[u8],
    root_slh_dsa_pk: &[u8],
    as_of: Option<u64>,
) -> Result<SubkeyPublicKeys, Error> {
    let sub_ml = hex::decode(&cert.ml_dsa_pk).map_err(|e| Error::HexDecode {
        field: "ml_dsa_pk",
        source: e,
    })?;
    let sub_slh = hex::decode(&cert.slh_dsa_pk).map_err(|e| Error::HexDecode {
        field: "slh_dsa_pk",
        source: e,
    })?;
    let cert_binding = hex::decode(&cert.root_binding).map_err(|e| Error::HexDecode {
        field: "root_binding",
        source: e,
    })?;
    let ml_sig = hex::decode(&cert.ml_dsa_sig).map_err(|e| Error::HexDecode {
        field: "ml_dsa_sig",
        source: e,
    })?;
    let slh_sig = hex::decode(&cert.slh_dsa_sig).map_err(|e| Error::HexDecode {
        field: "slh_dsa_sig",
        source: e,
    })?;

    // (1) Binding: the cert must be bound to *these* root keys.
    let expected = root_binding(root_ml_dsa_pk, root_slh_dsa_pk);
    if cert_binding != expected {
        return Err(Error::RootBindingMismatch);
    }

    let meta = SubkeyMeta {
        serial: cert.serial,
        purpose: cert.purpose,
        not_before: cert.not_before,
        not_after: cert.not_after,
    };

    // (2) Signature: the root must have signed exactly this cert.
    let msg = SubkeyCert::signing_bytes(&expected, &sub_ml, &sub_slh, &meta);
    let dual = DualSignature {
        ml_dsa: ml_sig,
        slh_dsa: slh_sig,
    };
    verify_dual(root_ml_dsa_pk, root_slh_dsa_pk, &msg, &dual)?;

    // (3) Validity window (only when a verification time is supplied).
    if let Some(now) = as_of {
        if cert.not_before != 0 && now < cert.not_before {
            return Err(Error::NotYetValid {
                not_before: cert.not_before,
                as_of: now,
            });
        }
        if cert.not_after != 0 && now >= cert.not_after {
            return Err(Error::Expired {
                not_after: cert.not_after,
                as_of: now,
            });
        }
    }

    Ok(SubkeyPublicKeys {
        ml_dsa_pk: sub_ml,
        slh_dsa_pk: sub_slh,
        purpose: cert.purpose,
        serial: cert.serial,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> SubkeyMeta {
        SubkeyMeta {
            serial: 7,
            purpose: SubkeyPurpose::Auth,
            not_before: 0,
            not_after: 0,
        }
    }

    fn issue_for(root: &PqRootKeypair, sub: &PqRootKeypair, m: &SubkeyMeta) -> SubkeyCert {
        issue(root, &sub.ml_dsa_pk(), &sub.slh_dsa_pk(), m)
    }

    #[test]
    fn issue_then_verify_passes() {
        let root = PqRootKeypair::generate();
        let sub = PqRootKeypair::generate();
        let cert = issue_for(&root, &sub, &meta());
        let out = verify(&cert, &root.ml_dsa_pk(), &root.slh_dsa_pk(), None)
            .expect("valid cert must verify");
        assert_eq!(out.ml_dsa_pk, sub.ml_dsa_pk());
        assert_eq!(out.slh_dsa_pk, sub.slh_dsa_pk());
        assert_eq!(out.serial, 7);
    }

    #[test]
    fn wrong_root_keys_rejected_as_binding_mismatch() {
        let root = PqRootKeypair::generate();
        let other = PqRootKeypair::generate();
        let sub = PqRootKeypair::generate();
        let cert = issue_for(&root, &sub, &meta());
        let err = verify(&cert, &other.ml_dsa_pk(), &other.slh_dsa_pk(), None).unwrap_err();
        assert!(matches!(err, Error::RootBindingMismatch), "got: {err}");
    }

    #[test]
    fn forged_binding_with_attacker_signature_fails_signature() {
        // Attacker copies the real root_binding but signs with their own key.
        let root = PqRootKeypair::generate();
        let attacker = PqRootKeypair::generate();
        let sub = PqRootKeypair::generate();
        let mut cert = issue_for(&attacker, &sub, &meta());
        cert.root_binding = hex::encode(root_binding(&root.ml_dsa_pk(), &root.slh_dsa_pk()));
        let err = verify(&cert, &root.ml_dsa_pk(), &root.slh_dsa_pk(), None).unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "got: {err}");
    }

    #[test]
    fn tampered_subkey_rejected() {
        let root = PqRootKeypair::generate();
        let sub = PqRootKeypair::generate();
        let mut cert = issue_for(&root, &sub, &meta());
        let mut pk = hex::decode(&cert.ml_dsa_pk).unwrap();
        pk[0] ^= 0xff;
        cert.ml_dsa_pk = hex::encode(&pk);
        let err = verify(&cert, &root.ml_dsa_pk(), &root.slh_dsa_pk(), None).unwrap_err();
        // Length is unchanged, so the key decodes but the root's signature no
        // longer matches the tampered canonical bytes.
        assert!(matches!(err, Error::Signature(_)), "got: {err}");
    }

    #[test]
    fn not_yet_valid_and_expired() {
        let root = PqRootKeypair::generate();
        let sub = PqRootKeypair::generate();
        let m = SubkeyMeta {
            serial: 1,
            purpose: SubkeyPurpose::Encryption,
            not_before: 1000,
            not_after: 2000,
        };
        let cert = issue_for(&root, &sub, &m);
        let (ml, slh) = (root.ml_dsa_pk(), root.slh_dsa_pk());

        assert!(matches!(
            verify(&cert, &ml, &slh, Some(500)).unwrap_err(),
            Error::NotYetValid { .. }
        ));
        assert!(verify(&cert, &ml, &slh, Some(1500)).is_ok());
        assert!(matches!(
            verify(&cert, &ml, &slh, Some(2000)).unwrap_err(),
            Error::Expired { .. }
        ));
    }

    #[test]
    fn json_round_trip() {
        let root = PqRootKeypair::generate();
        let sub = PqRootKeypair::generate();
        let cert = issue_for(&root, &sub, &meta());
        let restored = SubkeyCert::from_json(&cert.to_json().unwrap()).unwrap();
        assert_eq!(cert, restored);
    }
}
