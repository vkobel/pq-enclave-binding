//! `OpenTimestamps` (OTS) integration for the PQ enclave-binding demo.
//!
//! OTS commits a SHA-256 digest into a Bitcoin `OP_RETURN` via calendar servers.
//! Verification needs only Bitcoin block headers and SHA-256 — no signatures, no
//! certificate authority — so it is a **post-quantum-safe temporal anchor**:
//! Shor gives no advantage against SHA-256 / Bitcoin Proof-of-Work. This is what
//! extends the trust of the (quantum-breakable, ECDSA-signed) AWS Nitro quote
//! past Q-Day: prove the bundle existed *before* a given block, and the quote
//! could not have been forged at the time it was made.
//!
//! This crate is split into two halves:
//!
//! * **Verification** ([`verify`]) — pure, offline, fully tested. Parses a
//!   `.ots` proof, checks it commits to the expected digest, walks the operation
//!   tree, and for every Bitcoin attestation checks the committed Merkle root
//!   against a caller-supplied [`BitcoinHeaderSource`].
//! * **Stamping** ([`stamp`]) — submits a digest to a [`CalendarClient`] and
//!   assembles a `.ots` proof. Real HTTP clients live behind the
//!   `calendar-http` feature; tests inject mocks.
//!
//! The enclave never does any of this — timestamping happens on the host, which
//! is why it lives outside the attested boundary.

use std::io::Cursor;

use opentimestamps::attestation::Attestation;
use opentimestamps::ser::DigestType;
use opentimestamps::timestamp::{Step, StepData, Timestamp};
use opentimestamps::DetachedTimestampFile;

#[cfg(feature = "calendar-http")]
mod http;
#[cfg(feature = "calendar-http")]
pub use http::{EsploraHeaderSource, HttpCalendar};

/// Errors produced while stamping or verifying an OTS proof.
#[derive(Debug, thiserror::Error)]
pub enum OtsError {
    /// The `.ots` proof could not be parsed or serialized.
    #[error("opentimestamps codec error: {0}")]
    Codec(String),
    /// The proof commits to a different digest than the one supplied.
    #[error("proof digest mismatch: proof commits to {proof}, expected {expected}")]
    DigestMismatch {
        /// Digest the proof actually commits to (hex).
        proof: String,
        /// Digest the caller expected (hex).
        expected: String,
    },
    /// A Bitcoin attestation's committed Merkle root did not match the block
    /// header at that height. This is a hard failure — the proof is invalid.
    #[error("bitcoin attestation at height {height}: committed merkle root {committed} != block merkle root {actual}")]
    MerkleRootMismatch {
        /// Block height of the failing attestation.
        height: usize,
        /// Merkle root the proof claims (hex).
        committed: String,
        /// Merkle root reported by the header source (hex).
        actual: String,
    },
    /// The proof contains no Bitcoin attestation (still pending in calendars).
    #[error("proof is not anchored in Bitcoin yet (only pending attestations); upgrade it first")]
    NotAnchored,
    /// The Bitcoin header source failed to return a block.
    #[error("bitcoin header source error: {0}")]
    HeaderSource(String),
    /// A calendar submission failed.
    #[error("calendar error: {0}")]
    Calendar(String),
}

impl From<opentimestamps::error::Error> for OtsError {
    fn from(e: opentimestamps::error::Error) -> Self {
        OtsError::Codec(e.to_string())
    }
}

/// Supplies the Merkle root committed in a Bitcoin block header at a given
/// height. Inject a real implementation (a full node or a block explorer) for
/// production verification; inject a mock for tests.
///
/// The returned 32 bytes MUST be in the **internal** byte order used inside the
/// serialized block header (i.e. *not* the big-endian form shown by explorers
/// and block hashes; reverse explorer hex before returning it). OTS commits the
/// Merkle root in this internal order.
pub trait BitcoinHeaderSource {
    /// Return the Merkle root of the block at `height`, in internal byte order.
    ///
    /// # Errors
    /// Returns an error string if the height is unknown or the lookup failed.
    fn merkle_root(&self, height: usize) -> Result<[u8; 32], String>;
}

/// Submits a digest to an OTS calendar and returns the calendar's serialized
/// timestamp response (the bytes that would follow the digest in a `.ots` file).
pub trait CalendarClient {
    /// Submit `digest` (typically `SHA-256(file)`) to the calendar.
    ///
    /// # Errors
    /// Returns an error string if the submission failed.
    fn submit(&self, digest: &[u8]) -> Result<Vec<u8>, String>;
}

/// A Bitcoin attestation that was successfully matched against a block header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitcoinAnchor {
    /// Block height the bundle digest is anchored in.
    pub height: usize,
    /// The committed Merkle root (internal byte order), verified against the header.
    pub merkle_root: [u8; 32],
}

/// A pending (not-yet-anchored) attestation: the calendar URL to upgrade against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAttestation {
    /// Calendar URI to query for an upgraded (Bitcoin-anchored) proof.
    pub uri: String,
}

/// Parse a `.ots` proof from bytes.
///
/// # Errors
/// Returns [`OtsError::Codec`] if the bytes are not a valid `.ots` proof.
pub fn parse_proof(ots_bytes: &[u8]) -> Result<DetachedTimestampFile, OtsError> {
    Ok(DetachedTimestampFile::from_reader(Cursor::new(ots_bytes))?)
}

/// Walk a step tree, collecting Bitcoin and pending attestations.
fn collect_attestations(
    step: &Step,
    bitcoin: &mut Vec<(usize, Vec<u8>)>,
    pending: &mut Vec<String>,
) {
    match &step.data {
        StepData::Attestation(Attestation::Bitcoin { height }) => {
            // For an attestation step the output equals its input: the value
            // committed by the attestation (here, the block's Merkle root).
            bitcoin.push((*height, step.output.clone()));
        }
        StepData::Attestation(Attestation::Pending { uri }) => pending.push(uri.clone()),
        StepData::Attestation(Attestation::Unknown { .. }) | StepData::Op(_) | StepData::Fork => {}
    }
    for next in &step.next {
        collect_attestations(next, bitcoin, pending);
    }
}

/// List the pending calendar URIs in a proof (for upgrading).
///
/// # Errors
/// Returns [`OtsError::Codec`] if the proof cannot be parsed.
pub fn pending_calendars(ots_bytes: &[u8]) -> Result<Vec<PendingAttestation>, OtsError> {
    let dtf = parse_proof(ots_bytes)?;
    let mut bitcoin = Vec::new();
    let mut pending = Vec::new();
    collect_attestations(&dtf.timestamp.first_step, &mut bitcoin, &mut pending);
    Ok(pending
        .into_iter()
        .map(|uri| PendingAttestation { uri })
        .collect())
}

/// Verify a `.ots` proof commits `expected_digest` to Bitcoin.
///
/// Checks that the proof commits to `expected_digest`, then for every Bitcoin
/// attestation confirms the committed Merkle root matches the block header from
/// `source`. Returns every verified anchor (earliest block = strongest claim).
///
/// # Errors
/// - [`OtsError::DigestMismatch`] if the proof commits to a different digest.
/// - [`OtsError::MerkleRootMismatch`] if a Bitcoin attestation does not match
///   its block header (the proof is forged or corrupt).
/// - [`OtsError::NotAnchored`] if there is no Bitcoin attestation yet.
/// - [`OtsError::HeaderSource`] if a block header lookup fails.
pub fn verify(
    ots_bytes: &[u8],
    expected_digest: &[u8],
    source: &impl BitcoinHeaderSource,
) -> Result<Vec<BitcoinAnchor>, OtsError> {
    let dtf = parse_proof(ots_bytes)?;

    if dtf.timestamp.start_digest != expected_digest {
        return Err(OtsError::DigestMismatch {
            proof: hex::encode(&dtf.timestamp.start_digest),
            expected: hex::encode(expected_digest),
        });
    }

    let mut bitcoin = Vec::new();
    let mut pending = Vec::new();
    collect_attestations(&dtf.timestamp.first_step, &mut bitcoin, &mut pending);

    if bitcoin.is_empty() {
        return Err(OtsError::NotAnchored);
    }

    let mut anchors = Vec::with_capacity(bitcoin.len());
    for (height, committed) in bitcoin {
        let actual = source.merkle_root(height).map_err(OtsError::HeaderSource)?;
        if committed.as_slice() != actual.as_slice() {
            return Err(OtsError::MerkleRootMismatch {
                height,
                committed: hex::encode(&committed),
                actual: hex::encode(actual),
            });
        }
        anchors.push(BitcoinAnchor {
            height,
            merkle_root: actual,
        });
    }
    Ok(anchors)
}

/// Submit `digest` to `client` and assemble a `.ots` proof.
///
/// The resulting proof will normally contain a *pending* attestation; call the
/// calendar's upgrade endpoint after the digest is anchored (~a few hours) to
/// obtain the Bitcoin attestation. `digest` must be exactly 32 bytes
/// (`SHA-256(file)`).
///
/// Note: this submits the raw file digest (no privacy nonce). The bundle is a
/// public artifact, so the standard OTS privacy step is intentionally skipped;
/// this keeps `start_digest == SHA-256(file)` so verification is direct.
///
/// # Errors
/// - [`OtsError::Calendar`] if submission fails.
/// - [`OtsError::Codec`] if the response or assembled proof cannot be (de)serialized.
pub fn stamp(digest: &[u8; 32], client: &impl CalendarClient) -> Result<Vec<u8>, OtsError> {
    let response = client.submit(digest).map_err(OtsError::Calendar)?;
    let mut deser = opentimestamps::ser::Deserializer::new(Cursor::new(response));
    let timestamp = Timestamp::deserialize(&mut deser, digest.to_vec())?;

    let dtf = DetachedTimestampFile {
        digest_type: DigestType::Sha256,
        timestamp,
    };
    let mut out = Vec::new();
    dtf.to_writer(&mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentimestamps::op::Op;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;

    struct MockHeaders(HashMap<usize, [u8; 32]>);
    impl BitcoinHeaderSource for MockHeaders {
        fn merkle_root(&self, height: usize) -> Result<[u8; 32], String> {
            self.0
                .get(&height)
                .copied()
                .ok_or_else(|| format!("no block at height {height}"))
        }
    }

    /// Build a `.ots` proof: digest -> Append(suffix) -> SHA256 -> Bitcoin@height.
    /// Returns (`ots_bytes`, `file_digest`, `committed_root`).
    fn build_proof(file: &[u8], height: usize) -> (Vec<u8>, Vec<u8>, [u8; 32]) {
        let digest = Sha256::digest(file).to_vec();

        let append = Op::Append(vec![0xde, 0xad, 0xbe, 0xef]);
        let after_append = append.execute(&digest);
        let sha = Op::Sha256;
        let after_sha = sha.execute(&after_append);

        let mut root = [0u8; 32];
        root.copy_from_slice(&after_sha);

        let attest_step = Step {
            data: StepData::Attestation(Attestation::Bitcoin { height }),
            output: after_sha.clone(),
            next: vec![],
        };
        let sha_step = Step {
            data: StepData::Op(sha),
            output: after_sha,
            next: vec![attest_step],
        };
        let append_step = Step {
            data: StepData::Op(append),
            output: after_append,
            next: vec![sha_step],
        };
        let dtf = DetachedTimestampFile {
            digest_type: DigestType::Sha256,
            timestamp: Timestamp {
                start_digest: digest.clone(),
                first_step: append_step,
            },
        };
        let mut out = Vec::new();
        dtf.to_writer(&mut out).expect("serialize");
        (out, digest, root)
    }

    #[test]
    fn verifies_matching_anchor() {
        let (ots, digest, root) = build_proof(b"the bundle bytes", 800_000);
        let headers = MockHeaders(HashMap::from([(800_000usize, root)]));
        let anchors = verify(&ots, &digest, &headers).expect("should verify");
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].height, 800_000);
        assert_eq!(anchors[0].merkle_root, root);
    }

    #[test]
    fn rejects_wrong_digest() {
        let (ots, _digest, root) = build_proof(b"the bundle bytes", 800_000);
        let headers = MockHeaders(HashMap::from([(800_000usize, root)]));
        let wrong = Sha256::digest(b"a different file").to_vec();
        assert!(matches!(
            verify(&ots, &wrong, &headers),
            Err(OtsError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn rejects_forged_merkle_root() {
        let (ots, digest, _root) = build_proof(b"the bundle bytes", 800_000);
        // header source returns a different root than the proof committed
        let headers = MockHeaders(HashMap::from([(800_000usize, [0x11u8; 32])]));
        assert!(matches!(
            verify(&ots, &digest, &headers),
            Err(OtsError::MerkleRootMismatch { height: 800_000, .. })
        ));
    }

    #[test]
    fn header_source_failure_propagates() {
        let (ots, digest, _root) = build_proof(b"the bundle bytes", 800_000);
        let headers = MockHeaders(HashMap::new()); // no blocks known
        assert!(matches!(
            verify(&ots, &digest, &headers),
            Err(OtsError::HeaderSource(_))
        ));
    }

    #[test]
    fn pending_only_is_not_anchored() {
        let digest = Sha256::digest(b"x").to_vec();
        let pending_step = Step {
            data: StepData::Attestation(Attestation::Pending {
                uri: "https://alice.btc.calendar.opentimestamps.org".to_string(),
            }),
            output: digest.clone(),
            next: vec![],
        };
        let dtf = DetachedTimestampFile {
            digest_type: DigestType::Sha256,
            timestamp: Timestamp {
                start_digest: digest.clone(),
                first_step: pending_step,
            },
        };
        let mut ots = Vec::new();
        dtf.to_writer(&mut ots).unwrap();

        let headers = MockHeaders(HashMap::new());
        assert!(matches!(
            verify(&ots, &digest, &headers),
            Err(OtsError::NotAnchored)
        ));
        let pend = pending_calendars(&ots).unwrap();
        assert_eq!(pend.len(), 1);
        assert!(pend[0].uri.contains("opentimestamps.org"));
    }
}
