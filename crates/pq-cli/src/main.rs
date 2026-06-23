//! `pq` — verify and stamp PQ enclave-binding root key bundles.
//!
//! Ties together the pieces of the demo:
//! * [`pq_quote::NitroQuoteVerifier`] — parse + verify the NSM COSE quote to a
//!   pinned AWS root, as of a fixed instant.
//! * [`pq_ots`] — verify the `OpenTimestamps` Bitcoin anchor (or stamp a bundle).
//! * [`pq_bundle::verify`] — debug-mode rejection, PCR pinning, key binding, and
//!   dual PQ-signature checks.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use clap::{Parser, Subcommand};
use pq_bundle::{PqRootBundle, TimestampVerifier};
use pq_ots::{BitcoinHeaderSource, EsploraHeaderSource, HttpCalendar};
use pq_quote::NitroQuoteVerifier;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(name = "pq", about = "Verify and stamp PQ enclave-binding root key bundles")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print a summary of a bundle without verifying it.
    Inspect {
        /// Path to bundle.json.
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Fully verify a bundle: OTS anchor, Nitro quote, PCR pinning, binding, dual PQ sig.
    Verify {
        /// Path to bundle.json.
        #[arg(long)]
        bundle: PathBuf,
        /// Path to the `.ots` timestamp proof.
        #[arg(long)]
        ots: PathBuf,
        /// Path to the pinned AWS Nitro root CA (DER).
        #[arg(long)]
        root: PathBuf,
        /// Local JSON header source: `{ "<height>": { "merkle_root": "<hex>", "time": <unix> } }`.
        /// `merkle_root` is in internal byte order. Mutually exclusive with `--esplora`.
        #[arg(long)]
        headers: Option<PathBuf>,
        /// Esplora API base URL (e.g. `https://blockstream.info/api`). Requires `--quote-time-unix`.
        #[arg(long)]
        esplora: Option<String>,
        /// Override the instant (Unix seconds) to verify the Nitro certificate
        /// chain as of. Normally omitted: the anchor block's own timestamp is
        /// used (fetched from `--esplora`, or read from the `--headers` `time`
        /// field). Only needed if a header file omits `time`.
        #[arg(long = "quote-time-unix")]
        quote_time_unix: Option<u64>,
    },
    /// Submit a bundle's digest to OTS calendar servers, writing a `.ots` proof.
    Stamp {
        /// Path to bundle.json.
        #[arg(long)]
        bundle: PathBuf,
        /// Output path for the `.ots` proof.
        #[arg(long)]
        out: PathBuf,
        /// Calendar base URLs (tried in order; the first success wins).
        #[arg(long = "calendar", default_values_t = default_calendars())]
        calendars: Vec<String>,
    },
    /// Verify a subkey's birth-provenance (Merkle membership) and, if given a
    /// message, its dual signature.
    VerifySubkey {
        /// Path to bundle.json (provides the anchored subkey Merkle root).
        #[arg(long)]
        bundle: PathBuf,
        /// Path to the subkey JSON (a `/sign` or `/subkey/<i>` response).
        #[arg(long)]
        subkey: PathBuf,
        /// Optional message (hex) the subkey claims to have signed.
        #[arg(long = "message-hex")]
        message_hex: Option<String>,
    },
}

fn default_calendars() -> Vec<String> {
    vec![
        "https://alice.btc.calendar.opentimestamps.org".to_string(),
        "https://bob.btc.calendar.opentimestamps.org".to_string(),
        "https://finney.calendar.eternitywall.com".to_string(),
    ]
}

// ─── Header source ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct BlockInfo {
    merkle_root: String,
    #[serde(default)]
    time: Option<u64>,
}

/// Header source resolved from CLI flags. Concrete enum (not `dyn`) so it can be
/// passed to `pq_ots::verify`'s `&impl BitcoinHeaderSource`.
enum HeaderSource {
    Map {
        roots: BTreeMap<u64, [u8; 32]>,
        times: BTreeMap<u64, u64>,
    },
    Esplora(EsploraHeaderSource),
}

impl BitcoinHeaderSource for HeaderSource {
    fn merkle_root(&self, height: usize) -> Result<[u8; 32], String> {
        match self {
            HeaderSource::Map { roots, .. } => roots
                .get(&(height as u64))
                .copied()
                .ok_or_else(|| format!("no block at height {height} in header file")),
            HeaderSource::Esplora(e) => e.merkle_root(height),
        }
    }

    fn block_time(&self, height: usize) -> Result<Option<u64>, String> {
        match self {
            // The header file may omit `time`; then we have nothing to offer.
            HeaderSource::Map { times, .. } => Ok(times.get(&(height as u64)).copied()),
            HeaderSource::Esplora(e) => e.block_time(height),
        }
    }
}

fn load_header_file(path: &Path) -> Result<HeaderSource> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("reading header file {}", path.display()))?;
    let parsed: BTreeMap<u64, BlockInfo> =
        serde_json::from_str(&raw).context("parsing header file JSON")?;

    let mut roots = BTreeMap::new();
    let mut times = BTreeMap::new();
    for (height, info) in parsed {
        let bytes = hex::decode(&info.merkle_root)
            .with_context(|| format!("bad merkle_root hex for height {height}"))?;
        let root: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("merkle_root for height {height} is not 32 bytes"))?;
        roots.insert(height, root);
        if let Some(t) = info.time {
            times.insert(height, t);
        }
    }
    Ok(HeaderSource::Map { roots, times })
}

// ─── OTS timestamp verifier adapter ─────────────────────────────────────────

struct OtsTimestampVerifier<'a> {
    source: &'a HeaderSource,
}

impl TimestampVerifier for OtsTimestampVerifier<'_> {
    fn verify_timestamp(&self, bundle_digest: &[u8], ots_bytes: &[u8]) -> Result<(), String> {
        let anchors =
            pq_ots::verify(ots_bytes, bundle_digest, self.source).map_err(|e| e.to_string())?;
        if anchors.is_empty() {
            return Err("OTS proof has no Bitcoin anchor".to_string());
        }
        Ok(())
    }
}

// ─── Commands ───────────────────────────────────────────────────────────────

/// Hash the canonical `to_json()` form — must match `pq_bundle::verify`.
fn bundle_digest(bundle: &PqRootBundle) -> Result<[u8; 32]> {
    let json = bundle.to_json().context("serializing bundle")?;
    Ok(Sha256::digest(json.as_bytes()).into())
}

fn load_bundle(path: &Path) -> Result<PqRootBundle> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("reading bundle {}", path.display()))?;
    PqRootBundle::from_json(&raw).context("parsing bundle JSON")
}

fn cmd_inspect(path: &Path) -> Result<()> {
    let bundle = load_bundle(path)?;
    let ml = hex::decode(&bundle.ml_dsa_pk).context("ml_dsa_pk hex")?;
    let slh = hex::decode(&bundle.slh_dsa_pk).context("slh_dsa_pk hex")?;
    let quote = base64::engine::general_purpose::STANDARD
        .decode(&bundle.nsm_quote)
        .context("nsm_quote base64")?;

    println!("bundle version:      {}", bundle.version);
    println!("ml-dsa-65 pk:        {} bytes", ml.len());
    println!("slh-dsa-128f pk:     {} bytes", slh.len());
    println!("nsm quote:           {} bytes (COSE_Sign1)", quote.len());
    println!("aws root ca sha256:  {}", bundle.aws_root_ca_sha256);
    println!("expected PCR0:       {}", bundle.expected_pcrs.pcr0);
    println!("expected PCR1:       {}", bundle.expected_pcrs.pcr1);
    println!("expected PCR2:       {}", bundle.expected_pcrs.pcr2);
    println!("subkey merkle root:  {}", bundle.subkey_merkle_root);
    println!("subkey count:        {}", bundle.subkey_count);
    println!("digest (sha256):     {}", hex::encode(bundle_digest(&bundle)?));
    Ok(())
}

fn cmd_verify(
    bundle_path: &Path,
    ots_path: &Path,
    root_path: &Path,
    headers: Option<&Path>,
    esplora: Option<&str>,
    quote_time_unix: Option<u64>,
) -> Result<()> {
    let bundle = load_bundle(bundle_path)?;
    let ots_bytes =
        fs::read(ots_path).with_context(|| format!("reading ots {}", ots_path.display()))?;
    let root_der =
        fs::read(root_path).with_context(|| format!("reading root CA {}", root_path.display()))?;
    let digest = bundle_digest(&bundle)?;

    let source = match (headers, esplora) {
        (Some(_), Some(_)) => bail!("--headers and --esplora are mutually exclusive"),
        (Some(p), None) => load_header_file(p)?,
        (None, Some(url)) => HeaderSource::Esplora(EsploraHeaderSource::new(url.to_string())),
        (None, None) => {
            bail!("provide a Bitcoin header source: --headers <file> or --esplora <url>")
        }
    };

    println!("Verifying {} ...\n", bundle_path.display());

    // ── [1/7] OTS anchor ─────────────────────────────────────────────────────
    // Verify OTS up front so we can derive the anchor block time for the quote.
    let anchors = pq_ots::verify(&ots_bytes, &digest, &source)
        .context("OTS timestamp verification failed")?;
    let earliest = anchors
        .iter()
        .min_by_key(|a| a.height)
        .context("OTS proof produced no anchors")?;

    // Verify the (quantum-breakable) Nitro chain *as of the anchor block's time*.
    // Derive that instant from the proven anchor block itself; `--quote-time-unix`
    // is only an override (and the sole option if a header file omits `time`).
    let quote_time = match quote_time_unix {
        Some(t) => t,
        None => source
            .block_time(earliest.height)
            .map_err(|e| anyhow::anyhow!("looking up anchor block {} time: {e}", earliest.height))?
            .with_context(|| {
                format!(
                    "anchor block {} has no `time` (header file omitted it); \
                     pass --quote-time-unix",
                    earliest.height
                )
            })?,
    };
    println!("✓ [1/7] OTS timestamp — bundle digest committed to Bitcoin");
    println!("          digest {}", hex::encode(digest));
    println!("          anchored in block {} (time: unix {quote_time})", earliest.height);

    let quote_verifier = NitroQuoteVerifier::at_unix_secs(root_der, quote_time);

    // ── [2/7] Pinned root CA cross-check ─────────────────────────────────────
    if quote_verifier.root_sha256_hex() != bundle.aws_root_ca_sha256 {
        bail!(
            "pinned root CA sha256 ({}) does not match bundle.aws_root_ca_sha256 ({})",
            quote_verifier.root_sha256_hex(),
            bundle.aws_root_ca_sha256
        );
    }
    println!("✓ [2/7] Pinned AWS root CA matches the bundle");
    println!("          sha256 {}", bundle.aws_root_ca_sha256);

    // ── [3/7]–[7/7] quote sig, debug-reject, PCR pin, binding, dual PQ sig ────
    let ts_verifier = OtsTimestampVerifier { source: &source };
    let report = pq_bundle::verify(&bundle, &quote_verifier, Some((&ts_verifier, &ots_bytes)))
        .context("bundle verification failed")?;

    println!("✓ [3/7] NSM quote — COSE_Sign1 ES384 signature + cert chain valid");
    println!("          to the pinned root, as of unix {quote_time} (anchor block time)");
    println!("✓ [4/7] Debug-mode rejected — PCR0/1/2 are not all-zero");
    println!("✓ [5/7] PCR pinning — quote PCR0/1/2 == bundle.expected_pcrs");
    println!("          PCR0 {}", hex::encode(&report.pcr0));
    println!("          PCR1 {}", hex::encode(&report.pcr1));
    println!("          PCR2 {}", hex::encode(&report.pcr2));
    println!(
        "✓ [6/7] Key binding — quote.user_data == \"pq-keyfork-v1:\" || SHA-256(canonical_payload)"
    );
    println!("          user_data {}", hex::encode(&report.user_data));
    println!("✓ [7/7] Dual PQ signatures valid over canonical_payload");
    println!(
        "          ML-DSA-65 pk {} B  +  SLH-DSA-SHAKE-128f pk {} B",
        report.ml_dsa_pk_len, report.slh_dsa_pk_len
    );

    println!("\nVERIFIED — these PQ public keys were generated inside the attested");
    println!(
        "enclave (PCRs above) and the bundle existed before Bitcoin block {}.",
        earliest.height
    );
    Ok(())
}

fn cmd_stamp(bundle_path: &Path, out: &Path, calendars: &[String]) -> Result<()> {
    let bundle = load_bundle(bundle_path)?;
    let digest = bundle_digest(&bundle)?;

    let mut last_err = None;
    for url in calendars {
        let client = HttpCalendar::new(url.clone());
        match pq_ots::stamp(&digest, &client) {
            Ok(proof) => {
                fs::write(out, &proof)
                    .with_context(|| format!("writing proof {}", out.display()))?;
                println!(
                    "✓ stamped via {url}; wrote {} ({} bytes)",
                    out.display(),
                    proof.len()
                );
                println!("  upgrade the proof in ~a few hours once anchored in Bitcoin");
                return Ok(());
            }
            Err(e) => {
                eprintln!("calendar {url} failed: {e}");
                last_err = Some(e);
            }
        }
    }
    match last_err {
        Some(e) => Err(anyhow::anyhow!("all calendars failed; last error: {e}")),
        None => bail!("no calendars configured"),
    }
}

#[derive(serde::Deserialize)]
struct SubkeyResponse {
    index: u32,
    purpose_tag: u8,
    ml_dsa_pk: String,
    slh_dsa_pk: String,
    #[serde(default)]
    ml_dsa_sig: Option<String>,
    #[serde(default)]
    slh_dsa_sig: Option<String>,
    merkle_proof: Vec<String>,
}

fn verify_subkey(bundle_path: &Path, subkey_path: &Path, message_hex: Option<&str>) -> Result<()> {
    let bundle = PqRootBundle::from_json(&fs::read_to_string(bundle_path)?)?;
    let sk: SubkeyResponse = serde_json::from_str(&fs::read_to_string(subkey_path)?)?;

    let root: [u8; 32] = hex::decode(&bundle.subkey_merkle_root)
        .context("decoding bundle.subkey_merkle_root")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("subkey_merkle_root is not 32 bytes"))?;
    let ml_pk = hex::decode(&sk.ml_dsa_pk).context("subkey ml_dsa_pk")?;
    let slh_pk = hex::decode(&sk.slh_dsa_pk).context("subkey slh_dsa_pk")?;
    let siblings: Vec<[u8; 32]> = sk
        .merkle_proof
        .iter()
        .map(|h| {
            hex::decode(h)
                .ok()
                .and_then(|b| b.try_into().ok())
                .context("merkle_proof node must be 32-byte hex")
        })
        .collect::<Result<_>>()?;

    if !pq_merkle::verify_membership(&root, sk.index, sk.purpose_tag, &ml_pk, &slh_pk, &siblings) {
        bail!("✗ membership proof FAILED — subkey is not in the anchored set");
    }
    println!("✓ birth-provenance — subkey #{} is committed in the enclave's anchored set", sk.index);

    if let Some(msg_hex) = message_hex {
        let msg = hex::decode(msg_hex).context("--message-hex")?;
        let (Some(ml_sig), Some(slh_sig)) = (&sk.ml_dsa_sig, &sk.slh_dsa_sig) else {
            bail!("--message-hex given but subkey JSON has no signatures");
        };
        let dual = pq_core::DualSignature {
            ml_dsa: hex::decode(ml_sig).context("ml_dsa_sig")?,
            slh_dsa: hex::decode(slh_sig).context("slh_dsa_sig")?,
        };
        pq_core::verify_dual(&ml_pk, &slh_pk, &msg, &dual).context("subkey signature")?;
        println!("✓ authenticity — dual signature over the message verifies");
    }

    println!("\nVERIFIED — this subkey was generated inside the attested enclave.");
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Inspect { bundle } => cmd_inspect(&bundle),
        Command::Verify {
            bundle,
            ots,
            root,
            headers,
            esplora,
            quote_time_unix,
        } => cmd_verify(
            &bundle,
            &ots,
            &root,
            headers.as_deref(),
            esplora.as_deref(),
            quote_time_unix,
        ),
        Command::Stamp {
            bundle,
            out,
            calendars,
        } => cmd_stamp(&bundle, &out, &calendars),
        Command::VerifySubkey {
            bundle,
            subkey,
            message_hex,
        } => verify_subkey(&bundle, &subkey, message_hex.as_deref()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_file_parses_and_resolves() {
        let json = r#"{ "800000": { "merkle_root": "aa11bb22cc33dd44ee55ff66007788990011223344556677889900aabbccddee", "time": 1700000000 } }"#;
        let path = std::env::temp_dir().join("pq_cli_headers_test.json");
        fs::write(&path, json).unwrap();

        let src = load_header_file(&path).unwrap();
        let root = src.merkle_root(800_000).expect("present");
        assert_eq!(root[0], 0xaa);
        assert!(src.merkle_root(1).is_err());
        match src {
            HeaderSource::Map { times, .. } => {
                assert_eq!(times.get(&800_000), Some(&1_700_000_000));
            }
            HeaderSource::Esplora(_) => panic!("expected map"),
        }
        fs::remove_file(&path).ok();
    }

    #[test]
    fn ots_adapter_rejects_garbage() {
        let src = HeaderSource::Map {
            roots: BTreeMap::new(),
            times: BTreeMap::new(),
        };
        let tv = OtsTimestampVerifier { source: &src };
        assert!(tv.verify_timestamp(&[0u8; 32], b"not an ots proof").is_err());
    }

    #[test]
    fn inspect_runs_on_a_generated_bundle() {
        use pq_bundle::{ExpectedPcrs, PqRootBundle};
        use pq_core::{canonical_payload, PqRootKeypair};

        let kp = PqRootKeypair::generate();
        let payload = canonical_payload(&kp.ml_dsa_pk(), &kp.slh_dsa_pk());
        let sig = kp.sign_payload(&payload);

        let bundle = PqRootBundle {
            version: "1".to_string(),
            ml_dsa_pk: hex::encode(kp.ml_dsa_pk()),
            slh_dsa_pk: hex::encode(kp.slh_dsa_pk()),
            nsm_quote: String::new(),
            aws_root_ca_sha256: "00".repeat(32),
            expected_pcrs: ExpectedPcrs {
                pcr0: "11".repeat(48),
                pcr1: "22".repeat(48),
                pcr2: "33".repeat(48),
            },
            subkey_merkle_root: "00".repeat(32),
            subkey_count: 0,
            ml_dsa_sig: hex::encode(sig.ml_dsa),
            slh_dsa_sig: hex::encode(sig.slh_dsa),
        };
        let path = std::env::temp_dir().join("pq_cli_inspect_test.json");
        fs::write(&path, bundle.to_json().unwrap()).unwrap();
        cmd_inspect(&path).expect("inspect should succeed");
        fs::remove_file(&path).ok();
    }
}
