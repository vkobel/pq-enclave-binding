//! Real HTTP clients for OTS calendars and Bitcoin headers.
//!
//! Behind the `calendar-http` feature. Not exercised by the offline unit tests;
//! these talk to live network services.

use crate::{BitcoinHeaderSource, CalendarClient};

/// An OTS calendar reached over HTTP (e.g.
/// `https://alice.btc.calendar.opentimestamps.org`).
pub struct HttpCalendar {
    base_url: String,
}

impl HttpCalendar {
    /// Create a client for the calendar at `base_url` (no trailing slash).
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
}

impl CalendarClient for HttpCalendar {
    fn submit(&self, digest: &[u8]) -> Result<Vec<u8>, String> {
        let url = format!("{}/digest", self.base_url);
        ureq::post(&url)
            .header("Accept", "application/vnd.opentimestamps.v1")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(digest)
            .map_err(|e| format!("POST {url}: {e}"))?
            .into_body()
            .read_to_vec()
            .map_err(|e| format!("reading calendar response: {e}"))
    }
}

/// A Bitcoin header source backed by a Blockstream/esplora-compatible HTTP API
/// (e.g. `https://blockstream.info/api`).
pub struct EsploraHeaderSource {
    base_url: String,
}

impl EsploraHeaderSource {
    /// Create a source against the esplora API root at `base_url` (no trailing slash).
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }
}

impl BitcoinHeaderSource for EsploraHeaderSource {
    fn merkle_root(&self, height: usize) -> Result<[u8; 32], String> {
        // height -> block hash
        let hash_url = format!("{}/block-height/{height}", self.base_url);
        let block_hash = ureq::get(&hash_url)
            .call()
            .map_err(|e| format!("GET {hash_url}: {e}"))?
            .into_body()
            .read_to_string()
            .map_err(|e| format!("reading block hash: {e}"))?;
        let block_hash = block_hash.trim();

        // block hash -> block details (merkle_root as big-endian display hex)
        let block_url = format!("{}/block/{block_hash}", self.base_url);
        let body = ureq::get(&block_url)
            .call()
            .map_err(|e| format!("GET {block_url}: {e}"))?
            .into_body()
            .read_to_string()
            .map_err(|e| format!("reading block: {e}"))?;

        // crude extraction of the "merkle_root":"<hex>" field to avoid a JSON dep
        let key = "\"merkle_root\":\"";
        let start = body
            .find(key)
            .ok_or_else(|| "no merkle_root in block response".to_string())?
            + key.len();
        let end = body[start..]
            .find('"')
            .ok_or_else(|| "malformed merkle_root field".to_string())?
            + start;
        let display_hex = &body[start..end];

        let mut bytes = hex::decode(display_hex)
            .map_err(|e| format!("bad merkle_root hex {display_hex:?}: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("merkle_root is {} bytes, expected 32", bytes.len()));
        }
        // esplora reports big-endian display order; OTS commits internal order.
        bytes.reverse();
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Ok(root)
    }
}
