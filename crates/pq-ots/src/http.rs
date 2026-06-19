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

    /// Fetch the raw JSON body of the block at `height` (`height` → hash → block).
    /// The response carries both `merkle_root` and `timestamp`.
    fn block_json(&self, height: usize) -> Result<String, String> {
        let hash_url = format!("{}/block-height/{height}", self.base_url);
        let block_hash = ureq::get(&hash_url)
            .call()
            .map_err(|e| format!("GET {hash_url}: {e}"))?
            .into_body()
            .read_to_string()
            .map_err(|e| format!("reading block hash: {e}"))?;
        let block_hash = block_hash.trim();

        let block_url = format!("{}/block/{block_hash}", self.base_url);
        ureq::get(&block_url)
            .call()
            .map_err(|e| format!("GET {block_url}: {e}"))?
            .into_body()
            .read_to_string()
            .map_err(|e| format!("reading block: {e}"))
    }
}

/// Extract a quoted string field (`"name":"<value>"`) from a compact JSON body,
/// avoiding a JSON dependency. esplora returns compact, unspaced JSON.
fn json_str_field<'a>(body: &'a str, name: &str) -> Result<&'a str, String> {
    let key = format!("\"{name}\":\"");
    let start = body
        .find(&key)
        .ok_or_else(|| format!("no {name} in block response"))?
        + key.len();
    let end = body[start..]
        .find('"')
        .ok_or_else(|| format!("malformed {name} field"))?
        + start;
    Ok(&body[start..end])
}

/// Extract an unquoted numeric field (`"name":<digits>`) from a compact JSON body.
fn json_u64_field(body: &str, name: &str) -> Result<u64, String> {
    let key = format!("\"{name}\":");
    let start = body
        .find(&key)
        .ok_or_else(|| format!("no {name} in block response"))?
        + key.len();
    let rest = &body[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end]
        .parse::<u64>()
        .map_err(|e| format!("bad {name} number {:?}: {e}", &rest[..end]))
}

impl BitcoinHeaderSource for EsploraHeaderSource {
    fn merkle_root(&self, height: usize) -> Result<[u8; 32], String> {
        let body = self.block_json(height)?;
        // merkle_root is reported as big-endian display hex
        let display_hex = json_str_field(&body, "merkle_root")?;

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

    fn block_time(&self, height: usize) -> Result<Option<u64>, String> {
        let body = self.block_json(height)?;
        Ok(Some(json_u64_field(&body, "timestamp")?))
    }
}
