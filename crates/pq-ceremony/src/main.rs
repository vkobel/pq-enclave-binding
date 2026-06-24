//! `pq-ceremony` — the enclave-side binary.
//!
//! On startup it runs the one-shot burn-in ([`pq_ceremony::run_ceremony`]) and
//! then serves the resulting bundle over a tiny HTTP server so the host can
//! fetch it (the enclave has no filesystem export). It stays alive serving the
//! same immutable bundle and signing oracle, which keeps Caution's health check
//! satisfied.
//!
//! Endpoints:
//! * `GET /bundle.json`   — the finished bundle (JSON).
//! * `GET /health`, `GET /` — liveness probe (`ok`).
//! * `GET /subkeys`       — all pre-committed subkeys (public keys + Merkle proofs).
//! * `GET /subkey/<i>`    — public material + proof for subkey `i`.
//! * `POST /sign`         — re-derive subkey `i`, dual-sign (ML-DSA-65 **and**
//!   SLH-DSA-SHAKE-128f) in-process, return both signatures + Merkle proof.
//!
//! The real AWS NSM is used only with `--features nitro` (Linux/Nitro). Without
//! it, a [`MockNsm`] yields a structurally valid but cryptographically fake
//! bundle for local/QEMU smoke tests.

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use pq_ceremony::{run_ceremony, CeremonyConfig, CeremonyState};

#[cfg(feature = "nitro")]
use pq_enclave::nitro::NitroNsm;
#[cfg(not(feature = "nitro"))]
use pq_enclave::MockNsm;

#[derive(Parser)]
#[command(
    name = "pq-ceremony",
    about = "In-enclave PQ root key burn-in ceremony + signing oracle"
)]
struct Cli {
    /// Address to bind the bundle HTTP server to.
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: String,
    /// Path to the baked-in AWS Nitro root CA (DER). Its SHA-256 is archived in
    /// the bundle so verifiers can pin the same anchor.
    #[arg(long, default_value = "/etc/pq/aws_nitro_root.der")]
    root_ca: PathBuf,
}

fn config_from_env() -> CeremonyConfig {
    let parse = |k: &str, d: u32| env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d);
    CeremonyConfig {
        auth_count: parse("PQ_SUBKEYS_AUTH", 4),
        enc_count: parse("PQ_SUBKEYS_ENC", 0),
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let root_ca = std::fs::read(&cli.root_ca)
        .with_context(|| format!("reading AWS root CA {}", cli.root_ca.display()))?;

    #[cfg(feature = "nitro")]
    let nsm = NitroNsm;
    #[cfg(not(feature = "nitro"))]
    let nsm = MockNsm;

    let config = config_from_env();
    eprintln!(
        "pq-ceremony: generating root + {} auth / {} enc subkeys, attesting...",
        config.auth_count, config.enc_count
    );
    let state = run_ceremony(&nsm, &root_ca, &config).context("ceremony failed")?;
    let bundle_json = state.bundle.to_json().context("serializing bundle")?;
    eprintln!(
        "pq-ceremony: bundle ready ({} bytes); serving on http://{}",
        bundle_json.len(),
        cli.bind
    );

    serve(&cli.bind, &state, &bundle_json).context("HTTP server failed")
}

/// Build the JSON response for `POST /sign`. Returns `(status, body)`.
fn sign_response(state: &CeremonyState, body: &str) -> (String, String) {
    #[derive(serde::Deserialize)]
    struct Req {
        index: u32,
        message_hex: String,
    }
    let Ok(req) = serde_json::from_str::<Req>(body) else {
        return ("400 Bad Request".into(), "{\"error\":\"bad request\"}".into());
    };
    let Ok(message) = hex::decode(&req.message_hex) else {
        return ("400 Bad Request".into(), "{\"error\":\"bad message_hex\"}".into());
    };
    let Some(rec) = state.subkeys.iter().find(|r| r.global_index == req.index) else {
        return ("404 Not Found".into(), "{\"error\":\"unknown subkey index\"}".into());
    };
    let Some((sig, proof)) = state.sign_with_subkey(req.index, &message) else {
        return ("404 Not Found".into(), "{\"error\":\"unknown subkey index\"}".into());
    };
    let proof_hex: Vec<String> = proof.iter().map(hex::encode).collect();
    let json = serde_json::json!({
        "index": rec.global_index,
        "purpose_tag": rec.purpose_tag,
        "ml_dsa_pk": hex::encode(&rec.ml_dsa_pk),
        "slh_dsa_pk": hex::encode(&rec.slh_dsa_pk),
        "ml_dsa_sig": hex::encode(&sig.ml_dsa),
        "slh_dsa_sig": hex::encode(&sig.slh_dsa),
        "merkle_proof": proof_hex,
    });
    ("200 OK".into(), json.to_string())
}

/// Build the JSON for `GET /subkeys` — all pre-committed subkeys (public material + proofs).
fn subkeys_list_response(state: &CeremonyState) -> (String, String) {
    let list: Vec<serde_json::Value> = state
        .subkeys
        .iter()
        .map(|rec| {
            let proof_hex: Vec<String> = state
                .proof(rec.global_index)
                .unwrap_or_default()
                .iter()
                .map(hex::encode)
                .collect();
            serde_json::json!({
                "index": rec.global_index,
                "purpose_tag": rec.purpose_tag,
                "ml_dsa_pk": hex::encode(&rec.ml_dsa_pk),
                "slh_dsa_pk": hex::encode(&rec.slh_dsa_pk),
                "merkle_proof": proof_hex,
            })
        })
        .collect();
    ("200 OK".into(), serde_json::json!(list).to_string())
}

/// Build the JSON for `GET /subkey/<i>` (public material + proof, no signature).
fn subkey_response(state: &CeremonyState, index: u32) -> (String, String) {
    let Some(rec) = state.subkeys.iter().find(|r| r.global_index == index) else {
        return ("404 Not Found".into(), "{\"error\":\"unknown subkey index\"}".into());
    };
    let proof_hex: Vec<String> = state
        .proof(index)
        .unwrap_or_default()
        .iter()
        .map(hex::encode)
        .collect();
    let json = serde_json::json!({
        "index": rec.global_index,
        "purpose_tag": rec.purpose_tag,
        "ml_dsa_pk": hex::encode(&rec.ml_dsa_pk),
        "slh_dsa_pk": hex::encode(&rec.slh_dsa_pk),
        "merkle_proof": proof_hex,
    });
    ("200 OK".into(), json.to_string())
}

fn serve(addr: &str, state: &CeremonyState, bundle_json: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).with_context(|| format!("binding {addr}"))?;
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                if let Err(e) = handle(&mut s, state, bundle_json) {
                    eprintln!("pq-ceremony: request error: {e}");
                }
            }
            Err(e) => eprintln!("pq-ceremony: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(stream: &mut TcpStream, state: &CeremonyState, bundle_json: &str) -> std::io::Result<()> {
    // Read headers, then the body (Content-Length) if present.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let header_end = loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break buf.len();
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            // Ensure the full body is read.
            let headers = String::from_utf8_lossy(&buf[..pos]).to_string();
            let len = content_length(&headers);
            let need = pos + 4 + len;
            while buf.len() < need {
                let n = stream.read(&mut tmp)?;
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            break pos;
        }
    };

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("/");
    let body = String::from_utf8_lossy(&buf[(header_end + 4).min(buf.len())..]).to_string();

    let (status, content_type, body_out): (String, &str, String) = match (method, path) {
        ("GET", "/bundle.json") => ("200 OK".into(), "application/json", bundle_json.to_string()),
        ("GET", "/health" | "/") => ("200 OK".into(), "text/plain", "ok\n".to_string()),
        ("POST", "/sign") => {
            let (s, b) = sign_response(state, &body);
            (s, "application/json", b)
        }
        ("GET", "/subkeys") => {
            let (s, b) = subkeys_list_response(state);
            (s, "application/json", b)
        }
        ("GET", p) if p.starts_with("/subkey/") => {
            match p.trim_start_matches("/subkey/").parse::<u32>() {
                Ok(i) => {
                    let (s, b) = subkey_response(state, i);
                    (s, "application/json", b)
                }
                Err(_) => ("400 Bad Request".into(), "text/plain", "bad index\n".to_string()),
            }
        }
        _ => ("404 Not Found".into(), "text/plain", "not found\n".to_string()),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body_out}",
        body_out.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|l| {
            l.strip_prefix("Content-Length:")
                .or_else(|| l.strip_prefix("content-length:"))
        })
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pq_ceremony::{run_ceremony, CeremonyConfig};
    use pq_enclave::MockNsm;

    #[test]
    fn sign_response_signs_and_proves() {
        let state =
            run_ceremony(&MockNsm, b"r", &CeremonyConfig { auth_count: 2, enc_count: 0 }).unwrap();
        let body = r#"{"index":1,"message_hex":"68656c6c6f"}"#; // "hello"
        let (status, json) = sign_response(&state, body);
        assert_eq!(status, "200 OK");
        assert!(json.contains("merkle_proof"));
        assert!(json.contains("ml_dsa_sig"));
    }

    #[test]
    fn sign_response_rejects_unknown_index() {
        let state =
            run_ceremony(&MockNsm, b"r", &CeremonyConfig { auth_count: 1, enc_count: 0 }).unwrap();
        let (status, _json) = sign_response(&state, r#"{"index":99,"message_hex":"00"}"#);
        assert_eq!(status, "404 Not Found");
    }
}
