//! `pq-ceremony` — the enclave-side binary.
//!
//! On startup it runs the one-shot burn-in ([`pq_ceremony::run_ceremony`]) and
//! then serves the resulting `bundle.json` over a tiny HTTP endpoint so the host
//! can fetch it (the enclave has no filesystem export). It stays alive serving
//! the same immutable bundle, which keeps Caution's health check satisfied.
//!
//! Endpoints:
//! * `GET /bundle.json` — the finished bundle (JSON).
//! * `GET /health`, `GET /` — liveness probe (`ok`).
//!
//! The real AWS NSM is used only with `--features nitro` (Linux/Nitro). Without
//! it, a [`MockNsm`] yields a structurally valid but cryptographically fake
//! bundle for local/QEMU smoke tests.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use pq_ceremony::run_ceremony;

#[cfg(feature = "nitro")]
use pq_enclave::nitro::NitroNsm;
#[cfg(not(feature = "nitro"))]
use pq_enclave::MockNsm;

#[derive(Parser)]
#[command(name = "pq-ceremony", about = "In-enclave PQ root key burn-in ceremony")]
struct Cli {
    /// Address to bind the bundle HTTP server to.
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: String,
    /// Path to the baked-in AWS Nitro root CA (DER). Its SHA-256 is archived in
    /// the bundle so verifiers can pin the same anchor.
    #[arg(long, default_value = "/etc/pq/aws_nitro_root.der")]
    root_ca: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let root_ca = std::fs::read(&cli.root_ca)
        .with_context(|| format!("reading AWS root CA {}", cli.root_ca.display()))?;

    #[cfg(feature = "nitro")]
    let nsm = NitroNsm;
    #[cfg(not(feature = "nitro"))]
    let nsm = MockNsm;

    eprintln!("pq-ceremony: generating PQ keys and attesting...");
    let bundle = run_ceremony(&nsm, &root_ca).context("ceremony failed")?;
    let bundle_json = bundle.to_json().context("serializing bundle")?;
    eprintln!(
        "pq-ceremony: bundle ready ({} bytes); serving on http://{}/bundle.json",
        bundle_json.len(),
        cli.bind
    );

    serve(&cli.bind, &bundle_json).context("HTTP server failed")
}

/// Serve the immutable bundle forever. Single-threaded: one short-lived,
/// connection-closing response per request is all this endpoint needs.
fn serve(addr: &str, bundle_json: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).with_context(|| format!("binding {addr}"))?;
    for stream in listener.incoming() {
        match stream {
            Ok(mut s) => {
                if let Err(e) = handle(&mut s, bundle_json) {
                    eprintln!("pq-ceremony: request error: {e}");
                }
            }
            Err(e) => eprintln!("pq-ceremony: accept error: {e}"),
        }
    }
    Ok(())
}

fn handle(stream: &mut TcpStream, bundle_json: &str) -> std::io::Result<()> {
    let mut request_line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut request_line)?;
    let path = request_line.split_whitespace().nth(1).unwrap_or("/");

    let (status, content_type, body) = match path {
        "/bundle.json" => ("200 OK", "application/json", bundle_json),
        "/health" | "/" => ("200 OK", "text/plain", "ok\n"),
        _ => ("404 Not Found", "text/plain", "not found\n"),
    };

    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}
