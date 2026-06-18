# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A standalone Rust workspace that produces and verifies a **PQ Root Key Bundle**: an
immutable artifact proving a post-quantum keypair (ML-DSA-65 + SLH-DSA-SHAKE-128f) was
generated inside a specific AWS Nitro Enclave at a verifiable pre-Q-Day date. It is a
one-time key burn-in ceremony, **not** a live RA-TLS flow.

`demo-spec.md` is the design document and the source of truth for *why* each link in the
chain exists and which checks are security-critical. Read it before changing
cryptographic behavior. Note that several spec "Implementation note" callouts supersede
the surrounding prose — the actual build uses `fips204`/`fips205` (not RustCrypto
`ml-dsa`/`slh-dsa`) and the binary is `pq` (not `keyfork-*`).

This is **not** a fork of keyfork and imports zero keyfork code. It rides RustCrypto's
prerelease `signature` train indirectly via the COSE/X.509 stack, which is why crate
choices are constrained (see "Dependency constraints").

## Common commands

```bash
cargo build --workspace
cargo test --workspace                  # all crates use mocks; no network/hardware needed
cargo test -p pq-bundle verify          # single crate / filtered test
cargo clippy --workspace --all-targets  # lints are deny-by-default (see below)

# The `pq` CLI
cargo run -p pq-cli -- inspect --bundle bundle.json
cargo run -p pq-cli -- verify  --bundle bundle.json --ots bundle.json.ots \
    --root aws_nitro_root.der --headers headers.json
cargo run -p pq-cli -- stamp   --bundle bundle.json --out bundle.json.ots
```

Feature flags that change what builds:
- `pq-enclave/nitro` — real `aws-nitro-enclaves-nsm-api` driver; **Linux/Nitro only**, does not build on macOS. Default build uses `MockNsm`.
- `pq-ots/calendar-http` — real HTTP calendar + esplora clients (via `ureq`). Off by default so the crate builds and tests offline. `pq-cli` enables it.

Clippy runs with `clippy::all = deny` and `clippy::pedantic = warn` workspace-wide
(set in root `Cargo.toml`). Treat pedantic warnings as things to fix, not ignore.

## Architecture

Data flows in three stages — **ceremony (enclave)** → **stamping (host)** →
**verification (anywhere, anytime)** — and the crate boundaries mirror that the enclave
has no network and the host never touches secrets.

Crate dependency order (leaf → root):

- **`pq-core`** — PQ keygen + dual-signing. `PqRootKeypair::generate()` /
  `sign_payload()`, `verify_dual()`. Defines the two functions everything else must
  agree on: `canonical_payload(ml_pk, slh_pk)` (length-prefixed concat of the two
  public keys — the bytes that get signed) and `user_data_commitment(payload)`
  (= `USER_DATA_PREFIX || SHA-256(payload)` — the bytes placed in the NSM quote).
  Secrets live only in the live key object and are never serialized.
- **`pq-enclave`** — NSM attestation behind an `Nsm` trait (`attest` +
  `describe_pcr`). `MockNsm` (default, any platform) vs `nitro::*` (feature-gated).
  `attest_bundle_payload()` computes the `user_data` commitment and requests the
  quote. Runs inside the enclave.
- **`pq-ceremony`** — the enclave **binary**. `run_ceremony()` (lib, testable with
  `MockNsm`) does the one-shot burn-in: keygen → dual-sign → NSM attest → self-read
  PCR0/1/2 → compose `PqRootBundle`. `main.rs` serves the immutable bundle over a
  tiny std-only HTTP server (`GET /bundle.json`, `GET /health`). The `nitro` feature
  selects the real NSM; default build uses `MockNsm` for local/QEMU. The bundle's
  `expected_pcrs` come from the enclave measuring itself; the AWS root CA is baked
  into the image and its SHA-256 recorded.
- **`pq-bundle`** — the `PqRootBundle` JSON schema and `verify()`, the heart of the
  security model. `verify()` is I/O-free: it takes injected `QuoteVerifier` and
  `TimestampVerifier` traits so the same logic is exercised by mocks in tests and real
  verifiers in the CLI. It enforces, in order: (1) debug-mode rejection (PCR0/1/2 not
  all-zero), (2) PCR pinning (quote PCRs == `bundle.expected_pcrs`), (3) binding
  (`quote.user_data` == commitment), (4) dual PQ signature.
- **`pq-quote`** — `NitroQuoteVerifier` implements `pq_bundle::QuoteVerifier`. Parses
  the `COSE_Sign1` doc, verifies the ES384 signature + cert chain **against a pinned
  root CA as of a fixed instant** (the OTS anchor block time — see below), extracts
  PCRs + `user_data`.
- **`pq-ots`** — OpenTimestamps. `verify()` is pure/offline (walks the proof tree,
  checks Merkle roots against an injected `BitcoinHeaderSource`); `stamp()` submits to
  calendars. The host does this; the enclave never does.
- **`pq-cli`** (`pq` binary) — wires the real verifiers together for `inspect` /
  `verify` / `stamp`.

### Two load-bearing invariants

1. **The canonical payload / commitment formula must stay identical** across the
   enclave side (`attest_bundle_payload` embeds `user_data_commitment(canonical_payload)`)
   and the verifier side (`pq_bundle::verify` recomputes it). Both go through `pq-core`
   so there is one definition — keep it that way; don't inline a second copy.

2. **Verification time is the OTS anchor block time, not now.** A Nitro leaf cert lives
   only hours and AWS's ECDSA is quantum-breakable, so verifying with the current clock
   is both broken (expiry) and meaningless post-Q-Day. The CLI verifies OTS first,
   derives the earliest Bitcoin anchor block's time, and verifies the Nitro chain *as
   of that instant* (`NitroQuoteVerifier::at_unix_secs`). This is the whole point of the
   timestamp: it extends trust of the quantum-breakable quote past Q-Day.

### Security checks that must never be dropped

`demo-spec.md` Phase 5 steps 3 and 4 (debug-mode rejection + PCR pinning) are
non-negotiable. Without them a valid AWS cert chain plus a matching `user_data` is
satisfied by *any* enclave — including an attacker's. The verifier also cross-checks the
pinned root CA's SHA-256 against the bundle's archived `aws_root_ca_sha256`.

## Dependency constraints (don't "upgrade" these blindly)

- **`fips204`/`fips205`, not RustCrypto `ml-dsa`/`slh-dsa`.** The RustCrypto crates
  hard-require a prerelease `signature` crate that cannot coexist in one lockfile with
  the mature `x509-cert`/`nsm-nitro-enclave-utils` COSE stack the verifier needs.
  `fips204`/`fips205` pull no `signature` crate and are `no_std`.
- **`x509-cert` is capped at `0.2`** (transitive of `nsm-nitro-enclave-utils`). 0.3
  is still a prerelease (`0.3.0-rc`). The old hard `=0.2.4` pin was dropped once
  `nsm-nitro-enclave-utils 0.1.3` removed its `builder`-feature requirement.
- **`sha2` stays on `0.10`** (not 0.11): the RustCrypto `digest` 0.11 trait break
  hasn't propagated to `fips204`/`fips205` or the COSE/x509 stack, so bumping alone
  would fork `digest`.
- `pqcrypto-mldsa` / `pqcrypto-dilithium` are deprecated (RUSTSEC) — do not introduce them.

## Deployment (Caution)

The ceremony deploys as a Caution Nitro enclave app. Root-level `Containerfile`
(StageX reproducible Rust build, `--features nitro`, `FROM scratch`) and `Procfile`
(`run: /app/pq-ceremony ...`, serves port 8080) drive it; `demo/run_demo.sh` runs
the loop locally with `MockNsm`. See `README.md` for the full deploy steps. Two
prerequisites are intentionally **not** in the repo and must be supplied:
`aws_nitro_root.der` at the repo root (the Containerfile `COPY`s it), and a real
pinned StageX digest replacing the placeholder in `Containerfile`. A real NSM quote
needs production Nitro — QEMU has no NSM device, so the ceremony's attestation step
only fully succeeds when deployed.

## Status

Pre-1.0. The PQ crates (`fips204`/`fips205`) are young and `slh-dsa`-class
implementations are unaudited — pin versions and track RUSTSEC.
