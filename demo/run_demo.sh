#!/usr/bin/env bash
# Local end-to-end smoke test of the ceremony → bundle → host-CLI loop.
#
# This runs the ceremony with the MOCK NSM (no Nitro hardware), so the produced
# bundle is structurally valid but NOT cryptographically attested: `pq verify`
# cannot pass on it (the quote is a fake JSON doc, the PCRs are placeholders).
# It exercises everything that does not require real silicon: key generation,
# dual-signing, bundle assembly, HTTP serving, and `pq inspect`.
#
# For a real bundle, deploy to Caution (see README) and fetch /bundle.json from
# the live enclave, then `pq stamp` and `pq verify` against it.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT=18099
ROOT_DER="$(mktemp)"
BUNDLE="$(mktemp)"
head -c 256 /dev/urandom > "$ROOT_DER"   # stand-in for the real AWS Nitro root CA

echo "==> building pq-ceremony (mock NSM) and pq CLI"
cargo build -p pq-ceremony -p pq-cli

echo "==> starting ceremony on 127.0.0.1:$PORT"
target/debug/pq-ceremony --bind "127.0.0.1:$PORT" --root-ca "$ROOT_DER" 2>/tmp/pq-demo.log &
CEREMONY_PID=$!
trap 'kill "$CEREMONY_PID" 2>/dev/null || true' EXIT

echo "==> waiting for the ceremony to finish key generation"
for _ in $(seq 1 60); do
  grep -q "bundle ready" /tmp/pq-demo.log 2>/dev/null && break
  sleep 0.5
done
grep -q "bundle ready" /tmp/pq-demo.log || { echo "ceremony never became ready"; cat /tmp/pq-demo.log; exit 1; }

echo "==> fetching /bundle.json from the (mock) enclave"
curl -fsS "http://127.0.0.1:$PORT/bundle.json" -o "$BUNDLE"

echo "==> pq inspect"
target/debug/pq inspect --bundle "$BUNDLE"

echo
echo "Local demo OK. The bundle is real in shape but mock in attestation."
echo "Deploy to Caution for a genuine NSM quote, then: pq stamp / pq verify."
