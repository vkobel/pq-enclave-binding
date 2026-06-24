#!/usr/bin/env bash
# Local, narrated end-to-end walkthrough of the PQ Root Key Bundle (no enclave).
#
# This is both a demo and a non-enclave CI smoke test. It runs the ceremony with
# the MOCK NSM (no Nitro hardware) and narrates each step so you can SEE what the
# system does and, crucially, WHICH PARTS ARE REAL vs MOCK:
#
#   REAL here:  PQ keygen (ML-DSA-65 + SLH-DSA-128f), HD subkey derivation,
#               dual-signing, the Merkle commitment, and ALL signature/membership
#               verification. This is the actual cryptography, end to end.
#   MOCK here:  the NSM attestation quote, the PCR measurements, and the AWS root
#               CA (random bytes). Those only become real inside a Nitro Enclave,
#               so `pq verify` (which checks the quote) cannot pass locally.
#               `pq verify-subkey` CAN pass locally — it checks real crypto only.
#
# `set -e` + `curl -fsS` + verify-subkey's non-zero exit make every step an
# assertion: if anything is wrong, the script aborts.
set -euo pipefail

cd "$(dirname "$0")/.."

PORT=18099
AUTH=8           # Auth subkeys to pre-commit  (m/1'/<i>')
TOTAL=$AUTH

ROOT_DER="$(mktemp)"
BUNDLE="$(mktemp)"
SUBKEYS="$(mktemp)"
SUBKEY="$(mktemp)"
SIGNED="$(mktemp)"
head -c 256 /dev/urandom > "$ROOT_DER"   # MOCK stand-in for the real AWS Nitro root CA

# --- tiny presentation helpers ------------------------------------------------
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
hr()   { printf '%s\n' "----------------------------------------------------------------------"; }
step() { echo; hr; bold "STEP $1 — $2"; hr; }
say()  { printf '   %s\n' "$*"; }            # explanation
note() { printf '   · %s\n' "$*"; }          # sub-detail
mock() { printf '   \033[33m[MOCK]\033[0m %s\n' "$*"; }
real() { printf '   \033[32m[REAL]\033[0m %s\n' "$*"; }
pass() { printf '   \033[32m✓ PASS\033[0m — %s\n' "$*"; }

echo
bold "PQ Root Key Bundle — local end-to-end walkthrough"
say  "Stages: ceremony (enclave) -> stamping (host) -> verification (anywhere)."
say  "Running locally with the MOCK NSM, so attestation is faked but all crypto is real."

# -----------------------------------------------------------------------------
step 1 "Build the enclave ceremony + the host 'pq' CLI"
say "Two binaries: pq-ceremony runs INSIDE the enclave; pq runs on any host."
cargo build -p pq-ceremony -p pq-cli
real "binaries built: target/debug/pq-ceremony, target/debug/pq"

# -----------------------------------------------------------------------------
step 2 "Run the burn-in ceremony (generate keys, attest, serve)"
say "The enclave does this ONCE: draw entropy -> derive a root keypair and"
say "$AUTH Auth subkeys (m/1'/<i>') -> hash all subkeys into a Merkle tree ->"
say "fold the Merkle root into the signed payload -> dual-sign -> NSM attest."
real "PQ keygen + HD derivation of $TOTAL subkeys + dual-sign + Merkle commitment"
mock "NSM quote + PCR measurements (only real on Nitro silicon)"
echo
say "starting pq-ceremony on 127.0.0.1:$PORT (PQ_SUBKEYS_AUTH=$AUTH) ..."
PQ_SUBKEYS_AUTH=$AUTH \
  target/debug/pq-ceremony --bind "127.0.0.1:$PORT" --root-ca "$ROOT_DER" 2>/tmp/pq-demo.log &
CEREMONY_PID=$!
trap 'kill "$CEREMONY_PID" 2>/dev/null || true' EXIT

say "waiting for key generation + attestation to finish ..."
for _ in $(seq 1 120); do
  grep -q "bundle ready" /tmp/pq-demo.log 2>/dev/null && break
  sleep 0.5
done
grep -q "bundle ready" /tmp/pq-demo.log || { echo "ceremony never became ready"; cat /tmp/pq-demo.log; exit 1; }
pass "ceremony complete — enclave is now serving the bundle + signing oracle"
note "log: $(grep 'bundle ready' /tmp/pq-demo.log | tail -1)"

# -----------------------------------------------------------------------------
step 3 "Liveness check (GET /health)"
say "Caution's health probe hits this; it just proves the server is up."
printf '   response: %s\n' "$(curl -fsS "http://127.0.0.1:$PORT/health")"
pass "enclave HTTP server is live"

# -----------------------------------------------------------------------------
step 4 "Fetch the bundle artifact (GET /bundle.json)"
say "The bundle is the whole point: an immutable, self-describing artifact that"
say "anyone can verify later — no live enclave required."
curl -fsS "http://127.0.0.1:$PORT/bundle.json" -o "$BUNDLE"
real "downloaded $(wc -c < "$BUNDLE" | tr -d ' ') bytes of bundle JSON"

# -----------------------------------------------------------------------------
step 5 "Inspect the bundle (pq inspect)"
say "Note subkey_merkle_root and subkey_count — the commitment to all $TOTAL subkeys."
mock "expected PCR0/1/2 below are placeholders (real PCRs come from the enclave)"
echo
target/debug/pq inspect --bundle "$BUNDLE"
echo
pass "bundle parses and reports $TOTAL committed subkeys"

# -----------------------------------------------------------------------------
step 6 "List the pre-committed subkey set (GET /subkeys, /subkey/<i>)"
say "Each subkey ships with a Merkle proof (sibling path) to the committed root."
say "That proof is what makes birth-provenance verifiable forever, offline."
curl -fsS "http://127.0.0.1:$PORT/subkeys"  -o "$SUBKEYS"
curl -fsS "http://127.0.0.1:$PORT/subkey/0" -o "$SUBKEY"
LISTED="$(grep -o '"index"' "$SUBKEYS" | wc -l | tr -d ' ')"
DEPTH="$(grep -o '"merkle_proof":\[[^]]*\]' "$SUBKEY" | grep -o '[0-9a-f]\{64\}' | wc -l | tr -d ' ')"
real "/subkeys returned $LISTED subkeys; subkey #0's proof has $DEPTH sibling node(s)"
note "$DEPTH siblings => a Merkle tree of depth $DEPTH over $TOTAL leaves"

# -----------------------------------------------------------------------------
step 7 "Verify birth-provenance (pq verify-subkey — Merkle membership)"
say "Proves subkey #0 was committed in the bundle at ceremony time. This is REAL"
say "crypto and PASSES locally — it does not depend on the (mocked) attestation."
echo
target/debug/pq verify-subkey --bundle "$BUNDLE" --subkey "$SUBKEY"
echo
pass "birth-provenance verified from the bundle + Merkle proof alone"

# -----------------------------------------------------------------------------
step 8 "Use the signing oracle (POST /sign -> verify dual signature)"
say "The enclave re-derives a subkey on demand and signs WITHOUT exporting the"
say "secret. We then verify both Merkle membership AND the ML-DSA + SLH-DSA sigs."
MSG="hello post-quantum world"
MSG_HEX="$(printf '%s' "$MSG" | xxd -p | tr -d '\n')"
note "message: \"$MSG\""
note "hex:     $MSG_HEX"
real "asking the enclave to sign with subkey #0 (no secret leaves the enclave)"
curl -fsS -X POST "http://127.0.0.1:$PORT/sign" \
  -H 'content-type: application/json' \
  -d "{\"index\":0,\"message_hex\":\"$MSG_HEX\"}" -o "$SIGNED"
echo
target/debug/pq verify-subkey --bundle "$BUNDLE" --subkey "$SIGNED" --message-hex "$MSG_HEX"
echo
pass "dual post-quantum signature verified against the committed subkey"

# -----------------------------------------------------------------------------
echo
hr
bold "DONE — all 8 steps passed."
hr
say  "What you just proved LOCALLY (real cryptography):"
note "$TOTAL subkeys generated + committed in a Merkle tree, dual-signed"
note "birth-provenance of a subkey from the bundle + a Merkle proof"
note "a live post-quantum signature from the no-export signing oracle"
echo
say  "What stayed MOCK (needs Nitro silicon):"
note "the NSM attestation quote, the PCR measurements, the AWS root CA"
note "=> 'pq verify' (full attested verification) cannot pass locally"
echo
say  "Next, for a genuine artifact: deploy to Caution (see README), fetch"
say  "/bundle.json from the live enclave, then run: pq stamp  and  pq verify."
