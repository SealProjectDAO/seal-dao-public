#!/usr/bin/env bash
# scripts/measure-ringtail-cost.sh — host-side cost projection for
# the on-chain Ringtail verify path.
#
# Runs the example binary in `seal-ringtail-verify`, captures its
# output, and writes a snapshot under `target/ringtail-cost/`. Use
# this *before* the full bridge-test-ringtail.sh run to sanity-check
# the verify-path cost without spinning up Solana/Stellar local
# nets.
#
# Output:
#   target/ringtail-cost/host-projection.txt   (timing + projected CU/insns)
#   target/ringtail-cost/host-projection.csv   (one row per run, append-only)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="target/ringtail-cost"
mkdir -p "$OUT_DIR"

OUT_TXT="$OUT_DIR/host-projection.txt"
OUT_CSV="$OUT_DIR/host-projection.csv"

echo "==> Building seal-ringtail-verify example (release) ..."
cargo run --example measure_verify_cost \
    --features std-crosscheck \
    -p seal-ringtail-verify \
    --release 2>&1 | tee "$OUT_TXT"

# Pull the per-call µs out of the captured output for the CSV.
US_PER_CALL=$(grep -oE '\([0-9]+\.[0-9]+ µs/call\)' "$OUT_TXT" | head -1 | grep -oE '[0-9]+\.[0-9]+')
BPF_CU=$(grep -oE 'Projected Solana BPF cost  : ~[0-9]+ CU' "$OUT_TXT" | grep -oE '[0-9]+')
SOROBAN_INSTR=$(grep -oE 'Projected Soroban cost     : ~[0-9]+ instructions' "$OUT_TXT" | grep -oE '[0-9]+')

if [[ ! -f "$OUT_CSV" ]]; then
    echo "timestamp_unix,host_us_per_call,projected_bpf_cu,projected_soroban_insns" > "$OUT_CSV"
fi
echo "$(date +%s),${US_PER_CALL:-NA},${BPF_CU:-NA},${SOROBAN_INSTR:-NA}" >> "$OUT_CSV"

echo
echo "==> Wrote:"
echo "    $OUT_TXT"
echo "    $OUT_CSV  (append-only history)"
echo
echo "Next: ./scripts/bridge-test-ringtail.sh for real on-chain CU."
