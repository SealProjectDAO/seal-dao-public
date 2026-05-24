#!/usr/bin/env bash
# scripts/cuda-bringup.sh — first-run validation for CUDA-accelerated
# segment STARK proving on the RTX 6000 host.
#
# Run this on the RTX 6000 box (Linux x86_64, NVIDIA driver + CUDA
# toolkit installed) to confirm the risc0 cuda backend produces a
# real non-dev-mode receipt for the same guest the M-series CPU run
# measured at 10.9 s / 657 MB peak RSS / 205 842-byte receipt.
#
# This is **not a testnet-launch gate** (confirmed 2026-05-10 with
# the user). CUDA STARK proving is a STATUS row 7/8 first-number
# on the GPU host — testnet ships without it. The script lives
# here so the RTX 6000 host can run it without surprises; the
# parsed metrics get pasted into STATUS.md's "Real CPU vs GPU
# proving" line once they exist.
#
# # Required hosts / deps
#
# - Linux x86_64 (the script bails on non-Linux at sanity-check 0).
# - NVIDIA driver providing `nvidia-smi` on PATH.
# - `nvcc` is recommended but not required — risc0 vendors `cust`
#   for CUDA dispatch, but the toolkit is useful for diagnostics
#   and is checked with a warning rather than an exit.
# - `rustc` / `cargo` (any toolchain that the workspace `cargo
#   build` accepts).
# - `/usr/bin/time` (GNU time) is preferred for peak-RSS capture;
#   bash builtin `time` is used as a fallback but yields
#   `peak_rss_kb=NA` because the builtin doesn't expose RSS.
#
# # Output paths
#
# All under `target/cuda-bringup/` (created if missing):
#
#   host-info.txt   nvidia-smi + nvcc + rustc/cargo versions snapshot
#   results.txt     build log + prove log + parsed metrics block
#   time.log        GNU /usr/bin/time -v output (only when present)
#   results.csv     append-only history, one row per run
#
# `results.csv` columns (header written on first run):
#
#   timestamp_unix    seconds-since-epoch when this run completed
#   wall_seconds      Elapsed wall-clock for `cargo test … --exact …
#                     test_risc0_full_pipeline` (NA if /usr/bin/time
#                     was unavailable and the bash builtin's output
#                     couldn't be parsed)
#   peak_rss_kb       Maximum resident set size in KiB (NA if no
#                     /usr/bin/time)
#   receipt_bytes     Size of the non-dev-mode STARK receipt the
#                     guest emitted, parsed from stdout (NA if the
#                     test didn't print a receipt-size line)
#   gpu_name          `nvidia-smi --query-gpu=name` (or "unknown")
#
# The script is idempotent — re-running just appends a new CSV row.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUT_DIR="target/cuda-bringup"
mkdir -p "$OUT_DIR"

HOST_INFO="$OUT_DIR/host-info.txt"
RESULTS_TXT="$OUT_DIR/results.txt"
RESULTS_CSV="$OUT_DIR/results.csv"

# ── 0. sanity-check host ──────────────────────────────────────────────

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: cuda-bringup expects Linux (got $(uname -s))." >&2
    echo "       The risc0 cuda backend has no macOS/Windows path today." >&2
    exit 2
fi

if ! command -v nvidia-smi >/dev/null 2>&1; then
    echo "error: nvidia-smi not on PATH — install the NVIDIA driver first." >&2
    exit 2
fi

if ! command -v nvcc >/dev/null 2>&1; then
    echo "warning: nvcc not on PATH — risc0 builds bring their own CUDA via" >&2
    echo "         cust, but you'll usually want CUDA toolkit installed too." >&2
fi

{
    echo "=== cuda-bringup host snapshot ==="
    date -u +"%Y-%m-%dT%H:%M:%SZ"
    echo
    echo "--- uname -a ---"
    uname -a
    echo
    echo "--- nvidia-smi ---"
    nvidia-smi || true
    echo
    echo "--- nvcc --version ---"
    nvcc --version 2>/dev/null || echo "(nvcc not installed)"
    echo
    echo "--- rustc / cargo ---"
    rustc --version
    cargo --version
} > "$HOST_INFO"

echo "==> Host snapshot written to $HOST_INFO"

# ── 1. build + run the prove pipeline test under CUDA ────────────────

# Pinning CUDA_VISIBLE_DEVICES=0 keeps multi-GPU hosts deterministic;
# unset to let risc0 pick. RISC0_DEV_MODE=0 forces a real STARK proof
# (otherwise risc0 emits a dev-mode 361-byte receipt in 0.02 s, which
# does not exercise the CUDA segment prover).
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"
export RISC0_DEV_MODE=0
export RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"  # 16 MB — local-prover guidance

# Build first so wall-time only covers the prove run, not compile.
echo "==> Building seal-zk with cuda features (release) ..."
{
    echo "=== build ($(date -u +%FT%TZ)) ==="
    cargo build \
        -p seal-zk \
        --release \
        --features "risc0 local-prover risc0-zkvm/cuda gpu-cuda" \
        --tests
} 2>&1 | tee "$RESULTS_TXT"

# Run only test_risc0_full_pipeline — that's the canonical end-to-end
# prove path and matches the 10.9 s CPU baseline run from 2026-04-19.
echo "==> Running test_risc0_full_pipeline under CUDA ..."

# Capture wall-time + peak RSS via `time`. GNU time prefers `\time`
# to bypass the shell builtin; on hosts without /usr/bin/time we fall
# back to the bash `time` builtin, but the bash builtin doesn't
# expose peak RSS — the parsed_rss_kb column will be NA in that case.
TIME_LOG="$OUT_DIR/time.log"
rm -f "$TIME_LOG"

if command -v /usr/bin/time >/dev/null 2>&1; then
    /usr/bin/time -v -o "$TIME_LOG" \
        cargo test \
            -p seal-zk \
            --release \
            --features "risc0 local-prover risc0-zkvm/cuda gpu-cuda" \
            -- --exact --nocapture test_risc0_full_pipeline \
        2>&1 | tee -a "$RESULTS_TXT"
else
    { time \
        cargo test \
            -p seal-zk \
            --release \
            --features "risc0 local-prover risc0-zkvm/cuda gpu-cuda" \
            -- --exact --nocapture test_risc0_full_pipeline ; \
    } 2>&1 | tee -a "$RESULTS_TXT"
fi

# ── 2. parse metrics ──────────────────────────────────────────────────

# Wall-time: GNU `time -v` reports "Elapsed (wall clock) time" as
# H:MM:SS or M:SS. Convert to seconds.
WALL_S=NA
PEAK_RSS_KB=NA
RECEIPT_BYTES=NA

if [[ -s "$TIME_LOG" ]]; then
    WALL_RAW=$(grep -E "Elapsed \(wall clock\) time" "$TIME_LOG" \
        | awk -F': ' '{print $NF}' || true)
    if [[ -n "${WALL_RAW:-}" ]]; then
        # Parse H:MM:SS / M:SS / SS.
        WALL_S=$(awk -v t="$WALL_RAW" 'BEGIN{
            n=split(t,a,":"); s=0;
            if (n==3) s=a[1]*3600+a[2]*60+a[3];
            else if (n==2) s=a[1]*60+a[2];
            else s=a[1];
            printf "%.2f", s
        }')
    fi
    PEAK_RSS_KB=$(grep -E "Maximum resident set size" "$TIME_LOG" \
        | awk -F': ' '{print $NF}' | tr -d ' ' || echo NA)
fi

# Receipt size: the test prints something like "non-dev-mode receipt:
# 205842 bytes" in the CPU baseline. Try a few likely shapes.
RECEIPT_BYTES=$(grep -oE 'receipt[^0-9]*([0-9]{4,})[[:space:]]*bytes' "$RESULTS_TXT" \
    | grep -oE '[0-9]{4,}' | head -1 || echo NA)

{
    echo
    echo "=== parsed metrics ==="
    echo "wall_seconds        : ${WALL_S}"
    echo "peak_rss_kb         : ${PEAK_RSS_KB}"
    echo "receipt_bytes       : ${RECEIPT_BYTES:-NA}"
    echo "cpu_baseline_seconds: 10.9   (M-series, 2026-04-19)"
    echo "cpu_baseline_rss_kb : 672768  (657 MB, 2026-04-19)"
    echo "cpu_baseline_bytes  : 205842"
} | tee -a "$RESULTS_TXT"

if [[ ! -f "$RESULTS_CSV" ]]; then
    echo "timestamp_unix,wall_seconds,peak_rss_kb,receipt_bytes,gpu_name" > "$RESULTS_CSV"
fi
GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null \
    | head -1 | tr -d ',' | tr -s ' ' | sed 's/^ *//;s/ *$//' || echo unknown)
echo "$(date +%s),${WALL_S},${PEAK_RSS_KB},${RECEIPT_BYTES:-NA},${GPU_NAME}" >> "$RESULTS_CSV"

echo
echo "==> Wrote:"
echo "    $HOST_INFO"
echo "    $RESULTS_TXT"
echo "    $RESULTS_CSV  (append-only history)"
echo
echo "Next: paste the parsed-metrics block into STATUS.md's"
echo "      'Real CPU vs GPU proving' section (the one that today"
echo "      reads 'no longer hardware-blocked … bring-up:"
echo "      ./scripts/cuda-bringup.sh') so the row carries the"
echo "      first GPU wall-time / receipt-size numbers."
