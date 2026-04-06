#!/bin/bash
# Extract seal-merkle Rust code to Lean 4 using Charon + Aeneas.
#
# Prerequisites:
#   cargo install --git https://github.com/AeneasVerif/charon
#   cargo install --git https://github.com/AeneasVerif/aeneas
#
# Usage:
#   ./scripts/aeneas-extract.sh                    # Extract seal-merkle
#   ./scripts/aeneas-extract.sh --crate seal-crypto # Extract a different crate
#
# Output:
#   formal/lean/SealVerify/Aeneas/  — Generated Lean 4 files

set -e

CRATE=${2:-seal-merkle}
LLBC_DIR="formal/lean/SealVerify/Aeneas"
DEST_DIR="formal/lean/SealVerify/Aeneas"

echo "═══════════════════════════════════════════"
echo "  Aeneas Extraction Pipeline"
echo "  Crate: $CRATE"
echo "═══════════════════════════════════════════"
echo ""

# ── Step 1: Check prerequisites ────────────────
echo "── Step 1: Check prerequisites ──"

if ! command -v charon > /dev/null 2>&1; then
    echo "[ERROR] charon not found."
    echo "Install with:"
    echo "  cargo install --git https://github.com/AeneasVerif/charon"
    exit 1
fi

if ! command -v aeneas > /dev/null 2>&1; then
    echo "[ERROR] aeneas not found."
    echo "Install with:"
    echo "  cargo install --git https://github.com/AeneasVerif/aeneas"
    exit 1
fi

echo "  charon: $(charon --version 2>/dev/null || echo 'installed')"
echo "  aeneas: $(aeneas --version 2>/dev/null || echo 'installed')"
echo ""

# ── Step 2: Run Charon (Rust → ULLBC) ──────────
echo "── Step 2: Run Charon (Rust MIR → ULLBC) ──"

mkdir -p "$LLBC_DIR"

echo "  Compiling $CRATE to ULLBC..."
charon \
    --crate "$CRATE" \
    --input "crates/$CRATE" \
    --dest "$LLBC_DIR" \
    2>&1 | tail -10

LLBC_FILE="$LLBC_DIR/${CRATE//-/_}.llbc"
if [ ! -f "$LLBC_FILE" ]; then
    echo "[ERROR] LLBC file not generated: $LLBC_FILE"
    exit 1
fi
echo "  Generated: $LLBC_FILE ($(du -h "$LLBC_FILE" | cut -f1))"
echo ""

# ── Step 3: Run Aeneas (ULLBC → Lean 4) ────────
echo "── Step 3: Run Aeneas (ULLBC → Lean 4) ──"

echo "  Extracting $CRATE to Lean 4..."
aeneas \
    "$LLBC_FILE" \
    --backend lean \
    --dest "$DEST_DIR" \
    2>&1 | tail -10

# Count generated files
LEAN_COUNT=$(find "$DEST_DIR" -name "*.lean" -not -name "Aeneas.lean" | wc -l | tr -d ' ')
echo "  Generated $LEAN_COUNT Lean 4 files in $DEST_DIR/"
echo ""

# ── Step 4: Verify Lean build ──────────────────
echo "── Step 4: Verify Lean 4 build ──"

cd formal/lean
if lake build 2>&1 | tail -5; then
    SORRY_COUNT=$(grep -r "sorry" SealVerify/ 2>/dev/null | wc -l | tr -d ' ')
    echo "  Build successful ($SORRY_COUNT sorries remaining)"
else
    echo "  [WARN] Build failed — may need manual fixup of generated code"
fi

echo ""
echo "═══════════════════════════════════════════"
echo "  Extraction complete!"
echo ""
echo "  Next steps:"
echo "  1. Review generated files in $DEST_DIR/"
echo "  2. Update SealVerify/Aeneas.lean to import generated definitions"
echo "  3. Replace sorry proofs with real proofs using extracted types"
echo "═══════════════════════════════════════════"
