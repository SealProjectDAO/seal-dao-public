#!/usr/bin/env bash
# Seal DAO KMS Sidecar — reproducible build + binary signing
#
# Usage:
#   kms-sidecar-sign.sh build [--output-dir DIR]     # build, hash, sign
#   kms-sidecar-sign.sh verify <binary> <sig-file>    # verify signature + hash
#
# Artifacts:
#   kms-sidecar        — compiled binary
#   kms-sidecar.sha384 — SHA3-384 content hash of binary
#   kms-sidecar.sig    — Ed25519 signature of binary
#   kms-sidecar.pub    — PEM public key (for operator verification)
#
# Prerequisites: openssl (for SHA3), cargo, python3 + cryptography
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$REPO_ROOT/dist"

# ── helpers ────────────────────────────────────────────────────────────

# sign_or_verify_ed25519 — Python script for Ed25519 sign/verify.
# Ed25519 is not supported by openssl dgst/pkeyutl CLI in OpenSSL 3.0.
#
# Usage: sign   <hex_seed_32b> <hex_pubkey_32b> <input_file> <output_sig>
#        verify  <hex_pubkey_32b> <input_file> <sig_file>
# Exit 0 on success, 1 on failure (no stdout).
_ed25519_op() {
    local op="$1"
    shift
    python3 - "$op" "$@" <<'PYEOF'
import sys, os

def main():
    op = sys.argv[1]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization

    if op == "sign":
        # args: hex_seed hex_pubkey input_file output_sig
        seed_hex, pub_hex, infile, sigfile = sys.argv[2:]
        seed = bytes.fromhex(seed_hex)
        priv = Ed25519PrivateKey.from_private_bytes(seed)
        data = open(infile, "rb").read()
        sig = priv.sign(data)
        open(sigfile, "wb").write(sig)

    elif op == "verify":
        # args: hex_pubkey input_file sig_file
        pub_hex, infile, sigfile = sys.argv[2:]
        pubkey_bytes = bytes.fromhex(pub_hex)
        pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
        data = open(infile, "rb").read()
        sig = open(sigfile, "rb").read()
        pubkey.verify(sig, data)  # raises on mismatch
    else:
        sys.exit(1)

main()
PYEOF
}

# pubkey_from_seed — extract public key from seed hex
_pubkey_from_seed() {
    local seed_hex="$1"
    python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex('${seed_hex}'))
print(priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
).hex())
"
}

# PEM from public key hex
_pubkey_pem() {
    local pub_hex="$1"
    python3 -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex('${pub_hex}'))
import sys
sys.stdout.buffer.write(pub.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
))
"
}

usage() {
    cat <<EOF
Usage: $(basename "$0") <command> [options]

Commands:
  build [--output-dir DIR]    Build, hash, and sign the KMS sidecar binary
  verify <binary> <sig-file>  Verify binary signature and integrity

Environment:
  KMS_SIGNING_KEY     Hex-encoded Ed25519 key (64 bytes / 128 hex chars)
                       First 64 hex = seed (32B), last 64 hex = public key (32B)
  KMS_VERIFY_PUBKEY   Hex-encoded Ed25519 public key (32 bytes / 64 hex chars)
                       For 'verify'. Defaults to seed's derived public key.
EOF
}

# ── commands ───────────────────────────────────────────────────────────

cmd_build() {
    local output_dir="$OUTPUT_DIR"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --output-dir) output_dir="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    mkdir -p "$output_dir"

    # Step 1: Deterministic build
    RUSTFLAGS="-C link-args=-Wl,--build-id=none" \
        CARGO_INCREMENTAL=0 \
        cargo build --release -p seal-kms-sidecar --quiet

    local bin="$REPO_ROOT/target/release/seal-kms-sidecar"
    cp "$bin" "$output_dir/kms-sidecar"

    # Step 2: Compute SHA3-384 content hash
    local sha_hex
    sha_hex=$(openssl dgst -sha384 -binary "$output_dir/kms-sidecar" \
              | xxd -p | tr -d '\n')
    echo "$sha_hex  kms-sidecar" > "$output_dir/kms-sidecar.sha384"

    # Step 3: Sign with Ed25519
    if [[ -z "${KMS_SIGNING_KEY:-}" ]]; then
        echo "ERROR: KMS_SIGNING_KEY not set."
        echo "Set to hex-encoded Ed25519 seed (32B) + public key (32B) = 128 hex chars."
        exit 1
    fi

    local seed_hex="${KMS_SIGNING_KEY:0:64}"
    local pub_hex="${KMS_SIGNING_KEY:64:64}"

    _ed25519_op sign "$seed_hex" "$pub_hex" \
        "$output_dir/kms-sidecar" "$output_dir/kms-sidecar.sig"

    # Step 4: Save public key as PEM
    _pubkey_pem "$pub_hex" > "$output_dir/kms-sidecar.pub"

    echo "Build complete. Artifacts in $output_dir:"
    echo "  kms-sidecar      — compiled binary"
    echo "  kms-sidecar.sha384 — content hash (SHA3-384)"
    echo "  kms-sidecar.sig    — binary signature (Ed25519)"
    echo "  kms-sidecar.pub    — public key (PEM)"

    # Step 5: Self-verify
    if _ed25519_op verify "$pub_hex" \
        "$output_dir/kms-sidecar" "$output_dir/kms-sidecar.sig" 2>/dev/null; then
        echo "  Self-verification: OK"
    else
        echo "  Self-verification: FAILED (check signing key)"
        exit 1
    fi
}

cmd_verify() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: $(basename "$0") verify <binary> <sig-file>"
        exit 1
    fi

    local binary="$1"
    local sig_file="$2"

    if [[ ! -f "$binary" ]]; then
        echo "ERROR: binary not found: $binary"
        exit 1
    fi

    if [[ ! -f "$sig_file" ]]; then
        echo "ERROR: signature file not found: $sig_file"
        exit 1
    fi

    # Resolve public key hex
    local pub_hex=""
    if [[ -n "${KMS_VERIFY_PUBKEY:-}" ]]; then
        pub_hex="$KMS_VERIFY_PUBKEY"
    elif [[ -n "${KMS_SIGNING_KEY:-}" ]]; then
        pub_hex="${KMS_SIGNING_KEY:64:64}"
    elif [[ -f "${binary}.pub" ]]; then
        # Derive hex from PEM public key
        pub_hex=$(python3 -c "
from cryptography.hazmat.primitives import serialization
pem = open('${binary}.pub', 'rb').read()
pub = serialization.load_pem_public_key(pem)
print(pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
).hex())
" 2>/dev/null) || {
            echo "ERROR: failed to extract public key from ${binary}.pub"
            exit 1
        }
    fi

    if [[ -z "$pub_hex" ]]; then
        echo "ERROR: no public key available. Set KMS_VERIFY_PUBKEY or provide ${binary}.pub"
        exit 1
    fi

    # Verify signature
    if _ed25519_op verify "$pub_hex" "$binary" "$sig_file" 2>/dev/null; then
        echo "Signature verification: OK"
    else
        echo "Signature verification: FAILED"
        exit 1
    fi

    # Verify content hash if available
    local sha_file="${binary}.sha384"
    if [[ -f "$sha_file" ]]; then
        local expected_hash actual_hash
        expected_hash=$(awk '{print $1}' "$sha_file")
        actual_hash=$(openssl dgst -sha384 -binary "$binary" | xxd -p | tr -d '\n')
        if [[ "$expected_hash" == "$actual_hash" ]]; then
            echo "Content hash verification: OK"
        else
            echo "Content hash verification: FAILED"
            echo "  expected: $expected_hash"
            echo "  actual:   $actual_hash"
            exit 1
        fi
    else
        echo "No .sha384 file found — skipping content hash check"
    fi

    echo "Binary $binary is authenticated."
}

# ── main ───────────────────────────────────────────────────────────────

[[ $# -lt 1 ]] && { usage; exit 1; }

case "$1" in
    build)    shift; cmd_build "$@" ;;
    verify)   shift; cmd_verify "$@" ;;
    -h|--help|help) usage; exit 0 ;;
    *)        echo "Unknown command: $1"; usage; exit 1 ;;
esac
