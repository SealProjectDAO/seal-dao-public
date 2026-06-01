#!/usr/bin/env bash
# scripts/release.sh — Seal DAO release builder.
#
# Produces:
#   dist/seal-node-${VERSION}-linux-x86_64
#   dist/seal-node-${VERSION}-linux-aarch64
#   dist/seal-node-${VERSION}-darwin-aarch64   (only on macOS hosts)
#   dist/SHA256SUMS                            (one line per binary)
#   dist/SHA256SUMS.sig                        (ML-DSA-65 detached sig)
#   dist/SHA256SUMS.sig.pubkey                 (verifying-key hex)
#   dist/seal-node-${VERSION}.tar.gz           (binaries + sums + sig)
#
# Plus a Docker image tagged ghcr.io/seal-dao/seal-node:${VERSION}.
#
# Per CLAUDE.md the project is post-quantum first; classical
# sigstore / minisign would contradict that, so we ML-DSA-sign the
# SHA256SUMS file via `seal sign-file`.
#
# Usage:
#
#   ./scripts/release.sh [--version v0.1.0] [--key release-key.json]
#
# Defaults:
#   --version   parsed from `git describe --tags --always`
#   --key       ./release-key.json
#
# Default mode is **dry-run** — nothing leaves the host. To
# actually push the Docker image to ghcr.io and (in the future)
# upload artifacts to a release channel, set RELEASE_PUBLISH=1:
#
#   RELEASE_PUBLISH=1 ./scripts/release.sh --version v0.1.0
#
# Hosts:
#   - Linux x86_64 build runs in `rust:1.94-bookworm` container
#   - Linux ARM64  build runs in `rust:1.94-bookworm` --platform=linux/arm64
#   - macOS ARM64 build runs natively on Apple Silicon (the Linux
#     paths skipped if the host is Linux)
#
# Exit codes:
#   0  success
#   1  preflight failure
#   2  build failure
#   3  signing failure
#   4  Docker build / push failure

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

color() { printf '\033[%sm%s\033[0m\n' "$1" "${*:2}"; }
info() { color "36" "==> $*"; }
pass() { color "32" "[ok] $*"; }
fail() { color "31" "[!!] $*" >&2; }

# ── Args ────────────────────────────────────────────────

VERSION=""
KEY_FILE="release-key.json"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            VERSION="$2"; shift 2;;
        --key)
            KEY_FILE="$2"; shift 2;;
        --help|-h)
            head -40 "$0" | sed 's/^# \{0,1\}//'; exit 0;;
        *)
            fail "unknown arg: $1"; exit 1;;
    esac
done

if [[ -z "$VERSION" ]]; then
    VERSION="$(git describe --tags --always 2>/dev/null || echo dev)"
fi

DIST_DIR="$REPO_ROOT/dist"
mkdir -p "$DIST_DIR"

PUBLISH="${RELEASE_PUBLISH:-0}"
HOST_OS="$(uname -s)"
DOCKER_TAG="ghcr.io/seal-dao/seal-node:$VERSION"

info "Building Seal DAO release artifacts for $VERSION"
info "  dist dir:     $DIST_DIR"
info "  release key:  $KEY_FILE"
info "  publish:      $PUBLISH (default 0 = dry-run)"
info "  host OS:      $HOST_OS"

# ── Preflight ────────────────────────────────────────────

require() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "missing dependency: $1"
        exit 1
    fi
}

require cargo
require shasum  # macOS / Linux both ship `shasum` from Perl
require docker
require tar

if [[ ! -f "$KEY_FILE" ]]; then
    fail "release key file not found: $KEY_FILE"
    fail "  generate one with: cargo run -p seal-cli -- keygen --output $KEY_FILE"
    fail "  back it up — losing it means you can't sign future releases under the same identity"
    exit 1
fi

# ── 1. Build seal-node for each target ───────────────────

# Linux x86_64 (cross-compile via Docker so the artifact is
# byte-deterministic regardless of host).
build_linux_amd64() {
    info "Building linux-x86_64 (rust:1.94-bookworm)"
    docker run --rm \
        --platform linux/amd64 \
        -v "$REPO_ROOT":/app \
        -w /app \
        rust:1.94-bookworm \
        cargo build --release -p seal-node --target-dir target/release-linux-amd64
    cp "target/release-linux-amd64/release/seal-node" \
       "$DIST_DIR/seal-node-${VERSION}-linux-x86_64"
    pass "linux-x86_64"
}

build_linux_arm64() {
    info "Building linux-aarch64 (rust:1.94-bookworm --platform=linux/arm64)"
    docker run --rm \
        --platform linux/arm64 \
        -v "$REPO_ROOT":/app \
        -w /app \
        rust:1.94-bookworm \
        cargo build --release -p seal-node --target-dir target/release-linux-arm64
    cp "target/release-linux-arm64/release/seal-node" \
       "$DIST_DIR/seal-node-${VERSION}-linux-aarch64"
    pass "linux-aarch64"
}

build_darwin_arm64() {
    if [[ "$HOST_OS" != "Darwin" ]]; then
        info "Skipping darwin-aarch64 (host is $HOST_OS, not Apple Silicon)"
        return 0
    fi
    info "Building darwin-aarch64 (host)"
    cargo build --release -p seal-node --target-dir target/release-darwin-arm64
    cp "target/release-darwin-arm64/release/seal-node" \
       "$DIST_DIR/seal-node-${VERSION}-darwin-aarch64"
    pass "darwin-aarch64"
}

build_linux_amd64
build_linux_arm64
build_darwin_arm64

# ── 2. SHA256SUMS ────────────────────────────────────────

info "Computing SHA256SUMS"
(
    cd "$DIST_DIR"
    # Sort filenames for deterministic line order — two builds of the
    # same source tree should produce byte-identical SHA256SUMS files.
    # `shasum -a 256` matches the GNU `sha256sum` line format.
    shasum -a 256 seal-node-${VERSION}-* | sort > SHA256SUMS
)
pass "SHA256SUMS written"

# ── 3. ML-DSA-sign SHA256SUMS ────────────────────────────

info "Signing SHA256SUMS with $KEY_FILE (ML-DSA-65, PQC-native)"
cargo run --quiet --release -p seal-cli -- \
    sign-file "$DIST_DIR/SHA256SUMS" \
    --key "$KEY_FILE" \
    --out "$DIST_DIR/SHA256SUMS.sig" \
    >/dev/null
if [[ ! -s "$DIST_DIR/SHA256SUMS.sig" ]]; then
    fail "sign-file did not produce a non-empty signature"
    exit 3
fi
pass "SHA256SUMS.sig + SHA256SUMS.sig.pubkey written"

# Sanity-check: re-verify locally so we don't ship a sig that
# doesn't verify against its own pubkey.
PUBKEY_HEX="$(cat "$DIST_DIR/SHA256SUMS.sig.pubkey")"
if ! cargo run --quiet --release -p seal-cli -- \
        verify-file "$DIST_DIR/SHA256SUMS" \
        --pubkey-hex "$PUBKEY_HEX" \
        --sig-file "$DIST_DIR/SHA256SUMS.sig" \
        >/dev/null; then
    fail "post-sign verify failed; refusing to ship an unverifiable signature"
    exit 3
fi
pass "post-sign verify OK"

# ── 4. Tarball the binaries + sums + sig ─────────────────

info "Creating distribution tarball"
TARBALL="$DIST_DIR/seal-node-${VERSION}.tar.gz"
(
    cd "$DIST_DIR"
    # Include only the release artifacts; not target/ noise.
    tar -czf "$TARBALL" \
        seal-node-${VERSION}-* \
        SHA256SUMS \
        SHA256SUMS.sig \
        SHA256SUMS.sig.pubkey
)
pass "$TARBALL"

# ── 5. Docker image ──────────────────────────────────────

info "Building Docker image $DOCKER_TAG"
docker build -t "$DOCKER_TAG" "$REPO_ROOT"
pass "$DOCKER_TAG built"

if [[ "$PUBLISH" == "1" ]]; then
    info "Pushing Docker image (RELEASE_PUBLISH=1)"
    docker push "$DOCKER_TAG"
    pass "$DOCKER_TAG pushed"
else
    info "Dry run — not pushing $DOCKER_TAG (set RELEASE_PUBLISH=1 to push)"
fi

# ── 6. Summary ───────────────────────────────────────────

info "Release artifacts under $DIST_DIR:"
(
    cd "$DIST_DIR"
    ls -la \
        seal-node-${VERSION}-* \
        SHA256SUMS \
        SHA256SUMS.sig \
        SHA256SUMS.sig.pubkey \
        seal-node-${VERSION}.tar.gz \
        2>/dev/null || true
)
echo
info "Verify on a downloader's host:"
echo "  shasum -a 256 -c SHA256SUMS"
echo "  cargo run -p seal-cli -- verify-file SHA256SUMS \\"
echo "      --pubkey-hex \"\$(cat SHA256SUMS.sig.pubkey)\" \\"
echo "      --sig-file SHA256SUMS.sig"
echo
if [[ "$PUBLISH" != "1" ]]; then
    info "Re-run with RELEASE_PUBLISH=1 to push to ghcr.io."
fi
pass "release.sh completed for $VERSION"
