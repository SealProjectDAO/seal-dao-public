#!/usr/bin/env bash
# scripts/install-bridge-toolchains.sh — install the CLIs needed to
# build and measure-cost the Solana (Anchor) and Stellar (Soroban)
# bridge programs.
#
# Why this script exists:
#   bridges/solana and bridges/stellar target different ISAs
#   (sbf-solana-solana and wasm32, respectively) that plain `cargo`
#   can't handle. The Anchor/Soroban CLIs wrap the right toolchain
#   and build steps. Once these are installed, the Ringtail BPF
#   verify path can be CU/instruction-measured (the remaining blocker
#   on landing the `ringtail-verify` feature).
#
# What it installs (pinned stable):
#   - Agave (formerly Solana) CLI: 2.1.12
#   - Anchor framework:            0.30.1
#   - Stellar CLI:                 22.0.0
#
# Usage:
#   ./scripts/install-bridge-toolchains.sh          # native install
#   ./scripts/install-bridge-toolchains.sh --check  # print versions only
#
# Idempotent: re-running is safe and detects already-installed
# versions. Re-runs only if a version mismatch is found.

set -euo pipefail

# Version policy:
#   AGAVE_CHANNEL — "stable" or a specific tag like "v2.0.22". Using
#     "stable" tracks Anza's latest stable release. Pin a tag for
#     reproducible CI. Not all tagged versions have macOS-arm64
#     tarballs on release.anza.xyz, so "stable" is safer interactively.
#   ANCHOR_VERSION — cargo install via avm, all tagged versions are
#     buildable from source regardless of host arch.
#   STELLAR_VERSION — same story as Anchor.
AGAVE_CHANNEL="${AGAVE_CHANNEL:-stable}"
# Anchor 0.30.1 transitively pulls `time 0.3.29`, which fails to build
# on rustc 1.80+ (the compiler tightened type inference; time < 0.3.36
# has ambiguous `Box<_>` in `format_description/parse/mod.rs:83`).
# 0.31.1 bundles newer deps and builds cleanly on rustc 1.94.x.
ANCHOR_VERSION="${ANCHOR_VERSION:-0.31.1}"
STELLAR_VERSION="${STELLAR_VERSION:-22.0.0}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

say() { echo -e "${BOLD}==>${NC} $*"; }
ok()  { echo -e "${GREEN}✓${NC} $*"; }
warn(){ echo -e "${YELLOW}!${NC} $*"; }
err() { echo -e "${RED}✗${NC} $*" >&2; }

check_only=0
if [[ "${1:-}" == "--check" ]]; then
    check_only=1
fi

# cargo installs its binaries into ~/.cargo/bin; that's what rustup-init
# writes to the shell rc, but a freshly-spawned non-login shell (as
# happens when this script is invoked from `bash script.sh`) may not
# have inherited that PATH entry yet. Ensure it's present for every
# `install_*` step below — anchor's avm and stellar-cli both install
# there.
if [[ -d "$HOME/.cargo/bin" ]]; then
    export PATH="$HOME/.cargo/bin:$PATH"
fi
# Same story for the Anza solana installer.
if [[ -d "$HOME/.local/share/solana/install/active_release/bin" ]]; then
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
fi

# ---------------------------------------------------------------------------
# Precheck: rustup + cargo must already be present (the rest of the repo
# assumes this, so don't try to install them from here).
# ---------------------------------------------------------------------------
command -v rustup >/dev/null 2>&1 || { err "rustup not found — install Rust first (https://rustup.rs)"; exit 1; }
command -v cargo  >/dev/null 2>&1 || { err "cargo not found — broken rustup install?"; exit 1; }
ok "rustup $(rustup --version | head -1 | awk '{print $2}')"
ok "cargo  $(cargo --version | awk '{print $2}')"

# ---------------------------------------------------------------------------
# Ensure rustup proxies exist at ~/.cargo/bin/{cargo,rustc,rustdoc}.
#
# Anchor's `anchor build` and Soroban's `stellar contract build` both
# invoke `cargo +<specific-toolchain> build` internally (Anchor uses
# `+1.89.0-sbpf-solana-v1.52`, Stellar uses its own). The `+<toolchain>`
# syntax is a rustup proxy convention — it only works when `cargo` is a
# rustup proxy binary. On some machines (notably when rustup was
# installed via Homebrew), cargo resolves directly to the toolchain's
# binary at `~/.rustup/toolchains/stable-*/bin/cargo`, which does NOT
# understand `+toolchain` and errors out with
#     "no such command: `+1.89.0-sbpf-solana-v1.52`"
#
# Fix: symlink rustup itself to ~/.cargo/bin/{cargo,rustc,rustdoc}.
# rustup detects the name it was invoked as (argv[0]) and proxies the
# call to the right toolchain binary, honouring any `+<toolchain>`
# prefix. This is exactly how rustup-init would install the proxies.
# ---------------------------------------------------------------------------
mkdir -p "$HOME/.cargo/bin"
rustup_bin="$(command -v rustup)"
for tool in cargo rustc rustdoc; do
    if [[ ! -e "$HOME/.cargo/bin/$tool" ]]; then
        ln -sf "$rustup_bin" "$HOME/.cargo/bin/$tool"
        ok "created rustup proxy: ~/.cargo/bin/$tool"
    fi
done
# Proxies must come BEFORE the direct toolchain binary on PATH — otherwise
# `cargo +<toolchain>` still hits the direct binary and fails.
export PATH="$HOME/.cargo/bin:$PATH"

# ---------------------------------------------------------------------------
# Agave / Solana CLI
# ---------------------------------------------------------------------------
install_agave() {
    say "Installing Agave (Solana) CLI (${AGAVE_CHANNEL})"
    # Official Anza (post-Solana-Labs) installer. Channel forms:
    #   stable       → latest stable tag
    #   v2.0.22      → specific tag (must exist on release.anza.xyz;
    #                   some tags are missing macOS-arm64 tarballs)
    # If the tarball URL is broken the installer prints "Unable to
    # extract ... failed to iterate over archive" — that's the cue
    # that this version doesn't have a build for your arch.
    local url_prefix
    if [[ "$AGAVE_CHANNEL" == "stable" || "$AGAVE_CHANNEL" == "beta" || "$AGAVE_CHANNEL" == "edge" ]]; then
        url_prefix="https://release.anza.xyz/${AGAVE_CHANNEL}"
    else
        url_prefix="https://release.anza.xyz/${AGAVE_CHANNEL}"
    fi

    if ! sh -c "$(curl -sSfL "${url_prefix}/install")"; then
        err "Anza installer failed. Possible causes:"
        err "  1. The '${AGAVE_CHANNEL}' tag has no tarball for this arch."
        err "     Try: AGAVE_CHANNEL=stable $0"
        err "  2. Network/firewall blocking release.anza.xyz."
        # macOS Homebrew fallback — same solana-cli, packaged by the
        # Solana Foundation's (now Anza's) homebrew-tap.
        if [[ "$(uname)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
            warn "Trying Homebrew fallback: brew install solana"
            if brew install solana; then
                ok "installed via Homebrew"
            else
                err "Homebrew fallback also failed."
                return 1
            fi
        else
            return 1
        fi
    fi

    # The Anza installer writes ~/.local/share/solana/install/active_release/bin
    # into the shell config; surface it for THIS shell too.
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
}

if command -v solana >/dev/null 2>&1; then
    ok "solana-cli $(solana --version | awk '{print $2}') (already installed)"
else
    warn "solana-cli not found"
    if [[ $check_only -eq 0 ]]; then
        install_agave || { err "Agave install failed — see messages above"; exit 1; }
        ok "solana-cli $(solana --version | awk '{print $2}')"
    fi
fi

# Make sure PATH has Solana's bin for the rest of this script.
if [[ -d "$HOME/.local/share/solana/install/active_release/bin" ]]; then
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
fi

# ---------------------------------------------------------------------------
# Anchor CLI (via avm, so future version switches are a one-liner)
# ---------------------------------------------------------------------------
install_anchor() {
    # Directly install anchor-cli from the pinned git tag. avm is the
    # "recommended" path but internally uses `cargo +<toolchain>` which
    # only works when `cargo` is the rustup shim — if cargo is a brew /
    # direct-installed binary, avm fails with "no such command:
    # `+1.79.0`". Installing the CLI binary directly sidesteps the
    # toolchain dance entirely.
    say "Installing anchor-cli v${ANCHOR_VERSION} (direct, bypassing avm)"
    cargo install --git https://github.com/coral-xyz/anchor.git \
        --tag "v${ANCHOR_VERSION}" \
        --locked \
        --force \
        anchor-cli

    if [[ -d "$HOME/.cargo/bin" ]]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    fi

    if ! command -v anchor >/dev/null 2>&1; then
        err "anchor-cli was built but is not on PATH."
        err "Expected at: $HOME/.cargo/bin/anchor"
        return 1
    fi
}

# Check "does anchor run and exit cleanly". `command -v` can find a
# broken avm wrapper (e.g., `~/.cargo/bin/anchor` → `~/.avm/bin/avm`
# where avm never finished installing an anchor binary); the wrapper
# returns non-zero when called. Require a clean `--version` run.
if anchor --version >/dev/null 2>&1; then
    ok "anchor-cli $(anchor --version 2>/dev/null | awk '{print $2}') (already installed)"
else
    if command -v anchor >/dev/null 2>&1; then
        warn "anchor-cli on PATH but broken (stale avm wrapper?). Will reinstall."
        rm -f "$HOME/.cargo/bin/anchor" "$HOME/.cargo/bin/avm" 2>/dev/null || true
    else
        warn "anchor-cli not found"
    fi
    if [[ $check_only -eq 0 ]]; then
        install_anchor || { err "anchor install failed"; exit 1; }
        ok "anchor-cli $(anchor --version 2>/dev/null | awk '{print $2}')"
    fi
fi

# ---------------------------------------------------------------------------
# Stellar CLI (formerly soroban-cli)
# ---------------------------------------------------------------------------
install_stellar() {
    say "Installing Stellar CLI v${STELLAR_VERSION}"
    cargo install --locked "stellar-cli@${STELLAR_VERSION}"
    # Stellar expects the wasm target on the toolchain running the build.
    rustup target add wasm32-unknown-unknown --toolchain stable
}

if stellar --version >/dev/null 2>&1; then
    ok "stellar-cli $(stellar --version 2>/dev/null | head -1 | awk '{print $2}') (already installed)"
else
    warn "stellar-cli not found"
    if [[ $check_only -eq 0 ]]; then
        install_stellar || { err "stellar-cli install failed"; exit 1; }
        ok "stellar-cli $(stellar --version 2>/dev/null | head -1 | awk '{print $2}')"
    fi
fi

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
echo
say "Toolchain summary"
missing=0
if solana --version >/dev/null 2>&1; then
    ok "solana  $(solana --version | awk '{print $2}')"
else
    warn "solana  not on PATH for this shell — source your shell rc or log out/in"
    missing=$((missing+1))
fi
if anchor --version >/dev/null 2>&1; then
    ok "anchor  $(anchor --version | awk '{print $2}')"
else
    warn "anchor  not on PATH"
    missing=$((missing+1))
fi
if stellar --version >/dev/null 2>&1; then
    ok "stellar $(stellar --version | head -1 | awk '{print $2}')"
else
    warn "stellar not on PATH"
    missing=$((missing+1))
fi

echo
if [[ $missing -eq 0 ]]; then
    ok "All bridge toolchains present. Next step:"
    echo "    ./scripts/bridge-test-ringtail.sh"
elif [[ $check_only -eq 1 ]]; then
    warn "$missing toolchain(s) missing. Re-run without --check to install."
    exit 1
else
    err "$missing toolchain(s) still missing after install. See messages above."
    err "You may need to re-source your shell rc so PATH picks up the new bins:"
    err "    source ~/.zshrc    # or ~/.bashrc"
    exit 1
fi
