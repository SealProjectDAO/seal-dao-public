#!/usr/bin/env bash
# scripts/solana-gpg-wrapper.sh — Transparent GPG-encrypted key wrapper
# for the Solana CLI.
#
# Usage:  scripts/solana-gpg-wrapper.sh <solana-args...>
#
# Mechanism:
#   1. Decrypt ~/.config/solana/id.json.gpg → /tmp/.solana-id.json
#   2. Launch the real `solana` CLI with all args
#   3. On exit: wipe plaintext, restore CLI config
#
# The passphrase prompt happens ONCE per session (gpg-agent caches it).
# Config: ~/.solana-gpg.conf  (see init command below)
#
# SECURITY: Plaintext key lives in /tmp only for the duration of the
# command. /tmp is tmpfs on most Linux systems (RAM-backed, wiped on
# reboot). The key is zeroized before unlink.

set -euo pipefail

CONF="${HOME}/.solana-gpg.conf"
KEY_GPG="${HOME}/.config/solana/id.json.gpg"
KEY_TMP="/tmp/.solana-id.json"
REAL_SOLANA="${REAL_SOLANA:-$(command -v solana 2>/dev/null || true)}"

if [ -z "$REAL_SOLANA" ]; then
    echo "solana-gpg-wrapper: solana binary not found. Install it or set REAL_SOLANA." >&2
    exit 1
fi

# ── Config defaults ────────────────

CONF_TTL="${SOLANA_GPG_CACHE_TTL:-3600}"
CONF_MAX_TTL="${SOLANA_GPG_CACHE_MAX_TTL:-86400}"
CONF_PASSPHRASE="${SOLANA_GPG_PASSPHRASE:-}"

# ── Helpers ───────────────────────

# Decrypt with error propagation (NO silent swallow).
decrypt_key() {
    local dst="$1"
    local src="${2:-$KEY_GPG}"

    if [ ! -f "$src" ]; then
        echo "solana-gpg-wrapper: encrypted key not found: $src" >&2
        return 1
    fi

    local gpg_opts=(--batch --yes --decrypt --output "$dst")
    if [ -n "$CONF_PASSPHRASE" ]; then
        echo "WARNING: passphrase passed via env var (visible in ps)." >&2
        gpg --passphrase "$CONF_PASSPHRASE" "${gpg_opts[@]}" "$src"
    else
        gpg "${gpg_opts[@]}" "$src"
    fi
}

# Wipe a file safely (single-block zero, not byte-by-byte).
wipe_file() {
    local file="$1"
    [ -f "$file" ] || return 0
    local size
    size=$(wc -c < "$file")
    if [ "$size" -gt 0 ]; then
        dd if=/dev/zero of="$file" bs="$size" count=1 conv=notrunc 2>/dev/null || true
    fi
    rm -f "$file"
}

# ── Commands ──────────────────────

cmd_init() {
    echo "Initializing solana-gpg-wrapper..."

    mkdir -p "$(dirname "$CONF")"

    if [ -f "$CONF" ]; then
        echo "Config exists at $CONF, skipping."
        return 0
    fi

    cat > "$CONF" << 'EOF'
# solana-gpg-wrapper configuration
# Cache TTL in seconds (default: 1h). gpg-agent caches passphrase.
CACHE_TTL=3600
CACHE_MAX_TTL=86400

# Path to the encrypted key file
ENCRYPTED_KEY="${HOME}/.config/solana/id.json.gpg"

# If set, the passphrase is loaded from this file (avoid prompts).
# Use with care: this file must be secured separately.
# PASSPHRASE_FILE=/path/to/passphrase.txt

# Enable preloaded passphrase (no prompts, agent holds key in memory).
# WARNING: compromises security if machine is compromised.
# PRELOAD_PASSPHRASE=false
EOF

    # Encrypt existing plaintext key if present
    if [ -f "$KEY_GPG" ]; then
        echo "Encrypted key already exists."
    elif [ -f "${HOME}/.config/solana/id.json" ]; then
        echo "Encrypting existing key at ${HOME}/.config/solana/id.json..."
        if [ -n "$CONF_PASSPHRASE" ]; then
            gpg --batch --yes --symmetric --cipher-algo AES256 \
                --passphrase "$CONF_PASSPHRASE" \
                --output "$KEY_GPG" \
                "${HOME}/.config/solana/id.json"
        else
            gpg --batch --yes --symmetric --cipher-algo AES256 \
                --output "$KEY_GPG" \
                "${HOME}/.config/solana/id.json"
        fi
        mv "${HOME}/.config/solana/id.json" "${HOME}/.config/solana/id.json.plaintext.bak"
        chmod 600 "$KEY_GPG"
        rm -f "${HOME}/.config/solana/id.json"
        echo "Key encrypted. Plaintext backed up to *.plaintext.bak — delete it."
    else
        # Generate new keypair: temp file → encrypt → wipe temp
        echo "No key found. Generating new Solana keypair..."
        mkdir -p "$(dirname "$KEY_GPG")"

        local tmpkey
        tmpkey=$(mktemp /tmp/.solana-id-gen.XXXXXX)
        trap 'rm -f "$tmpkey"' EXIT

        solana-keygen new --no-passphrase -o "$tmpkey" 2>&1 | head -5

        if [ -n "$CONF_PASSPHRASE" ]; then
            gpg --batch --yes --symmetric --cipher-algo AES256 \
                --passphrase "$CONF_PASSPHRASE" \
                --output "$KEY_GPG" "$tmpkey"
        else
            gpg --batch --yes --symmetric --cipher-algo AES256 \
                --output "$KEY_GPG" "$tmpkey"
        fi
        chmod 600 "$KEY_GPG"
        wipe_file "$tmpkey"

        echo ""
        echo "New key generated and encrypted at:"
        echo "  $KEY_GPG"
        echo ""
        echo "Fund with:"
        echo "  scripts/solana-gpg-wrapper.sh airdrop 2 \$(scripts/solana-gpg-wrapper.sh address)"
    fi

    echo ""
    echo "Config: $CONF"
    echo "Encrypted key: $KEY_GPG"
    echo "Tweak: $CONF or env vars SOLANA_GPG_CACHE_TTL / SOLANA_GPG_PASSPHRASE"
}

cmd_status() {
    echo "=== solana-gpg-wrapper status ==="
    echo ""

    if [ -f "$CONF" ]; then
        echo "Config: $CONF"
        # Parse key=value lines (skip comments/blanks), avoid subshell variable loss
        while IFS='=' read -r key val; do
            [ -n "$key" ] && echo "  $key = $val"
        done < <(grep -v '^#' "$CONF" | grep -v '^$' || true)
    else
        echo "Config: NOT FOUND (run 'init' first)"
    fi
    echo ""

    if [ -f "$KEY_GPG" ]; then
        echo "Encrypted key: $KEY_GPG ($(du -h "$KEY_GPG" | cut -f1))"
        echo "  Permissions: $(stat -c '%a' "$KEY_GPG")"
    else
        echo "Encrypted key: NOT FOUND"
    fi
    echo ""

    if [ -f "${HOME}/.config/solana/id.json" ]; then
        echo "WARNING: Plaintext key EXISTS at ${HOME}/.config/solana/id.json"
        echo "  This should only exist during a wrapper command or after 'install'."
    else
        echo "Plaintext key: NOT on disk (good)"
    fi
    echo ""

    # gpg-agent status
    if gpg-connect-agent /bye >/dev/null 2>&1; then
        echo "gpg-agent: running (cache active)"
    else
        echo "gpg-agent: NOT running (start with: gpg-connect-agent /bye)"
    fi
}

cmd_encrypt() {
    local src="${1:?Usage: $0 encrypt <plaintext-keyfile>}"
    [ -f "$src" ] || { echo "File not found: $src" >&2; exit 1; }

    if [ -n "$CONF_PASSPHRASE" ]; then
        gpg --batch --yes --symmetric --cipher-algo AES256 \
            --passphrase "$CONF_PASSPHRASE" --output "$KEY_GPG" "$src"
    else
        gpg --batch --yes --symmetric --cipher-algo AES256 \
            --output "$KEY_GPG" "$src"
    fi
    chmod 600 "$KEY_GPG"
    echo "Encrypted to $KEY_GPG"
}

cmd_decrypt() {
    local dst="${1:-$KEY_TMP}"
    decrypt_key "$dst" && echo "Decrypted to $dst"
}

cmd_preload() {
    local passphrase

    if [ -n "$CONF_PASSPHRASE" ]; then
        passphrase="$CONF_PASSPHRASE"
    elif [ -n "${SOLANA_GPG_PASSPHRASE_FILE:-}" ] && [ -f "$SOLANA_GPG_PASSPHRASE_FILE" ]; then
        passphrase=$(cat "$SOLANA_GPG_PASSPHRASE_FILE")
    else
        echo -n "Enter passphrase to preload into gpg-agent: "
        read -rs passphrase
        echo
    fi

    [ -n "$passphrase" ] || { echo "Empty passphrase, aborting." >&2; exit 1; }

    local b64
    b64=$(printf '%s' "$passphrase" | base64 -w0)
    gpg-connect-agent "preset_passphrase $b64 $CONF_TTL $CONF_MAX_TTL" /bye 2>/dev/null

    echo "Passphrase preloaded. No prompts for ${CONF_TTL}s (${CONF_TTL}/3600h)."
}

cmd_install() {
    # Decrypt to ~/.config/solana/id.json for scripts that call `solana`
    # directly (anchor deploy, etc.). Must be wiped with `wipe` afterward.
    #
    # Usage: scripts/solana-gpg-wrapper.sh install [--force]
    #        scripts/solana-gpg-wrapper.sh wipe

    if [ ! -f "$KEY_GPG" ]; then
        echo "solana-gpg-wrapper: encrypted key not found at $KEY_GPG" >&2
        echo "Run: $0 init" >&2
        exit 1
    fi

    local keyfile="${HOME}/.config/solana/id.json"
    if [ -f "$keyfile" ]; then
        if [[ "${1:-}" == "--force" ]]; then
            wipe_file "$keyfile"
        else
            echo "Plaintext key already exists at $keyfile" >&2
            echo "Remove it or use: $0 install --force" >&2
            exit 1
        fi
    fi

    decrypt_key "$keyfile" || { echo "Decryption failed." >&2; exit 1; }
    chmod 600 "$keyfile"
    echo "Plaintext key installed at $keyfile"
    echo "Run '$0 wipe' when done to remove it from disk."
}

cmd_wipe() {
    # Remove plaintext key from ~/.config/solana/id.json
    wipe_file "${HOME}/.config/solana/id.json"
    echo "Plaintext key wiped."
}

# ── Core: decrypt → run → wipe ─────

run_wrapped() {
    # Ensure gpg-agent is running
    gpg-connect-agent /bye >/dev/null 2>&1 || true

    # Load config (only once)
    if [ -f "$CONF" ]; then
        source "$CONF" 2>/dev/null || true
    fi

    # Decrypt to /tmp
    decrypt_key "$KEY_TMP" || { echo "Decryption failed." >&2; exit 1; }
    chmod 600 "$KEY_TMP"

    # Save and update Solana CLI config so the keypair resolves
    local solana_cfg="${HOME}/.config/solana/cli/config.yml"
    local orig_keypair=""
    local has_cfg=false
    local cfg_was_created=false

    if [ -f "$solana_cfg" ]; then
        has_cfg=true
        orig_keypair=$(grep -E '^\s*keypair\s*:' "$solana_cfg" 2>/dev/null | head -1 | sed 's/.*keypair\s*:\s*//' | tr -d ' "' || true)
    fi

    mkdir -p "$(dirname "$solana_cfg")"

    if $has_cfg && [ -f "$solana_cfg" ]; then
        if [ -n "$orig_keypair" ] && [ "$orig_keypair" != "$KEY_TMP" ]; then
            cp "$solana_cfg" "${solana_cfg}.gpg-bak"
            # Only touch the keypair line, nothing else
            sed -i "s|^\(\s*keypair\s*:\s*\).*|\1$KEY_TMP|" "$solana_cfg"
        fi
    else
        # Create config pointing to our /tmp key; fetch URL from
        # the user's real solana config if available, else default
        # to devnet (same as solana CLI's own default).
        local fallback_url="https://api.devnet.solana.com"
        if [ -f "${HOME}/.config/solana/config.yml" ]; then
            fallback_url=$(grep -E '^\s*url\s*:' "${HOME}/.config/solana/config.yml" 2>/dev/null | head -1 | sed 's/.*url\s*:\s*//' | tr -d ' "' || true)
        fi
        [ -n "$fallback_url" ] || fallback_url="https://api.devnet.solana.com"
        cat > "$solana_cfg" << EOF
context:
  keypair: $KEY_TMP
  url: $fallback_url
EOF
        cfg_was_created=true
    fi

    # Cleanup: restore config backup, wipe /tmp plaintext
    # Run in a subshell so the trap fires even though the last
    # command is exec (exec replaces the shell, killing the trap).
    cleanup_and_run() {
        # Restore original CLI config
        if $has_cfg && [ -f "${solana_cfg}.gpg-bak" ]; then
            mv "${solana_cfg}.gpg-bak" "$solana_cfg"
        elif $cfg_was_created && [ -f "$solana_cfg" ]; then
            rm -f "$solana_cfg"
        fi

        # Wipe the /tmp plaintext key
        wipe_file "$KEY_TMP"
    }

    trap cleanup_and_run EXIT INT TERM

    # exec replaces the shell — trap fires on INT/TERM but not
    # normal exit. That's why we wrap in a subshell.
    exec "$REAL_SOLANA" "$@"
}

# ── Main ──────────────────────────

case "${1:-wrapped}" in
    init)       cmd_init ;;
    status)     cmd_status ;;
    encrypt)    shift; cmd_encrypt "$@" ;;
    decrypt)    shift; cmd_decrypt "$@" ;;
    preload)    cmd_preload ;;
    install)    shift; cmd_install "$@" ;;
    wipe)       shift; cmd_wipe "$@" ;;
    *)          run_wrapped "$@" ;;
esac
