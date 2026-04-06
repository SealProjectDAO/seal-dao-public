# Seal Wallet — Android

Post-quantum secure mobile wallet for Seal DAO.

## Architecture

```
Kotlin/Jetpack Compose UI
    │
    ├── Wallet screen (address, balances, send)
    ├── Import/Export (BIP-39 24-word mnemonic)
    ├── Block explorer (browse chain)
    └── Settings (testnet toggle, password)
    │
    ▼
Rust FFI (JNI via uniffi or jni-rs)
    │
    ├── seal-wallet   → ML-DSA keygen, signing, addresses
    ├── seal-crypto   → SHA3-256, ML-KEM, bech32m
    └── seal-vrf      → VRF key management
    │
    ▼
Native .so (compiled for aarch64-linux-android, armv7-linux-androideabi)
```

**Key principle:** Private keys never leave the Rust layer. The Kotlin UI
only sees public data (`WalletInfo`, addresses, signature hex strings).

## Two Approaches

### Option A: Tauri Mobile (Recommended for code reuse)

Reuses the existing Svelte frontend and Rust commands from the desktop wallet.

```bash
# Install Tauri mobile prerequisites
cargo install tauri-cli
# Initialize Android target
cargo tauri android init
# Build
cargo tauri android build
```

**Pros:** 90% code reuse from desktop, single Svelte codebase
**Cons:** Tauri Mobile is newer, may have rough edges

### Option B: Native Kotlin + Rust FFI

Pure Android app with Kotlin/Jetpack Compose calling Rust via JNI.

```bash
# Cross-compile seal-wallet for Android
rustup target add aarch64-linux-android armv7-linux-androideabi
cargo build --target aarch64-linux-android --release -p seal-wallet

# Generate JNI bindings (using uniffi)
# Add to crates/seal-wallet/Cargo.toml:
# [lib]
# crate-type = ["cdylib"]
```

**Pros:** Native Android feel, full platform access
**Cons:** Separate UI codebase, more maintenance

## Rust FFI Commands (same as desktop)

The Rust backend exposes these functions via FFI:

| Function | Input | Output | Description |
|----------|-------|--------|-------------|
| `create_wallet` | testnet: bool | WalletInfo JSON | Generate new wallet |
| `import_wallet` | mnemonic_hex: String | WalletInfo JSON | Restore from hex seed |
| `import_wallet_bip39` | words: String | WalletInfo JSON | Restore from 24 words |
| `get_address` | — | String | Bech32m address |
| `sign_message` | message: String | hex signature | ML-DSA-65 sign |
| `verify_signature` | message, sig_hex | bool | ML-DSA-65 verify |
| `export_mnemonic` | — | hex string | 64-char hex seed |
| `export_mnemonic_bip39` | — | 24 words | BIP-39 mnemonic |
| `save_wallet` | path, password | — | Encrypted save |
| `load_wallet` | path, password | WalletInfo JSON | Encrypted load |

## Build Prerequisites

```bash
# Android SDK + NDK
# Install via Android Studio or:
sdkmanager "ndk;25.2.9519653" "build-tools;34.0.0" "platforms;android-34"

# Rust Android targets
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android       # x86 emulator
rustup target add x86_64-linux-android     # x86_64 emulator

# Android linker config (~/.cargo/config.toml)
# [target.aarch64-linux-android]
# linker = "/path/to/ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang"
```

## Security Considerations

- **Secure enclave**: Use Android Keystore for wrapping the wallet encryption key
- **Biometric**: Require fingerprint/face to unlock wallet
- **Screen capture**: Disable screenshots on mnemonic backup screen
- **Clipboard**: Auto-clear clipboard after copying addresses
- **Root detection**: Warn (don't block) on rooted devices
