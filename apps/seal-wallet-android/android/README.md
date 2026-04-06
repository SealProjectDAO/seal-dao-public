# Seal Wallet — Android

Post-quantum secure wallet for Seal DAO on Android.

## Architecture

```
Kotlin UI (Material Design)
  │
  │ JNI calls
  ▼
Rust FFI (libseal_wallet_ffi.so)
  │
  ├── ML-DSA-65 signing (FIPS 204)
  ├── ML-KEM-768 encryption (FIPS 203)
  ├── SHA3-256 hashing (FIPS 202)
  └── BIP-39 mnemonic generation
```

All cryptography runs in Rust. The Kotlin layer is UI only.

## Build

```bash
# Prerequisites
rustup target add aarch64-linux-android x86_64-linux-android
# Install Android NDK via Android Studio
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/27.0.12077973

# Debug build
./build-android.sh                  # Build debug APK
./build-android.sh install          # Build + install on device/emulator

# Release build
./build-android.sh release          # Build release APK
./build-android.sh release install  # Build release + install
```

## Features

- Create new wallet (ML-DSA-65 keypair)
- Import from BIP-39 mnemonic
- Sign messages with ML-DSA-65
- Verify signatures
- Export recovery phrase
- Dark theme matching seal-dao.network

## Running on Emulator

```bash
# List available emulators
$ANDROID_HOME/emulator/emulator -list-avds

# Start an emulator
$ANDROID_HOME/emulator/emulator @test-device &

# Wait for boot, then build + install
./build-android.sh install

# Or install manually
adb install -r android/app/build/outputs/apk/debug/app-debug.apk

# Check connected devices
adb devices
```

### Connecting to Local Node from Emulator

The Android emulator uses special IPs to reach the host machine:

| From emulator | Reaches | Use for |
|---------------|---------|---------|
| `10.0.2.2` | Host machine `127.0.0.1` | RPC on localhost |
| `10.0.2.2:8545` | Host `127.0.0.1:8545` | `seal-node --rpc-port 8545` |

So if your node runs with `--rpc-port 8545` on your Mac, the emulator
app would connect to `http://10.0.2.2:8545`.

**Important**: The RPC server binds to `127.0.0.1` by default, which
the emulator CAN reach via `10.0.2.2`. No config change needed on the node.

For a physical phone on the same network, the node would need to bind
to `0.0.0.0` (not recommended without PQ-encrypted transport).

## Status

Pre-mainnet testnet wallet. Generates `sealt1...` addresses.
