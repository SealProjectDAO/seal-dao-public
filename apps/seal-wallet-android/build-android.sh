#!/bin/bash
# Build the Seal Wallet Android app.
#
# Prerequisites:
#   rustup target add aarch64-linux-android
#   Install Android NDK via Android Studio or sdkmanager
#   Set ANDROID_NDK_HOME environment variable
#
# Usage:
#   ./build-android.sh              # Build debug APK
#   ./build-android.sh release      # Build release APK
#   ./build-android.sh install      # Build + install on connected device
#   ./build-android.sh release install  # Build release + install

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_DIR="$SCRIPT_DIR/android"
JNI_DIR="$ANDROID_DIR/app/src/main/jniLibs/arm64-v8a"

MODE="debug"
INSTALL=false
for arg in "$@"; do
    case "$arg" in
        release) MODE="release" ;;
        install) INSTALL=true ;;
    esac
done

echo "=== Seal Wallet Android Build ==="
echo ""

# Step 1: Build Rust FFI library for Android
echo "── Building Rust FFI (aarch64-linux-android) ──"
if ! rustup target list --installed | grep -q aarch64-linux-android; then
    echo "Adding Android target..."
    rustup target add aarch64-linux-android
fi

# Check for NDK
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    echo "ERROR: ANDROID_NDK_HOME not set."
    echo "Install Android NDK via Android Studio or:"
    echo "  sdkmanager 'ndk;27.0.12077973'"
    echo "  export ANDROID_NDK_HOME=\$ANDROID_HOME/ndk/27.0.12077973"
    exit 1
fi

# Find the linker
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt"
if [ -d "$TOOLCHAIN/darwin-x86_64" ]; then
    TOOLCHAIN="$TOOLCHAIN/darwin-x86_64"
elif [ -d "$TOOLCHAIN/linux-x86_64" ]; then
    TOOLCHAIN="$TOOLCHAIN/linux-x86_64"
else
    echo "ERROR: Cannot find NDK toolchain in $TOOLCHAIN"
    exit 1
fi

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/aarch64-linux-android26-clang"
export CC_aarch64_linux_android="$TOOLCHAIN/bin/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$TOOLCHAIN/bin/llvm-ar"
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER="$TOOLCHAIN/bin/x86_64-linux-android26-clang"
export CC_x86_64_linux_android="$TOOLCHAIN/bin/x86_64-linux-android26-clang"
export AR_x86_64_linux_android="$TOOLCHAIN/bin/llvm-ar"

CARGO_FLAGS=""
if [ "$MODE" = "release" ]; then
    CARGO_FLAGS="--release"
fi

# The FFI crate depends on `jni` which is not in the workspace vendor set.
# Temporarily disable vendor config so cargo can fetch from crates.io.
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
mv "$REPO_ROOT/.cargo/config.toml" "$REPO_ROOT/.cargo/config.toml.android-bak" 2>/dev/null || true

# Build for both arm64 (device) and x86_64 (emulator)
for TARGET in aarch64-linux-android x86_64-linux-android; do
    echo "  Building for $TARGET..."
    cargo build --manifest-path "$SCRIPT_DIR/Cargo.toml" \
        --target "$TARGET" $CARGO_FLAGS
done

mv "$REPO_ROOT/.cargo/config.toml.android-bak" "$REPO_ROOT/.cargo/config.toml" 2>/dev/null || true

# Step 2: Copy .so to jniLibs
echo ""
echo "── Copying native libraries ──"
PROFILE=$([ "$MODE" = "release" ] && echo "release" || echo "debug")
TARGET_DIR="$SCRIPT_DIR/target"

mkdir -p "$JNI_DIR"
mkdir -p "$ANDROID_DIR/app/src/main/jniLibs/x86_64"

cp "$TARGET_DIR/aarch64-linux-android/$PROFILE/libseal_wallet_ffi.so" "$JNI_DIR/libseal_wallet_ffi.so"
cp "$TARGET_DIR/x86_64-linux-android/$PROFILE/libseal_wallet_ffi.so" "$ANDROID_DIR/app/src/main/jniLibs/x86_64/libseal_wallet_ffi.so"

echo "  arm64-v8a: $(du -h "$JNI_DIR/libseal_wallet_ffi.so" | cut -f1)"
echo "  x86_64:    $(du -h "$ANDROID_DIR/app/src/main/jniLibs/x86_64/libseal_wallet_ffi.so" | cut -f1)"

# Step 3: Build APK
echo ""
echo "── Building APK ($MODE) ──"
cd "$ANDROID_DIR"
if [ "$MODE" = "release" ]; then
    ./gradlew assembleRelease
    echo ""
    echo "APK: $ANDROID_DIR/app/build/outputs/apk/release/app-release-unsigned.apk"
else
    ./gradlew assembleDebug
    echo ""
    echo "APK: $ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
fi

# Step 4: Install on device (if requested)
if $INSTALL; then
    echo ""
    echo "── Installing on device ──"
    if [ "$MODE" = "release" ]; then
        adb install -r "$ANDROID_DIR/app/build/outputs/apk/release/app-release-unsigned.apk"
    else
        adb install -r "$ANDROID_DIR/app/build/outputs/apk/debug/app-debug.apk"
    fi
fi

echo ""
echo "=== Build complete ==="
