# Seal DAO — Applications

## Planned Apps

### 1. Seal Wallet Desktop (Tauri + Svelte) — IMPLEMENTED
- Rust backend: 11 IPC commands (create, import, sign, verify, save, load...)
- Svelte UI: wallet dashboard, import/export, balance display, signing
- All crypto in Rust (ML-DSA-65, SHA3-256, bech32m) — keys never leave Rust
- 5 tests for the Rust command layer

### 2. Seal Wallet Android (Tauri Mobile or Kotlin) — PLANNED
- Same Rust crypto backend via FFI (JNI or Tauri Mobile)
- QR code for address sharing
- Biometric auth for encrypted wallet
- See `seal-wallet-android/README.md` for architecture + build plan

### 3. Seal Marketplace — IMPLEMENTED
- Interactive REPL: .list, .buy, .browse, .balances, .produce
- Multi-user marketplace with checked balance transfers
- Demonstrates: app deployment, RLS, SQL-as-transactions, Merkle state

## Tech Stack

```
Frontend: Svelte (or React)
Backend:  Rust (seal-node as library)
Desktop:  Tauri (Rust + WebView)
Mobile:   Tauri Mobile or Kotlin + JNI
```

## Getting Started

```bash
# Install Tauri prerequisites
# macOS:
xcode-select --install
brew install pkg-config

# Install Tauri CLI
cargo install create-tauri-app
cargo install tauri-cli

# Create wallet app (when ready):
cd apps/
cargo tauri init
```

## Architecture

```
apps/
├── README.md                ← This file
├── seal-wallet/             ← Desktop wallet (Tauri + Svelte)
│   ├── src-tauri/           ← Rust backend (commands.rs)
│   ├── src/                 ← Svelte frontend (App.svelte)
│   └── package.json
├── seal-wallet-android/     ← Android wallet (planned)
│   └── README.md            ← Architecture + build plan
└── (seal-marketplace)       ← In examples/seal-marketplace/
```

The Tauri backend calls seal-node and seal-wallet crates directly —
no RPC or HTTP needed. Rust ↔ JavaScript communication via Tauri commands.
