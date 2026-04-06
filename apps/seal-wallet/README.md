# Seal Wallet — Desktop Application

## Tech Stack
- **Backend**: Rust (Tauri, uses seal-node + seal-wallet crates)
- **Frontend**: Svelte (or React)
- **Platform**: macOS, Linux, Windows via Tauri

## Features (planned)
- Generate/import/backup mnemonic (32-word phrase)
- Display bech32m address + balance
- Send SEAL tokens
- Block explorer (browse chain)
- App store (deploy/browse SQL schemas)
- Governance (proposals + voting)

## Setup
```bash
# Prerequisites
cargo install create-tauri-app tauri-cli
npm install  # or pnpm install

# Development
cargo tauri dev

# Build release
cargo tauri build
```

## Architecture
```
apps/seal-wallet/
├── src-tauri/          ← Rust backend
│   ├── src/
│   │   └── main.rs     ← Tauri commands (calls seal-node, seal-wallet)
│   ├── Cargo.toml
│   └── tauri.conf.json
├── src/                ← Svelte frontend
│   ├── App.svelte
│   ├── routes/
│   │   ├── Wallet.svelte
│   │   ├── Explorer.svelte
│   │   └── Governance.svelte
│   └── lib/
│       └── api.ts       ← Tauri invoke wrappers
├── package.json
└── svelte.config.js
```

## Tauri Commands (Rust → JavaScript)
```rust
#[tauri::command]
fn get_wallet_info() -> WalletInfo { ... }

#[tauri::command]
fn send_transfer(to: String, amount: u64) -> Result<String, String> { ... }

#[tauri::command]
fn get_block(height: u64) -> Option<BlockInfo> { ... }

#[tauri::command]
fn execute_sql(sql: String) -> Result<QueryResult, String> { ... }

#[tauri::command]
fn create_proposal(title: String, payload: String) -> Result<u64, String> { ... }
```
