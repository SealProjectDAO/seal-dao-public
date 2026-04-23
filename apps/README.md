# Seal DAO — Applications

## Apps

### 1. Seal Wallet Desktop (Electron) — IMPLEMENTED
- Electron shell (`electron.cjs`) loading a self-contained `standalone.html`
- All ML-DSA-65 / SHA3-256 / bech32m crypto runs in-process as WebAssembly
  compiled from the Rust `seal-*` crates (see `sdks/wasm/`)
- Supports: create / import / backup (24-word BIP-39), sign + verify,
  encrypted save/load, node RPC (query, send, token, DEX)
- See `seal-wallet/README.md`; crypto tests via `cargo test -p seal-wallet`

### 2. Seal Wallet Browser Extension (MV3) — IMPLEMENTED
- Chromium MV3 extension at `seal-wallet-extension/`
- Same WASM crypto; EIP-1193-shaped `window.seal` injected provider

### 3. Seal Wallet Android — PLANNED
- Kotlin UI + Rust crypto via JNI
- See `seal-wallet-android/README.md`

### 4. Seal Explorer (web) — IMPLEMENTED
- `seal-explorer-web/`: block/tx/account browser

### 5. Seal Marketplace — IMPLEMENTED
- `examples/seal-marketplace/`: interactive REPL
  (.list, .buy, .browse, .balances, .produce)

## Tech stack

```
Desktop shell:     Electron
Wallet UI:         plain HTML + inline JS (standalone.html)
Crypto:            Rust → WebAssembly (sdks/wasm/)
Mobile (planned):  Kotlin + JNI to the same Rust crates
```

## Getting started

```bash
cd apps/seal-wallet
npm install
npm run electron       # launches the desktop wallet
```

## Layout

```
apps/
├── README.md                  ← this file
├── seal-wallet/               ← Electron desktop wallet
│   ├── electron.cjs           ← Electron main process
│   ├── standalone.html        ← the wallet UI
│   └── seal_dao_wasm*         ← Rust crypto, compiled to WASM
├── seal-wallet-extension/     ← Chromium MV3 extension
├── seal-wallet-android/       ← Android wallet (planned)
├── seal-explorer-web/         ← Web block explorer
└── seal-explorer/             ← CLI explorer
```
