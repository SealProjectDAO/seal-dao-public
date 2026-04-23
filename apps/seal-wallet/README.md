# Seal Wallet — Desktop Application

## Tech stack
- **Shell**: Electron (`electron.cjs` loads `standalone.html`)
- **UI**: single-file `standalone.html` (HTML + inline JS, no framework)
- **Crypto**: in-process WebAssembly compiled from the Rust `seal-*` crates
  (`seal_dao_wasm_bg.wasm` + `seal_dao_wasm.js`, built from `sdks/wasm/`)
- **Platforms**: macOS, Linux, Windows (anywhere Electron runs)

## Features
- Generate / import / backup a 24-word BIP-39 mnemonic
- Display bech32m `sealt1…` address + balances
- Sign and verify messages (ML-DSA-65)
- Send SEAL + token transfers via node RPC
- Block explorer, governance, DEX panels

## Run

```bash
cd apps/seal-wallet
npm install           # first time only
npm run electron      # launches the desktop app
```

For the crypto library tests (covers create / import / sign / verify /
BIP-39 / encrypted save+load):

```bash
cargo test -p seal-wallet
```

## Layout

```
apps/seal-wallet/
├── electron.cjs            ← Electron main process; loads standalone.html
├── standalone.html         ← the entire wallet UI (self-contained)
├── seal_dao_wasm.js        ← WASM glue (generated from sdks/wasm)
├── seal_dao_wasm_bg.wasm   ← Rust crypto compiled to WASM
├── icon.svg, seal-logo.png ← assets
└── package.json            ← Electron launch script
```

The `src/`, `index.html`, and `vite.config.js` files are an older Svelte
dev harness and are not used by the Electron build.

## Regenerating the WASM bundle

```bash
cd sdks/wasm && ./build.sh
# then copy sdks/wasm/pkg/seal_dao_wasm{.js,_bg.wasm} into apps/seal-wallet/
```
