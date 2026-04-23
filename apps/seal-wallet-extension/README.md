# Seal Wallet — browser extension (Manifest V3)

Post-quantum (ML-DSA / FIPS 204) Seal DAO wallet for Chromium-based
browsers. Connects dApps to a Seal node, signs transactions with the
WASM build of `seal-crypto`.

## Layout

```
apps/seal-wallet-extension/
├── manifest.json          # MV3 manifest
├── icons/icon-128.png     # toolbar icon (placeholder)
├── pkg/                   # wasm-bindgen output (built from sdks/wasm)
│   ├── seal_dao_wasm.js
│   └── seal_dao_wasm_bg.wasm
└── src/
    ├── background.js      # service worker — message routing + storage
    ├── content.js         # injects inject.js into the page
    ├── inject.js          # window.seal provider
    ├── popup.html         # UI shell
    ├── popup.css          # styles (system fonts, dark default)
    └── popup.js           # owns WASM signing + vault crypto
```

## Architecture

```
   dApp              content      background       popup
  (page)            (isolated)    (service worker)  (extension page)
    │                    │              │              │
    ├── window.seal ─────┤              │              │
    │  request(...)      │              │              │
    │                    ├─ chrome.runtime.sendMessage ┤
    │                    │              ├── pending ───┤
    │                    │              │   request    │
    │                    │              │              │ user clicks
    │                    │              │              │ Approve → sign
    │                    │              ├──── result ──┤
    │   signature ◀──────┤◀─────────────┤              │
```

### Why the popup owns signing

- Service workers in MV3 cannot reliably hold WASM module state across
  idle suspensions. The popup is a regular extension page, so the
  WASM module + decrypted vault live there for the duration of the
  pop-out only.
- Secret key bytes never leave the popup. The vault on disk is AES-GCM
  ciphertext keyed by a PBKDF2(SHA-256, 310k) derivation from the user
  passphrase the user sets on Create / Import. The decrypted vault
  lives in a single `Uint8Array` (`unlocked`) in the popup context and
  is zeroed on Lock and on `pagehide`/`beforeunload` (closing the
  popup already tears down the JS context, so auto-lock is implicit).
- After signing, `sk.fill(0)` scrubs the local plaintext copy.
- Follow-up (TODOS.md): move the decrypted secret into the WASM module
  so JS only holds an opaque handle.

## Build the WASM bundle

The extension consumes the same WASM artefact as `apps/seal-wallet`.
Build it from the SDK and copy in:

```bash
cd sdks/wasm
wasm-pack build --target web --out-dir ../../apps/seal-wallet-extension/pkg
```

Then load the unpacked extension in Chrome:

1. `chrome://extensions`
2. Toggle **Developer mode** on.
3. Click **Load unpacked** and pick `apps/seal-wallet-extension/`.

## In-page provider (`window.seal`)

Mirrors EIP-1193 so dApps that already speak that shape can switch to
Seal with a one-liner:

```js
const accounts = await window.seal.request({ method: "seal_requestAccounts" });
const sigHex = await window.seal.request({
  method: "seal_signMessage",
  params: { address: accounts[0], message_hex: "deadbeef" },
});
```

Other JSON-RPC methods (`seal_getNamespaces`, `seal_dexPlaceOrder`, …)
are forwarded to the configured RPC URL via `seal:rpc`.

## Permissions

- `storage` — vault + approved-origins list + RPC URL
- `scripting` — declared for `chrome.scripting` APIs reserved for v0.2
- `host_permissions: ["http://localhost:*/*"]` — local node access; add
  your testnet/mainnet host explicitly before publishing

CSP allows `'wasm-unsafe-eval'` (required to instantiate the
seal-dao-wasm module). No remote script eval is permitted.
