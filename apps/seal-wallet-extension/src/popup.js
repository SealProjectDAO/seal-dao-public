// Seal Wallet — popup UI.
//
// Owns the WASM ML-DSA signing surface. Loads `seal-dao-wasm` once at
// open time, decrypts the vault when the user unlocks with their
// passphrase, signs whatever the background service worker has queued,
// and writes the result back.
//
// Vault layout in chrome.storage.local:
//   "seal:vault"    → { ciphertext_b64, iv_b64, salt_b64, kdf, iter }
//   "seal:accounts" → ["seal1...", ...]   (public addresses, not keys)
//   "seal:rpc_url"  → "http://localhost:8545"
//
// The vault is encrypted with AES-GCM-256 under a key derived from the
// user's passphrase via PBKDF2-HMAC-SHA256(310000). The decrypted key
// material only ever lives in this popup's memory, inside the single
// `unlocked` Uint8Array below, and is wiped on Lock / popup close.
// (Follow-up: move ownership of the secret bytes into the WASM module
// so JS never sees the plaintext at all — see TODOS.md.)

import init, {
  generate_keypair,
  import_from_mnemonic,
  sign as wasmSign,
} from "../pkg/seal_dao_wasm.js";

const VAULT_KEY = "seal:vault";
const ACCOUNTS_KEY = "seal:accounts";
const RPC_URL_KEY = "seal:rpc_url";

// Single in-memory plaintext buffer. `null` means locked. We never
// stash derived values anywhere else — signing walks straight off
// this buffer and zeroes its local scratch.
let unlocked = null;

// Stash for a just-created vault payload that hasn't been persisted
// yet, used only during the set-passphrase flow.
let pendingNewVault = null;

let wasmReady = false;
async function ensureWasm() {
  if (!wasmReady) {
    await init(new URL("../pkg/seal_dao_wasm_bg.wasm", import.meta.url));
    wasmReady = true;
  }
}

// ── Vault crypto ───────────────────────────────────────────────────
async function deriveKey(passphrase, saltBytes) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: 310_000 },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

const b64 = {
  encode(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s);
  },
  decode(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  },
};

async function saveVault(plaintextBytes, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintextBytes),
  );
  await chrome.storage.local.set({
    [VAULT_KEY]: {
      ciphertext_b64: b64.encode(ct),
      iv_b64: b64.encode(iv),
      salt_b64: b64.encode(salt),
      kdf: "PBKDF2-HMAC-SHA256",
      iter: 310_000,
    },
  });
}

async function hasVault() {
  const out = await chrome.storage.local.get(VAULT_KEY);
  return !!out[VAULT_KEY];
}

async function decryptVault(passphrase) {
  const out = await chrome.storage.local.get(VAULT_KEY);
  const v = out[VAULT_KEY];
  if (!v) return null;
  const key = await deriveKey(passphrase, b64.decode(v.salt_b64));
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64.decode(v.iv_b64) },
    key,
    b64.decode(v.ciphertext_b64),
  );
  return new Uint8Array(pt);
}

function zeroize(bytes) {
  if (bytes && bytes.fill) bytes.fill(0);
}

function lock() {
  zeroize(unlocked);
  unlocked = null;
}

// ── Wallet ops ─────────────────────────────────────────────────────
async function createWallet(passphrase) {
  await ensureWasm();
  const json = JSON.parse(generate_keypair(false));
  const vaultPayload = new TextEncoder().encode(JSON.stringify(json));
  await saveVault(vaultPayload, passphrase);
  await chrome.storage.local.set({ [ACCOUNTS_KEY]: [json.address] });
  unlocked = vaultPayload;
  return json;
}

async function importMnemonic(mnemonic, passphrase) {
  await ensureWasm();
  const json = JSON.parse(import_from_mnemonic(mnemonic, false));
  const vaultPayload = new TextEncoder().encode(JSON.stringify(json));
  await saveVault(vaultPayload, passphrase);
  await chrome.storage.local.set({ [ACCOUNTS_KEY]: [json.address] });
  unlocked = vaultPayload;
  return json;
}

async function signHexMessage(messageHex) {
  await ensureWasm();
  if (!unlocked) throw new Error("vault locked");
  const json = JSON.parse(new TextDecoder().decode(unlocked));
  const sk = hexToBytes(json.signing_key);
  const msg = hexToBytes(messageHex);
  const sig = wasmSign(sk, msg);
  zeroize(sk);
  return bytesToHex(sig);
}

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

// ── UI ─────────────────────────────────────────────────────────────
function show(id) {
  for (const el of document.querySelectorAll("main > section")) {
    el.hidden = el.id !== id;
  }
}

function showError(elId, message) {
  const el = document.getElementById(elId);
  el.textContent = message;
  el.hidden = false;
}

function clearError(elId) {
  const el = document.getElementById(elId);
  el.textContent = "";
  el.hidden = true;
}

async function routeOnOpen() {
  if (!(await hasVault())) {
    show("screen-empty");
    return;
  }
  if (!unlocked) {
    show("screen-unlock");
    document.getElementById("unlock-pass").focus();
    return;
  }
  await renderAccount();
}

async function renderAccount() {
  const out = await chrome.storage.local.get([ACCOUNTS_KEY, RPC_URL_KEY]);
  const accounts = out[ACCOUNTS_KEY] || [];
  if (accounts.length === 0) {
    show("screen-empty");
    return;
  }
  document.getElementById("addr").textContent = accounts[0];
  document.getElementById("rpc-url").value =
    out[RPC_URL_KEY] || "http://localhost:8545";
  await renderRequests();
  show("screen-account");
}

async function renderRequests() {
  const list = await chrome.runtime.sendMessage({ type: "seal:popup:listRequests" });
  const ul = document.getElementById("requests");
  ul.innerHTML = "";
  if (!list || list.length === 0) {
    ul.innerHTML = "<li>No pending requests.</li>";
    return;
  }
  for (const item of list) {
    const li = document.createElement("li");
    if (item.kind === "approve") {
      li.innerHTML = `
        <strong>Connect</strong> ${item.origin}
        <div class="actions">
          <button data-action="approve" data-id="${item.id}">Approve</button>
          <button class="secondary" data-action="reject" data-id="${item.id}">Reject</button>
        </div>`;
    } else if (item.kind === "sign") {
      li.innerHTML = `
        <strong>Sign</strong> from ${item.origin}<br>
        <code>${item.messageHex.slice(0, 64)}${item.messageHex.length > 64 ? "…" : ""}</code>
        <div class="actions">
          <button data-action="sign" data-id="${item.id}" data-msg="${item.messageHex}">Sign</button>
          <button class="secondary" data-action="reject" data-id="${item.id}">Reject</button>
        </div>`;
    }
    ul.appendChild(li);
  }
}

document.addEventListener("click", async (e) => {
  const action = e.target.dataset?.action;
  if (!action) return;
  const id = parseInt(e.target.dataset.id, 10);
  let result;
  if (action === "approve") {
    result = { approved: true };
  } else if (action === "reject") {
    result = { ok: false, error: "user rejected" };
  } else if (action === "sign") {
    try {
      const sigHex = await signHexMessage(e.target.dataset.msg);
      result = { ok: true, signature_hex: sigHex };
    } catch (err) {
      result = { ok: false, error: String(err) };
    }
  }
  await chrome.runtime.sendMessage({
    type: "seal:popup:resolveRequest",
    id,
    result,
  });
  await renderRequests();
});

// ── Create: collect passphrase first, then generate the keypair ───
document.getElementById("btn-create").addEventListener("click", () => {
  pendingNewVault = { mode: "create" };
  clearError("setpass-err");
  document.getElementById("setpass-1").value = "";
  document.getElementById("setpass-2").value = "";
  show("screen-setpass");
  document.getElementById("setpass-1").focus();
});

document.getElementById("btn-import").addEventListener("click", () => {
  const mnemonic = document.getElementById("import-mnemonic").value.trim();
  if (!mnemonic) {
    alert("Enter a mnemonic first.");
    return;
  }
  pendingNewVault = { mode: "import", mnemonic };
  clearError("setpass-err");
  document.getElementById("setpass-1").value = "";
  document.getElementById("setpass-2").value = "";
  show("screen-setpass");
  document.getElementById("setpass-1").focus();
});

document.getElementById("btn-setpass-cancel").addEventListener("click", () => {
  pendingNewVault = null;
  show("screen-empty");
});

document.getElementById("btn-setpass").addEventListener("click", async () => {
  const p1 = document.getElementById("setpass-1").value;
  const p2 = document.getElementById("setpass-2").value;
  if (p1.length < 8) {
    showError("setpass-err", "Passphrase must be at least 8 characters.");
    return;
  }
  if (p1 !== p2) {
    showError("setpass-err", "Passphrases do not match.");
    return;
  }
  try {
    let json;
    if (pendingNewVault?.mode === "import") {
      json = await importMnemonic(pendingNewVault.mnemonic, p1);
    } else {
      json = await createWallet(p1);
    }
    pendingNewVault = null;
    document.getElementById("setpass-1").value = "";
    document.getElementById("setpass-2").value = "";
    document.getElementById("mnemonic").textContent = json.mnemonic;
    show("screen-mnemonic");
  } catch (e) {
    showError("setpass-err", String(e));
  }
});

// ── Unlock / Lock ──────────────────────────────────────────────────
document.getElementById("btn-unlock").addEventListener("click", async () => {
  const pass = document.getElementById("unlock-pass").value;
  clearError("unlock-err");
  try {
    const pt = await decryptVault(pass);
    if (!pt) {
      showError("unlock-err", "No vault on disk.");
      return;
    }
    unlocked = pt;
    document.getElementById("unlock-pass").value = "";
    await renderAccount();
  } catch (e) {
    // Wrong passphrase surfaces as a generic OperationError from
    // WebCrypto's AES-GCM tag check — don't leak which one.
    showError("unlock-err", "Wrong passphrase.");
  }
});

document.getElementById("unlock-pass").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("btn-unlock").click();
});

document.getElementById("btn-lock").addEventListener("click", () => {
  lock();
  show("screen-unlock");
  document.getElementById("unlock-pass").value = "";
  document.getElementById("unlock-pass").focus();
});

// ── Change passphrase ──────────────────────────────────────────────
function openChangePass() {
  clearError("chpass-err");
  document.getElementById("chpass-ok").hidden = true;
  for (const id of ["chpass-old", "chpass-new1", "chpass-new2"]) {
    document.getElementById(id).value = "";
  }
  show("screen-changepass");
  document.getElementById("chpass-old").focus();
}

document
  .getElementById("btn-change-pass")
  .addEventListener("click", openChangePass);

document.getElementById("btn-chpass-cancel").addEventListener("click", () => {
  for (const id of ["chpass-old", "chpass-new1", "chpass-new2"]) {
    document.getElementById(id).value = "";
  }
  renderAccount();
});

document.getElementById("btn-chpass-save").addEventListener("click", async () => {
  clearError("chpass-err");
  const oldPass = document.getElementById("chpass-old").value;
  const n1 = document.getElementById("chpass-new1").value;
  const n2 = document.getElementById("chpass-new2").value;
  if (n1.length < 8) {
    showError("chpass-err", "New passphrase must be at least 8 characters.");
    return;
  }
  if (n1 !== n2) {
    showError("chpass-err", "New passphrases do not match.");
    return;
  }
  if (n1 === oldPass) {
    showError("chpass-err", "New passphrase must differ from the current one.");
    return;
  }
  let plaintext;
  try {
    plaintext = await decryptVault(oldPass);
  } catch (e) {
    showError("chpass-err", "Current passphrase is wrong.");
    return;
  }
  if (!plaintext) {
    showError("chpass-err", "No vault on disk.");
    return;
  }
  try {
    await saveVault(plaintext, n1);
    // Keep the session unlocked under the new passphrase. Replace
    // `unlocked` with the freshly decrypted buffer and zero the old
    // one.
    const prev = unlocked;
    unlocked = plaintext;
    zeroize(prev);
    for (const id of ["chpass-old", "chpass-new1", "chpass-new2"]) {
      document.getElementById(id).value = "";
    }
    document.getElementById("chpass-ok").hidden = false;
    setTimeout(() => renderAccount(), 600);
  } catch (e) {
    zeroize(plaintext);
    showError("chpass-err", String(e));
  }
});

// ── Reset wallet ───────────────────────────────────────────────────
function openReset() {
  clearError("reset-err");
  document.getElementById("reset-confirm").value = "";
  show("screen-reset");
  document.getElementById("reset-confirm").focus();
}

document
  .getElementById("btn-reset-from-unlock")
  .addEventListener("click", openReset);
document
  .getElementById("btn-reset-from-account")
  .addEventListener("click", openReset);

document.getElementById("btn-reset-cancel").addEventListener("click", () => {
  document.getElementById("reset-confirm").value = "";
  routeOnOpen();
});

document.getElementById("btn-reset-confirm").addEventListener("click", async () => {
  const typed = document.getElementById("reset-confirm").value.trim();
  if (typed !== "RESET") {
    showError("reset-err", 'Type RESET (all caps) to confirm.');
    return;
  }
  try {
    await chrome.storage.local.remove([VAULT_KEY, ACCOUNTS_KEY]);
    lock();
    pendingNewVault = null;
    document.getElementById("reset-confirm").value = "";
    show("screen-empty");
  } catch (e) {
    showError("reset-err", String(e));
  }
});

document
  .getElementById("btn-mnemonic-done")
  .addEventListener("click", renderAccount);

document.getElementById("btn-copy").addEventListener("click", async () => {
  await navigator.clipboard.writeText(document.getElementById("addr").textContent);
});

document.getElementById("btn-save-rpc").addEventListener("click", async () => {
  const url = document.getElementById("rpc-url").value.trim();
  await chrome.storage.local.set({ [RPC_URL_KEY]: url });
});

// Best-effort wipe when the popup is torn down (also happens naturally
// when the popup closes — the JS context is discarded — but this makes
// the intent explicit and covers the rare bfcache case).
window.addEventListener("pagehide", lock);
window.addEventListener("beforeunload", lock);

routeOnOpen();
