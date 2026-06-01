// Seal Wallet — popup UI.
//
// Owns the WASM ML-DSA signing surface. Loads `seal-dao-wasm` once at
// open time, decrypts the vault when the user unlocks with their
// passphrase, signs whatever the background service worker has queued,
// and writes the result back.
//
// `browserApi` is a cross-browser alias for `chrome`/`browser`.
// Inlined; same logic in `browser-polyfill.js` for the content
// script. On Chromium `browserApi === chrome`; on Firefox/Safari
// it's `browser`.
const browserApi =
  typeof globalThis.browser !== "undefined" && globalThis.browser?.runtime
    ? globalThis.browser
    : globalThis.chrome;

// Vault layout in browserApi.storage.local:
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
  await browserApi.storage.local.set({
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
  const out = await browserApi.storage.local.get(VAULT_KEY);
  return !!out[VAULT_KEY];
}

async function decryptVault(passphrase) {
  const out = await browserApi.storage.local.get(VAULT_KEY);
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
  cancelIdleTimer();
  stopBalancePoll();
  // Reset DEX tape state so it doesn't bleed across sessions.
  selectedPair = null;
  tradeTapeBuffer = [];
  tradeTapeLastId = 0;
  // Hide the QR if it was visible — locking the wallet shouldn't
  // leave the address image up after the user navigates away.
  if (qrShown) toggleAddressQR();
}

// ── Idle auto-lock ─────────────────────────────────────────────────
//
// While `unlocked` is non-null, schedule a `lock()` after
// `IDLE_TIMEOUT_MS` of no user input. Any click / keydown / focus
// resets the timer. Closing the popup also wipes `unlocked` via
// pagehide (see bottom of file), so the popup-closed case is
// already covered; this handles "user opened the popup, walked
// away".
//
// Service-worker `chrome.alarms` would let us also enforce a max
// session length across closes — but the popup's `unlocked` buffer
// is gone the moment the popup closes (JS context discarded), so
// that's already implicit. Tracking idle outside the popup would
// only matter if we cached a hot key in the service worker, which
// we explicitly do not (see seal:signMessage flow in background.js).
const IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
let idleTimer = null;

function resetIdleTimer() {
  if (!unlocked) return;
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (!unlocked) return; // race: user locked between schedule and fire
    lock();
    // Best-effort: route back to the unlock screen so the user knows
    // why the popup changed state. show() is no-op if the section
    // isn't in the DOM (the popup may have been torn down already).
    try {
      show("screen-unlock");
      const passEl = document.getElementById("unlock-pass");
      if (passEl) {
        passEl.value = "";
        passEl.focus();
      }
    } catch (_) {
      // Popup torn down between fire and DOM access — fine.
    }
  }, IDLE_TIMEOUT_MS);
}

function cancelIdleTimer() {
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
}

// ── Wallet ops ─────────────────────────────────────────────────────
async function createWallet(passphrase) {
  await ensureWasm();
  const json = JSON.parse(generate_keypair(false));
  const vaultPayload = new TextEncoder().encode(JSON.stringify(json));
  await saveVault(vaultPayload, passphrase);
  await browserApi.storage.local.set({ [ACCOUNTS_KEY]: [json.address] });
  unlocked = vaultPayload;
  resetIdleTimer();
  return json;
}

async function importMnemonic(mnemonic, passphrase) {
  await ensureWasm();
  const json = JSON.parse(import_from_mnemonic(mnemonic, false));
  const vaultPayload = new TextEncoder().encode(JSON.stringify(json));
  await saveVault(vaultPayload, passphrase);
  await browserApi.storage.local.set({ [ACCOUNTS_KEY]: [json.address] });
  unlocked = vaultPayload;
  resetIdleTimer();
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
  // Balance polling only runs on the account screen.
  if (id !== "screen-account") stopBalancePoll();
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
  const out = await browserApi.storage.local.get([ACCOUNTS_KEY, RPC_URL_KEY]);
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
  // Refresh once on entry, then keep ticking while the screen is up.
  refreshBalances();
  startBalancePoll();
}

// ── Balance polling ───────────────────────────────────────────────
//
// Polls `seal_getBalance(self)` plus any custom-token balances every
// `BAL_POLL_MS` while the account screen is visible. Stops on lock,
// reset, or screen change. The query is unsigned — public read of the
// caller's own balance — so we never touch the unlocked vault.
const BAL_POLL_MS = 5_000;
let balPollTimer = null;
let knownTokens = []; // [{ symbol, decimals }, ...] — refreshed on each tick

async function jsonRpc(method, params) {
  const out = await browserApi.storage.local.get(RPC_URL_KEY);
  const url = out[RPC_URL_KEY] || "http://localhost:8545";
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", method, params, id: 1 }),
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error.message);
  return data.result;
}

function getMyAddress() {
  return document.getElementById("addr").textContent;
}

async function refreshBalances() {
  const addr = getMyAddress();
  if (!addr) return;
  const errEl = document.getElementById("balances-err");
  errEl.hidden = true;
  // Native SEAL.
  try {
    const r = await jsonRpc("seal_getBalance", { address: addr });
    const bal = r?.balance ?? r?.available ?? 0;
    document.getElementById("bal-seal").textContent =
      Number(bal).toLocaleString();
  } catch (e) {
    document.getElementById("bal-seal").textContent = "?";
    errEl.textContent = "Balance fetch failed: " + e.message;
    errEl.hidden = false;
    return; // don't try tokens if the node's unreachable
  }
  // Tokens — list-then-fetch each. Cheap, and resilient to mid-poll
  // token creations (the next tick picks up the new symbol).
  let tokens = [];
  try {
    const r = await jsonRpc("seal_listTokens", {});
    tokens = (r?.tokens || []).map((t) => ({
      symbol: t.symbol,
      decimals: t.decimals,
      frozen: t.frozen === true,
    }));
  } catch (_) {
    // Token RPC may be unimplemented on a stripped-down node — leave
    // the list empty; the SEAL row above stays.
  }
  knownTokens = tokens;
  await renderTokenBalances(addr, tokens);
}

async function renderTokenBalances(addr, tokens) {
  const list = document.getElementById("balances");
  // Wipe everything below the SEAL row, rebuild from `tokens`.
  while (list.children.length > 1) list.removeChild(list.lastChild);
  for (const t of tokens) {
    let bal;
    try {
      const r = await jsonRpc("seal_getTokenBalance", {
        symbol: t.symbol,
        address: addr,
      });
      bal = r?.balance ?? 0;
    } catch (_) {
      bal = "?";
    }
    const li = document.createElement("li");
    li.className = "bal-row";
    const sym = document.createElement("span");
    sym.className = "bal-sym";
    sym.textContent = t.symbol;
    if (t.frozen) sym.title = "Token is globally frozen — transfers will reject";
    const amt = document.createElement("span");
    amt.className = "bal-amt mono";
    amt.textContent =
      typeof bal === "number" ? bal.toLocaleString() : String(bal);
    const unit = document.createElement("span");
    unit.className = "bal-unit muted";
    if (t.frozen) {
      unit.textContent = "FROZEN";
      unit.style.color = "#c33";
    } else {
      unit.textContent = t.decimals != null ? `10^-${t.decimals}` : "";
    }
    li.appendChild(sym);
    li.appendChild(amt);
    li.appendChild(unit);
    list.appendChild(li);
  }
}

function startBalancePoll() {
  if (balPollTimer) return;
  balPollTimer = setInterval(() => {
    refreshBalances();
    refreshPairs();          // cheap, also detects newly-listed pairs
    if (selectedPair) pollTrades();
  }, BAL_POLL_MS);
}

function stopBalancePoll() {
  if (balPollTimer) {
    clearInterval(balPollTimer);
    balPollTimer = null;
  }
}

// ── DEX trade tape ────────────────────────────────────────────────
//
// Same RPC shape as the Electron / explorer tapes
// (`seal_listTrades`, `seal_listPairs`). The popup reuses the
// 5-second balance poll cadence so we don't run two timers; the
// budget per tick is one balance + one tokens roundtrip + one
// pairs + (if selected) one trades. Comfortably under 1s for a
// nearby node.
const TRADE_TAPE_MAX = 30; // popup is 360px wide — keep this tight
let knownPairs = new Set();
let selectedPair = null;
let tradeTapeBuffer = [];
let tradeTapeLastId = 0;

async function refreshPairs() {
  let pairs;
  try {
    const r = await jsonRpc("seal_listPairs", {});
    pairs = r?.pairs || [];
  } catch (_) {
    return; // no DEX RPC on this node — leave dropdown empty
  }
  const names = pairs.map((p) =>
    typeof p === "string" ? p : p.pair || `${p.base}/${p.quote}`,
  );
  const next = new Set(names);
  if (
    next.size === knownPairs.size &&
    [...next].every((p) => knownPairs.has(p))
  ) {
    return;
  }
  knownPairs = next;
  const sel = document.getElementById("market-pair");
  const prev = selectedPair || sel.value;
  sel.innerHTML = "";
  const empty = document.createElement("option");
  empty.value = "";
  empty.textContent = names.length ? "Pick a pair…" : "No pairs";
  sel.appendChild(empty);
  for (const name of names) {
    const opt = document.createElement("option");
    opt.value = name;
    opt.textContent = name;
    if (name === prev) opt.selected = true;
    sel.appendChild(opt);
  }
  if (prev && !next.has(prev)) {
    selectedPair = null;
    tradeTapeBuffer = [];
    tradeTapeLastId = 0;
    renderTradeTape();
  }
}

async function pollTrades() {
  if (!selectedPair) return;
  let r;
  try {
    r = await jsonRpc("seal_listTrades", {
      pair: selectedPair,
      since_id: tradeTapeLastId,
      limit: TRADE_TAPE_MAX,
    });
  } catch (e) {
    document.getElementById("market-summary").textContent =
      "err: " + e.message;
    return;
  }
  const newTrades = r?.trades || [];
  if (newTrades.length) {
    tradeTapeBuffer = [...tradeTapeBuffer, ...newTrades].slice(
      -TRADE_TAPE_MAX,
    );
    tradeTapeLastId = r.last_id || tradeTapeLastId;
  }
  document.getElementById("market-summary").textContent = selectedPair
    ? `${tradeTapeBuffer.length} · #${tradeTapeLastId || "—"}`
    : "";
  renderTradeTape();
}

function renderTradeTape() {
  const ul = document.getElementById("trade-tape");
  ul.innerHTML = "";
  if (!selectedPair || !tradeTapeBuffer.length) return;
  for (const t of [...tradeTapeBuffer].reverse()) {
    const li = document.createElement("li");
    const id = document.createElement("span");
    id.className = "tape-id";
    id.textContent = "#" + (t.id ?? "");
    const price = document.createElement("span");
    price.className = "tape-price";
    price.textContent = String(t.price ?? "");
    const qty = document.createElement("span");
    qty.className = "tape-qty";
    qty.textContent = String(t.quantity ?? "");
    const side = document.createElement("span");
    side.className =
      "tape-side " + (t.side === "bid" ? "side-bid" : "side-ask");
    side.textContent = (t.side || "").toUpperCase();
    li.appendChild(id);
    li.appendChild(price);
    li.appendChild(qty);
    li.appendChild(side);
    ul.appendChild(li);
  }
}

function onPairChange(e) {
  const v = e.target.value || null;
  if (v === selectedPair) return;
  selectedPair = v;
  tradeTapeBuffer = [];
  tradeTapeLastId = 0;
  if (selectedPair) pollTrades();
  else renderTradeTape();
}

// ── Address QR ────────────────────────────────────────────────────
let qrShown = false;
function toggleAddressQR() {
  const host = document.getElementById("qr-host");
  const btn = document.getElementById("btn-toggle-qr");
  if (qrShown) {
    host.classList.remove("shown");
    host.innerHTML = "";
    btn.textContent = "Show QR";
    qrShown = false;
    return;
  }
  if (!globalThis.SealQR) {
    host.textContent = "QR unavailable";
    host.classList.add("shown");
    return;
  }
  host.innerHTML = "";
  const canvas = document.createElement("canvas");
  host.appendChild(canvas);
  try {
    globalThis.SealQR.draw(canvas, getMyAddress(), 4);
    host.classList.add("shown");
    btn.textContent = "Hide QR";
    qrShown = true;
  } catch (e) {
    host.textContent = "QR error: " + e.message;
    host.classList.add("shown");
  }
}

async function renderRequests() {
  const list = await browserApi.runtime.sendMessage({ type: "seal:popup:listRequests" });
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
  await browserApi.runtime.sendMessage({
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
    resetIdleTimer();
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
    resetIdleTimer();
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
    await browserApi.storage.local.remove([VAULT_KEY, ACCOUNTS_KEY]);
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

document
  .getElementById("btn-toggle-qr")
  .addEventListener("click", toggleAddressQR);

document
  .getElementById("market-pair")
  .addEventListener("change", onPairChange);

document.getElementById("btn-save-rpc").addEventListener("click", async () => {
  const url = document.getElementById("rpc-url").value.trim();
  await browserApi.storage.local.set({ [RPC_URL_KEY]: url });
});

// Best-effort wipe when the popup is torn down (also happens naturally
// when the popup closes — the JS context is discarded — but this makes
// the intent explicit and covers the rare bfcache case).
window.addEventListener("pagehide", lock);
window.addEventListener("beforeunload", lock);

// Activity sources that count as "user is here" — reset the idle
// timer on each. Capture phase on document so all clicks, keys, and
// focus changes are observed regardless of which child element
// caught the event.
document.addEventListener("click", resetIdleTimer, { capture: true });
document.addEventListener("keydown", resetIdleTimer, { capture: true });
window.addEventListener("focus", resetIdleTimer);

routeOnOpen();
