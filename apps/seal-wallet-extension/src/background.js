// Seal Wallet — MV3 background service worker.
//
// Runs in a non-DOM context. Holds NO secret material in memory: the
// encrypted vault lives in `browserApi.storage.local`, decryption
// only happens in the popup right before signing. The service
// worker's job is purely message routing between the in-page
// provider and the popup, plus persisting connection-approved
// origins.
//
// Message protocol (all `browserApi.runtime.sendMessage` payloads):
//   { type: "seal:getAccounts" }          → ["seal1...", ...]
//   { type: "seal:requestAccounts", origin } → opens popup if not approved
//   { type: "seal:signMessage", origin, message_hex } → opens popup, returns sig
//   { type: "seal:rpc", method, params }  → forwarded to configured RPC URL
//
// `browserApi` is a cross-browser alias for `chrome`/`browser`.
// Inlined for both module + classic contexts; the same logic also
// lives in `browser-polyfill.js` (loaded as a content_script).
// On Chromium browsers `browserApi === chrome`; on Firefox/Safari
// it's `browser` (Promise-native). Chromium MV3's `chrome.*` returns
// Promises since Chrome 88, so picking the right namespace is all
// we need.
const browserApi =
  typeof globalThis.browser !== "undefined" && globalThis.browser?.runtime
    ? globalThis.browser
    : globalThis.chrome;

const RPC_URL_KEY = "seal:rpc_url";
const ACCOUNTS_KEY = "seal:accounts"; // public metadata only (addresses, not keys)
const APPROVED_ORIGINS_KEY = "seal:approved_origins";

async function getApprovedOrigins() {
  const out = await browserApi.storage.local.get(APPROVED_ORIGINS_KEY);
  return out[APPROVED_ORIGINS_KEY] || [];
}

async function approveOrigin(origin) {
  const list = await getApprovedOrigins();
  if (!list.includes(origin)) {
    list.push(origin);
    await browserApi.storage.local.set({ [APPROVED_ORIGINS_KEY]: list });
  }
}

async function getAccounts() {
  const out = await browserApi.storage.local.get(ACCOUNTS_KEY);
  return out[ACCOUNTS_KEY] || [];
}

async function getRpcUrl() {
  const out = await browserApi.storage.local.get(RPC_URL_KEY);
  return out[RPC_URL_KEY] || "http://localhost:8545";
}

// Track in-flight sign requests so the popup can pull its work item.
const pendingRequests = new Map();
let nextRequestId = 1;

function enqueueRequest(req) {
  const id = nextRequestId++;
  return new Promise((resolve, reject) => {
    pendingRequests.set(id, { req, resolve, reject });
    browserApi.action.openPopup().catch(() => {
      // openPopup is gated; user must click toolbar icon. The popup
      // will pull pending requests on open.
    });
  });
}

browserApi.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    try {
      switch (msg.type) {
        case "seal:getAccounts": {
          const origin = sender.origin || (sender.url && new URL(sender.url).origin);
          const approved = await getApprovedOrigins();
          sendResponse(approved.includes(origin) ? await getAccounts() : []);
          return;
        }

        case "seal:requestAccounts": {
          const origin = sender.origin || (sender.url && new URL(sender.url).origin);
          const approved = await getApprovedOrigins();
          if (approved.includes(origin)) {
            sendResponse({ ok: true, accounts: await getAccounts() });
            return;
          }
          // Queue an approval request for the popup.
          const result = await enqueueRequest({ kind: "approve", origin });
          if (result.approved) {
            await approveOrigin(origin);
            sendResponse({ ok: true, accounts: await getAccounts() });
          } else {
            sendResponse({ ok: false, error: "user rejected" });
          }
          return;
        }

        case "seal:signMessage": {
          const origin = sender.origin || (sender.url && new URL(sender.url).origin);
          const approved = await getApprovedOrigins();
          if (!approved.includes(origin)) {
            sendResponse({ ok: false, error: "origin not connected" });
            return;
          }
          const messageHex = msg.message_hex;
          // The message is rendered in the popup and signed by the user's
          // key. Reject anything that isn't even-length hex up front so a
          // dApp can't push a malformed payload into the pending-request
          // queue (the popup displays it, and it's what gets signed).
          if (
            typeof messageHex !== "string" ||
            messageHex.length % 2 !== 0 ||
            !/^[0-9a-fA-F]*$/.test(messageHex)
          ) {
            sendResponse({ ok: false, error: "message_hex must be even-length hex" });
            return;
          }
          const result = await enqueueRequest({
            kind: "sign",
            origin,
            messageHex,
            address: msg.address,
          });
          sendResponse(result);
          return;
        }

        case "seal:popup:listRequests": {
          // Popup-only: reject anything from a web page (`sender.tab` set)
          // or another extension (`sender.id` mismatch). The content script
          // relays page postMessages, and request IDs are a small enumerable
          // counter, so an unguarded handler lets any page enumerate — and
          // then resolve — a signature request the user never approved.
          if (sender.id !== browserApi.runtime.id || sender.tab) return;
          const out = [];
          for (const [id, { req }] of pendingRequests) {
            out.push({ id, ...req });
          }
          sendResponse(out);
          return;
        }

        case "seal:popup:resolveRequest": {
          // Popup-only, same guard as listRequests: only the extension's own
          // popup may settle a pending request.
          if (sender.id !== browserApi.runtime.id || sender.tab) return;
          const entry = pendingRequests.get(msg.id);
          if (!entry) {
            sendResponse({ ok: false, error: "no such request" });
            return;
          }
          pendingRequests.delete(msg.id);
          entry.resolve(msg.result);
          sendResponse({ ok: true });
          return;
        }

        case "seal:rpc": {
          // Plain JSON-RPC pass-through. Origin is logged but not
          // gated — read RPCs are public. Mutating RPCs require a
          // signature (built via seal:signMessage).
          const url = await getRpcUrl();
          const resp = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              jsonrpc: "2.0",
              id: 1,
              method: msg.method,
              params: msg.params || {},
            }),
          });
          sendResponse(await resp.json());
          return;
        }

        default:
          sendResponse({ ok: false, error: `unknown message type ${msg.type}` });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  })();
  return true; // keep the channel open for async sendResponse
});
