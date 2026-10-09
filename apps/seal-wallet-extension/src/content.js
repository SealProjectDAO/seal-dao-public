// Seal Wallet — content script. Runs in the page's isolated world.
// Loads the in-page provider (`inject.js`) into the MAIN world so
// dApps can access `window.seal`, then bridges postMessage events
// to/from the extension's background service worker.
//
// Content scripts are classic scripts (not modules), so the
// cross-browser polyfill is loaded BEFORE this file in the manifest's
// `content_scripts.js` array. It exposes `globalThis.browserApi`.
// On Chromium browsers `browserApi === chrome`; on Firefox/Safari
// it's `browser` (Promise-native). See `browser-polyfill.js`.

(function () {
  const api = globalThis.browserApi;

  // Inject the provider into the main world.
  const script = document.createElement("script");
  script.src = api.runtime.getURL("src/inject.js");
  script.onload = () => script.remove();
  (document.head || document.documentElement).appendChild(script);

  // Only these message types make up the page → extension API. The content
  // script runs in a web page's isolated world and the page can postMessage
  // *anything* to it, so we must not forward arbitrary payload types to the
  // background — in particular the `seal:popup:*` handlers, which enumerate
  // and resolve pending signature requests (a page could otherwise forge a
  // "signature" result into a request the user never approved). The
  // background independently rejects `seal:popup:*` from any sender with a
  // tab, as defense in depth.
  const RELAYED_TYPES = new Set([
    "seal:getAccounts",
    "seal:requestAccounts",
    "seal:signMessage",
    "seal:rpc",
  ]);

  // Bridge: page → background.
  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.target !== "seal-wallet-content") return;
    const payload = data.payload;
    if (!payload || !RELAYED_TYPES.has(payload.type)) return;

    try {
      const response = await api.runtime.sendMessage(payload);
      window.postMessage(
        { target: "seal-wallet-page", id: data.id, response },
        window.location.origin,
      );
    } catch (err) {
      window.postMessage(
        {
          target: "seal-wallet-page",
          id: data.id,
          response: { ok: false, error: String(err) },
        },
        window.location.origin,
      );
    }
  });
})();
