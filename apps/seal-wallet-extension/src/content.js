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

  // Bridge: page → background.
  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.target !== "seal-wallet-content") return;

    try {
      const response = await api.runtime.sendMessage(data.payload);
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
