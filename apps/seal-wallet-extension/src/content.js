// Seal Wallet — content script. Runs in the page's isolated world.
// Loads the in-page provider (`inject.js`) into the MAIN world so
// dApps can access `window.seal`, then bridges postMessage events
// to/from the extension's background service worker.

(function () {
  // Inject the provider into the main world.
  const script = document.createElement("script");
  script.src = chrome.runtime.getURL("src/inject.js");
  script.onload = () => script.remove();
  (document.head || document.documentElement).appendChild(script);

  // Bridge: page → background.
  window.addEventListener("message", async (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.target !== "seal-wallet-content") return;

    try {
      const response = await chrome.runtime.sendMessage(data.payload);
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
