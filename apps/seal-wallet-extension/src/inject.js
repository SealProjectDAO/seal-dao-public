// Seal Wallet — provider injected into the page's MAIN world.
//
// Surfaces a minimal `window.seal` object so dApps can sign things
// without bundling any wallet code themselves. Mirrors the shape of
// EIP-1193 (`request({ method, params })`) but with Seal-native
// methods. Everything goes through `window.postMessage` because the
// page can't talk to `chrome.runtime` directly.

(function () {
  if (window.seal) return; // don't double-inject

  let nextId = 1;
  const pending = new Map();

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.target !== "seal-wallet-page") return;
    const handler = pending.get(data.id);
    if (!handler) return;
    pending.delete(data.id);
    handler.resolve(data.response);
  });

  function utf8ToHex(s) {
    const bytes = new TextEncoder().encode(s);
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out;
  }

  function send(payload) {
    return new Promise((resolve) => {
      const id = nextId++;
      pending.set(id, { resolve });
      window.postMessage(
        { target: "seal-wallet-content", id, payload },
        window.location.origin,
      );
    });
  }

  window.seal = {
    isSealWallet: true,

    // EIP-1193-ish entry point so dApps that already speak that shape
    // can switch to Seal with one line.
    async request({ method, params }) {
      switch (method) {
        case "seal_accounts":
          return await send({ type: "seal:getAccounts" });
        case "seal_requestAccounts": {
          const r = await send({ type: "seal:requestAccounts" });
          if (!r.ok) throw new Error(r.error || "request rejected");
          return r.accounts;
        }
        case "seal_signMessage": {
          // Accept three shapes:
          //   params: ["hello"]                          → UTF-8 → hex
          //   params: { message: "hello" }               → UTF-8 → hex
          //   params: { address, message_hex }           → pass-through
          let address, message_hex;
          if (Array.isArray(params)) {
            address = undefined;
            message_hex = utf8ToHex(String(params[0] ?? ""));
          } else if (params && typeof params === "object") {
            address = params.address;
            if (typeof params.message_hex === "string") {
              message_hex = params.message_hex;
            } else if (typeof params.message === "string") {
              message_hex = utf8ToHex(params.message);
            } else {
              throw new Error(
                "seal_signMessage: provide params[0] as a string, or { message } / { message_hex }",
              );
            }
          } else {
            throw new Error("seal_signMessage: missing params");
          }
          const r = await send({
            type: "seal:signMessage",
            address,
            message_hex,
          });
          if (!r.ok) throw new Error(r.error || "signing rejected");
          return r.signature_hex;
        }
        default: {
          // Anything else is forwarded to the configured Seal node
          // as plain JSON-RPC.
          return await send({ type: "seal:rpc", method, params });
        }
      }
    },
  };

  // Announce ourselves so dApps know to use us. Matches the
  // pattern multi-wallet pages use to discover providers.
  window.dispatchEvent(new Event("seal#initialized"));
})();
