// Cross-browser polyfill — aliases the WebExtension API namespace.
//
// Chromium browsers (Chrome 119+, Edge, Brave, Opera) expose `chrome.*`
// with Promise-returning methods under MV3. Firefox MV3 exposes both
// `browser.*` (Promise-native) and a callback-only `chrome.*` for
// compatibility. Safari Web Extensions ships `browser.*` only.
//
// This file is loaded both as a content_script (classic) and as a
// module-side dependency by background.js / popup.js. To work in
// both contexts it uses no module syntax (`import`/`export`); every
// consumer reads `globalThis.browserApi` instead.
//
// The `browser?.runtime` guard avoids a false positive: some pages
// declare a global `browser` variable (e.g. via the `browser-polyfill`
// npm package) without the WebExtension runtime.
//
// MV3-specific note: Chromium's `chrome.*` already returns Promises
// when no callback is given (since Chrome 88), so picking the right
// namespace is enough — no Promise-wrapping needed.

(function (root) {
  if (root.browserApi) return; // idempotent
  root.browserApi =
    typeof root.browser !== "undefined" && root.browser?.runtime
      ? root.browser
      : root.chrome;
})(typeof globalThis !== "undefined" ? globalThis : self);
