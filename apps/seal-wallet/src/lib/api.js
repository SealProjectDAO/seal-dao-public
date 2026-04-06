/**
 * Tauri IPC API wrapper for Seal Wallet.
 *
 * In Tauri mode: calls Rust commands via IPC.
 * In browser mode (dev without Tauri): uses mock data.
 */

const IS_TAURI = typeof window !== "undefined" && window.__TAURI__;

async function invoke(cmd, args = {}) {
  if (IS_TAURI) {
    const { invoke: tauriInvoke } = await import("@tauri-apps/api/core");
    return tauriInvoke(cmd, args);
  }
  // Mock fallback for browser development
  return mockInvoke(cmd, args);
}

// --- Wallet commands ---

export async function createWallet(testnet = true) {
  const json = await invoke("create_wallet", { testnet });
  return JSON.parse(json);
}

export async function importWallet(mnemonicHex, testnet = true) {
  const json = await invoke("import_wallet", {
    mnemonicHex,
    testnet,
  });
  return JSON.parse(json);
}

export async function importWalletBip39(words, testnet = true) {
  const json = await invoke("import_wallet_bip39", { words, testnet });
  return JSON.parse(json);
}

export async function getWalletInfo() {
  const json = await invoke("get_wallet_info");
  return JSON.parse(json);
}

export async function getAddress() {
  return invoke("get_address");
}

export async function getBalance() {
  const json = await invoke("get_balance");
  return JSON.parse(json);
}

// --- Mnemonic ---

export async function exportMnemonic() {
  return invoke("export_mnemonic");
}

export async function exportMnemonicBip39() {
  return invoke("export_mnemonic_bip39");
}

export async function exportMnemonicWords() {
  return invoke("export_mnemonic_words");
}

// --- Crypto ---

export async function signMessage(message) {
  return invoke("sign_message", { message });
}

export async function verifySignature(message, signatureHex) {
  return invoke("verify_signature", { message, signatureHex });
}

// --- Storage ---

export async function saveWallet(path, password) {
  return invoke("save_wallet", { path, password });
}

export async function loadWallet(path, password) {
  const json = await invoke("load_wallet", { path, password });
  return JSON.parse(json);
}

// --- Node RPC ---

export async function rpcGetHeight(nodeUrl) {
  return invoke("rpc_get_height", { nodeUrl });
}

export async function rpcQuery(nodeUrl, sql) {
  return invoke("rpc_query", { nodeUrl, sql });
}

export async function rpcSend(nodeUrl, sql) {
  return invoke("rpc_send", { nodeUrl, sql });
}

export async function rpcMpc(nodeUrl, function_, table, column) {
  return invoke("rpc_mpc_aggregate", { nodeUrl, function: function_, table, column });
}

export async function rpcZkProve(nodeUrl, table, statement) {
  return invoke("rpc_zk_prove", { nodeUrl, statement, table });
}

// --- Token operations ---

export async function rpcCreateToken(nodeUrl, symbol, name, maxSupply) {
  return invoke("rpc_create_token", { nodeUrl, symbol, name, maxSupply });
}

export async function rpcMintToken(nodeUrl, symbol, to, amount) {
  return invoke("rpc_mint_token", { nodeUrl, symbol, to, amount });
}

export async function rpcListTokens(nodeUrl) {
  return invoke("rpc_list_tokens", { nodeUrl });
}

// --- DEX operations ---

export async function rpcCreatePair(nodeUrl, base, quote) {
  return invoke("rpc_create_pair", { nodeUrl, base, quote });
}

export async function rpcPlaceOrder(nodeUrl, pair, side, price, quantity) {
  return invoke("rpc_place_order", { nodeUrl, pair, side, price, quantity });
}

export async function rpcCancelOrder(nodeUrl, pair, orderId) {
  return invoke("rpc_cancel_order", { nodeUrl, pair, orderId });
}

export async function rpcGetOrderBook(nodeUrl, pair) {
  return invoke("rpc_get_order_book", { nodeUrl, pair });
}

export async function rpcListPairs(nodeUrl) {
  return invoke("rpc_list_pairs", { nodeUrl });
}

// --- Mock data for browser development ---

let mockWallet = null;

function mockInvoke(cmd, args) {
  switch (cmd) {
    case "create_wallet":
      mockWallet = {
        seal_address: "sealt1mock" + Math.random().toString(36).slice(2, 10),
        seal_pubkey_hex: "0".repeat(64),
        ed25519_pubkey_hex: "0".repeat(64),
      };
      return JSON.stringify(mockWallet);

    case "get_wallet_info":
      return JSON.stringify(
        mockWallet || { seal_address: "no wallet", seal_pubkey_hex: "", ed25519_pubkey_hex: "" }
      );

    case "get_address":
      return mockWallet?.seal_address || "no wallet";

    case "get_balance":
      return JSON.stringify({ seal: 1000000, wSOL: 0, wXLM: 0, wUSDC: 0 });

    case "export_mnemonic":
      return "0".repeat(64);

    case "export_mnemonic_bip39":
      return "abandon ".repeat(24).trim();

    case "sign_message":
      return "mocksig" + "0".repeat(100);

    case "verify_signature":
      return true;

    case "rpc_get_height":
      return JSON.stringify({ jsonrpc: "2.0", result: { height: 42 }, id: 1 });

    case "rpc_query":
      return JSON.stringify({ jsonrpc: "2.0", result: { columns: ["id", "name"], rows: [["1", "mock"]] }, id: 1 });

    case "rpc_send":
      return JSON.stringify({ jsonrpc: "2.0", result: { rows_affected: 1 }, id: 1 });

    case "rpc_mpc_aggregate":
      return JSON.stringify({ jsonrpc: "2.0", result: { result: 100, row_count: 3 }, id: 1 });

    case "rpc_zk_prove":
      return JSON.stringify({ jsonrpc: "2.0", result: { satisfied: true, proof: "mock" + "0".repeat(60) }, id: 1 });

    case "rpc_create_token":
      return JSON.stringify({ jsonrpc: "2.0", result: { symbol: args.symbol, status: "created" }, id: 1 });

    case "rpc_mint_token":
      return JSON.stringify({ jsonrpc: "2.0", result: { symbol: args.symbol, minted: args.amount }, id: 1 });

    case "rpc_list_tokens":
      return JSON.stringify({ jsonrpc: "2.0", result: { tokens: [{ symbol: "GOLD", name: "Gold Token", total_supply: 1000, max_supply: 1000000 }] }, id: 1 });

    case "rpc_create_pair":
      return JSON.stringify({ jsonrpc: "2.0", result: { pair: args.base + "/" + args.quote, status: "created" }, id: 1 });

    case "rpc_place_order":
      return JSON.stringify({ jsonrpc: "2.0", result: { order_id: 1, trades: 0 }, id: 1 });

    case "rpc_cancel_order":
      return JSON.stringify({ jsonrpc: "2.0", result: { cancelled: true }, id: 1 });

    case "rpc_get_order_book":
      return JSON.stringify({ jsonrpc: "2.0", result: { bids: [], asks: [] }, id: 1 });

    case "rpc_list_pairs":
      return JSON.stringify({ jsonrpc: "2.0", result: { pairs: [] }, id: 1 });

    default:
      return null;
  }
}
