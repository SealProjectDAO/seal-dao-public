//! Terminal wallet — interactive TUI for managing Seal keys and signing.
//!
//! Usage: seal wallet

use seal_wallet::keystore::Wallet;
use seal_wallet::mnemonic::Seed;
use std::io::{self, BufRead, Write};

pub fn run_wallet() {
    println!("=== Seal Wallet (TUI) ===");
    println!("Post-quantum secure. ML-DSA-65 + ML-KEM-768 + SHA3-256.");
    println!("Type 'help' for commands.\n");

    let mut wallet: Option<WalletState> = None;

    print_prompt(&wallet);
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            print_prompt(&wallet);
            continue;
        }

        match parts[0] {
            "help" | "h" => print_help(),
            "create" | "new" => {
                wallet = Some(create_wallet(parts.get(1).copied()));
            }
            "import" => {
                if parts.len() < 2 {
                    eprintln!("Usage: import <bip39 words...>");
                } else {
                    wallet = import_wallet(&parts[1..]);
                }
            }
            "restore" => {
                if parts.len() < 2 {
                    eprintln!("Usage: restore <64-char hex seed>");
                } else {
                    wallet = restore_wallet(parts[1]);
                }
            }
            "address" | "addr" => show_address(&wallet),
            "info" => show_info(&wallet),
            "sign" => {
                if parts.len() < 2 {
                    eprintln!("Usage: sign <message>");
                } else {
                    sign_message(&wallet, &parts[1..].join(" "));
                }
            }
            "verify" => {
                if parts.len() < 3 {
                    eprintln!("Usage: verify <message> <signature_hex>");
                } else {
                    let sig_hex = parts.last().unwrap();
                    let msg = parts[1..parts.len() - 1].join(" ");
                    verify_message(&wallet, &msg, sig_hex);
                }
            }
            "connect" => {
                if parts.len() < 2 {
                    eprintln!("Usage: connect http://localhost:8545");
                } else {
                    connect_node(&mut wallet, parts[1]);
                }
            }
            "balance" | "bal" => show_balance(&wallet),
            "height" => show_height(&wallet),
            "send" => {
                if parts.len() < 2 {
                    eprintln!("Usage: send <SQL statement>");
                } else {
                    send_tx(&wallet, &parts[1..].join(" "));
                }
            }
            "query" | "sql" => {
                if parts.len() < 2 {
                    eprintln!("Usage: query <SQL statement>");
                } else {
                    query_node(&wallet, &parts[1..].join(" "));
                }
            }
            "transfer" => {
                if parts.len() < 3 {
                    eprintln!("Usage: transfer <to_address> <amount>");
                } else {
                    transfer_seal(&wallet, parts[1], parts[2]);
                }
            }
            "create-token" => {
                if parts.len() < 3 {
                    eprintln!("Usage: create-token <SYMBOL> <name> [max_supply]");
                } else {
                    let max = parts.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                    create_token(&wallet, parts[1], parts[2], max);
                }
            }
            "mint-token" => {
                if parts.len() < 4 {
                    eprintln!("Usage: mint-token <SYMBOL> <to_address> <amount>");
                } else {
                    mint_token(&wallet, parts[1], parts[2], parts[3]);
                }
            }
            "tokens" => list_tokens(&wallet),
            "create-pair" => {
                if parts.len() < 3 {
                    eprintln!("Usage: create-pair <BASE> <QUOTE>");
                } else {
                    create_pair(&wallet, parts[1], parts[2]);
                }
            }
            "place-order" | "order" => {
                if parts.len() < 5 {
                    eprintln!("Usage: place-order <PAIR> <bid|ask> <price> <quantity>");
                } else {
                    place_order(&wallet, parts[1], parts[2], parts[3], parts[4]);
                }
            }
            "cancel-order" => {
                if parts.len() < 3 {
                    eprintln!("Usage: cancel-order <PAIR> <order_id>");
                } else {
                    cancel_order(&wallet, parts[1], parts[2]);
                }
            }
            "orderbook" | "book" => {
                if parts.len() < 2 {
                    eprintln!("Usage: orderbook <PAIR>");
                } else {
                    show_orderbook(&wallet, parts[1]);
                }
            }
            "pairs" => list_pairs(&wallet),
            "mpc" => {
                if parts.len() < 4 {
                    eprintln!("Usage: mpc <sum|count|avg> <table> <column>");
                } else {
                    mpc_aggregate(&wallet, parts[1], parts[2], parts[3]);
                }
            }
            "zk" | "prove" => {
                if parts.len() < 3 {
                    eprintln!("Usage: zk <table> <statement>");
                } else {
                    zk_prove(&wallet, parts[1], &parts[2..].join(" "));
                }
            }
            "mnemonic" | "backup" => show_mnemonic(&wallet),
            "export" => export_key(&wallet, parts.get(1).copied()),
            "quit" | "exit" | "q" => {
                println!("Goodbye.");
                return;
            }
            _ => eprintln!("Unknown command: '{}'. Type 'help' for commands.", parts[0]),
        }

        print_prompt(&wallet);
    }
}

struct WalletState {
    wallet: Wallet,
    address: String,
    mnemonic_display: String,
    seed_hex: String,
    node_url: Option<String>,
}

fn print_prompt(wallet: &Option<WalletState>) {
    if let Some(w) = wallet {
        let short = if w.address.len() > 16 {
            format!("{}...", &w.address[..16])
        } else {
            w.address.clone()
        };
        print!("[{}] > ", short);
    } else {
        print!("[no wallet] > ");
    }
    io::stdout().flush().ok();
}

fn print_help() {
    println!("Wallet:");
    println!("  create [testnet|mainnet]   Create a new wallet");
    println!("  import <words...>          Import from BIP-39 mnemonic");
    println!("  restore <hex>              Restore from hex seed (64 chars)");
    println!("  address                    Show wallet address");
    println!("  info                       Show wallet details");
    println!("  mnemonic                   Show recovery phrase");
    println!("  export [keyfile.json]      Export key to JSON file");
    println!();
    println!("Crypto:");
    println!("  sign <message>             Sign a message (ML-DSA-65)");
    println!("  verify <msg> <sig_hex>     Verify a signature");
    println!();
    println!("Node:");
    println!("  connect <url>              Connect to a Seal node RPC");
    println!("  balance                    Show balance on connected node");
    println!("  height                     Show chain height");
    println!("  query <SQL>                Execute read-only SQL on node");
    println!("  send <SQL>                 Send signed SQL transaction");
    println!("  transfer <to> <amount>     Transfer SEAL tokens");
    println!("  create-token <SYM> <name>  Create custom token");
    println!("  mint-token <SYM> <to> <n>  Mint custom tokens");
    println!("  tokens                     List all tokens");
    println!("  create-pair <BASE> <QUOTE> Create DEX trading pair");
    println!("  place-order <PAIR> <side> <price> <qty>");
    println!("                             Place bid/ask order");
    println!("  cancel-order <PAIR> <id>   Cancel an order");
    println!("  orderbook <PAIR>           Show order book");
    println!("  pairs                      List trading pairs");
    println!("  mpc <func> <table> <col>   MPC aggregate (sum/count/avg)");
    println!("  zk <table> <statement>     ZK proof of SQL condition");
    println!();
    println!("  quit                       Exit");
}

fn create_wallet(network: Option<&str>) -> WalletState {
    let testnet = network != Some("mainnet");
    let seed = Seed::generate();
    let mnemonic_display = seed.to_mnemonic_display();
    let seed_hex = seed.to_hex();
    let wallet = Wallet::from_seed(seed, testnet);
    let address = wallet.address().to_string();

    println!("Created new wallet");
    println!("  Address:  {}", address);
    println!("  Network:  {}", if testnet { "testnet" } else { "mainnet" });
    println!();
    println!("  RECOVERY PHRASE (write this down!):");
    println!("  {}", mnemonic_display);
    println!();
    println!("  WARNING: This phrase cannot be recovered. Store it safely.");

    WalletState {
        wallet,
        address,
        mnemonic_display,
        seed_hex,
        node_url: None,
    }
}

fn restore_wallet(hex_seed: &str) -> Option<WalletState> {
    match Seed::from_hex(hex_seed) {
        Ok(seed) => {
            let mnemonic_display = seed.to_mnemonic_display();
            let seed_hex = seed.to_hex();
            let wallet = Wallet::from_seed(seed, true);
            let address = wallet.address().to_string();
            println!("Restored wallet");
            println!("  Address: {}", address);
            Some(WalletState {
                wallet,
                address,
                mnemonic_display,
                seed_hex,
                node_url: None,
            })
        }
        Err(e) => {
            eprintln!("Restore failed: {}", e);
            None
        }
    }
}

fn import_wallet(words: &[&str]) -> Option<WalletState> {
    let phrase = words.join(" ");
    match Seed::from_words(&phrase.split_whitespace().map(String::from).collect::<Vec<_>>()) {
        Ok(seed) => {
            let mnemonic_display = seed.to_mnemonic_display();
            let seed_hex = seed.to_hex();
            let wallet = Wallet::from_seed(seed, true);
            let address = wallet.address().to_string();
            println!("Imported wallet");
            println!("  Address: {}", address);
            Some(WalletState {
                wallet,
                address,
                mnemonic_display,
                seed_hex,
                node_url: None,
            })
        }
        Err(e) => {
            eprintln!("Import failed: {}", e);
            None
        }
    }
}

fn show_address(wallet: &Option<WalletState>) {
    match wallet {
        Some(w) => println!("{}", w.address),
        None => eprintln!("No wallet loaded. Use 'create' or 'import'."),
    }
}

fn show_info(wallet: &Option<WalletState>) {
    match wallet {
        Some(w) => {
            let vk = w.wallet.verifying_key();
            println!("Address:     {}", w.address);
            println!("Public key:  {}...{}", &hex::encode(vk.to_bytes())[..16], &hex::encode(vk.to_bytes())[vk.to_bytes().len()*2-16..]);
            println!("Key type:    ML-DSA-65 (FIPS 204)");
            println!("Key size:    {} bytes (signing), {} bytes (verifying)", 4032, 1952);
        }
        None => eprintln!("No wallet loaded."),
    }
}

fn sign_message(wallet: &Option<WalletState>, message: &str) {
    match wallet {
        Some(w) => {
            match w.wallet.sign(message.as_bytes()) {
                Ok(sig) => {
                    let sig_hex = hex::encode(sig.to_bytes());
                    println!("Signature: {}...{}", &sig_hex[..32], &sig_hex[sig_hex.len()-32..]);
                    println!("Full ({} bytes): {}", sig.to_bytes().len(), sig_hex);
                }
                Err(e) => eprintln!("Signing failed: {}", e),
            }
        }
        None => eprintln!("No wallet loaded."),
    }
}

fn verify_message(wallet: &Option<WalletState>, message: &str, sig_hex: &str) {
    match wallet {
        Some(w) => {
            let sig_bytes = match hex::decode(sig_hex) {
                Ok(b) => b,
                Err(_) => {
                    eprintln!("Invalid signature hex");
                    return;
                }
            };
            let sig = seal_crypto::signature::Signature::from_bytes(sig_bytes);
            match w.wallet.verifying_key().verify(message.as_bytes(), &sig) {
                Ok(()) => println!("VALID"),
                Err(_) => println!("INVALID"),
            }
        }
        None => eprintln!("No wallet loaded."),
    }
}

fn show_mnemonic(wallet: &Option<WalletState>) {
    match wallet {
        Some(w) => {
            println!("Words: {}", w.mnemonic_display);
            println!("Hex:   {}", w.seed_hex);
        }
        None => eprintln!("No wallet loaded."),
    }
}

fn export_key(wallet: &Option<WalletState>, filename: Option<&str>) {
    match wallet {
        Some(w) => {
            let output = filename.unwrap_or("seal-key.json");
            let vk = w.wallet.verifying_key();
            let key_json = serde_json::json!({
                "type": "ml-dsa-65",
                "address": w.address,
                "verifying_key": hex::encode(vk.to_bytes()),
                "mnemonic": w.mnemonic_display,
            });
            match std::fs::write(output, serde_json::to_string_pretty(&key_json).unwrap_or_default()) {
                Ok(()) => println!("Exported to {}", output),
                Err(e) => eprintln!("Failed to write: {}", e),
            }
        }
        None => eprintln!("No wallet loaded."),
    }
}

// ─── RPC Functions ──────────────────────────────────

fn connect_node(wallet: &mut Option<WalletState>, url: &str) {
    match wallet {
        Some(w) => {
            match rpc_call(url, "seal_getHeight", &serde_json::json!({})) {
                Ok(resp) => {
                    let height = resp.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
                    w.node_url = Some(url.to_string());
                    println!("Connected to {} (height: {})", url, height);
                }
                Err(e) => eprintln!("Connection failed: {}", e),
            }
        }
        None => eprintln!("Create a wallet first, then connect."),
    }
}

fn show_balance(wallet: &Option<WalletState>) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected. Use: connect <url>"); return; } };

    // Query SEAL balance
    match rpc_call(url, "seal_getBalance", &serde_json::json!({"address": w.address})) {
        Ok(resp) => {
            let bal = resp.get("balance").and_then(|b| b.as_u64()).unwrap_or(0);
            let supply = resp.get("total_supply").and_then(|s| s.as_u64()).unwrap_or(0);
            println!("SEAL balance: {} ({:.4} SEAL)", bal, bal as f64 / 1_000_000_000.0);
            println!("Total supply: {}", supply);
        }
        Err(e) => eprintln!("Balance query failed: {}", e),
    }

    // Query custom tokens
    match rpc_call(url, "seal_listTokens", &serde_json::json!({})) {
        Ok(resp) => {
            if let Some(tokens) = resp.get("tokens").and_then(|t| t.as_array()) {
                for token in tokens {
                    let symbol = token.get("symbol").and_then(|s| s.as_str()).unwrap_or("?");
                    match rpc_call(url, "seal_getTokenBalance", &serde_json::json!({"symbol": symbol, "address": w.address})) {
                        Ok(tb) => {
                            let bal = tb.get("balance").and_then(|b| b.as_u64()).unwrap_or(0);
                            if bal > 0 {
                                println!("{} balance: {}", symbol, bal);
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
        }
        Err(_) => {}
    }
}

fn show_height(wallet: &Option<WalletState>) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match rpc_call(url, "seal_getHeight", &serde_json::json!({})) {
        Ok(resp) => {
            let height = resp.get("height").and_then(|h| h.as_u64()).unwrap_or(0);
            println!("Chain height: {}", height);
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn query_node(wallet: &Option<WalletState>, sql: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match rpc_call(url, "seal_querySql", &serde_json::json!({"sql": sql})) {
        Ok(resp) => {
            if let Some(columns) = resp.get("columns").and_then(|c| c.as_array()) {
                let cols: Vec<&str> = columns.iter().filter_map(|c| c.as_str()).collect();
                if !cols.is_empty() {
                    println!("{}", cols.join(" | "));
                    println!("{}", "-".repeat(cols.len() * 15));
                }
            }
            if let Some(rows) = resp.get("rows").and_then(|r| r.as_array()) {
                for row in rows {
                    if let Some(vals) = row.as_array() {
                        let strs: Vec<String> = vals.iter().map(|v| format!("{}", v)).collect();
                        println!("{}", strs.join(" | "));
                    }
                }
                println!("({} rows)", rows.len());
            }
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn send_tx(wallet: &Option<WalletState>, sql: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match signed_rpc_call(url, "seal_submitSql", &serde_json::json!({"sql": sql}), &w.wallet) {
        Ok(result) => {
            if let Some(affected) = result.get("rows_affected") {
                println!("OK ({} rows affected)", affected);
            } else {
                println!("OK");
            }
            println!("Signed by: {}", w.address);
        }
        Err(e) => eprintln!("Send failed: {}", e),
    }
}

fn transfer_seal(wallet: &Option<WalletState>, to: &str, amount_str: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    let amount: u64 = match amount_str.parse() {
        Ok(a) => a,
        Err(_) => { eprintln!("Invalid amount"); return; }
    };
    match signed_rpc_call(url, "seal_transfer", &serde_json::json!({"to": to, "amount": amount}), &w.wallet) {
        Ok(resp) => {
            println!("Transferred {} SEAL to {}", amount, to);
            if let Some(status) = resp.get("status").and_then(|s| s.as_str()) {
                println!("Status: {}", status);
            }
        }
        Err(e) => eprintln!("Transfer failed: {}", e),
    }
}

fn create_token(wallet: &Option<WalletState>, symbol: &str, name: &str, max_supply: u64) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match signed_rpc_call(url, "seal_createToken", &serde_json::json!({
        "symbol": symbol, "name": name, "decimals": 9, "max_supply": max_supply
    }), &w.wallet) {
        Ok(resp) => {
            println!("Token created: {}", symbol);
            if let Some(creator) = resp.get("creator").and_then(|c| c.as_str()) {
                println!("Creator: {}", creator);
            }
        }
        Err(e) => eprintln!("Create failed: {}", e),
    }
}

fn mint_token(wallet: &Option<WalletState>, symbol: &str, to: &str, amount_str: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    let amount: u64 = match amount_str.parse() {
        Ok(a) => a,
        Err(_) => { eprintln!("Invalid amount"); return; }
    };
    match signed_rpc_call(url, "seal_mintToken", &serde_json::json!({"symbol": symbol, "to": to, "amount": amount}), &w.wallet) {
        Ok(_) => println!("Minted {} {} to {}", amount, symbol, to),
        Err(e) => eprintln!("Mint failed: {}", e),
    }
}

fn list_tokens(wallet: &Option<WalletState>) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match rpc_call(url, "seal_listTokens", &serde_json::json!({})) {
        Ok(resp) => {
            if let Some(tokens) = resp.get("tokens").and_then(|t| t.as_array()) {
                if tokens.is_empty() {
                    println!("No custom tokens created yet.");
                } else {
                    println!("{:<8} {:<15} {:>12} {:>12}", "SYMBOL", "NAME", "SUPPLY", "MAX");
                    println!("{}", "-".repeat(50));
                    for t in tokens {
                        println!("{:<8} {:<15} {:>12} {:>12}",
                            t.get("symbol").and_then(|s| s.as_str()).unwrap_or("?"),
                            t.get("name").and_then(|s| s.as_str()).unwrap_or("?"),
                            t.get("total_supply").and_then(|s| s.as_u64()).unwrap_or(0),
                            t.get("max_supply").and_then(|s| s.as_u64()).unwrap_or(0),
                        );
                    }
                }
            }
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn create_pair(wallet: &Option<WalletState>, base: &str, quote: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match signed_rpc_call(url, "seal_createPair", &serde_json::json!({"base": base, "quote": quote}), &w.wallet) {
        Ok(_) => println!("Pair created: {}/{}", base, quote),
        Err(e) => eprintln!("Create pair failed: {}", e),
    }
}

fn place_order(wallet: &Option<WalletState>, pair: &str, side: &str, price_str: &str, qty_str: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    let price: u64 = match price_str.parse() { Ok(p) => p, Err(_) => { eprintln!("Invalid price"); return; } };
    let quantity: u64 = match qty_str.parse() { Ok(q) => q, Err(_) => { eprintln!("Invalid quantity"); return; } };
    match signed_rpc_call(url, "seal_placeOrder", &serde_json::json!({
        "pair": pair, "side": side, "price": price, "quantity": quantity
    }), &w.wallet) {
        Ok(resp) => {
            let oid = resp.get("order_id").and_then(|o| o.as_u64()).unwrap_or(0);
            let trades = resp.get("trades").and_then(|t| t.as_u64()).unwrap_or(0);
            println!("Order #{} placed ({} trades matched)", oid, trades);
        }
        Err(e) => eprintln!("Place order failed: {}", e),
    }
}

fn cancel_order(wallet: &Option<WalletState>, pair: &str, order_id_str: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    let order_id: u64 = match order_id_str.parse() { Ok(o) => o, Err(_) => { eprintln!("Invalid order ID"); return; } };
    match signed_rpc_call(url, "seal_cancelOrder", &serde_json::json!({"pair": pair, "order_id": order_id}), &w.wallet) {
        Ok(_) => println!("Order #{} cancelled", order_id),
        Err(e) => eprintln!("Cancel failed: {}", e),
    }
}

fn show_orderbook(wallet: &Option<WalletState>, pair: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match rpc_call(url, "seal_getOrderBook", &serde_json::json!({"pair": pair})) {
        Ok(resp) => {
            let bids: Vec<(u64, u64)> = resp.get("bids").and_then(|b| b.as_array()).map(|arr| {
                arr.iter().map(|o| (
                    o.get("price").and_then(|p| p.as_u64()).unwrap_or(0),
                    o.get("quantity").and_then(|q| q.as_u64()).unwrap_or(0),
                )).collect()
            }).unwrap_or_default();
            let asks: Vec<(u64, u64)> = resp.get("asks").and_then(|a| a.as_array()).map(|arr| {
                arr.iter().map(|o| (
                    o.get("price").and_then(|p| p.as_u64()).unwrap_or(0),
                    o.get("quantity").and_then(|q| q.as_u64()).unwrap_or(0),
                )).collect()
            }).unwrap_or_default();

            let max_qty = bids.iter().chain(asks.iter()).map(|(_, q)| *q).max().unwrap_or(1);
            let bar_width: u64 = 20;

            println!("  {}", pair);
            println!("  {:>8}  {:>6}  {:>10}  {}", "QTY", "PRICE", "TOTAL", "");
            println!("  {}", "-".repeat(50));

            // Asks: sorted highest-first (top), red
            let mut sorted_asks = asks.clone();
            sorted_asks.sort_by(|a, b| b.0.cmp(&a.0));
            if sorted_asks.is_empty() {
                println!("  {:>8}  {:>6}  {:>10}  {}", "--", "--", "--", "(no asks)");
            }
            for (price, qty) in &sorted_asks {
                let total = price * qty;
                let bars = (qty * bar_width / max_qty) as usize;
                println!("  \x1b[31m{:>8}\x1b[0m  {:>6}  {:>10}  \x1b[31m{}\x1b[0m",
                    qty, price, total, "\u{2588}".repeat(bars));
            }

            // Spread
            let best_bid = bids.iter().map(|(p, _)| *p).max().unwrap_or(0);
            let best_ask = sorted_asks.last().map(|(p, _)| *p).unwrap_or(0);
            if best_bid > 0 && best_ask > 0 {
                let spread = best_ask.saturating_sub(best_bid);
                println!("  {:>8}  \x1b[33m{:>6}\x1b[0m  {:>10}  spread",
                    "", spread, "");
            } else {
                println!("  {:>8}  {:>6}  {:>10}  spread: --", "", "--", "");
            }

            // Bids: sorted highest-first (top), green
            let mut sorted_bids = bids.clone();
            sorted_bids.sort_by(|a, b| b.0.cmp(&a.0));
            if sorted_bids.is_empty() {
                println!("  {:>8}  {:>6}  {:>10}  {}", "--", "--", "--", "(no bids)");
            }
            for (price, qty) in &sorted_bids {
                let total = price * qty;
                let bars = (qty * bar_width / max_qty) as usize;
                println!("  \x1b[32m{:>8}\x1b[0m  {:>6}  {:>10}  \x1b[32m{}\x1b[0m",
                    qty, price, total, "\u{2588}".repeat(bars));
            }
            println!("  {}", "-".repeat(50));
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn list_pairs(wallet: &Option<WalletState>) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match rpc_call(url, "seal_listPairs", &serde_json::json!({})) {
        Ok(resp) => {
            if let Some(pairs) = resp.get("pairs").and_then(|p| p.as_array()) {
                if pairs.is_empty() {
                    println!("No trading pairs created yet.");
                } else {
                    for p in pairs {
                        println!("  {}", p.as_str().unwrap_or("?"));
                    }
                }
            }
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn mpc_aggregate(wallet: &Option<WalletState>, function: &str, table: &str, column: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match rpc_call(url, "seal_mpcAggregate", &serde_json::json!({"function": function, "table": table, "column": column})) {
        Ok(resp) => {
            let result = resp.get("result").and_then(|r| r.as_i64()).unwrap_or(0);
            let count = resp.get("row_count").and_then(|r| r.as_u64()).unwrap_or(0);
            println!("{}({}.{}) = {} ({} rows)", function, table, column, result, count);
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn zk_prove(wallet: &Option<WalletState>, table: &str, statement: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    match rpc_call(url, "seal_zkProve", &serde_json::json!({"table": table, "statement": statement})) {
        Ok(resp) => {
            let satisfied = resp.get("satisfied").and_then(|s| s.as_bool()).unwrap_or(false);
            let proof = resp.get("proof").and_then(|p| p.as_str()).unwrap_or("");
            let height = resp.get("block_height").and_then(|h| h.as_u64()).unwrap_or(0);
            println!("Statement: {} WHERE {}", table, statement);
            println!("Satisfied: {}", if satisfied { "YES" } else { "NO" });
            println!("Proof:     {}...{}", &proof[..16.min(proof.len())], &proof[proof.len().saturating_sub(16)..]);
            println!("Height:    {}", height);
        }
        Err(e) => eprintln!("{}", e),
    }
}

fn rpc_call(url: &str, method: &str, params: &serde_json::Value) -> Result<serde_json::Value, String> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    let resp = rpc_call_raw(url, &body)?;
    if let Some(error) = resp.get("error") {
        return Err(error.get("message").and_then(|m| m.as_str()).unwrap_or("unknown").to_string());
    }
    resp.get("result").cloned().ok_or("no result".to_string())
}

fn signed_rpc_call(url: &str, method: &str, params: &serde_json::Value, wallet: &Wallet) -> Result<serde_json::Value, String> {
    let params_json = serde_json::to_string(params).unwrap_or_default();
    let message = format!("{}{}", method, params_json);
    let message_hash = seal_crypto::hash::sha3_256(message.as_bytes());
    let sig = wallet.sign(message_hash.as_ref()).map_err(|e| format!("signing failed: {}", e))?;
    let vk = wallet.verifying_key();
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "signature": hex::encode(sig.to_bytes()),
        "sender": hex::encode(vk.to_bytes()),
        "id": 1
    });
    let resp = rpc_call_raw(url, &body)?;
    if let Some(error) = resp.get("error") {
        return Err(error.get("message").and_then(|m| m.as_str()).unwrap_or("unknown").to_string());
    }
    resp.get("result").cloned().ok_or("no result".to_string())
}

fn rpc_call_raw(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    use std::io::{Read, Write};
    let addr = url.trim_start_matches("http://");
    let mut stream = std::net::TcpStream::connect(addr)
        .map_err(|e| format!("connect: {}", e))?;
    let body_str = body.to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_str.len(), body_str
    );
    stream.write_all(req.as_bytes()).map_err(|e| format!("send: {}", e))?;
    let mut response = String::new();
    stream.read_to_string(&mut response).map_err(|e| format!("read: {}", e))?;
    let json_start = response.find("\r\n\r\n").map(|p| p + 4).ok_or("bad response")?;
    serde_json::from_str(&response[json_start..]).map_err(|e| format!("parse: {}", e))
}
