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
        let parts_owned = tokenize_line(line.trim());
        let parts: Vec<&str> = parts_owned.iter().map(|s| s.as_str()).collect();
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
            "faucet" => {
                if parts.len() < 2 {
                    faucet_drip(&wallet, None);
                } else {
                    // Join `parts[1..]` so `faucet 500 SEAL` and `faucet 1.5`
                    // both survive the whitespace tokenizer.
                    match parse_amount(&parts[1..].join(" ")) {
                        Ok(a) => faucet_drip(&wallet, Some(a)),
                        Err(e) => eprintln!("Invalid amount: {e}"),
                    }
                }
            }
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
                    // Join `parts[2..]` so `transfer <addr> 5 SEAL` parses.
                    transfer_seal(&wallet, parts[1], &parts[2..].join(" "));
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
                    // Join `parts[3..]` so `mint-token GOLD <addr> 1.5` and
                    // `mint-token GOLD <addr> 5 SEAL` both work.
                    mint_token(&wallet, parts[1], parts[2], &parts[3..].join(" "));
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
    println!("  faucet [amount]            Dev-faucet drip to self (same amount syntax as transfer;");
    println!("                             requires --dev-faucet on node)");
    println!("  height                     Show chain height");
    println!("  query <SQL>                Execute read-only SQL on node");
    println!("  send <SQL>                 Send signed SQL transaction");
    println!("  transfer <to> <amount>     Transfer SEAL. Amount: `50` = 50 base units,");
    println!("                             `50.0` or `50 SEAL` = 50 SEAL (50×10⁹ base units)");
    println!("  create-token <SYM> <name>  Create custom token");
    println!("  mint-token <SYM> <to> <n>  Mint custom tokens (same amount syntax as transfer)");
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
            println!("SEAL balance: {}", format_seal(bal));
            println!("Total supply: {}", format_seal(supply));
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

fn faucet_drip(wallet: &Option<WalletState>, amount: Option<u64>) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    let mut params = serde_json::json!({ "address": w.address });
    if let Some(a) = amount {
        params["amount"] = serde_json::json!(a);
    }
    match rpc_call(url, "seal_faucet", &params) {
        Ok(resp) => {
            let amt = resp.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
            let bal = resp.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("Faucet dripped {}", format_seal(amt));
            println!("Balance now {}", format_seal(bal));
        }
        Err(e) => eprintln!(
            "Faucet failed: {e}\n  (Did the node start with --dev-faucet?)"
        ),
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

/// Split a REPL line into arguments, honoring `"…"` and `'…'` quoting
/// so `create-token GOLD "Gold Coin" 1000000` yields exactly three
/// args (the quotes are stripped, the space between "Gold" and "Coin"
/// is preserved, and the trailing `1000000` lands at index 3). Supports
/// backslash-escaping inside double quotes (`\"`, `\\`). Unbalanced
/// quotes are accepted — the trailing unclosed segment becomes its own
/// arg — so the REPL never eats a partial line.
fn tokenize_line(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_arg = false;
    let mut quote: Option<char> = None;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('"'), '\\') => {
                if let Some(&n) = chars.peek() {
                    if n == '"' || n == '\\' {
                        cur.push(n);
                        chars.next();
                        continue;
                    }
                }
                cur.push('\\');
            }
            (Some(q), ch) if ch == q => {
                quote = None;
                // quote-end does not itself terminate the arg; the
                // next whitespace/quote decides.
            }
            (None, '"') | (None, '\'') => {
                quote = Some(c);
                in_arg = true;
            }
            (None, ch) if ch.is_whitespace() => {
                if in_arg {
                    out.push(std::mem::take(&mut cur));
                    in_arg = false;
                }
            }
            (_, ch) => {
                cur.push(ch);
                in_arg = true;
            }
        }
    }
    if in_arg {
        out.push(cur);
    }
    out
}

/// Parse an amount that may be expressed as:
///   - a bare integer      → base units (legacy, 1 = 10⁻⁹ SEAL)
///   - a decimal           → SEAL (`1.5` = 1 500 000 000 base units)
///   - trailing `SEAL`     → force SEAL interpretation (`50 SEAL`, `1.5SEAL`)
/// Returns the amount in base units (9-decimal precision).
pub fn parse_amount(raw: &str) -> Result<u64, String> {
    const DECIMALS: u32 = 9;
    let trimmed = raw.trim();
    let (num_part, had_suffix) = match trimmed.to_ascii_uppercase().strip_suffix("SEAL") {
        Some(rest) => (rest.trim().to_string(), true),
        None => (trimmed.to_string(), false),
    };
    if num_part.is_empty() {
        return Err("empty amount".into());
    }

    // Decide whether to interpret as SEAL or raw base units:
    // explicit suffix OR presence of a decimal point → SEAL.
    let is_seal = had_suffix || num_part.contains('.');

    if !is_seal {
        return num_part
            .parse::<u64>()
            .map_err(|_| format!("invalid integer amount: {raw}"));
    }

    // SEAL-denominated: allow at most DECIMALS fractional digits.
    let (int_str, frac_str) = match num_part.split_once('.') {
        Some((i, f)) => (i, f),
        None => (num_part.as_str(), ""),
    };
    if int_str.is_empty() && frac_str.is_empty() {
        return Err("empty amount".into());
    }
    if frac_str.len() > DECIMALS as usize {
        return Err(format!(
            "too many fractional digits ({} > {DECIMALS})",
            frac_str.len()
        ));
    }
    let int_val: u64 = if int_str.is_empty() {
        0
    } else {
        int_str
            .parse()
            .map_err(|_| format!("invalid integer part: {int_str}"))?
    };
    let frac_val: u64 = if frac_str.is_empty() {
        0
    } else {
        let padded = format!("{:0<width$}", frac_str, width = DECIMALS as usize);
        padded
            .parse()
            .map_err(|_| format!("invalid fractional part: {frac_str}"))?
    };
    let scale = 10u64.pow(DECIMALS);
    int_val
        .checked_mul(scale)
        .and_then(|v| v.checked_add(frac_val))
        .ok_or_else(|| format!("amount overflows u64: {raw}"))
}

/// Render a base-units amount as a SEAL-denominated string
/// (e.g. `25 000 000 000` → `25 SEAL (25000000000 base units)`).
pub fn format_seal(base_units: u64) -> String {
    let whole = base_units / 1_000_000_000;
    let frac = base_units % 1_000_000_000;
    if frac == 0 {
        format!("{whole} SEAL ({base_units} base units)")
    } else {
        let frac_str = format!("{frac:09}").trim_end_matches('0').to_string();
        format!("{whole}.{frac_str} SEAL ({base_units} base units)")
    }
}

fn transfer_seal(wallet: &Option<WalletState>, to: &str, amount_str: &str) {
    let w = match wallet { Some(w) => w, None => { eprintln!("No wallet."); return; } };
    let url = match &w.node_url { Some(u) => u, None => { eprintln!("Not connected."); return; } };
    let amount: u64 = match parse_amount(amount_str) {
        Ok(a) => a,
        Err(e) => { eprintln!("Invalid amount: {e}"); return; }
    };
    match signed_rpc_call(url, "seal_transfer", &serde_json::json!({"to": to, "amount": amount}), &w.wallet) {
        Ok(resp) => {
            println!("Transferred {} to {}", format_seal(amount), to);
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
    // Custom tokens use the same 9-decimal convention as SEAL (see
    // create_token `"decimals": 9`), so `parse_amount` applies.
    let amount: u64 = match parse_amount(amount_str) {
        Ok(a) => a,
        Err(e) => { eprintln!("Invalid amount: {e}"); return; }
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

#[cfg(test)]
mod tests {
    use super::{format_seal, parse_amount, tokenize_line};

    #[test]
    fn tokenize_plain_words() {
        assert_eq!(tokenize_line("create-token GOLD Gold 1000000"),
                   vec!["create-token", "GOLD", "Gold", "1000000"]);
    }

    #[test]
    fn tokenize_double_quoted() {
        // The original bug: `"Gold Coin"` was split into two args and the
        // trailing number was shoved down an index.
        assert_eq!(tokenize_line("create-token GOLD \"Gold Coin\" 1000000"),
                   vec!["create-token", "GOLD", "Gold Coin", "1000000"]);
    }

    #[test]
    fn tokenize_single_quoted() {
        assert_eq!(tokenize_line("mint GOLD 'with spaces' 5"),
                   vec!["mint", "GOLD", "with spaces", "5"]);
    }

    #[test]
    fn tokenize_escaped_quote() {
        assert_eq!(tokenize_line(r#"sign "hello \"world\"""#),
                   vec!["sign", r#"hello "world""#]);
    }

    #[test]
    fn tokenize_empty_and_whitespace() {
        assert_eq!(tokenize_line(""), Vec::<String>::new());
        assert_eq!(tokenize_line("   \t "), Vec::<String>::new());
    }

    #[test]
    fn bare_integer_is_base_units() {
        assert_eq!(parse_amount("50").unwrap(), 50);
        assert_eq!(parse_amount("0").unwrap(), 0);
        assert_eq!(parse_amount("25000000000").unwrap(), 25_000_000_000);
    }

    #[test]
    fn decimal_is_seal_denominated() {
        assert_eq!(parse_amount("1.0").unwrap(), 1_000_000_000);
        assert_eq!(parse_amount("50.0").unwrap(), 50_000_000_000);
        assert_eq!(parse_amount("0.5").unwrap(), 500_000_000);
        assert_eq!(parse_amount("1.234567891").unwrap(), 1_234_567_891);
        assert_eq!(parse_amount(".5").unwrap(), 500_000_000);
    }

    #[test]
    fn seal_suffix_forces_seal() {
        assert_eq!(parse_amount("50 SEAL").unwrap(), 50_000_000_000);
        assert_eq!(parse_amount("50SEAL").unwrap(), 50_000_000_000);
        assert_eq!(parse_amount("50 seal").unwrap(), 50_000_000_000);
        assert_eq!(parse_amount("1.5 SEAL").unwrap(), 1_500_000_000);
    }

    #[test]
    fn rejects_bad_inputs() {
        assert!(parse_amount("").is_err());
        assert!(parse_amount("abc").is_err());
        assert!(parse_amount("1.2345678901").is_err()); // >9 frac digits
        assert!(parse_amount("-1").is_err());
    }

    #[test]
    fn format_seal_round_trip() {
        assert_eq!(format_seal(25_000_000_000), "25 SEAL (25000000000 base units)");
        assert_eq!(format_seal(500_000_000), "0.5 SEAL (500000000 base units)");
        assert_eq!(format_seal(1_234_567_891), "1.234567891 SEAL (1234567891 base units)");
        assert_eq!(format_seal(50), "0.00000005 SEAL (50 base units)");
        assert_eq!(format_seal(0), "0 SEAL (0 base units)");
    }
}
