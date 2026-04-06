//! Seal CLI — developer tool for interacting with a Seal node.
//!
//! Usage:
//!   seal app deploy --name my_app --schema schema.sql
//!   seal sql --app my_app "SELECT * FROM users"
//!   seal node info
//!   seal demo

mod wallet;

use seal_node::state::NodeState;
use seal_sql::namespace::NamespaceRegistry;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "demo" => run_demo(),
        "dev" => run_dev(&args[2..]),
        "keygen" => run_keygen(&args[2..]),
        "wallet" => wallet::run_wallet(),
        "migrate" => run_migrate(&args[2..]),
        "app" => run_app(&args[2..]),
        "sql" => run_sql(&args[2..]),
        "help" | "--help" | "-h" => print_usage(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
        }
    }
}

fn print_usage() {
    println!("Seal DAO CLI");
    println!();
    println!("Usage:");
    println!("  seal dev                           Start local devnet (1s slots)");
    println!("  seal dev --slots <n>               Run devnet for N slots then exit");
    println!("  seal demo                          Run interactive demo");
    println!("  seal app deploy --name <n> --schema <f>  Deploy app schema");
    println!("  seal keygen [--output key.json]     Generate ML-DSA signing keypair");
    println!("  seal keygen --kem [--output f]      Generate ML-KEM encryption keypair");
    println!("  seal wallet                        Interactive TUI wallet");
    println!("  seal sql \"<query>\"                  Execute SQL on local node");
    println!("  seal sql \"<query>\" --node <url>     Execute SQL on remote node");
    println!("  seal sql \"INSERT..\" --node <url> --key key.json  Signed write");
    println!("  seal migrate analyze <file.sql>    Convert pg_dump to Seal SQL");
    println!("  seal help                          Show this help");
}

fn run_keygen(args: &[String]) {
    let is_kem = args.iter().any(|a| a == "--kem");
    let output = args
        .iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or(if is_kem { "seal-kem.json" } else { "seal-key.json" });

    if is_kem {
        run_keygen_kem(output);
    } else {
        run_keygen_signing(output);
    }
}

fn run_keygen_signing(output: &str) {
    let (sk, vk) = seal_crypto::signature::SigningKey::generate();
    let address = {
        let vk_bytes = vk.to_bytes();
        let addr_hash = seal_crypto::hash::sha3_256(&vk_bytes);
        format!("seal1{}", hex::encode(&addr_hash.0[..20]))
    };

    let key_json = serde_json::json!({
        "type": "ml-dsa-65",
        "address": address,
        "signing_key": hex::encode(sk.to_bytes()),
        "verifying_key": hex::encode(vk.to_bytes()),
    });

    match std::fs::write(output, serde_json::to_string_pretty(&key_json).unwrap_or_default()) {
        Ok(()) => {
            println!("Generated ML-DSA-65 signing keypair");
            println!("  Address: {}", address);
            println!("  Key file: {}", output);
        }
        Err(e) => eprintln!("Failed to write key file: {}", e),
    }
}

fn run_keygen_kem(output: &str) {
    let kp = seal_crypto::kem::KemKeypair::generate();
    let pk_bytes = kp.public.to_bytes();
    let sk_bytes = kp.secret.to_bytes();

    let key_json = serde_json::json!({
        "type": "ml-kem-768",
        "public_key": hex::encode(&pk_bytes),
        "secret_key": hex::encode(&sk_bytes),
    });

    match std::fs::write(output, serde_json::to_string_pretty(&key_json).unwrap_or_default()) {
        Ok(()) => {
            println!("Generated ML-KEM-768 encryption keypair");
            println!("  Public key: {}...{}", &hex::encode(&pk_bytes)[..16], &hex::encode(&pk_bytes)[pk_bytes.len()*2-16..]);
            println!("  Key file: {}", output);
            println!();
            println!("Use the public_key value for PQ handshake:");
            println!("  curl -s localhost:8545 -H \"Content-Type: application/json\" \\");
            println!("    -d '{{\"jsonrpc\":\"2.0\",\"method\":\"seal_pqHandshake\",\"params\":{{\"client_public_key\":\"{}\"}},...}}'", &hex::encode(&pk_bytes)[..32]);
        }
        Err(e) => eprintln!("Failed to write key file: {}", e),
    }
}

fn run_migrate(args: &[String]) {
    if args.is_empty() || args[0] != "analyze" {
        eprintln!("Usage: seal migrate analyze <file.sql>");
        eprintln!("       seal migrate analyze -  (read from stdin)");
        return;
    }

    let sql = if args.len() > 1 && args[1] != "-" {
        // Read from file
        match std::fs::read_to_string(&args[1]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Error reading {}: {}", args[1], e);
                return;
            }
        }
    } else {
        // Read from stdin
        use std::io::Read;
        let mut buf = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut buf) {
            eprintln!("Error reading stdin: {}", e);
            return;
        }
        buf
    };

    let result = seal_cli::migrate::analyze_schema(&sql);
    seal_cli::migrate::print_report(&result);
}

fn run_app(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: seal app deploy --name <name> --schema <file>");
        return;
    }

    match args[0].as_str() {
        "deploy" => {
            let mut name = None;
            let mut schema_file = None;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--name" if i + 1 < args.len() => {
                        name = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--schema" if i + 1 < args.len() => {
                        schema_file = Some(args[i + 1].clone());
                        i += 2;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }

            let name = match name {
                Some(n) => n,
                None => {
                    eprintln!("Missing --name");
                    return;
                }
            };
            let schema_file = match schema_file {
                Some(f) => f,
                None => {
                    eprintln!("Missing --schema");
                    return;
                }
            };

            let schema_sql = match std::fs::read_to_string(&schema_file) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("Error reading {}: {}", schema_file, e);
                    return;
                }
            };

            let mut registry = seal_sql::namespace::NamespaceRegistry::new();
            match registry.deploy_app(name.clone(), "local".into(), &schema_sql) {
                Ok(()) => {
                    if let Some(ns) = registry.get(&name) {
                        println!("Deployed '{}' with tables: {:?}", name, ns.table_names());
                    }
                }
                Err(e) => eprintln!("Deploy failed: {}", e),
            }
        }
        _ => eprintln!("Unknown app command: {}", args[0]),
    }
}

fn run_sql(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: seal sql \"SELECT * FROM table\"");
        eprintln!("       seal sql \"SELECT * FROM table\" --node http://localhost:8545");
        eprintln!("       seal sql \"INSERT ...\" --node http://localhost:8545 --key keyfile.json");
        return;
    }

    // Parse flags
    let mut node_url = None;
    let mut key_file = None;
    let mut sql_parts = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--node" if i + 1 < args.len() => { node_url = Some(args[i + 1].clone()); i += 2; }
            "--key" if i + 1 < args.len() => { key_file = Some(args[i + 1].clone()); i += 2; }
            _ => { sql_parts.push(args[i].as_str()); i += 1; }
        }
    }
    let sql = sql_parts.join(" ");

    if let Some(url) = node_url {
        run_sql_remote(&sql, &url, key_file.as_deref());
    } else {
        run_sql_local(&sql);
    }
}

fn run_sql_local(sql: &str) {
    let mut node = seal_node::state::NodeState::new();

    match node.execute_sql(sql) {
        Ok(result) => print_query_result(&result),
        Err(e) => eprintln!("SQL error: {}", e),
    }
}

fn run_sql_remote(sql: &str, url: &str, key_file: Option<&str>) {
    let is_write = {
        let upper = sql.trim().to_uppercase();
        upper.starts_with("INSERT")
            || upper.starts_with("UPDATE")
            || upper.starts_with("DELETE")
            || upper.starts_with("CREATE")
            || upper.starts_with("DROP")
            || upper.starts_with("ALTER")
    };

    let method = if is_write {
        "seal_submitSql"
    } else {
        "seal_querySql"
    };

    let params = serde_json::json!({ "sql": sql });

    // Sign the request if a key file is provided
    let (signature, sender) = if let Some(kf) = key_file {
        match sign_request(method, &params, kf) {
            Ok((sig, snd)) => (Some(sig), Some(snd)),
            Err(e) => {
                eprintln!("Failed to sign request: {}", e);
                return;
            }
        }
    } else {
        (None, None)
    };

    let mut body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });
    if let Some(sig) = &signature {
        body["signature"] = serde_json::Value::String(sig.clone());
    }
    if let Some(snd) = &sender {
        body["sender"] = serde_json::Value::String(snd.clone());
    }

    let client = match std::net::TcpStream::connect(url.trim_start_matches("http://")) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("Failed to connect to {}: {}", url, e);
            return;
        }
    };

    let body_str = body.to_string();
    let request = format!(
        "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_str.len(),
        body_str
    );

    use std::io::{Read, Write};
    let mut stream = client;
    if let Err(e) = stream.write_all(request.as_bytes()) {
        eprintln!("Failed to send request: {}", e);
        return;
    }

    let mut response = String::new();
    if let Err(e) = stream.read_to_string(&mut response) {
        eprintln!("Failed to read response: {}", e);
        return;
    }

    // Parse HTTP response — find JSON body after \r\n\r\n
    let json_start = match response.find("\r\n\r\n") {
        Some(pos) => pos + 4,
        None => {
            eprintln!("Invalid HTTP response");
            return;
        }
    };
    let json_body = &response[json_start..];

    match serde_json::from_str::<serde_json::Value>(json_body) {
        Ok(resp) => {
            if let Some(error) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    error.get("message").and_then(|m| m.as_str()).unwrap_or("unknown")
                );
            } else if let Some(result) = resp.get("result") {
                // Print columns + rows if present
                if let Some(columns) = result.get("columns").and_then(|c| c.as_array()) {
                    let col_names: Vec<&str> = columns.iter().filter_map(|c| c.as_str()).collect();
                    if !col_names.is_empty() {
                        println!("{}", col_names.join(" | "));
                        println!("{}", "-".repeat(col_names.len() * 15));
                    }
                    if let Some(rows) = result.get("rows").and_then(|r| r.as_array()) {
                        for row in rows {
                            if let Some(vals) = row.as_array() {
                                let strs: Vec<String> =
                                    vals.iter().map(|v| format!("{}", v)).collect();
                                println!("{}", strs.join(" | "));
                            }
                        }
                        println!("({} rows)", rows.len());
                    }
                } else if let Some(affected) = result.get("rows_affected") {
                    println!("OK ({} rows affected)", affected);
                } else {
                    println!("{}", serde_json::to_string_pretty(result).unwrap_or_default());
                }
            }
        }
        Err(e) => eprintln!("Failed to parse response: {}", e),
    }
}

/// Sign an RPC request with ML-DSA. Returns (signature_hex, sender_hex).
fn sign_request(method: &str, params: &serde_json::Value, key_file: &str) -> Result<(String, String), String> {
    let key_json = std::fs::read_to_string(key_file)
        .map_err(|e| format!("cannot read key file '{}': {}", key_file, e))?;
    let key_data: serde_json::Value = serde_json::from_str(&key_json)
        .map_err(|e| format!("invalid key file JSON: {}", e))?;

    let sk_hex = key_data.get("signing_key")
        .and_then(|v| v.as_str())
        .ok_or("key file missing 'signing_key' field")?;
    let vk_hex = key_data.get("verifying_key")
        .and_then(|v| v.as_str())
        .ok_or("key file missing 'verifying_key' field")?;

    let sk_bytes = hex::decode(sk_hex).map_err(|_| "invalid signing_key hex")?;
    let vk_bytes = hex::decode(vk_hex).map_err(|_| "invalid verifying_key hex")?;

    let sk = seal_crypto::signature::SigningKey::from_bytes(&sk_bytes)
        .map_err(|e| format!("invalid signing key: {}", e))?;

    // Sign SHA3(method || params_json)
    let params_json = serde_json::to_string(params).unwrap_or_default();
    let message = format!("{}{}", method, params_json);
    let message_hash = seal_crypto::hash::sha3_256(message.as_bytes());

    let signature = sk.sign(message_hash.as_ref())
        .map_err(|e| format!("signing failed: {}", e))?;

    Ok((hex::encode(signature.to_bytes()), hex::encode(&vk_bytes)))
}

fn print_query_result(result: &seal_sql::engine::QueryResult) {
    if !result.columns.is_empty() {
        println!("{}", result.columns.join(" | "));
        println!("{}", "-".repeat(result.columns.len() * 15));
        for row in &result.rows {
            let vals: Vec<String> = row.values.iter().map(|v| format!("{:?}", v)).collect();
            println!("{}", vals.join(" | "));
        }
        println!("({} rows)", result.rows.len());
    } else if result.rows_affected > 0 {
        println!("OK ({} rows affected)", result.rows_affected);
    } else {
        println!("OK");
    }
}

fn run_dev(args: &[String]) {
    println!("=== Seal Local Devnet ===");
    println!();

    // Parse --slots argument
    let mut max_slots: u64 = 100; // default: run 100 slots
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--slots" if i + 1 < args.len() => {
                max_slots = args[i + 1].parse().unwrap_or(100);
                i += 2;
            }
            _ => i += 1,
        }
    }

    // Create devnet consensus config (fast: 1s slots, 8-slot epochs)
    let config = seal_consensus::config::ConsensusConfig {
        slot_duration: std::time::Duration::from_secs(1),
        slots_per_epoch: 8,
        committee_size: 1,
        ..seal_consensus::config::ConsensusConfig::default()
    };

    let mut runner = seal_node::consensus_runner::ConsensusRunner::new(config);
    let pk_bytes = runner.verifying_key.to_bytes();
    let pk_short: String = pk_bytes.iter().take(8).map(|b| format!("{:02x}", b)).collect();

    println!("Chain ID:     seal-devnet-local");
    println!("Slot time:    1 second");
    println!("Epoch size:   8 slots");
    println!("Validator:    {}...", pk_short);
    println!("Max slots:    {}", max_slots);
    println!();
    println!("Producing blocks... (Ctrl+C to stop)");
    println!("{:-<60}", "");

    let mut blocks_produced = 0u64;
    let mut total_txs = 0u64;

    for slot in 0..max_slots {
        // Simulate some activity every few slots
        if slot % 3 == 0 && slot > 0 {
            let _ = runner.submit_sql(&format!(
                "CREATE TABLE IF NOT EXISTS devnet_t{} (id BIGINT PRIMARY KEY, val TEXT)",
                slot / 3
            ));
        }
        if slot % 3 == 1 {
            let _ = runner.submit_sql(&format!(
                "INSERT INTO devnet_t{} (id, val) VALUES ({}, 'slot_{}')",
                slot / 3,
                slot,
                slot
            ));
        }

        if let Some(block) = runner.advance_slot() {
            blocks_produced += 1;
            let tx_count = block.block.transactions.len() as u64;
            total_txs += tx_count;

            println!(
                "Block #{:<4} | slot {:<4} | epoch {:<3} | {} txs | state: {}",
                block.block.header.height,
                slot + 1,
                (slot + 1) / 8,
                tx_count,
                &format!("{}", block.block.header.state_root)[..16],
            );
        }

        // Sleep to simulate real timing (but fast)
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    println!("{:-<60}", "");
    println!();
    println!("Devnet summary:");
    println!("  Slots:    {}", max_slots);
    println!("  Blocks:   {}", blocks_produced);
    println!("  Txs:      {}", total_txs);
    println!("  Height:   {}", runner.height());
    println!("  State:    {}", runner.state_root());
    println!();

    // Show final state
    if blocks_produced > 0 {
        println!("Final SQL state:");
        match runner.query_sql("SELECT name FROM sqlite_master WHERE type='table'") {
            Ok(result) => {
                for row in &result.rows {
                    println!("  table: {:?}", row.values);
                }
            }
            Err(_) => {
                // Not a real sqlite, just show what we know
                println!("  ({} blocks with SQL data)", blocks_produced);
            }
        }
    }

    println!("\n=== Devnet stopped ===");
}

fn run_demo() {
    println!("=== Seal DAO Interactive Demo (Phase 2) ===\n");

    // Create node
    let mut node = NodeState::new();
    println!("Node identity: {}", node.node_address());

    // Create namespace registry
    let mut registry = NamespaceRegistry::new();

    // Deploy a blog app
    println!("\n--- Deploying blog.seal ---");
    if let Err(e) = registry.deploy_app(
        "blog.seal".into(),
        node.node_address().to_string(),
        "CREATE TABLE posts (
            id BIGINT PRIMARY KEY,
            author TEXT NOT NULL,
            body TEXT NOT NULL,
            created_at BIGINT
        );
        CREATE TABLE comments (
            id BIGINT PRIMARY KEY,
            post_id BIGINT,
            author TEXT NOT NULL,
            body TEXT NOT NULL
        )",
    ) {
        eprintln!("Failed to deploy blog.seal: {}", e);
        return;
    }
    println!("Deployed: blog.seal with tables [posts, comments]");

    // Deploy a marketplace app
    println!("\n--- Deploying market.seal ---");
    if let Err(e) = registry.deploy_app(
        "market.seal".into(),
        node.node_address().to_string(),
        "CREATE TABLE products (
            id BIGINT PRIMARY KEY,
            seller TEXT NOT NULL,
            name TEXT NOT NULL,
            price BIGINT NOT NULL
        );
        CREATE TABLE orders (
            id BIGINT PRIMARY KEY,
            product_id BIGINT,
            buyer TEXT NOT NULL,
            amount BIGINT
        )",
    ) {
        eprintln!("Failed to deploy market.seal: {}", e);
        return;
    }
    println!("Deployed: market.seal with tables [products, orders]");

    // Set visibility
    if let Some(blog) = registry.get_mut("blog.seal") {
        blog.set_visibility("posts", seal_sql::namespace::Visibility::Public);
        println!("\nSet blog.seal/posts visibility: PUBLIC");
    } else {
        eprintln!("blog.seal not found in registry");
        return;
    }

    // Enable RLS on market products
    let market = match registry.get_mut("market.seal") {
        Some(m) => m,
        None => {
            eprintln!("market.seal not found in registry");
            return;
        }
    };
    market.rls.enable_rls("products");
    if let Err(e) = market.rls.add_policy(seal_sql::rls::Policy {
        name: "public_read".into(),
        table_name: "products".into(),
        action: seal_sql::rls::PolicyAction::Select,
        using_expr: "true".into(),
        with_check_expr: None,
    }) {
        eprintln!("Failed to add public_read policy: {}", e);
    }
    if let Err(e) = market.rls.add_policy(seal_sql::rls::Policy {
        name: "seller_write".into(),
        table_name: "products".into(),
        action: seal_sql::rls::PolicyAction::All,
        using_expr: "seller = CURRENT_USER()".into(),
        with_check_expr: None,
    }) {
        eprintln!("Failed to add seller_write policy: {}", e);
    }
    println!("RLS on market.seal/products: public read, seller-only write");

    // Insert data into blog
    println!("\n--- Inserting data ---");
    let blog = match registry.get_mut("blog.seal") {
        Some(b) => b,
        None => {
            eprintln!("blog.seal not found in registry");
            return;
        }
    };
    for (sql, user) in [
        ("INSERT INTO posts (id, author, body, created_at) VALUES (1, 'alice', 'Hello World!', 1710000000)", "alice"),
        ("INSERT INTO posts (id, author, body, created_at) VALUES (2, 'bob', 'Seal is awesome', 1710001000)", "bob"),
        ("INSERT INTO comments (id, post_id, author, body) VALUES (1, 1, 'charlie', 'Great post!')", "charlie"),
    ] {
        if let Err(e) = blog.execute_as(sql, user) {
            eprintln!("blog.seal insert failed: {}", e);
        }
    }
    println!("Inserted 2 posts + 1 comment into blog.seal");

    let market = match registry.get_mut("market.seal") {
        Some(m) => m,
        None => {
            eprintln!("market.seal not found in registry");
            return;
        }
    };
    for (sql, user) in [
        ("INSERT INTO products (id, seller, name, price) VALUES (1, 'alice', 'Widget', 100)", "alice"),
        ("INSERT INTO products (id, seller, name, price) VALUES (2, 'bob', 'Gadget', 250)", "bob"),
    ] {
        if let Err(e) = market.execute_as(sql, user) {
            eprintln!("market.seal insert failed: {}", e);
        }
    }
    println!("Inserted 2 products into market.seal");

    // Query
    println!("\n--- Querying ---");
    if let Some(blog) = registry.get_mut("blog.seal") {
        match blog.execute_as("SELECT * FROM posts", "anyone") {
            Ok(result) => {
                println!("blog.seal: SELECT * FROM posts => {} rows", result.rows.len());
                for (i, row) in result.rows.iter().enumerate() {
                    println!("  row {}: {:?}", i, row.values);
                }
            }
            Err(e) => eprintln!("blog.seal query failed: {}", e),
        }
    }

    if let Some(market) = registry.get_mut("market.seal") {
        match market.execute_as("SELECT * FROM products WHERE price > 150", "anyone") {
            Ok(result) => {
                println!(
                    "\nmarket.seal: SELECT * FROM products WHERE price > 150 => {} rows",
                    result.rows.len()
                );
            }
            Err(e) => eprintln!("market.seal query failed: {}", e),
        }
    }

    // Cross-app visibility check
    println!("\n--- Cross-app access ---");
    if let Some(blog) = registry.get("blog.seal") {
        println!(
            "market.seal can read blog.seal/posts? {}",
            blog.can_read("posts", "market.seal")
        );
        println!(
            "stranger.seal can read blog.seal/posts? {}",
            blog.can_read("posts", "stranger.seal")
        );
        println!(
            "stranger.seal can read blog.seal/comments? {}",
            blog.can_read("comments", "stranger.seal")
        ); // Private by default
    }

    // RLS check
    println!("\n--- RLS checks ---");
    if let Some(market) = registry.get("market.seal") {
        println!(
            "alice can update products she owns? {}",
            market.rls.check_access(
                "products",
                &seal_sql::rls::PolicyAction::Update,
                "alice",
                Some("alice")
            )
        );
        println!(
            "bob can update alice's products? {}",
            market.rls.check_access(
                "products",
                &seal_sql::rls::PolicyAction::Update,
                "bob",
                Some("alice")
            )
        );
        println!(
            "anyone can read products? {}",
            market.rls.check_access(
                "products",
                &seal_sql::rls::PolicyAction::Select,
                "anyone",
                None
            )
        );
    }

    // Produce block via node
    println!("\n--- Block production ---");
    if let Err(e) = node.execute_sql("CREATE TABLE t (id BIGINT PRIMARY KEY)") {
        eprintln!("SQL execution failed: {}", e);
    }
    let block = node.produce_block();
    println!(
        "Block #{}: {} txs, state_root: {}",
        block.header.height,
        block.transactions.len(),
        block.header.state_root
    );

    // List deployed apps
    println!("\n--- Deployed apps ---");
    for name in registry.app_names() {
        if let Some(ns) = registry.get(name) {
            println!(
                "  {} (owner: {}, tables: {:?})",
                name,
                ns.owner,
                ns.table_names()
            );
        }
    }

    println!("\n=== Demo complete ===");
}
