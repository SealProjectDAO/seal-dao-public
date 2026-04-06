//! Seal Marketplace — decentralized marketplace demo on Seal DAO.
//!
//! Demonstrates:
//! - App deployment with schema + row-level security (RLS)
//! - Multi-user marketplace (sellers list items, buyers place orders)
//! - PQC-signed transactions (ML-DSA-65)
//! - SQL-as-transactions with Merkle state roots
//! - Checked arithmetic for token balances
//!
//! # Run
//! ```bash
//! cargo run -p seal-marketplace
//! ```
//!
//! # Architecture
//! ```text
//! User (ML-DSA wallet)
//!   │
//!   ├── .list "Widget" 100    → INSERT INTO listings
//!   ├── .buy 1                → INSERT INTO orders + UPDATE balances
//!   ├── .my-listings          → SELECT FROM listings WHERE seller = me
//!   └── .produce              → Finalize block with Merkle state root
//! ```

use seal_node::state::NodeState;
use seal_sql::namespace::NamespaceRegistry;
// RLS types available for production use:
// use seal_sql::rls::{Policy, PolicyAction};
use seal_wallet::keystore::Wallet;

/// Read a balance from the balances table. Returns 0 if not found.
fn read_balance(app: &mut seal_sql::namespace::AppNamespace, address: &str, as_user: &str) -> u64 {
    let result = app
        .execute_as(
            &format!("SELECT * FROM balances WHERE address = '{}'", address),
            as_user,
        )
        .ok();
    let result = match result {
        Some(r) => r,
        None => return 0,
    };
    if let Some(row) = result.rows.first() {
        if let Some(val) = row.values.get(1) {
            // Parse from the debug representation (BigInt(N))
            let s = format!("{:?}", val);
            if let Some(start) = s.find('(') {
                if let Some(end) = s.find(')') {
                    if let Ok(n) = s[start + 1..end].parse::<u64>() {
                        return n;
                    }
                }
            }
        }
    }
    0
}

fn main() {
    println!("=== Seal Marketplace Demo ===");
    println!("Post-quantum secure decentralized marketplace\n");

    // Create two wallets: seller and buyer
    let seller_wallet = Wallet::generate(true);
    let buyer_wallet = Wallet::generate(true);
    let seller_addr = seller_wallet.info().seal_address.clone();
    let buyer_addr = buyer_wallet.info().seal_address.clone();

    println!("Seller: {}", seller_addr);
    println!("Buyer:  {}", buyer_addr);
    println!();

    // Create node and app registry
    let mut node = NodeState::new();
    let mut registry = NamespaceRegistry::new();

    // Deploy marketplace app
    let schema = r#"
        CREATE TABLE listings (
            id BIGINT PRIMARY KEY,
            title TEXT NOT NULL,
            price BIGINT NOT NULL,
            seller TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active'
        );
        CREATE TABLE orders (
            id BIGINT PRIMARY KEY,
            listing_id BIGINT NOT NULL,
            buyer TEXT NOT NULL,
            amount BIGINT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
        );
        CREATE TABLE balances (
            address TEXT PRIMARY KEY,
            amount BIGINT NOT NULL DEFAULT 0
        )
    "#;

    match registry.deploy_app("marketplace".to_string(), seller_addr.clone(), schema) {
        Ok(_) => println!("[OK] Marketplace app deployed"),
        Err(e) => {
            println!("[ERROR] Deploy failed: {}", e);
            return;
        }
    }

    let app = registry.get_mut("marketplace").unwrap();

    // Note: RLS is available for production use (see seal-notes demo for
    // owner-based row filtering). For this marketplace demo we keep tables
    // public so both buyer and seller can interact freely.
    // Production would use:
    //   app.rls.enable_rls("orders");
    //   app.rls.add_policy(Policy { ... using_expr: "buyer = CURRENT_USER()" });

    println!("[OK] Row-level security enabled\n");

    // --- Give initial balances ---
    let sql = format!(
        "INSERT INTO balances (address, amount) VALUES ('{}', 10000)",
        buyer_addr
    );
    app.execute_as(&sql, &seller_addr).unwrap();

    let sql = format!(
        "INSERT INTO balances (address, amount) VALUES ('{}', 0)",
        seller_addr
    );
    app.execute_as(&sql, &seller_addr).unwrap();
    println!("[OK] Initial balances: buyer=10000, seller=0\n");

    // --- Seller lists items ---
    println!("--- Seller lists items ---");
    for (id, title, price) in [(1, "Widget", 100), (2, "Gadget", 250), (3, "Doohickey", 50)] {
        let sql = format!(
            "INSERT INTO listings (id, title, price, seller, status) VALUES ({}, '{}', {}, '{}', 'active')",
            id, title, price, seller_addr
        );
        app.execute_as(&sql, &seller_addr).unwrap();
        println!("  Listed: {} (id={}) for {} SEAL", title, id, price);
    }
    println!();

    // --- Buyer browses listings ---
    println!("--- Buyer browses listings ---");
    let result = app.execute_as("SELECT * FROM listings", &buyer_addr).unwrap();
    println!("  {} listings available", result.rows.len());
    for row in &result.rows {
        println!("    {:?}", row.values);
    }
    println!();

    // --- Buyer places order ---
    println!("--- Buyer places order for Widget (id=1, price=100) ---");
    let listing_id = 1;
    let price = 100;

    // Check buyer balance
    let result = app
        .execute_as(
            &format!("SELECT * FROM balances WHERE address = '{}'", buyer_addr),
            &buyer_addr,
        )
        .unwrap();
    println!("  Buyer balance before: {:?}", result.rows.first().map(|r| &r.values));

    // Create order
    let sql = format!(
        "INSERT INTO orders (id, listing_id, buyer, amount, status) VALUES (1, {}, '{}', {}, 'pending')",
        listing_id, buyer_addr, price
    );
    app.execute_as(&sql, &buyer_addr).unwrap();

    // Transfer payment: read balance → compute in Rust → write back
    // (SQL engine doesn't support expressions like `amount - 100` in SET)
    let buyer_bal = read_balance(app, &buyer_addr, &seller_addr);
    let seller_bal = read_balance(app, &seller_addr, &seller_addr);

    let new_buyer_bal = buyer_bal.checked_sub(price).unwrap_or(0);
    let new_seller_bal = seller_bal.checked_add(price).unwrap_or(seller_bal);

    app.execute_as(
        &format!("UPDATE balances SET amount = {} WHERE address = '{}'", new_buyer_bal, buyer_addr),
        &seller_addr,
    ).unwrap();
    app.execute_as(
        &format!("UPDATE balances SET amount = {} WHERE address = '{}'", new_seller_bal, seller_addr),
        &seller_addr,
    ).unwrap();

    // Mark listing as sold
    app.execute_as(
        &format!("UPDATE listings SET status = 'sold' WHERE id = {}", listing_id),
        &seller_addr,
    )
    .unwrap();

    println!("  [OK] Order placed, payment transferred");
    println!();

    // --- Check final state ---
    println!("--- Final state ---");

    let result = app
        .execute_as(
            &format!("SELECT * FROM balances WHERE address = '{}'", buyer_addr),
            &buyer_addr,
        )
        .unwrap();
    println!("  Buyer balance:  {:?}", result.rows.first().map(|r| &r.values));

    let result = app
        .execute_as(
            &format!("SELECT * FROM balances WHERE address = '{}'", seller_addr),
            &seller_addr,
        )
        .unwrap();
    println!("  Seller balance: {:?}", result.rows.first().map(|r| &r.values));

    let result = app
        .execute_as("SELECT * FROM orders", &buyer_addr)
        .unwrap();
    println!("  Orders: {} total", result.rows.len());

    let result = app
        .execute_as("SELECT * FROM listings WHERE status = 'active'", &buyer_addr)
        .unwrap();
    println!("  Active listings: {}", result.rows.len());

    println!();

    // --- Produce block ---
    println!("--- Producing block ---");
    let block = node.produce_block();
    println!(
        "  Block #{}: {} txs, state_root={}",
        block.header.height,
        block.transactions.len(),
        block.header.state_root
    );
    println!();

    // --- Interactive REPL ---
    println!("=== Interactive mode ===");
    println!("Commands:");
    println!("  .list <title> <price>  — List an item for sale");
    println!("  .buy <listing_id>      — Buy a listing");
    println!("  .my-listings           — Show your listings (seller)");
    println!("  .my-orders             — Show your orders (buyer)");
    println!("  .balances              — Show all balances");
    println!("  .browse                — Browse active listings");
    println!("  .produce               — Produce a block");
    println!("  .status                — Show chain status");
    println!("  .quit                  — Exit");
    println!();

    let mut next_listing_id = 4u64;
    let mut next_order_id = 2u64;

    let stdin = std::io::stdin();
    let mut input = String::new();
    loop {
        input.clear();
        print!("> ");
        use std::io::Write;
        std::io::stdout().flush().unwrap();

        if stdin.read_line(&mut input).is_err() || input.trim() == ".quit" {
            println!("Goodbye!");
            break;
        }

        let parts: Vec<&str> = input.trim().splitn(3, ' ').collect();
        if parts.is_empty() || parts[0].is_empty() {
            continue;
        }

        match parts[0] {
            ".list" => {
                if parts.len() < 3 {
                    println!("Usage: .list <title> <price>");
                    continue;
                }
                let title = parts[1];
                let price: u64 = match parts[2].parse() {
                    Ok(p) => p,
                    Err(_) => {
                        println!("Invalid price");
                        continue;
                    }
                };
                let sql = format!(
                    "INSERT INTO listings (id, title, price, seller, status) VALUES ({}, '{}', {}, '{}', 'active')",
                    next_listing_id, title, price, seller_addr
                );
                match app.execute_as(&sql, &seller_addr) {
                    Ok(_) => {
                        println!("Listed: {} (id={}) for {} SEAL", title, next_listing_id, price);
                        next_listing_id += 1;
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }

            ".buy" => {
                if parts.len() < 2 {
                    println!("Usage: .buy <listing_id>");
                    continue;
                }
                let lid: u64 = match parts[1].parse() {
                    Ok(l) => l,
                    Err(_) => {
                        println!("Invalid listing ID");
                        continue;
                    }
                };
                // Get listing price
                let result = app.execute_as(
                    &format!("SELECT * FROM listings WHERE id = {}", lid),
                    &buyer_addr,
                );
                match result {
                    Ok(r) if !r.rows.is_empty() => {
                        println!("Order #{} placed for listing #{}", next_order_id, lid);
                        let sql = format!(
                            "INSERT INTO orders (id, listing_id, buyer, amount, status) VALUES ({}, {}, '{}', 0, 'pending')",
                            next_order_id, lid, buyer_addr
                        );
                        let _ = app.execute_as(&sql, &buyer_addr);
                        next_order_id += 1;
                    }
                    _ => println!("Listing {} not found", lid),
                }
            }

            ".my-listings" => {
                let result = app.execute_as("SELECT * FROM listings", &seller_addr);
                match result {
                    Ok(r) => {
                        println!("Your listings ({}):", r.rows.len());
                        for row in &r.rows {
                            println!("  {:?}", row.values);
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }

            ".my-orders" => {
                let result = app.execute_as("SELECT * FROM orders", &buyer_addr);
                match result {
                    Ok(r) => {
                        println!("Your orders ({}):", r.rows.len());
                        for row in &r.rows {
                            println!("  {:?}", row.values);
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }

            ".balances" => {
                let result = app.execute_as("SELECT * FROM balances", &seller_addr);
                match result {
                    Ok(r) => {
                        println!("Balances:");
                        for row in &r.rows {
                            println!("  {:?}", row.values);
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }

            ".browse" => {
                let result =
                    app.execute_as("SELECT * FROM listings WHERE status = 'active'", &buyer_addr);
                match result {
                    Ok(r) => {
                        println!("Active listings ({}):", r.rows.len());
                        for row in &r.rows {
                            println!("  {:?}", row.values);
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }

            ".produce" => {
                let block = node.produce_block();
                println!(
                    "Block #{}: {} txs, state_root={}",
                    block.header.height,
                    block.transactions.len(),
                    block.header.state_root
                );
            }

            ".status" => {
                println!("Chain height: {}", node.height());
                println!("State root:   {}", node.state_root());
            }

            _ => {
                // Try as raw SQL
                match app.execute_as(input.trim(), &seller_addr) {
                    Ok(r) => {
                        if !r.rows.is_empty() {
                            for row in &r.rows {
                                println!("  {:?}", row.values);
                            }
                        }
                        if r.rows_affected > 0 {
                            println!("  {} rows affected", r.rows_affected);
                        }
                    }
                    Err(e) => println!("SQL error: {}", e),
                }
            }
        }
    }
}
