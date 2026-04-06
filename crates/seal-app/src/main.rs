//! Seal REPL — interactive SQL shell for Seal DAO.
//!
//! Usage: cargo run -p seal-app
//!
//! Commands:
//!   Any SQL statement (e.g., SELECT * FROM users)
//!   .help          Show help
//!   .status        Show node status
//!   .wallet        Show wallet info
//!   .block         Show latest block
//!   .produce       Manually produce a block
//!   .quit          Exit

use seal_node::state::NodeState;
use seal_wallet::Wallet;
use std::io::{self, BufRead, Write};

fn main() {
    let mut node = NodeState::new();
    let wallet = Wallet::generate(true);

    println!("=== Seal DAO REPL ===");
    println!("Node: {}", node.node_address());
    println!("Wallet: {}", wallet.address());
    println!("Type .help for commands, or enter SQL directly.\n");

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("seal> ");
        if let Err(e) = stdout.flush() {
            eprintln!("Failed to flush stdout: {}", e);
            break;
        }

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                eprintln!("Failed to read input: {}", e);
                break;
            }
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match line {
            ".quit" | ".exit" | ".q" => {
                println!("Goodbye.");
                break;
            }
            ".help" | ".h" => {
                println!("Commands:");
                println!("  <SQL>       Execute SQL (SELECT, INSERT, CREATE TABLE, etc.)");
                println!("  .tables     List all tables");
                println!("  .status     Show node status (height, state root)");
                println!("  .wallet     Show wallet info (address, pubkey)");
                println!("  .block      Show latest block info");
                println!("  .produce    Produce a block from pending transactions");
                println!("  .pending    Show pending transaction count");
                println!("  .quit       Exit the REPL");
            }
            ".status" | ".s" => {
                println!("Height: {}", node.height());
                println!("State root: {}", node.state_root());
                println!("Address: {}", node.node_address());
            }
            ".wallet" | ".w" => {
                let info = wallet.info();
                println!("Address: {}", info.seal_address);
                println!("PQC pubkey: {}...", &info.seal_pubkey_hex[..32]);
                println!("Ed25519 pubkey: {}...", &info.ed25519_pubkey_hex[..32]);
            }
            ".tables" | ".t" => {
                let tables = node.table_names();
                if tables.is_empty() {
                    println!("No tables. Use CREATE TABLE to create one.");
                } else {
                    println!("Tables:");
                    for t in &tables {
                        let count = node.row_count(t).unwrap_or(0);
                        println!("  {} ({} rows)", t, count);
                    }
                }
            }
            ".pending" => {
                println!("Pending transactions: {}", node.pending_tx_count());
            }
            ".block" | ".b" => {
                println!("Chain height: {}", node.height());
                println!("State root: {}", node.state_root());
            }
            _ if line.starts_with(".block ") => {
                let height_str = line.strip_prefix(".block ").unwrap_or("").trim();
                match height_str.parse::<u64>() {
                    Ok(h) => match node.get_block(h) {
                        Some(block) => {
                            println!("Block #{}", block.header.height);
                            println!("  State root:  {}", block.header.state_root);
                            println!("  Parent hash: {}", block.header.parent_hash);
                            println!("  Timestamp:   {}", block.header.timestamp);
                            println!(
                                "  Proposer:    {}...",
                                hex::encode(
                                    &block.header.proposer[..16.min(block.header.proposer.len())]
                                )
                            );
                            println!("  Transactions: {}", block.transactions.len());
                            for (i, tx) in block.transactions.iter().enumerate() {
                                let payload_preview = std::str::from_utf8(&tx.payload)
                                    .unwrap_or("<binary>")
                                    .chars()
                                    .take(60)
                                    .collect::<String>();
                                println!("    [{}] {:?}: {}", i, tx.tx_type, payload_preview);
                            }
                        }
                        None => println!("Block {} not found (height: {})", h, node.height()),
                    },
                    Err(_) => println!("Usage: .block <height>"),
                }
            }
            ".produce" | ".p" => {
                let block = node.produce_block();
                println!(
                    "Block #{}: {} txs, state: {}",
                    block.header.height,
                    block.transactions.len(),
                    block.header.state_root,
                );
            }
            sql => {
                match node.execute_sql(sql) {
                    Ok(result) => {
                        if !result.columns.is_empty() {
                            // Print column headers
                            println!("{}", result.columns.join(" | "));
                            println!("{}", "-".repeat(result.columns.len() * 15));
                            // Print rows
                            for row in &result.rows {
                                let vals: Vec<String> =
                                    row.values.iter().map(|v| format!("{:?}", v)).collect();
                                println!("{}", vals.join(" | "));
                            }
                            println!("({} rows)", result.rows.len());
                        } else if result.rows_affected > 0 {
                            println!("OK ({} rows affected)", result.rows_affected);
                        } else {
                            println!("OK");
                        }
                    }
                    Err(e) => {
                        println!("ERROR: {}", e);
                    }
                }
            }
        }
    }
}
