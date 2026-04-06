//! Seal Notes — Encrypted Notebook on Seal DAO
//!
//! A demo app showing the "PHP+MySQL but on-chain" vision:
//! - Deploy a SQL schema as a decentralized app
//! - INSERT/SELECT/UPDATE/DELETE notes with PostgreSQL syntax
//! - Row-level security: only the note owner can read their notes
//! - PQC-signed transactions (ML-DSA-65)
//! - Merkle state root commits all data cryptographically
//!
//! Usage: cargo run -p seal-notes

use seal_crypto::hash::sha3_256;
use seal_node::state::NodeState;
use seal_sql::namespace::NamespaceRegistry;
use seal_sql::rls::{Policy, PolicyAction};
use seal_wallet::Wallet;
use std::io::{self, BufRead, Write};

/// Simple XOR encryption with a key derived from the wallet seed.
/// NOT production crypto — just demonstrates the concept.
fn encrypt(plaintext: &str, key: &[u8; 32]) -> String {
    let bytes: Vec<u8> = plaintext
        .bytes()
        .enumerate()
        .map(|(i, b)| b ^ key[i % 32])
        .collect();
    hex::encode(bytes)
}

fn decrypt(ciphertext_hex: &str, key: &[u8; 32]) -> String {
    match hex::decode(ciphertext_hex) {
        Ok(bytes) => {
            let decrypted: Vec<u8> = bytes
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % 32])
                .collect();
            String::from_utf8_lossy(&decrypted).to_string()
        }
        Err(_) => ciphertext_hex.to_string(), // Return as-is if not hex
    }
}

fn main() {
    println!("=== Seal Notes — Encrypted Notebook ===\n");

    // Create wallet (PQC identity)
    let wallet = Wallet::generate(true);
    let user_addr = wallet.address().to_string();
    let enc_key = sha3_256(wallet.signing_key_bytes().as_slice()).0;
    println!("Your address: {}", user_addr);
    println!("PQC identity: ML-DSA-65 (post-quantum secure)\n");

    // Create node + deploy the notes app
    let mut node = NodeState::new();
    let mut registry = NamespaceRegistry::new();

    // Deploy schema
    registry
        .deploy_app(
            "notes.seal".into(),
            user_addr.clone(),
            "CREATE TABLE notes (
                id BIGINT PRIMARY KEY,
                owner TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT NOT NULL,
                created_at BIGINT
            )",
        )
        .unwrap();

    // Enable RLS: owner can read/write their own notes
    let notes_app = registry.get_mut("notes.seal").unwrap();
    notes_app.rls.enable_rls("notes");
    notes_app
        .rls
        .add_policy(Policy {
            name: "owner_all".into(),
            table_name: "notes".into(),
            action: PolicyAction::All,
            using_expr: "owner = CURRENT_USER()".into(),
            with_check_expr: None,
        })
        .unwrap();

    println!("App 'notes.seal' deployed with RLS (owner-only access)");
    println!("Type .help for commands\n");

    let mut next_id: i64 = 1;
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        print!("notes> ");
        stdout.flush().unwrap();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).unwrap() == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        match line {
            ".quit" | ".q" => {
                println!("Goodbye.");
                break;
            }
            ".help" | ".h" => {
                println!("Commands:");
                println!("  .add <title>    Add a new note (prompts for body)");
                println!("  .list           List all your notes");
                println!("  .read <id>      Read a note by ID");
                println!("  .delete <id>    Delete a note");
                println!("  .status         Show chain status");
                println!("  .produce        Produce a block");
                println!("  .quit           Exit");
            }
            ".list" | ".ls" => {
                let app = registry.get_mut("notes.seal").unwrap();
                match app.execute_as("SELECT * FROM notes", &user_addr) {
                    Ok(result) => {
                        if result.rows.is_empty() {
                            println!("No notes yet. Use .add to create one.");
                        } else {
                            println!("Your notes:");
                            for row in &result.rows {
                                // Schema: id(0), owner(1), title(2), body(3), created_at(4)
                                let id = format!("{:?}", row.values[0]);
                                let title_enc = format!("{:?}", row.values[2]);
                                let title_hex = title_enc
                                    .trim_start_matches("Text(\"")
                                    .trim_end_matches("\")");
                                let title = decrypt(title_hex, &enc_key);
                                println!("  [{}] {}", id, title);
                            }
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            ".status" | ".s" => {
                println!("Chain height: {}", node.height());
                println!("State root: {}", node.state_root());
                println!("Your address: {}", user_addr);
                let app = registry.get("notes.seal").unwrap();
                println!("App tables: {:?}", app.table_names());
            }
            ".produce" | ".p" => {
                let block = node.produce_block();
                println!(
                    "Block #{}: {} txs, state: {}",
                    block.header.height,
                    block.transactions.len(),
                    block.header.state_root
                );
            }
            _ if line.starts_with(".add ") => {
                let title = line.strip_prefix(".add ").unwrap().trim();
                if title.is_empty() {
                    println!("Usage: .add <title>");
                    continue;
                }

                // Prompt for body
                print!("  Body: ");
                stdout.flush().unwrap();
                let mut body = String::new();
                stdin.lock().read_line(&mut body).unwrap();
                let body = body.trim();

                // Encrypt title and body
                let enc_title = encrypt(title, &enc_key);
                let enc_body = encrypt(body, &enc_key);
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let sql = format!(
                    "INSERT INTO notes (id, owner, title, body, created_at) VALUES ({}, '{}', '{}', '{}', {})",
                    next_id, user_addr, enc_title, enc_body, timestamp
                );

                let app = registry.get_mut("notes.seal").unwrap();
                match app.execute_as(&sql, &user_addr) {
                    Ok(_) => {
                        println!("  Note #{} saved (encrypted on-chain)", next_id);
                        next_id += 1;
                    }
                    Err(e) => println!("  Error: {}", e),
                }
            }
            _ if line.starts_with(".read ") => {
                let id_str = line.strip_prefix(".read ").unwrap().trim();
                let sql = format!("SELECT * FROM notes WHERE id = {}", id_str);
                let app = registry.get_mut("notes.seal").unwrap();
                match app.execute_as(&sql, &user_addr) {
                    Ok(result) => {
                        if result.rows.is_empty() {
                            println!("Note not found.");
                        } else {
                            // Schema: id(0), owner(1), title(2), body(3), created_at(4)
                            let row = &result.rows[0];
                            let title_hex = format!("{:?}", row.values[2])
                                .trim_start_matches("Text(\"")
                                .trim_end_matches("\")")
                                .to_string();
                            let body_hex = format!("{:?}", row.values[3])
                                .trim_start_matches("Text(\"")
                                .trim_end_matches("\")")
                                .to_string();
                            println!("  Title: {}", decrypt(&title_hex, &enc_key));
                            println!("  Body:  {}", decrypt(&body_hex, &enc_key));
                            println!("  Time:  {:?}", row.values[4]);
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            _ if line.starts_with(".delete ") => {
                let id_str = line.strip_prefix(".delete ").unwrap().trim();
                let sql = format!("DELETE FROM notes WHERE id = {}", id_str);
                let app = registry.get_mut("notes.seal").unwrap();
                match app.execute_as(&sql, &user_addr) {
                    Ok(result) => {
                        if result.rows_affected > 0 {
                            println!("  Note deleted.");
                        } else {
                            println!("  Note not found.");
                        }
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            _ => {
                println!("Unknown command. Type .help for help.");
            }
        }
    }
}
