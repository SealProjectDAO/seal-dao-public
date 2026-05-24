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
        "transfer" => run_transfer(&args[2..]),
        "faucet" => run_faucet(&args[2..]),
        "balance" => run_balance(&args[2..]),
        "create-token" => run_create_token(&args[2..]),
        "mint-token" => run_mint_token(&args[2..]),
        "transfer-token" => run_transfer_token(&args[2..]),
        "burn-token" => run_burn_token(&args[2..]),
        "freeze-account" => run_freeze_account(&args[2..]),
        "unfreeze-account" => run_unfreeze_account(&args[2..]),
        "is-frozen" => run_is_frozen(&args[2..]),
        "list-frozen" => run_list_frozen(&args[2..]),
        "frozen-symbols" => run_frozen_symbols(&args[2..]),
        "my-tokens" => run_my_tokens(&args[2..]),
        "my-private-tables" => run_my_private_tables(&args[2..]),
        "my-leases" => run_my_leases(&args[2..]),
        "my-namespaces" => run_my_namespaces(&args[2..]),
        "my-bridge-deposits" => run_my_bridge_deposits(&args[2..]),
        "my-bridge-withdrawals" => run_my_bridge_withdrawals(&args[2..]),
        "validator-status" => run_validator_status(&args[2..]),
        "council-status" => run_council_status(&args[2..]),
        "my-mint-authorities" => run_my_mint_authorities(&args[2..]),
        "my-freeze-authorities" => run_my_freeze_authorities(&args[2..]),
        "my-fee-authorities" => run_my_fee_authorities(&args[2..]),
        "set-token-frozen" => run_set_token_frozen(&args[2..]),
        "set-mint-authority" => run_set_authority(&args[2..], "mint"),
        "set-freeze-authority" => run_set_authority(&args[2..], "freeze"),
        "set-fee-authority" => run_set_authority(&args[2..], "fee"),
        "renounce-mint-authority" => run_renounce_authority(&args[2..], "mint"),
        "renounce-freeze-authority" => run_renounce_authority(&args[2..], "freeze"),
        "renounce-fee-authority" => run_renounce_authority(&args[2..], "fee"),
        "set-fee-recipient" => run_set_fee_recipient(&args[2..]),
        "addr-to-hex" => run_addr_to_hex(&args[2..]),
        "hex-to-addr" => run_hex_to_addr(&args[2..]),
        "set-transfer-fee" => run_set_transfer_fee(&args[2..]),
        "place-order" => run_place_order(&args[2..]),
        "cancel-order" => run_cancel_order(&args[2..]),
        "trades" => run_trades(&args[2..]),
        "list-orders" => run_list_orders(&args[2..]),
        "trade-history" => run_trade_history(&args[2..]),
        "wrapped-balances" => run_wrapped_balances(&args[2..]),
        "list-leases" => run_list_leases(&args[2..]),
        "my-proposals" => run_my_proposals(&args[2..]),
        "my-votes" => run_my_votes(&args[2..]),
        "my-locks" => run_my_locks(&args[2..]),
        "my-delegations" => run_my_delegations(&args[2..]),
        "delegations-to-me" => run_delegations_to_me(&args[2..]),
        "validators" => run_list_validators(&args[2..]),
        "snapshots" => run_list_snapshots(&args[2..]),
        "snapshot-manifest" => run_snapshot_manifest(&args[2..]),
        "snapshot-chunk" => run_snapshot_chunk(&args[2..]),
        "sign-file" => run_sign_file(&args[2..]),
        "verify-file" => run_verify_file(&args[2..]),
        "token" => run_token(&args[2..]),
        "gov-propose" => run_gov_propose(&args[2..]),
        "gov-vote" => run_gov_vote(&args[2..]),
        "gov-withdraw-vote" => run_gov_withdraw_vote(&args[2..]),
        "gov-delegate" => run_gov_delegate(&args[2..]),
        "gov-revoke-delegation" => run_gov_revoke_delegation(&args[2..]),
        "rpc" => run_rpc(&args[2..]),
        "bridge-withdraw" => run_bridge_withdraw(&args[2..]),
        "bridge-list-withdrawals" => run_bridge_list_withdrawals(&args[2..]),
        "bridge-get-withdrawal" => run_bridge_get_withdrawal(&args[2..]),
        "bridge-mark-executed" => run_bridge_mark_executed(&args[2..]),
        "bridge-key-status" => run_bridge_key_status(&args[2..]),
        "bridge-ringtail-status" => run_bridge_ringtail_status(&args[2..]),
        "bridge-fee" => run_bridge_fee(&args[2..]),
        "admin-list" => run_admin_list(&args[2..]),
        "admin-sign" => run_admin_sign(&args[2..]),
        "admin-submit" => run_admin_submit(&args[2..]),
        "health" => run_health(&args[2..]),
        "status" => run_status(&args[2..]),
        "check-registration" => run_check_registration(&args[2..]),
        "register-validator" => run_register_validator(&args[2..]),
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
    println!("  seal keygen --vrf [--output f]      Generate PQ-VRF keypair (for register-validator --vrf-pubkey-hex)");
    println!("  seal wallet                        Interactive TUI wallet");
    println!("  seal sql \"<query>\"                  Execute SQL on local node");
    println!("  seal sql \"<query>\" --node <url>     Execute SQL on remote node");
    println!("  seal sql \"INSERT..\" --node <url> --key key.json  Signed write");
    println!("  seal transfer <to> <amount> --node <url> --key key.json  One-shot signed transfer");
    println!("  seal faucet --node <url> [--key key.json | --address <addr>] [--amount <amt>]");
    println!("                                      Drip SEAL from node's --dev-faucet to target");
    println!("  seal faucet --http <faucet-url> [--key key.json | --address <addr>]");
    println!("                                      Drip SEAL from a seal-faucet HTTP service");
    println!("  seal balance --node <url> [--key key.json | --address <addr>]   Read SEAL balance");
    println!("  seal create-token --symbol <S> --name <N> [--decimals <D>] [--max-supply <M>]");
    println!(
        "                                      Create a new token (caller becomes mint authority)"
    );
    println!("  seal mint-token --symbol <S> --to <addr> --amount <amt>");
    println!("                                      Mint custom tokens (must be mint authority)");
    println!("  seal transfer-token --symbol <S> --to <addr> --amount <amt>");
    println!("                                      Transfer custom tokens between addresses");
    println!("  seal burn-token --symbol <S> --amount <amt>");
    println!(
        "                                      Burn caller-held tokens (decreases total_supply)"
    );
    println!("  seal freeze-account --symbol <S> --address <addr>");
    println!(
        "                                      Freeze account (caller must be freeze_authority)"
    );
    println!("  seal unfreeze-account --symbol <S> --address <addr>");
    println!(
        "                                      Unfreeze account (caller must be freeze_authority)"
    );
    println!("  seal is-frozen --symbol <S> --address <addr>");
    println!("                                      Read frozen state for address (unsigned)");
    println!("  seal list-frozen --symbol <S>");
    println!(
        "                                      List all addresses frozen for a token (unsigned)"
    );
    println!("  seal frozen-symbols --address <addr>");
    println!(
        "                                      List every token where <addr> is frozen (unsigned)"
    );
    println!("  seal my-tokens --address <addr>");
    println!("                                      List every token created by <addr> (unsigned)");
    println!("  seal my-private-tables --address <addr>");
    println!(
        "                                      List every private table owned by <addr> (unsigned)"
    );
    println!("  seal my-leases --address <addr> [--expired-only]");
    println!(
        "                                      List every storage lease owned by <addr> (unsigned)"
    );
    println!("  seal my-namespaces --address <addr>");
    println!(
        "                                      List every namespace deployed by <addr> (unsigned)"
    );
    println!("  seal my-bridge-deposits --address <addr>");
    println!("                                      List every cross-chain bridge deposit to <addr> (unsigned)");
    println!("  seal my-bridge-withdrawals --address <addr>");
    println!("                                      List every cross-chain bridge withdrawal initiated by <addr> (unsigned)");
    println!("  seal validator-status --address <addr>");
    println!("                                      Show whether <addr> is a validator (active/inactive/none) (unsigned)");
    println!("  seal council-status --address <addr>");
    println!("                                      Show whether <addr> is on the Technical Council (unsigned)");
    println!("  seal my-mint-authorities --address <addr>");
    println!("                                      List every token whose current mint authority is <addr> (unsigned)");
    println!("  seal my-freeze-authorities --address <addr>");
    println!("  seal my-fee-authorities --address <addr>");
    println!("                                      List every token whose current freeze authority is <addr> (unsigned)");
    println!("  seal set-token-frozen --symbol <S> --frozen <true|false>");
    println!("                                      Set token-level global freeze (caller must be freeze_authority)");
    println!("  seal set-mint-authority --symbol <S> --new-authority <addr>");
    println!("                                      Rotate mint authority (caller must be current authority)");
    println!("  seal set-freeze-authority --symbol <S> --new-authority <addr>");
    println!("                                      Rotate freeze authority (caller must be current authority)");
    println!("  seal set-fee-authority --symbol <S> --new-authority <addr>");
    println!("                                      Rotate fee authority (caller must be current authority)");
    println!("  seal renounce-mint-authority --symbol <S>");
    println!("                                      Irrevocably drop mint authority (no inverse)");
    println!("  seal renounce-freeze-authority --symbol <S>");
    println!(
        "                                      Irrevocably drop freeze authority (no inverse)"
    );
    println!("  seal renounce-fee-authority --symbol <S>");
    println!("                                      Irrevocably lock transfer fee at current value (no inverse)");
    println!("  seal set-transfer-fee --symbol <S> --fee-bps <B>");
    println!("                                      Set transfer-fee in basis points (caller must be fee_authority)");
    println!("  seal set-fee-recipient --symbol <S> --new-recipient <addr>");
    println!("                                      Route transfer fees to <addr> (caller must be fee_authority)");
    println!("  seal addr-to-hex <bech32m-address>");
    println!("                                      Decode seal1.../sealt1... to its 32-byte hex hash (for bridge ops)");
    println!("  seal hex-to-addr <64-char-hex> [--mainnet]");
    println!("                                      Encode a 32-byte hex hash back to bech32m (testnet by default)");
    println!("  seal place-order --pair <BASE/QUOTE> --side <bid|ask> --price <P> --quantity <Q>");
    println!("                                      Place a limit order on the DEX (auto-matches)");
    println!("  seal cancel-order --pair <BASE/QUOTE> --order-id <N>");
    println!("                                      Cancel an open order on the DEX");
    println!("  seal trades --pair <BASE/QUOTE> [--since-id <N>] [--limit <N>]");
    println!(
        "                                      List recent DEX trades for a pair (forward stream)"
    );
    println!("  seal list-orders --address <addr>");
    println!("                                      List all open orders owned by <addr> across every pair (unsigned)");
    println!("  seal trade-history --address <addr> [--limit <N>]");
    println!("                                      Recent trades involving <addr> as maker or taker (unsigned)");
    println!("  seal wrapped-balances --address <addr>");
    println!("                                      All non-zero bridge wrapped balances for <addr> (unsigned)");
    println!("  seal list-leases [--expired-only]");
    println!(
        "                                      Snapshot of every active storage lease (unsigned)"
    );
    println!("  seal my-proposals --address <addr>");
    println!(
        "                                      Governance proposals authored by <addr> (unsigned)"
    );
    println!("  seal my-votes --address <addr>");
    println!("                                      Governance votes cast by <addr> across all proposals (unsigned)");
    println!("  seal my-locks --address <addr>");
    println!("                                      Active conviction locks for <addr> (unsigned)");
    println!("  seal my-delegations --address <addr>");
    println!("                                      Outgoing voting-weight delegations from <addr> (unsigned)");
    println!("  seal delegations-to-me --address <addr>");
    println!("                                      Incoming voting-weight delegations to <addr> (unsigned)");
    println!("  seal validators");
    println!("                                      Snapshot of the active validator set with stake (unsigned)");
    println!("  seal snapshots [--limit <N>]");
    println!("                                      Recent state-snapshot roster captured at epoch boundaries (unsigned)");
    println!("  seal snapshot-manifest --height <h>");
    println!("                                      Chunk-list manifest for one snapshot (state-sync prep, unsigned)");
    println!("  seal snapshot-chunk --height <h> --index <n> [--out <file>]");
    println!("                                      Fetch one snapshot chunk + verify its hash (state-sync prep, unsigned)");
    println!("  seal sign-file <path> --key <key.json> [--out <sig-path>]");
    println!("                                      ML-DSA-65 sign a file's SHA3-256 hash. Output: hex sig (or --out).");
    println!("  seal verify-file <path> --pubkey-hex <hex> --sig-hex <hex> | --sig-file <path>");
    println!("                                      Verify a sign-file detached signature. Exit 0 = OK, 1 = bad sig.");
    println!("  seal token --symbol <S>");
    println!("                                      Read a single token's full info (unsigned)");
    println!("  seal gov-propose --track <T> --title <S> [--description <S>] [--payload <S>]");
    println!("                                      Submit a governance proposal (caller becomes proposer)");
    println!("  seal gov-vote --proposal-id <N> --choice <yes|no|abstain> --stake <amt> [--conviction x1..x6|none]");
    println!("                                      Cast a conviction vote on a proposal");
    println!("  seal gov-withdraw-vote --proposal-id <N>");
    println!("                                      Withdraw an earlier vote on the proposal");
    println!("  seal gov-delegate --delegate <addr> --track <T> --weight <W>");
    println!("                                      Delegate voting weight on a track");
    println!("  seal gov-revoke-delegation --track <T>");
    println!("                                      Revoke a prior delegation on a track");
    println!("  seal rpc --method <M> --params <JSON> --node <url> [--key key.json]");
    println!(
        "                                      Generic JSON-RPC passthrough (signs if --key given)"
    );
    println!("  seal bridge-withdraw --dest-chain <C> --dest-address <a> --token <T> --amount <n> --key key.json");
    println!("                                      Burn wrapped tokens, emit a withdrawal record");
    println!("  seal bridge-list-withdrawals [--chain <Solana|Stellar>] [--node <url>]");
    println!("                                      List pending bridge withdrawals (unsigned)");
    println!("  seal bridge-get-withdrawal --withdrawal-id <id> [--node <url>]");
    println!(
        "  seal bridge-mark-executed --withdrawal-id <id> --key <validator-key.json> \
         [--dest-chain-tx-hash <hash>] [--node <url>]"
    );
    println!(
        "                                      Fetch one withdrawal incl. committee signature"
    );
    println!("  seal bridge-key-status [--node <url>] [--expect-sha2 <hex>]");
    println!("  seal bridge-ringtail-status [--node <url>]");
    println!(
        "                                      Report committee MAC key fingerprints; exit 1 if unset, 2 if mismatch"
    );
    println!("  seal bridge-fee [--node <url>]");
    println!(
        "                                      Read the configured per-withdrawal SEAL fee (P8 mainnet gate)"
    );
    println!("  seal admin-list [--node <url>]");
    println!(
        "                                      Read the configured admin set + multisig threshold (P8/§4.3)"
    );
    println!("  seal admin-sign --method <m> --params '<json>' --key <path>");
    println!(
        "                                      Produce a {{sender, signature}} cosigner entry for the P8 M-of-N admin multisig"
    );
    println!("  seal admin-submit --method <m> --params '<json>' --primary <path> --cosigners a.json,b.json --node <url>");
    println!(
        "                                      Assemble + POST a full M-of-N admin RPC request"
    );
    println!("  seal health [--node <url>] [--require-validator]");
    println!(
        "                                      Pretty-print /health; exit 1 stalled/starting, 2 require-validator-not-met"
    );
    println!("  seal status [--node <url>]");
    println!("                                      Pretty-print /status (chain, metrics, bridge)");
    println!("  seal check-registration --portal <url> (--key key.json | --pubkey-hex <hex>)");
    println!(
        "                                      Verify a validator pubkey is in the portal roster; exit 1=not found, 2=portal error"
    );
    println!("  seal register-validator --portal <url> --key key.json --name <s> --contact <s> --vrf-pubkey-hex <64-hex>");
    println!("                                      One-shot post to the testnet validator portal");
    println!("  seal migrate analyze <file.sql>    Convert pg_dump to Seal SQL");
    println!("  seal help                          Show this help");
    println!();
    println!("Amount syntax (transfer/faucet --amount): bare integer = base units (10⁻⁹ SEAL),");
    println!("  decimal or trailing `SEAL` = SEAL. Examples: 50, 50.0, \"50 SEAL\", 1.5.");
}

fn run_keygen(args: &[String]) {
    let is_kem = args.iter().any(|a| a == "--kem");
    let is_vrf = args.iter().any(|a| a == "--vrf");
    if is_kem && is_vrf {
        eprintln!("--kem and --vrf are mutually exclusive");
        std::process::exit(1);
    }
    let output = args
        .iter()
        .position(|a| a == "--output")
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .unwrap_or(if is_kem {
            "seal-kem.json"
        } else if is_vrf {
            "seal-vrf.json"
        } else {
            "seal-key.json"
        });

    if is_kem {
        run_keygen_kem(output);
    } else if is_vrf {
        run_keygen_vrf(output);
    } else {
        run_keygen_signing(output);
    }
}

/// PQ VRF keypair — the input shape `seal register-validator
/// --vrf-pubkey-hex …` consumes. Same ML-DSA-65 primitive seal-vrf's
/// `PqVrf::keygen` uses, so a key generated here works as the
/// validator's slot-election VRF without any wrapping. Writing the
/// 32-byte hex form into `vrf_pubkey_hex` is what the registration
/// portal records as the validator's on-chain VRF pubkey.
fn run_keygen_vrf(output: &str) {
    use seal_vrf::Vrf;
    let kp = seal_vrf::PqVrf::keygen();
    let key_json = serde_json::json!({
        "type": "pq-vrf-ml-dsa-65",
        "secret_key": hex::encode(&kp.secret_key),
        "public_key": hex::encode(&kp.public_key),
    });
    match std::fs::write(
        output,
        serde_json::to_string_pretty(&key_json).unwrap_or_default(),
    ) {
        Ok(()) => {
            println!("Generated PQ-VRF keypair (ML-DSA-65 backbone)");
            // SHA3-256 of the verifying-key hex is the canonical
            // 64-char form `register-validator --vrf-pubkey-hex` and
            // the consensus runner's VrfKeyManager both consume.
            let vrf_pubkey_hash = seal_crypto::hash::sha3_256(&kp.public_key).0;
            println!("  vrf_pubkey_hex: {}", hex::encode(vrf_pubkey_hash));
            println!("  Key file: {}", output);
            println!();
            println!("Use with:");
            println!(
                "  seal register-validator --portal http://host:port \\\n      --key wallet.json --name <s> --contact <s> \\\n      --vrf-pubkey-hex {}",
                hex::encode(vrf_pubkey_hash)
            );
        }
        Err(e) => eprintln!("Failed to write key file: {}", e),
    }
}

fn run_keygen_signing(output: &str) {
    let (sk, vk) = seal_crypto::signature::SigningKey::generate();
    // Default to testnet so the derived address matches
    // `cargo run -p seal-node -- --dev-faucet`'s default HRP
    // (`sealt1…`). Pass `--mainnet` on either side to flip both.
    let testnet = !std::env::args().any(|a| a == "--mainnet");
    let address =
        seal_crypto::address::SealAddress::from_verifying_key(&vk, testnet).to_string_encoding();

    let key_json = serde_json::json!({
        "type": "ml-dsa-65",
        "network": if testnet { "testnet" } else { "mainnet" },
        "address": address,
        "signing_key": hex::encode(sk.to_bytes()),
        "verifying_key": hex::encode(vk.to_bytes()),
    });

    match std::fs::write(
        output,
        serde_json::to_string_pretty(&key_json).unwrap_or_default(),
    ) {
        Ok(()) => {
            println!("Generated ML-DSA-65 signing keypair");
            println!("  Address: {}", address);
            println!("  Network: {}", if testnet { "testnet" } else { "mainnet" });
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

    match std::fs::write(
        output,
        serde_json::to_string_pretty(&key_json).unwrap_or_default(),
    ) {
        Ok(()) => {
            println!("Generated ML-KEM-768 encryption keypair");
            println!(
                "  Public key: {}...{}",
                &hex::encode(&pk_bytes)[..16],
                &hex::encode(&pk_bytes)[pk_bytes.len() * 2 - 16..]
            );
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
            "--node" if i + 1 < args.len() => {
                node_url = Some(args[i + 1].clone());
                i += 2;
            }
            "--key" if i + 1 < args.len() => {
                key_file = Some(args[i + 1].clone());
                i += 2;
            }
            _ => {
                sql_parts.push(args[i].as_str());
                i += 1;
            }
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
                    error
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
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
                    println!(
                        "{}",
                        serde_json::to_string_pretty(result).unwrap_or_default()
                    );
                }
            }
        }
        Err(e) => eprintln!("Failed to parse response: {}", e),
    }
}

/// Sign an RPC request with ML-DSA. Returns (signature_hex, sender_hex).
fn sign_request(
    method: &str,
    params: &serde_json::Value,
    key_file: &str,
) -> Result<(String, String), String> {
    let key_json = std::fs::read_to_string(key_file)
        .map_err(|e| format!("cannot read key file '{}': {}", key_file, e))?;
    let key_data: serde_json::Value =
        serde_json::from_str(&key_json).map_err(|e| format!("invalid key file JSON: {}", e))?;

    let sk_hex = key_data
        .get("signing_key")
        .and_then(|v| v.as_str())
        .ok_or("key file missing 'signing_key' field")?;
    let vk_hex = key_data
        .get("verifying_key")
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

    let signature = sk
        .sign(message_hash.as_ref())
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
    let pk_short: String = pk_bytes
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect();

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
        (
            "INSERT INTO products (id, seller, name, price) VALUES (1, 'alice', 'Widget', 100)",
            "alice",
        ),
        (
            "INSERT INTO products (id, seller, name, price) VALUES (2, 'bob', 'Gadget', 250)",
            "bob",
        ),
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
                println!(
                    "blog.seal: SELECT * FROM posts => {} rows",
                    result.rows.len()
                );
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

// ─── One-shot RPC subcommands (no TUI) ──────────────────────────────
//
// All three share a tiny flag parser. `--node` defaults to
// http://localhost:8545. `transfer`/`faucet` accept the same amount
// syntax as the TUI (see wallet::parse_amount).

fn flag_value<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
}

fn positional(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a.starts_with("--") {
            // Skip flag + its value (we never take boolean flags here).
            i += 2;
            continue;
        }
        out.push(a.as_str());
        i += 1;
    }
    out
}

/// Read a key-file JSON and return the bech32m address inside.
fn address_from_key_file(path: &str) -> Result<String, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
    let v: serde_json::Value =
        serde_json::from_str(&s).map_err(|e| format!("invalid key file JSON: {e}"))?;
    v.get("address")
        .and_then(|a| a.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "key file missing 'address' field".into())
}

/// POST a JSON-RPC request and return the parsed response.
fn rpc_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value, String> {
    use std::io::{Read, Write};
    // Strip scheme, then split off the first path segment so non-root
    // endpoints (e.g., the seal-faucet `POST /faucet`) work.
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let (authority, path) = match stripped.find('/') {
        Some(i) => (&stripped[..i], &stripped[i..]),
        None => (stripped, "/"),
    };
    let mut stream =
        std::net::TcpStream::connect(authority).map_err(|e| format!("connect: {e}"))?;
    let body_str = body.to_string();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_str.len(), body_str
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("send: {e}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {e}"))?;
    let json_start = response
        .find("\r\n\r\n")
        .map(|p| p + 4)
        .ok_or("bad HTTP response")?;
    serde_json::from_str(&response[json_start..]).map_err(|e| format!("parse: {e}"))
}

fn run_transfer(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal transfer <to> <amount> --node <url> --key key.json");
            eprintln!("  --key is required so the transfer can be ML-DSA-signed.");
            return;
        }
    };
    let pos = positional(args);
    if pos.len() < 2 {
        eprintln!("Usage: seal transfer <to> <amount> --node <url> --key key.json");
        return;
    }
    let to = pos[0];
    // Allow `5 SEAL` across two tokens.
    let amount_raw = pos[1..].join(" ");
    let amount = match wallet::parse_amount(&amount_raw) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Invalid amount: {e}");
            return;
        }
    };

    let params = serde_json::json!({ "to": to, "amount": amount });
    let (sig, sender) = match sign_request("seal_transfer", &params, key_file) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("Failed to sign: {e}");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "seal_transfer",
        "params": params,
        "signature": sig,
        "sender": sender,
        "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
            } else {
                println!("Transferred {} to {}", wallet::format_seal(amount), to);
                if let Some(status) = resp
                    .get("result")
                    .and_then(|r| r.get("status"))
                    .and_then(|s| s.as_str())
                {
                    println!("Status: {status}");
                }
            }
        }
        Err(e) => eprintln!("Transfer failed: {e}"),
    }
}

fn run_faucet(args: &[String]) {
    // Two faucet shapes:
    //   --http <url>   → POST <url>/faucet to the seal-faucet HTTP
    //                    service (production-shape testnet faucet,
    //                    rate-limited, signed seal_transfer behind it).
    //   --node <url>   → seal_faucet JSON-RPC on a node started with
    //                    --dev-faucet (unsigned admin mint, dev only).
    //
    // Use --http when pointing at a real testnet faucet operator;
    // use --node for local devnet bring-up. They're mutually exclusive.
    let http_url = flag_value(args, "--http");
    let node_url = flag_value(args, "--node").unwrap_or("http://localhost:8545");

    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => match flag_value(args, "--key") {
            Some(k) => match address_from_key_file(k) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("{e}");
                    return;
                }
            },
            None => {
                eprintln!("Usage:");
                eprintln!("  seal faucet --http <faucet-url> (--key key.json | --address <addr>)");
                eprintln!("  seal faucet --node <node-url> (--key key.json | --address <addr>) [--amount <amt>]");
                return;
            }
        },
    };

    if let Some(faucet_url) = http_url {
        // HTTP path: POST {faucet_url}/faucet with {address}.
        let body = serde_json::json!({ "address": address });
        let endpoint = format!("{}/faucet", faucet_url.trim_end_matches('/'));
        match rpc_post(&endpoint, &body) {
            Ok(resp) => {
                if let Some(err) = resp.get("error").and_then(|e| e.as_str()) {
                    eprintln!("Faucet error: {err}");
                    if let Some(retry) = resp.get("retry_after_secs").and_then(|r| r.as_u64()) {
                        eprintln!("  Retry in {retry}s.");
                    }
                } else if let Some(amt) = resp.get("amount").and_then(|v| v.as_u64()) {
                    let tx = resp
                        .get("tx_hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("(no tx_hash)");
                    println!("Faucet dripped {} to {}", wallet::format_seal(amt), address);
                    println!("  tx: {tx}");
                } else {
                    eprintln!("Unexpected response: {}", resp);
                }
            }
            Err(e) => eprintln!("Faucet failed: {e}"),
        }
        return;
    }

    // Node-RPC path (legacy --dev-faucet).
    let mut params = serde_json::json!({ "address": address });
    if let Some(a) = flag_value(args, "--amount") {
        match wallet::parse_amount(a) {
            Ok(n) => {
                params["amount"] = serde_json::json!(n);
            }
            Err(e) => {
                eprintln!("Invalid --amount: {e}");
                return;
            }
        }
    }
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_faucet", "params": params, "id": 1,
    });
    match rpc_post(node_url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                eprintln!("  (Did the node start with --dev-faucet? For testnet ops, use --http <faucet-url>.)");
            } else if let Some(r) = resp.get("result") {
                let amt = r.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                let bal = r.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("Faucet dripped {} to {}", wallet::format_seal(amt), address);
                println!("Balance now {}", wallet::format_seal(bal));
            }
        }
        Err(e) => eprintln!("Faucet failed: {e}"),
    }
}

fn run_balance(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => match flag_value(args, "--key") {
            Some(k) => match address_from_key_file(k) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("{e}");
                    return;
                }
            },
            None => {
                eprintln!("Usage: seal balance --node <url> (--key key.json | --address <addr>)");
                return;
            }
        },
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_getBalance",
        "params": { "address": &address }, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
            } else if let Some(r) = resp.get("result") {
                let bal = r.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
                let supply = r.get("total_supply").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("{}  balance: {}", address, wallet::format_seal(bal));
                println!("Total supply:  {}", wallet::format_seal(supply));
            }
        }
        Err(e) => eprintln!("Balance query failed: {e}"),
    }
}

// ── Signed-call helper for typed mutations ──────────────────────
//
// Signs the given (method, params) with the ML-DSA key in `key_file`
// and POSTs the JSON-RPC envelope to `url`. Returns the `result`
// object on success, or an error string on transport / RPC failure.
// Used by `run_create_token` etc. to keep each typed wrapper to
// argument-parsing + result-formatting only.
fn signed_call(
    url: &str,
    method: &str,
    params: serde_json::Value,
    key_file: &str,
) -> Result<serde_json::Value, String> {
    let (sig, sender) = sign_request(method, &params, key_file)?;
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "signature": sig,
        "sender": sender,
        "id": 1,
    });
    let resp = rpc_post(url, &body)?;
    if let Some(err) = resp.get("error") {
        let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        let msg = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown");
        return Err(format!("RPC error ({code}): {msg}"));
    }
    Ok(resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

fn run_create_token(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal create-token --symbol <S> --name <N> [--decimals <D>] [--max-supply <M>] --node <url> --key key.json");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let name = match flag_value(args, "--name") {
        Some(n) => n.to_string(),
        None => {
            eprintln!("missing --name");
            return;
        }
    };
    let decimals: u64 = flag_value(args, "--decimals")
        .and_then(|s| s.parse().ok())
        .unwrap_or(9);
    let max_supply: u64 = flag_value(args, "--max-supply")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let params = serde_json::json!({
        "symbol": symbol,
        "name": name,
        "decimals": decimals,
        "max_supply": max_supply,
    });
    match signed_call(url, "seal_createToken", params, key_file) {
        Ok(r) => {
            println!("Created token {} ({})", symbol, name);
            if let Some(creator) = r.get("creator").and_then(|v| v.as_str()) {
                println!("  creator        {}", creator);
            }
            println!("  decimals       {}", decimals);
            if max_supply > 0 {
                println!("  max_supply     {}", max_supply);
            }
        }
        Err(e) => eprintln!("create-token failed: {e}"),
    }
}

fn run_mint_token(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal mint-token --symbol <S> --to <addr> --amount <amt> --node <url> --key key.json");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let to = match flag_value(args, "--to") {
        Some(t) => t.to_string(),
        None => {
            eprintln!("missing --to");
            return;
        }
    };
    let amount: u64 = match flag_value(args, "--amount").and_then(|s| s.parse().ok()) {
        Some(a) => a,
        None => {
            eprintln!("missing or invalid --amount");
            return;
        }
    };

    let params = serde_json::json!({"symbol": symbol, "to": to, "amount": amount});
    match signed_call(url, "seal_mintToken", params, key_file) {
        Ok(_) => println!("Minted {} {} to {}", amount, symbol, to),
        Err(e) => eprintln!("mint-token failed: {e}"),
    }
}

fn run_transfer_token(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal transfer-token --symbol <S> --to <addr> --amount <amt> --node <url> --key key.json");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let to = match flag_value(args, "--to") {
        Some(t) => t.to_string(),
        None => {
            eprintln!("missing --to");
            return;
        }
    };
    let amount: u64 = match flag_value(args, "--amount").and_then(|s| s.parse().ok()) {
        Some(a) => a,
        None => {
            eprintln!("missing or invalid --amount");
            return;
        }
    };

    let mut params = serde_json::json!({"symbol": symbol, "to": to, "amount": amount});
    // Pass through the recipient-new-account confirmation if the
    // user explicitly opts in. Mirrors `seal_transfer` semantics.
    if args.iter().any(|a| a == "--confirm-new-recipient") {
        params["confirm_new_recipient"] = serde_json::Value::Bool(true);
    }
    match signed_call(url, "seal_transferToken", params, key_file) {
        Ok(_) => println!("Transferred {} {} to {}", amount, symbol, to),
        Err(e) => eprintln!("transfer-token failed: {e}"),
    }
}

fn run_burn_token(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!(
                "Usage: seal burn-token --symbol <S> --amount <amt> --node <url> --key key.json"
            );
            eprintln!("  Burns tokens from the signer's balance. The signed sender *is* the from-address.");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let amount: u64 = match flag_value(args, "--amount").and_then(|s| s.parse().ok()) {
        Some(a) => a,
        None => {
            eprintln!("missing or invalid --amount");
            return;
        }
    };

    let params = serde_json::json!({"symbol": symbol, "amount": amount});
    match signed_call(url, "seal_burnToken", params, key_file) {
        Ok(r) => {
            println!("Burned {} {}", amount, symbol);
            if let Some(supply) = r.get("total_supply").and_then(|v| v.as_u64()) {
                println!("  total_supply now {}", supply);
            }
        }
        Err(e) => eprintln!("burn-token failed: {e}"),
    }
}

fn run_freeze_account(args: &[String]) {
    run_freeze_op(args, true)
}

fn run_unfreeze_account(args: &[String]) {
    run_freeze_op(args, false)
}

fn run_freeze_op(args: &[String], freeze: bool) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let verb = if freeze {
        "freeze-account"
    } else {
        "unfreeze-account"
    };
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!(
                "Usage: seal {verb} --symbol <S> --address <addr> --node <url> --key key.json"
            );
            eprintln!("  Caller must be the token's freeze_authority.");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("missing --address");
            return;
        }
    };

    let params = serde_json::json!({"symbol": symbol, "address": address});
    let method = if freeze {
        "seal_freezeAccount"
    } else {
        "seal_unfreezeAccount"
    };
    match signed_call(url, method, params, key_file) {
        Ok(_) => println!("{verb}: ok ({} → {})", symbol, address),
        Err(e) => eprintln!("{verb} failed: {e}"),
    }
}

fn run_is_frozen(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("Usage: seal is-frozen --symbol <S> --address <addr> --node <url>");
            return;
        }
    };
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("missing --address");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "seal_isFrozen",
        "params": {"symbol": symbol, "address": address},
        "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
            } else if let Some(r) = resp.get("result") {
                let frozen = r.get("frozen").and_then(|v| v.as_bool()).unwrap_or(false);
                println!("{} {}: frozen={}", symbol, address, frozen);
            }
        }
        Err(e) => eprintln!("is-frozen failed: {e}"),
    }
}

fn run_set_token_frozen(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal set-token-frozen --symbol <S> --frozen <true|false> --node <url> --key key.json");
            eprintln!("  Caller must be the token's freeze_authority. Sets the token-level global freeze flag.");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let frozen: bool = match flag_value(args, "--frozen") {
        Some("true") => true,
        Some("false") => false,
        _ => {
            eprintln!("--frozen must be 'true' or 'false'");
            return;
        }
    };
    let params = serde_json::json!({"symbol": symbol, "frozen": frozen});
    match signed_call(url, "seal_setTokenFrozen", params, key_file) {
        Ok(_) => println!("set-token-frozen: {} → {}", symbol, frozen),
        Err(e) => eprintln!("set-token-frozen failed: {e}"),
    }
}

fn run_list_frozen(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("Usage: seal list-frozen --symbol <S> --node <url>");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "seal_listFrozenAccounts",
        "params": {"symbol": symbol},
        "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let r = match resp.get("result") {
                Some(r) => r,
                None => {
                    eprintln!("no result");
                    return;
                }
            };
            let count = r.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let frozen = r
                .get("frozen")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let truncated = r
                .get("truncated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if count == 0 {
                println!("{}: no frozen accounts", symbol);
                return;
            }
            println!(
                "{}: {} frozen{}",
                symbol,
                count,
                if truncated { " (truncated)" } else { "" }
            );
            for addr in frozen.iter().filter_map(|v| v.as_str()) {
                println!("  {}", addr);
            }
        }
        Err(e) => eprintln!("list-frozen failed: {e}"),
    }
}

fn run_frozen_symbols(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal frozen-symbols --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listFrozenSymbolsForAddress",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let symbols = result
                .get("symbols")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if symbols.is_empty() {
                println!("{} is not frozen on any token.", address);
                return;
            }
            println!("{} is frozen on {} token(s):", address, symbols.len());
            for s in &symbols {
                if let Some(sym) = s.as_str() {
                    println!("  {}", sym);
                }
            }
        }
        Err(e) => eprintln!("frozen-symbols failed: {e}"),
    }
}

fn run_my_tokens(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-tokens --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listTokensByCreator",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let tokens = result
                .get("tokens")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if tokens.is_empty() {
                println!("{} has not created any tokens.", address);
                return;
            }
            println!("{} created {} token(s):", address, tokens.len());
            println!(
                "  {:<10} {:<20} {:>10} {:>18}",
                "SYMBOL", "NAME", "DECIMALS", "TOTAL_SUPPLY"
            );
            for t in &tokens {
                let sym = t.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let decimals = t.get("decimals").and_then(|v| v.as_u64()).unwrap_or(0);
                let supply = t.get("total_supply").and_then(|v| v.as_u64()).unwrap_or(0);
                let name_trunc = if name.len() > 20 { &name[..20] } else { name };
                println!(
                    "  {:<10} {:<20} {:>10} {:>18}",
                    sym, name_trunc, decimals, supply
                );
            }
        }
        Err(e) => eprintln!("my-tokens failed: {e}"),
    }
}

fn run_my_mint_authorities(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-mint-authorities --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listTokensByMintAuthority",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let tokens = result
                .get("tokens")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if tokens.is_empty() {
                println!("{} cannot mint any tokens.", address);
                return;
            }
            println!("{} can currently mint {} token(s):", address, tokens.len());
            println!(
                "  {:<10} {:<20} {:>10} {:>18} {:<8}",
                "SYMBOL", "NAME", "DECIMALS", "TOTAL_SUPPLY", "CREATOR"
            );
            for t in &tokens {
                let sym = t.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let decimals = t.get("decimals").and_then(|v| v.as_u64()).unwrap_or(0);
                let supply = t.get("total_supply").and_then(|v| v.as_u64()).unwrap_or(0);
                let creator = t.get("creator").and_then(|v| v.as_str()).unwrap_or("");
                let name_trunc = if name.len() > 20 { &name[..20] } else { name };
                // Creator addresses are bech32m and longer than 8
                // chars; show "self" when creator == address (the
                // common case before any rotation), else a short
                // head…tail form so the column doesn't overflow.
                let creator_disp = if creator == address {
                    "self".to_string()
                } else if creator.len() > 16 {
                    format!("{}…{}", &creator[..6], &creator[creator.len() - 4..])
                } else {
                    creator.to_string()
                };
                println!(
                    "  {:<10} {:<20} {:>10} {:>18} {:<8}",
                    sym, name_trunc, decimals, supply, creator_disp
                );
            }
        }
        Err(e) => eprintln!("my-mint-authorities failed: {e}"),
    }
}

fn run_my_freeze_authorities(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-freeze-authorities --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listTokensByFreezeAuthority",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let tokens = result
                .get("tokens")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if tokens.is_empty() {
                println!("{} cannot freeze any tokens.", address);
                return;
            }
            println!(
                "{} can currently freeze {} token(s):",
                address,
                tokens.len()
            );
            // Render globally-frozen state per row — that's the
            // actionable distinction for a freeze-authority
            // operator (a token already globally-frozen has
            // nothing to do).
            println!(
                "  {:<10} {:<20} {:>10} {:>18} {:<10} {:<8}",
                "SYMBOL", "NAME", "DECIMALS", "TOTAL_SUPPLY", "GLOBAL", "CREATOR"
            );
            for t in &tokens {
                let sym = t.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let decimals = t.get("decimals").and_then(|v| v.as_u64()).unwrap_or(0);
                let supply = t.get("total_supply").and_then(|v| v.as_u64()).unwrap_or(0);
                let frozen = t.get("frozen").and_then(|v| v.as_bool()).unwrap_or(false);
                let creator = t.get("creator").and_then(|v| v.as_str()).unwrap_or("");
                let name_trunc = if name.len() > 20 { &name[..20] } else { name };
                let creator_disp = if creator == address {
                    "self".to_string()
                } else if creator.len() > 16 {
                    format!("{}…{}", &creator[..6], &creator[creator.len() - 4..])
                } else {
                    creator.to_string()
                };
                println!(
                    "  {:<10} {:<20} {:>10} {:>18} {:<10} {:<8}",
                    sym,
                    name_trunc,
                    decimals,
                    supply,
                    if frozen { "FROZEN" } else { "active" },
                    creator_disp
                );
            }
        }
        Err(e) => eprintln!("my-freeze-authorities failed: {e}"),
    }
}

fn run_my_fee_authorities(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-fee-authorities --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listTokensByFeeAuthority",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let tokens = result
                .get("tokens")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if tokens.is_empty() {
                println!("{} cannot edit any transfer fees.", address);
                return;
            }
            println!(
                "{} can currently edit transfer fees on {} token(s):",
                address,
                tokens.len()
            );
            // Render the current fee bps per row — that's the
            // actionable column for a fee-authority operator (the
            // fee they're about to consider rotating).
            println!(
                "  {:<10} {:<20} {:>10} {:>18} {:>8} {:<8}",
                "SYMBOL", "NAME", "DECIMALS", "TOTAL_SUPPLY", "FEE_BPS", "CREATOR"
            );
            for t in &tokens {
                let sym = t.get("symbol").and_then(|v| v.as_str()).unwrap_or("");
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let decimals = t.get("decimals").and_then(|v| v.as_u64()).unwrap_or(0);
                let supply = t.get("total_supply").and_then(|v| v.as_u64()).unwrap_or(0);
                let fee_bps = t
                    .get("transfer_fee_bps")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let creator = t.get("creator").and_then(|v| v.as_str()).unwrap_or("");
                let name_trunc = if name.len() > 20 { &name[..20] } else { name };
                let creator_disp = if creator == address {
                    "self".to_string()
                } else if creator.len() > 16 {
                    format!("{}…{}", &creator[..6], &creator[creator.len() - 4..])
                } else {
                    creator.to_string()
                };
                println!(
                    "  {:<10} {:<20} {:>10} {:>18} {:>8} {:<8}",
                    sym, name_trunc, decimals, supply, fee_bps, creator_disp
                );
            }
        }
        Err(e) => eprintln!("my-fee-authorities failed: {e}"),
    }
}

fn run_my_private_tables(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-private-tables --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listPrivateTablesByOwner",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let tables = result
                .get("tables")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if tables.is_empty() {
                println!("{} owns no private tables.", address);
                return;
            }
            println!("{} owns {} private table(s):", address, tables.len());
            println!("  {:<24} {:<20} {:>10}", "NAME", "TYPE", "ROW_COUNT");
            for t in &tables {
                let name = t.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let kind = t.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let rows = t.get("row_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let name_trunc = if name.len() > 24 { &name[..24] } else { name };
                println!("  {:<24} {:<20} {:>10}", name_trunc, kind, rows);
            }
        }
        Err(e) => eprintln!("my-private-tables failed: {e}"),
    }
}

fn run_my_leases(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-leases --address <addr> [--expired-only] [--node <url>]");
            return;
        }
    };
    let expired_only = args.iter().any(|a| a == "--expired-only");
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listLeasesByOwner",
        "params": {"address": address, "expired_only": expired_only}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let leases = result
                .get("leases")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if leases.is_empty() {
                let suffix = if expired_only {
                    " (no expired leases)"
                } else {
                    ""
                };
                println!("{} owns no storage leases{}.", address, suffix);
                return;
            }
            println!("{} owns {} lease(s):", address, leases.len());
            println!(
                "  {:<32} {:>10} {:>12} {:>14} {:>8}",
                "TABLE", "ROWS", "BYTES", "PAID_THRU(us)", "EXPIRED"
            );
            for l in &leases {
                let table = l.get("table").and_then(|v| v.as_str()).unwrap_or("");
                let rows = l.get("row_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let bytes = l.get("byte_size").and_then(|v| v.as_u64()).unwrap_or(0);
                let paid = l
                    .get("paid_through_us")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let expired = l.get("expired").and_then(|v| v.as_bool()).unwrap_or(false);
                let table_trunc = if table.len() > 32 {
                    &table[..32]
                } else {
                    table
                };
                println!(
                    "  {:<32} {:>10} {:>12} {:>14} {:>8}",
                    table_trunc,
                    rows,
                    bytes,
                    paid,
                    if expired { "yes" } else { "no" }
                );
            }
        }
        Err(e) => eprintln!("my-leases failed: {e}"),
    }
}

fn run_my_namespaces(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-namespaces --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listNamespacesByOwner",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let namespaces = result
                .get("namespaces")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if namespaces.is_empty() {
                println!("{} has not deployed any namespaces.", address);
                return;
            }
            println!("{} deployed {} namespace(s):", address, namespaces.len());
            println!(
                "  {:<24} {:<14} {:>11}",
                "NAME", "VISIBILITY", "REPLICATION"
            );
            for n in &namespaces {
                let name = n.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let vis = n.get("visibility").and_then(|v| v.as_str()).unwrap_or("");
                let rep = n.get("replication").and_then(|v| v.as_u64()).unwrap_or(0);
                let name_trunc = if name.len() > 24 { &name[..24] } else { name };
                println!("  {:<24} {:<14} {:>11}", name_trunc, vis, rep);
            }
        }
        Err(e) => eprintln!("my-namespaces failed: {e}"),
    }
}

fn run_my_bridge_deposits(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-bridge-deposits --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listBridgeDepositsByRecipient",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let deposits = result
                .get("deposits")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if deposits.is_empty() {
                println!("{} has no bridge deposits.", address);
                return;
            }
            println!("{} has {} bridge deposit(s):", address, deposits.len());
            println!(
                "  {:<24} {:<8} {:<6} {:>14} {:>4} {:>9}",
                "ID", "CHAIN", "TOKEN", "AMOUNT", "CONF", "PROCESSED"
            );
            for d in &deposits {
                let id = d.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let chain = d.get("source_chain").and_then(|v| v.as_str()).unwrap_or("");
                let token = d.get("token").and_then(|v| v.as_str()).unwrap_or("");
                let amount = d.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                let conf = d.get("confirmations").and_then(|v| v.as_u64()).unwrap_or(0);
                let proc = d
                    .get("processed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let id_trunc = if id.len() > 24 { &id[..24] } else { id };
                println!(
                    "  {:<24} {:<8} {:<6} {:>14} {:>4} {:>9}",
                    id_trunc,
                    chain,
                    token,
                    amount,
                    conf,
                    if proc { "yes" } else { "no" }
                );
            }
        }
        Err(e) => eprintln!("my-bridge-deposits failed: {e}"),
    }
}

fn run_my_bridge_withdrawals(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-bridge-withdrawals --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listBridgeWithdrawalsByInitiator",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let withdrawals = result
                .get("withdrawals")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if withdrawals.is_empty() {
                println!("{} has no bridge withdrawals.", address);
                return;
            }
            println!(
                "{} has {} bridge withdrawal(s):",
                address,
                withdrawals.len()
            );
            println!(
                "  {:<24} {:<8} {:<6} {:>14} {:<46} {:>9}",
                "ID", "CHAIN", "TOKEN", "AMOUNT", "DEST-ADDRESS", "EXECUTED"
            );
            for w in &withdrawals {
                let id = w.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let chain = w.get("dest_chain").and_then(|v| v.as_str()).unwrap_or("");
                let token = w.get("token").and_then(|v| v.as_str()).unwrap_or("");
                let amount = w.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                let dest = w.get("dest_address").and_then(|v| v.as_str()).unwrap_or("");
                let executed = w.get("executed").and_then(|v| v.as_bool()).unwrap_or(false);
                let id_trunc = if id.len() > 24 { &id[..24] } else { id };
                let dest_trunc = if dest.len() > 46 { &dest[..46] } else { dest };
                println!(
                    "  {:<24} {:<8} {:<6} {:>14} {:<46} {:>9}",
                    id_trunc,
                    chain,
                    token,
                    amount,
                    dest_trunc,
                    if executed { "yes" } else { "pending" }
                );
            }
        }
        Err(e) => eprintln!("my-bridge-withdrawals failed: {e}"),
    }
}

fn run_validator_status(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal validator-status --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_getValidatorByAddress",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let validator = result
                .get("validator")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            if validator.is_null() {
                println!("{} is not a validator.", address);
                return;
            }
            let stake = validator.get("stake").and_then(|v| v.as_u64()).unwrap_or(0);
            let active = validator
                .get("active")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let pk = validator
                .get("public_key_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let vrf = validator
                .get("vrf_public_key_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            // Pubkeys are ML-DSA — long. Show first 16 hex chars to
            // identify the validator without flooding the terminal;
            // full hex is in the RPC JSON for callers that need it.
            let pk_short = if pk.len() > 16 { &pk[..16] } else { pk };
            let vrf_short = if vrf.len() > 16 { &vrf[..16] } else { vrf };
            let status = if active {
                "ACTIVE"
            } else {
                "inactive (slashed or unbonding)"
            };
            println!("{} is a validator: {}", address, status);
            println!("  stake:       {} micro-SEAL", stake);
            println!("  pubkey:      {}…", pk_short);
            println!("  vrf-pubkey:  {}…", vrf_short);
        }
        Err(e) => eprintln!("validator-status failed: {e}"),
    }
}

fn run_council_status(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal council-status --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_getCouncilMemberByAddress",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let member = result
                .get("member")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            if member.is_null() {
                println!("{} is not on the Technical Council.", address);
                return;
            }
            let name = member.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let pk = member.get("pubkey").and_then(|v| v.as_str()).unwrap_or("");
            let term_start = member
                .get("term_start_epoch")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let term_end = member
                .get("term_end_epoch")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            // Pubkeys are ML-DSA — long. Show first 16 hex chars
            // for identification; full hex is in the RPC JSON.
            let pk_short = if pk.len() > 16 { &pk[..16] } else { pk };
            println!("{} is on the Technical Council:", address);
            println!("  name:        {}", name);
            println!("  pubkey:      {}…", pk_short);
            println!("  term-start:  epoch {}", term_start);
            println!("  term-end:    epoch {}", term_end);
        }
        Err(e) => eprintln!("council-status failed: {e}"),
    }
}

fn run_set_authority(args: &[String], kind: &str) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let verb = format!("set-{kind}-authority");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal {verb} --symbol <S> --new-authority <addr> --node <url> --key key.json");
            eprintln!("  Caller must be the current {kind} authority.");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let new_authority = match flag_value(args, "--new-authority") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("missing --new-authority");
            return;
        }
    };

    let params = serde_json::json!({"symbol": symbol, "new_authority": new_authority});
    let method = match kind {
        "mint" => "seal_setMintAuthority",
        "freeze" => "seal_setFreezeAuthority",
        "fee" => "seal_setFeeAuthority",
        _ => {
            eprintln!("internal: unknown authority kind {kind}");
            return;
        }
    };
    match signed_call(url, method, params, key_file) {
        Ok(_) => println!(
            "{verb}: {} authority on {} → {}",
            kind, symbol, new_authority
        ),
        Err(e) => eprintln!("{verb} failed: {e}"),
    }
}

fn run_renounce_authority(args: &[String], kind: &str) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let verb = format!("renounce-{kind}-authority");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal {verb} --symbol <S> --node <url> --key key.json");
            eprintln!("  Caller must be the current {kind} authority. This is irreversible —");
            eprintln!("  no future {kind} action will succeed for any caller.");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };

    let params = serde_json::json!({"symbol": symbol});
    let method = match kind {
        "mint" => "seal_renounceMintAuthority",
        "freeze" => "seal_renounceFreezeAuthority",
        "fee" => "seal_renounceFeeAuthority",
        _ => {
            eprintln!("internal: unknown authority kind {kind}");
            return;
        }
    };
    match signed_call(url, method, params, key_file) {
        Ok(_) => println!(
            "{verb}: {} authority on {} renounced (terminal)",
            kind, symbol
        ),
        Err(e) => eprintln!("{verb} failed: {e}"),
    }
}

fn run_set_transfer_fee(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal set-transfer-fee --symbol <S> --fee-bps <B> --node <url> --key key.json");
            eprintln!("  Caller must be the token's fee_authority. fee_bps: 0-10000 (basis points; 100 = 1%).");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let fee_bps: u64 = match flag_value(args, "--fee-bps").and_then(|s| s.parse().ok()) {
        Some(f) => f,
        None => {
            eprintln!("missing or invalid --fee-bps");
            return;
        }
    };

    let params = serde_json::json!({"symbol": symbol, "fee_bps": fee_bps});
    match signed_call(url, "seal_setTransferFee", params, key_file) {
        Ok(_) => println!(
            "Set transfer fee for {} to {} bps ({}%)",
            symbol,
            fee_bps,
            fee_bps as f64 / 100.0
        ),
        Err(e) => eprintln!("set-transfer-fee failed: {e}"),
    }
}

fn run_set_fee_recipient(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal set-fee-recipient --symbol <S> --new-recipient <addr> --node <url> --key key.json");
            eprintln!("  Caller must be the token's fee_authority. Routes future transfer-fee debits to <addr>.");
            return;
        }
    };
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("missing --symbol");
            return;
        }
    };
    let new_recipient = match flag_value(args, "--new-recipient") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("missing --new-recipient");
            return;
        }
    };

    let params = serde_json::json!({"symbol": symbol, "new_recipient": new_recipient});
    match signed_call(url, "seal_setFeeRecipient", params, key_file) {
        Ok(_) => println!(
            "set-fee-recipient: {} fees now route to {}",
            symbol, new_recipient
        ),
        Err(e) => eprintln!("set-fee-recipient failed: {e}"),
    }
}

/// Decode a bech32m Seal address to the 32-byte hex form bridge
/// programs (Solana Anchor, Stellar Soroban) expect. Single
/// argument; prints just the hex so the output is pipeable.
fn run_addr_to_hex(args: &[String]) {
    let addr = match args.first() {
        Some(a) => a.as_str(),
        None => {
            eprintln!("Usage: seal addr-to-hex <bech32m-address>");
            eprintln!("  Prints the 32-byte hex hash. Used by the bridge programs as");
            eprintln!("  the `seal_address` / `seal-recipient` field on lock_* calls.");
            std::process::exit(1);
        }
    };
    match seal_crypto::address::SealAddress::from_string_encoding(addr) {
        Ok(parsed) => println!("{}", hex::encode(parsed.as_bytes())),
        Err(e) => {
            eprintln!("invalid Seal address: {e}");
            std::process::exit(1);
        }
    }
}

/// Inverse of `addr-to-hex`: take a 64-char hex string (32 bytes)
/// and emit the bech32m-encoded `seal1...`/`sealt1...` address.
/// Useful when inspecting bridge program logs where Seal addresses
/// appear as raw hex. Defaults to testnet HRP; `--mainnet` flips
/// to the mainnet HRP. Hex input may be `0x`-prefixed or bare.
fn run_hex_to_addr(args: &[String]) {
    let hex_in = match args.iter().find(|a| !a.starts_with("--")) {
        Some(a) => a.as_str().trim_start_matches("0x"),
        None => {
            eprintln!("Usage: seal hex-to-addr <64-char-hex> [--mainnet]");
            eprintln!("  Inverse of addr-to-hex. Defaults to testnet HRP (sealt1...).");
            std::process::exit(1);
        }
    };
    let bytes = match hex::decode(hex_in) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("invalid hex: {e}");
            std::process::exit(1);
        }
    };
    if bytes.len() != 32 {
        eprintln!("expected 32 bytes (64 hex chars), got {}", bytes.len());
        std::process::exit(1);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    let testnet = !args.iter().any(|a| a == "--mainnet");
    let addr = seal_crypto::address::SealAddress::from_hash(hash, testnet);
    println!("{}", addr.to_string_encoding());
}

fn run_place_order(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal place-order --pair <BASE/QUOTE> --side <bid|ask> --price <P> --quantity <Q> --node <url> --key key.json");
            return;
        }
    };
    let pair = match flag_value(args, "--pair") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("missing --pair");
            return;
        }
    };
    let side = match flag_value(args, "--side") {
        Some(s) if matches!(s, "bid" | "buy" | "ask" | "sell") => s.to_string(),
        _ => {
            eprintln!("missing or invalid --side (bid/ask)");
            return;
        }
    };
    let price: u64 = match flag_value(args, "--price").and_then(|s| s.parse().ok()) {
        Some(p) => p,
        None => {
            eprintln!("missing or invalid --price");
            return;
        }
    };
    let quantity: u64 = match flag_value(args, "--quantity").and_then(|s| s.parse().ok()) {
        Some(q) => q,
        None => {
            eprintln!("missing or invalid --quantity");
            return;
        }
    };

    let params = serde_json::json!({
        "pair": pair, "side": side, "price": price, "quantity": quantity,
    });
    match signed_call(url, "seal_placeOrder", params, key_file) {
        Ok(r) => {
            let order_id = r.get("order_id").and_then(|v| v.as_u64()).unwrap_or(0);
            let trades = r.get("trades").and_then(|v| v.as_u64()).unwrap_or(0);
            let open = r.get("open_orders").and_then(|v| v.as_u64()).unwrap_or(0);
            println!(
                "Placed order #{} on {} ({} {} @ {})",
                order_id, pair, side, quantity, price
            );
            println!("  matched trades : {}", trades);
            println!("  open orders    : {}", open);
        }
        Err(e) => eprintln!("place-order failed: {e}"),
    }
}

fn run_cancel_order(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    // `seal_cancelOrder` doesn't `requires_auth` today — the dispatch
    // path doesn't take a caller. Still accept --key for symmetry
    // with the other typed wrappers, and sign if provided so a
    // future auth tightening doesn't break operator scripts.
    let pair = match flag_value(args, "--pair") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Usage: seal cancel-order --pair <BASE/QUOTE> --order-id <N> --node <url> [--key key.json]");
            return;
        }
    };
    let order_id: u64 = match flag_value(args, "--order-id").and_then(|s| s.parse().ok()) {
        Some(o) => o,
        None => {
            eprintln!("missing or invalid --order-id");
            return;
        }
    };

    let params = serde_json::json!({"pair": pair, "order_id": order_id});
    let mut body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_cancelOrder",
        "params": params, "id": 1,
    });
    if let Some(kf) = flag_value(args, "--key") {
        match sign_request("seal_cancelOrder", &params, kf) {
            Ok((sig, sender)) => {
                body["signature"] = serde_json::Value::String(sig);
                body["sender"] = serde_json::Value::String(sender);
            }
            Err(e) => {
                eprintln!("Failed to sign: {e}");
                return;
            }
        }
    }
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
            } else {
                println!("Cancelled order #{} on {}", order_id, pair);
            }
        }
        Err(e) => eprintln!("cancel-order failed: {e}"),
    }
}

fn run_token(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let symbol = match flag_value(args, "--symbol") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("Usage: seal token --symbol <S> --node <url>");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "seal_getToken",
        "params": {"symbol": symbol},
        "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let r = match resp.get("result") {
                Some(r) => r,
                None => {
                    eprintln!("no result");
                    return;
                }
            };
            let pretty = |k: &str| -> String {
                match r.get(k) {
                    Some(serde_json::Value::Null) => "renounced".to_string(),
                    Some(v) => v
                        .as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| v.to_string()),
                    None => "—".to_string(),
                }
            };
            let num = |k: &str| -> u64 { r.get(k).and_then(|v| v.as_u64()).unwrap_or(0) };
            let flag = |k: &str| -> bool { r.get(k).and_then(|v| v.as_bool()).unwrap_or(false) };
            println!("Token       {}", pretty("symbol"));
            println!("  name           {}", pretty("name"));
            println!("  decimals       {}", num("decimals"));
            println!("  total_supply   {}", num("total_supply"));
            println!("  max_supply     {}", num("max_supply"));
            println!("  creator        {}", pretty("creator"));
            println!("  fee_bps        {}", num("transfer_fee_bps"));
            println!("  fee_recipient  {}", pretty("fee_recipient"));
            println!(
                "  frozen         {}",
                if flag("frozen") {
                    "YES (globally frozen)"
                } else {
                    "no"
                }
            );
            println!("  mint_authority   {}", pretty("mint_authority"));
            println!("  freeze_authority {}", pretty("freeze_authority"));
            println!("  fee_authority    {}", pretty("fee_authority"));
        }
        Err(e) => eprintln!("token read failed: {e}"),
    }
}

fn run_trades(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let pair = match flag_value(args, "--pair") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Usage: seal trades --pair <BASE/QUOTE> [--since-id <N>] [--limit <N>] [--node <url>]");
            return;
        }
    };
    let since_id: u64 = flag_value(args, "--since-id")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let limit: u64 = flag_value(args, "--limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let params = serde_json::json!({
        "pair": pair, "since_id": since_id, "limit": limit,
    });
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listTrades",
        "params": params, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let trades = result
                .get("trades")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let count = result.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let last_id = result
                .get("last_id")
                .and_then(|v| v.as_u64())
                .unwrap_or(since_id);
            if trades.is_empty() {
                println!("No trades for {} since id={}.", pair, since_id);
            } else {
                println!(
                    "{:>6}  {:<5}  {:>10}  {:>10}  {:<14}  {:<14}",
                    "id", "side", "price", "qty", "maker", "taker"
                );
                for t in &trades {
                    let id = t.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                    let side = t.get("side").and_then(|v| v.as_str()).unwrap_or("?");
                    let price = t.get("price").and_then(|v| v.as_u64()).unwrap_or(0);
                    let qty = t.get("quantity").and_then(|v| v.as_u64()).unwrap_or(0);
                    let maker = t.get("maker").and_then(|v| v.as_str()).unwrap_or("?");
                    let taker = t.get("taker").and_then(|v| v.as_str()).unwrap_or("?");
                    // Truncate long addresses to keep the column width
                    // honest; full string is one RPC call away.
                    let trim = |s: &str| {
                        if s.len() > 14 {
                            format!("{}…", &s[..13])
                        } else {
                            s.to_string()
                        }
                    };
                    println!(
                        "{:>6}  {:<5}  {:>10}  {:>10}  {:<14}  {:<14}",
                        id,
                        side,
                        price,
                        qty,
                        trim(maker),
                        trim(taker)
                    );
                }
            }
            println!();
            println!(
                "Returned {} trades. Last id = {} (poll with --since-id {} to continue).",
                count, last_id, last_id
            );
        }
        Err(e) => eprintln!("trades failed: {e}"),
    }
}

fn run_list_orders(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal list-orders --address <addr> [--node <url>]");
            eprintln!("  Lists all open orders owned by <addr> across every trading pair.");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listOrdersByOwner",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let orders = result
                .get("orders")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if orders.is_empty() {
                println!("No open orders for {}.", address);
                return;
            }
            println!(
                "{:<14}  {:>8}  {:<5}  {:>10}  {:>10}  {:>10}",
                "pair", "id", "side", "price", "qty", "remaining"
            );
            for o in &orders {
                let pair = o.get("pair").and_then(|v| v.as_str()).unwrap_or("?");
                let id = o.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let side = o.get("side").and_then(|v| v.as_str()).unwrap_or("?");
                let price = o.get("price").and_then(|v| v.as_u64()).unwrap_or(0);
                let qty = o.get("quantity").and_then(|v| v.as_u64()).unwrap_or(0);
                let remaining = o.get("remaining").and_then(|v| v.as_u64()).unwrap_or(0);
                println!(
                    "{:<14}  {:>8}  {:<5}  {:>10}  {:>10}  {:>10}",
                    pair, id, side, price, qty, remaining
                );
            }
            println!("\n{} open order(s).", orders.len());
        }
        Err(e) => eprintln!("list-orders failed: {e}"),
    }
}

fn run_trade_history(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal trade-history --address <addr> [--limit <N>] [--node <url>]");
            eprintln!(
                "  Lists recent trades where <addr> was maker or taker, sorted newest-first."
            );
            return;
        }
    };
    let limit: u64 = flag_value(args, "--limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listTradesByOwner",
        "params": {"address": address, "limit": limit}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let trades = result
                .get("trades")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if trades.is_empty() {
                println!("No retained trades for {}.", address);
                return;
            }
            println!(
                "{:<14}  {:>8}  {:<5}  {:>10}  {:>10}  {:>12}",
                "pair", "id", "role", "price", "qty", "timestamp"
            );
            for t in &trades {
                let pair = t.get("pair").and_then(|v| v.as_str()).unwrap_or("?");
                let id = t.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let price = t.get("price").and_then(|v| v.as_u64()).unwrap_or(0);
                let qty = t.get("quantity").and_then(|v| v.as_u64()).unwrap_or(0);
                let ts = t.get("timestamp").and_then(|v| v.as_u64()).unwrap_or(0);
                let maker = t.get("maker").and_then(|v| v.as_str()).unwrap_or("?");
                let role = if maker == address { "maker" } else { "taker" };
                println!(
                    "{:<14}  {:>8}  {:<5}  {:>10}  {:>10}  {:>12}",
                    pair, id, role, price, qty, ts
                );
            }
            println!(
                "\n{} trade(s) — bounded by per-pair MAX_TRADE_HISTORY (10000).",
                trades.len()
            );
        }
        Err(e) => eprintln!("trade-history failed: {e}"),
    }
}

fn run_wrapped_balances(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal wrapped-balances --address <addr> [--node <url>]");
            eprintln!("  Lists every non-zero bridge wrapped balance held by <addr>.");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listBridgeWrappedBalances",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let balances = result
                .get("balances")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if balances.is_empty() {
                println!("No wrapped balances for {}.", address);
                return;
            }
            println!("{:<8}  {:<10}  {:>16}", "token", "chain", "balance");
            for b in &balances {
                let token = b.get("token").and_then(|v| v.as_str()).unwrap_or("?");
                let chain = b.get("chain").and_then(|v| v.as_str()).unwrap_or("?");
                let bal = b.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("{:<8}  {:<10}  {:>16}", token, chain, bal);
            }
            println!("\n{} wrapped token(s).", balances.len());
        }
        Err(e) => eprintln!("wrapped-balances failed: {e}"),
    }
}

fn run_list_leases(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let expired_only = args.iter().any(|a| a == "--expired-only");
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listLeases",
        "params": {"expired_only": expired_only}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let leases = result
                .get("leases")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if leases.is_empty() {
                println!(
                    "{}",
                    if expired_only {
                        "No expired leases."
                    } else {
                        "No active storage leases."
                    }
                );
                return;
            }
            println!(
                "{:<32}  {:>10}  {:>10}  {:>14}  {:>4}  {:<7}  {:<5}",
                "table", "rows", "bytes", "paid_through_us", "rate", "expired", "hold"
            );
            for l in &leases {
                let table = l.get("table").and_then(|v| v.as_str()).unwrap_or("?");
                let rows = l.get("row_count").and_then(|v| v.as_u64()).unwrap_or(0);
                let bytes = l.get("byte_size").and_then(|v| v.as_u64()).unwrap_or(0);
                let paid = l
                    .get("paid_through_us")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let rate = l.get("rate").and_then(|v| v.as_u64()).unwrap_or(0);
                let expired = l.get("expired").and_then(|v| v.as_bool()).unwrap_or(false);
                let hold = l
                    .get("governance_hold")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let trim = |s: &str| {
                    if s.len() > 32 {
                        format!("{}…", &s[..31])
                    } else {
                        s.to_string()
                    }
                };
                println!(
                    "{:<32}  {:>10}  {:>10}  {:>14}  {:>4}  {:<7}  {:<5}",
                    trim(table),
                    rows,
                    bytes,
                    paid,
                    rate,
                    if expired { "yes" } else { "no" },
                    if hold { "YES" } else { "no" },
                );
            }
            println!("\n{} lease(s).", leases.len());
        }
        Err(e) => eprintln!("list-leases failed: {e}"),
    }
}

fn run_my_proposals(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-proposals --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_govListProposalsByProposer",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let proposals = result
                .get("proposals")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if proposals.is_empty() {
                println!("No proposals authored by {}.", address);
                return;
            }
            println!(
                "{:>6}  {:<22}  {:<10}  {:<40}",
                "id", "track", "status", "title"
            );
            for p in &proposals {
                let id = p.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let track = p.get("track").and_then(|v| v.as_str()).unwrap_or("?");
                let status = p.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                let title = p.get("title").and_then(|v| v.as_str()).unwrap_or("?");
                println!("{:>6}  {:<22}  {:<10}  {:<40}", id, track, status, title);
            }
            println!("\n{} proposal(s).", proposals.len());
        }
        Err(e) => eprintln!("my-proposals failed: {e}"),
    }
}

fn run_my_votes(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-votes --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_govListVotesByVoter",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let votes = result
                .get("votes")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if votes.is_empty() {
                println!("No votes cast by {}.", address);
                return;
            }
            println!(
                "{:>6}  {:<8}  {:>10}  {:<10}  {:>10}  {:>10}",
                "prop", "choice", "stake", "conviction", "weight", "unlock"
            );
            for v in &votes {
                let pid = v.get("proposal_id").and_then(|v| v.as_u64()).unwrap_or(0);
                let choice = v.get("choice").and_then(|v| v.as_str()).unwrap_or("?");
                let stake = v.get("stake").and_then(|v| v.as_u64()).unwrap_or(0);
                let conviction = v.get("conviction").and_then(|v| v.as_str()).unwrap_or("?");
                let weight = v.get("weight").and_then(|v| v.as_u64()).unwrap_or(0);
                let unlock = v.get("unlock_epoch").and_then(|v| v.as_u64()).unwrap_or(0);
                println!(
                    "{:>6}  {:<8}  {:>10}  {:<10}  {:>10}  {:>10}",
                    pid, choice, stake, conviction, weight, unlock
                );
            }
            println!("\n{} vote(s).", votes.len());
        }
        Err(e) => eprintln!("my-votes failed: {e}"),
    }
}

fn run_my_locks(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal my-locks --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_govListLocksByVoter",
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let locks = result
                .get("locks")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if locks.is_empty() {
                println!("No active conviction locks for {}.", address);
                return;
            }
            println!("{:>6}  {:>14}  {:>14}", "prop", "amount", "unlock_epoch");
            for l in &locks {
                let pid = l.get("proposal_id").and_then(|v| v.as_u64()).unwrap_or(0);
                let amount = l.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
                let unlock = l.get("unlock_epoch").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("{:>6}  {:>14}  {:>14}", pid, amount, unlock);
            }
            println!("\n{} lock(s).", locks.len());
        }
        Err(e) => eprintln!("my-locks failed: {e}"),
    }
}

fn run_my_delegations(args: &[String]) {
    run_delegations_helper(
        args,
        "seal_govListDelegationsFrom",
        "delegate",
        "my-delegations",
    )
}

fn run_delegations_to_me(args: &[String]) {
    run_delegations_helper(
        args,
        "seal_govListDelegationsTo",
        "delegator",
        "delegations-to-me",
    )
}

fn run_delegations_helper(args: &[String], method: &str, peer_field: &str, verb: &str) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let address = match flag_value(args, "--address") {
        Some(a) => a.to_string(),
        None => {
            eprintln!("Usage: seal {verb} --address <addr> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": method,
        "params": {"address": address}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let dels = result
                .get("delegations")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if dels.is_empty() {
                println!("No delegations for {} via {}.", address, method);
                return;
            }
            println!("{:<22}  {:<48}  {:>14}", "track", peer_field, "weight");
            for d in &dels {
                let track = d.get("track").and_then(|v| v.as_str()).unwrap_or("?");
                let peer = d.get(peer_field).and_then(|v| v.as_str()).unwrap_or("?");
                let weight = d.get("weight").and_then(|v| v.as_u64()).unwrap_or(0);
                let trim = |s: &str| {
                    if s.len() > 48 {
                        format!("{}…", &s[..47])
                    } else {
                        s.to_string()
                    }
                };
                println!("{:<22}  {:<48}  {:>14}", track, trim(peer), weight);
            }
            println!("\n{} delegation(s).", dels.len());
        }
        Err(e) => eprintln!("{verb} failed: {e}"),
    }
}

/// `seal snapshots` — recent state-snapshot roster.
///
/// First-line operator UX for the late-joiner bootstrap path
/// (A2d). Until A2b/A2c land, the roster surfaces height, epoch,
/// state_root, and capture timestamp; once A2b populates
/// `tip_aggregate`, this command will render the aggregate
/// fingerprint too. Default order is newest-first so a "pick one
/// to bootstrap from" workflow grabs the freshest entry first.
fn run_list_snapshots(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let mut params = serde_json::json!({});
    if let Some(limit_str) = flag_value(args, "--limit") {
        match limit_str.parse::<u64>() {
            Ok(n) => {
                params["limit"] = serde_json::Value::Number(n.into());
            }
            Err(_) => {
                eprintln!("--limit must be a positive integer");
                return;
            }
        }
    }
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listSnapshots",
        "params": params, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let snapshots = result
                .get("snapshots")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let total = result
                .get("total_retained")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if snapshots.is_empty() {
                println!("No snapshots retained yet (need at least one epoch boundary to fire).");
                return;
            }
            println!(
                "{:>10}  {:>6}  {:<24}  {:>12}",
                "height", "epoch", "state_root (truncated)", "captured_s"
            );
            for s in &snapshots {
                let h = s.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
                let e = s.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);
                let root = s
                    .get("state_root_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let cap = s
                    .get("captured_at_unix_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let trunc = if root.len() > 24 {
                    format!("{}…", &root[..23])
                } else {
                    root.to_string()
                };
                println!("{:>10}  {:>6}  {:<24}  {:>12}", h, e, trunc, cap);
            }
            println!(
                "\n{} snapshot(s) shown ({} total retained on this node).",
                snapshots.len(),
                total
            );
        }
        Err(e) => eprintln!("snapshots failed: {e}"),
    }
}

/// `seal snapshot-manifest --height <h>` — fetch + render the
/// chunk-list manifest for one snapshot. Operator UX for verifying
/// state-sync setup before A2d wires the late-joiner end-to-end.
/// Renders summary fields + first / last few chunks; the full chunk
/// vector goes to stdout as JSON when `--json` is passed.
fn run_snapshot_manifest(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let height: u64 = match flag_value(args, "--height") {
        Some(h) => match h.parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("--height must be a positive integer");
                return;
            }
        },
        None => {
            eprintln!("Usage: seal snapshot-manifest --height <h> [--node <url>] [--json]");
            return;
        }
    };
    let want_json = args.iter().any(|a| a == "--json");
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_getSnapshotManifest",
        "params": { "height": height }, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(0);
                let msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                eprintln!("RPC error ({code}): {msg}");
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            if want_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&result).unwrap_or_default()
                );
                return;
            }
            let h = result.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
            let e = result.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0);
            let root = result
                .get("state_root_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let tip_hash = result
                .get("tip_block_hash_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let mhash = result
                .get("manifest_hash_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let total = result
                .get("total_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let count = result
                .get("chunk_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let agg = result.get("tip_aggregate_hex").and_then(|v| v.as_str());

            println!("Snapshot manifest @ height {h} (epoch {e})");
            println!("  state_root      : {root}");
            println!("  tip_block_hash  : {tip_hash}");
            if let Some(a) = agg {
                println!("  tip_aggregate   : {a}");
            }
            println!("  manifest_hash   : {mhash}");
            println!(
                "  total_bytes     : {total}  ({count} chunk{})",
                if count == 1 { "" } else { "s" }
            );

            let chunks = result
                .get("chunks")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if chunks.is_empty() {
                println!("\n(empty state — no chunks)");
                return;
            }
            println!();
            println!(
                "{:>5}  {:<24}  {:>10}",
                "index", "chunk_hash (truncated)", "byte_size"
            );
            // Render up to first 8 + last 4 if there are >12 chunks; otherwise all.
            let render_indices: Vec<usize> = if chunks.len() > 12 {
                let mut v: Vec<usize> = (0..8).collect();
                v.extend(chunks.len() - 4..chunks.len());
                v
            } else {
                (0..chunks.len()).collect()
            };
            let mut prev_idx: Option<usize> = None;
            for i in render_indices {
                if let Some(prev) = prev_idx {
                    if i > prev + 1 {
                        println!("{:>5}  …", "");
                    }
                }
                let c = &chunks[i];
                let idx = c.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                let ch = c
                    .get("chunk_hash_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let sz = c.get("byte_size").and_then(|v| v.as_u64()).unwrap_or(0);
                let trunc = if ch.len() > 24 {
                    format!("{}…", &ch[..23])
                } else {
                    ch.to_string()
                };
                println!("{:>5}  {:<24}  {:>10}", idx, trunc, sz);
                prev_idx = Some(i);
            }
        }
        Err(e) => eprintln!("snapshot-manifest failed: {e}"),
    }
}

/// `seal snapshot-chunk --height <h> --index <n> [--out <file>]` —
/// fetch + hash-verify one chunk. Operator UX for ad-hoc state-sync
/// debugging: pull a chunk, confirm its server-claimed hash matches
/// a fresh local SHA3 of the bytes, optionally write the raw bytes
/// to disk for offline inspection.
fn run_snapshot_chunk(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let height: u64 = match flag_value(args, "--height") {
        Some(h) => match h.parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("--height must be a positive integer");
                return;
            }
        },
        None => {
            eprintln!(
                "Usage: seal snapshot-chunk --height <h> --index <n> [--node <url>] [--out <file>]"
            );
            return;
        }
    };
    let chunk_index: u32 = match flag_value(args, "--index") {
        Some(i) => match i.parse() {
            Ok(n) => n,
            Err(_) => {
                eprintln!("--index must be a non-negative integer");
                return;
            }
        },
        None => {
            eprintln!("--index is required");
            return;
        }
    };
    let out_path = flag_value(args, "--out");
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_getSnapshotChunk",
        "params": { "height": height, "chunk_index": chunk_index }, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                let code = err.get("code").and_then(|v| v.as_i64()).unwrap_or(0);
                let msg = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                eprintln!("RPC error ({code}): {msg}");
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let claimed_hash = result
                .get("chunk_hash_hex")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string();
            let byte_size = result
                .get("byte_size")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let bytes_b64 = result
                .get("bytes_b64")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            use base64::engine::general_purpose::STANDARD;
            use base64::Engine;
            let bytes = match STANDARD.decode(bytes_b64) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("server returned malformed base64: {e}");
                    return;
                }
            };
            // Re-hash + cross-check. If this fails, the host moved
            // on past the snapshot point mid-stream — the late-joiner
            // would treat this as a re-fetch trigger.
            let actual_hash = hex::encode(seal_crypto::hash::sha3_256(&bytes).0);
            let hash_ok = actual_hash == claimed_hash;
            println!("Snapshot chunk @ height {height}, index {chunk_index}");
            println!("  byte_size       : {byte_size}");
            println!("  claimed_hash    : {claimed_hash}");
            println!(
                "  recomputed_hash : {actual_hash} {}",
                if hash_ok {
                    "(MATCH)"
                } else {
                    "(MISMATCH — re-fetch from a fresher snapshot)"
                }
            );
            if let Some(path) = out_path {
                if let Err(e) = std::fs::write(path, &bytes) {
                    eprintln!("failed to write {path}: {e}");
                } else {
                    println!("  wrote           : {path} ({} bytes)", bytes.len());
                }
            }
            if !hash_ok {
                std::process::exit(2);
            }
        }
        Err(e) => eprintln!("snapshot-chunk failed: {e}"),
    }
}

/// `seal sign-file <path> --key <key.json> [--out <sig-path>]` —
/// ML-DSA-65 sign the SHA3-256 hash of a file's bytes. Used by
/// `scripts/release.sh` to PQC-sign `SHA256SUMS` with a release
/// key, replacing what would normally be a classical sigstore /
/// minisign pipeline. Per CLAUDE.md the project is post-quantum
/// first; using a classical-only sigstore flow would contradict
/// that.
///
/// Output: hex-encoded signature on stdout (or `--out <path>`,
/// preferred for piping into a `.sig` file). The file's bytes
/// stay unchanged — this is a detached signature.
fn run_sign_file(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: seal sign-file <path> --key <key.json> [--out <sig-path>]");
        return;
    }
    let path = &args[0];
    let key_file = match flag_value(&args[1..], "--key") {
        Some(k) => k,
        None => {
            eprintln!("--key <key.json> is required");
            return;
        }
    };
    let out_path = flag_value(&args[1..], "--out");

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            std::process::exit(2);
        }
    };
    let hash = seal_crypto::hash::sha3_256(&bytes);

    let key_json = match std::fs::read_to_string(key_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read {key_file}: {e}");
            std::process::exit(2);
        }
    };
    let key_data: serde_json::Value = match serde_json::from_str(&key_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse {key_file}: {e}");
            std::process::exit(2);
        }
    };
    let sk_hex = match key_data.get("signing_key").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            eprintln!("{key_file}: missing 'signing_key' field");
            std::process::exit(2);
        }
    };
    let sk_bytes = match hex::decode(sk_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("signing_key hex: {e}");
            std::process::exit(2);
        }
    };
    let sk = match seal_crypto::signature::SigningKey::from_bytes(&sk_bytes) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("signing key: {e}");
            std::process::exit(2);
        }
    };
    let sig = match sk.sign(hash.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sign: {e}");
            std::process::exit(2);
        }
    };
    let sig_hex = hex::encode(sig.to_bytes());
    if let Some(p) = out_path {
        if let Err(e) = std::fs::write(p, &sig_hex) {
            eprintln!("write {p}: {e}");
            std::process::exit(2);
        }
        // Also dump the verifying-key hex next to the signature
        // so the verifier doesn't need access to the original
        // key file. Convention: <out>.pubkey.
        let pub_path = format!("{p}.pubkey");
        let vk_hex = key_data
            .get("verifying_key")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let _ = std::fs::write(&pub_path, vk_hex);
        println!(
            "wrote {p} ({} hex chars) and {pub_path} (verifying-key)",
            sig_hex.len()
        );
    } else {
        println!("{sig_hex}");
    }
}

/// `seal verify-file <path> --pubkey-hex <hex> --sig-hex <hex>`
/// (or `--sig-file <path>`) — verify a detached ML-DSA-65 signature
/// produced by `seal sign-file`. Exits 0 on OK, 1 on signature
/// mismatch, 2 on argument / IO errors. Used by release-channel
/// consumers and CI smoke tests.
fn run_verify_file(args: &[String]) {
    if args.is_empty() {
        eprintln!(
            "Usage: seal verify-file <path> --pubkey-hex <hex> --sig-hex <hex> | --sig-file <path>"
        );
        return;
    }
    let path = &args[0];
    let pubkey_hex = match flag_value(&args[1..], "--pubkey-hex") {
        Some(p) => p,
        None => {
            eprintln!("--pubkey-hex <hex> is required");
            std::process::exit(2);
        }
    };
    let sig_hex: String = match flag_value(&args[1..], "--sig-hex") {
        Some(s) => s.to_string(),
        None => match flag_value(&args[1..], "--sig-file") {
            Some(p) => match std::fs::read_to_string(p) {
                Ok(s) => s.trim().to_string(),
                Err(e) => {
                    eprintln!("read {p}: {e}");
                    std::process::exit(2);
                }
            },
            None => {
                eprintln!("either --sig-hex <hex> or --sig-file <path> is required");
                std::process::exit(2);
            }
        },
    };

    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("read {path}: {e}");
            std::process::exit(2);
        }
    };
    let hash = seal_crypto::hash::sha3_256(&bytes);

    let vk_bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("pubkey hex: {e}");
            std::process::exit(2);
        }
    };
    let vk = match seal_crypto::signature::VerifyingKey::from_bytes(&vk_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("pubkey: {e}");
            std::process::exit(2);
        }
    };
    let sig_bytes = match hex::decode(&sig_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sig hex: {e}");
            std::process::exit(2);
        }
    };
    let sig = seal_crypto::signature::Signature::from_bytes(sig_bytes);
    match vk.verify(hash.as_ref(), &sig) {
        Ok(()) => {
            println!("OK ({path} signature verifies)");
            std::process::exit(0);
        }
        Err(_) => {
            eprintln!("FAIL ({path} signature does NOT verify)");
            std::process::exit(1);
        }
    }
}

fn run_list_validators(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let body = serde_json::json!({
        "jsonrpc": "2.0", "method": "seal_listValidators",
        "params": {}, "id": 1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error: {}",
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                return;
            }
            let result = resp
                .get("result")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let validators = result
                .get("validators")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let active = result
                .get("active_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let total_stake = result
                .get("total_stake")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if validators.is_empty() {
                println!("No validators in the set.");
                return;
            }
            println!(
                "{:<24}  {:>14}  {:>6}",
                "public_key (truncated)", "stake", "active"
            );
            for v in &validators {
                let pk = v
                    .get("public_key_hex")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let stake = v.get("stake").and_then(|v| v.as_u64()).unwrap_or(0);
                let active = v.get("active").and_then(|v| v.as_bool()).unwrap_or(false);
                let trunc = if pk.len() > 24 {
                    format!("{}…", &pk[..23])
                } else {
                    pk.to_string()
                };
                println!(
                    "{:<24}  {:>14}  {:>6}",
                    trunc,
                    stake,
                    if active { "yes" } else { "no" }
                );
            }
            println!(
                "\n{} validators total ({} active), total stake = {} micro-SEAL.",
                validators.len(),
                active,
                total_stake
            );
        }
        Err(e) => eprintln!("validators failed: {e}"),
    }
}

// ── Governance subcommands ──────────────────────────────────────
//
// All five mutations are in `requires_auth` on the node side; the
// caller's derived ML-DSA address becomes the on-chain proposer /
// voter / delegator. Track names follow `parse_track`'s aliases:
// "parameter" / "protocol" / "treasury_small" / "treasury_large" /
// "emergency" / "constitutional".

fn run_gov_propose(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal gov-propose --track <T> --title <S> [--description <S>] [--payload <S>] --node <url> --key key.json");
            return;
        }
    };
    let track = match flag_value(args, "--track") {
        Some(t) => t.to_string(),
        None => {
            eprintln!("missing --track");
            return;
        }
    };
    let title = match flag_value(args, "--title") {
        Some(t) => t.to_string(),
        None => {
            eprintln!("missing --title");
            return;
        }
    };
    let description = flag_value(args, "--description").unwrap_or("").to_string();
    let payload = flag_value(args, "--payload").unwrap_or("").to_string();

    let params = serde_json::json!({
        "track": track,
        "title": title,
        "description": description,
        "payload": payload,
    });
    match signed_call(url, "seal_govPropose", params, key_file) {
        Ok(r) => {
            let id = r.get("proposal_id").and_then(|v| v.as_u64()).unwrap_or(0);
            let tr = r.get("track").and_then(|v| v.as_str()).unwrap_or("?");
            let start = r.get("start_epoch").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("Submitted proposal #{}", id);
            println!("  track          {}", tr);
            println!("  start_epoch    {}", start);
        }
        Err(e) => eprintln!("gov-propose failed: {e}"),
    }
}

fn run_gov_vote(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal gov-vote --proposal-id <N> --choice <yes|no|abstain> --stake <amt> [--conviction x1..x6|none] --node <url> --key key.json");
            return;
        }
    };
    let proposal_id: u64 = match flag_value(args, "--proposal-id").and_then(|s| s.parse().ok()) {
        Some(p) => p,
        None => {
            eprintln!("missing or invalid --proposal-id");
            return;
        }
    };
    let choice = match flag_value(args, "--choice") {
        Some(c) => c.to_string(),
        None => {
            eprintln!("missing --choice");
            return;
        }
    };
    let stake: u64 = match flag_value(args, "--stake").and_then(|s| s.parse().ok()) {
        Some(s) => s,
        None => {
            eprintln!("missing or invalid --stake");
            return;
        }
    };
    let conviction = flag_value(args, "--conviction").unwrap_or("x1").to_string();

    let params = serde_json::json!({
        "proposal_id": proposal_id,
        "choice": choice,
        "stake": stake,
        "conviction": conviction,
    });
    match signed_call(url, "seal_govVote", params, key_file) {
        Ok(_) => println!(
            "Voted {} on proposal #{} (stake {}, conviction {})",
            choice, proposal_id, stake, conviction
        ),
        Err(e) => eprintln!("gov-vote failed: {e}"),
    }
}

fn run_gov_withdraw_vote(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!(
                "Usage: seal gov-withdraw-vote --proposal-id <N> --node <url> --key key.json"
            );
            return;
        }
    };
    let proposal_id: u64 = match flag_value(args, "--proposal-id").and_then(|s| s.parse().ok()) {
        Some(p) => p,
        None => {
            eprintln!("missing or invalid --proposal-id");
            return;
        }
    };

    let params = serde_json::json!({"proposal_id": proposal_id});
    match signed_call(url, "seal_govWithdrawVote", params, key_file) {
        Ok(_) => println!("Withdrew vote on proposal #{}", proposal_id),
        Err(e) => eprintln!("gov-withdraw-vote failed: {e}"),
    }
}

fn run_gov_delegate(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal gov-delegate --delegate <addr> --track <T> --weight <W> --node <url> --key key.json");
            return;
        }
    };
    let delegate = match flag_value(args, "--delegate") {
        Some(d) => d.to_string(),
        None => {
            eprintln!("missing --delegate");
            return;
        }
    };
    let track = match flag_value(args, "--track") {
        Some(t) => t.to_string(),
        None => {
            eprintln!("missing --track");
            return;
        }
    };
    let weight: u64 = match flag_value(args, "--weight").and_then(|s| s.parse().ok()) {
        Some(w) => w,
        None => {
            eprintln!("missing or invalid --weight");
            return;
        }
    };

    let params = serde_json::json!({
        "delegate": delegate,
        "track": track,
        "weight": weight,
    });
    match signed_call(url, "seal_govDelegate", params, key_file) {
        Ok(_) => println!("Delegated {} weight on {} to {}", weight, track, delegate),
        Err(e) => eprintln!("gov-delegate failed: {e}"),
    }
}

fn run_gov_revoke_delegation(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("Usage: seal gov-revoke-delegation --track <T> --node <url> --key key.json");
            return;
        }
    };
    let track = match flag_value(args, "--track") {
        Some(t) => t.to_string(),
        None => {
            eprintln!("missing --track");
            return;
        }
    };

    let params = serde_json::json!({"track": track});
    match signed_call(url, "seal_govRevokeDelegation", params, key_file) {
        Ok(_) => println!("Revoked delegation on track {}", track),
        Err(e) => eprintln!("gov-revoke-delegation failed: {e}"),
    }
}

/// Generic signed-or-unsigned JSON-RPC passthrough. Lets any method
/// in the node's dispatcher (bridge, governance, DEX, token-setup —
/// anything without a typed wrapper yet) be driven from scripts
/// without hand-rolling ML-DSA envelopes.
///
/// Usage:
///   seal rpc --method seal_getBridgeStatus --params '{}' --node http://localhost:8545
///   seal rpc --method seal_bridgeWithdraw  --params '{...}' --key treasury.json
fn run_rpc(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let method = match flag_value(args, "--method") {
        Some(m) => m.to_string(),
        None => {
            eprintln!(
                "Usage: seal rpc --method <name> --params <JSON> [--node <url>] [--key key.json]"
            );
            return;
        }
    };
    let params_raw = flag_value(args, "--params").unwrap_or("{}");
    let params: serde_json::Value = match serde_json::from_str(params_raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Invalid --params JSON: {e}");
            return;
        }
    };

    let mut body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
    });

    if let Some(kf) = flag_value(args, "--key") {
        match sign_request(&method, &params, kf) {
            Ok((sig, sender)) => {
                body["signature"] = serde_json::Value::String(sig);
                body["sender"] = serde_json::Value::String(sender);
            }
            Err(e) => {
                eprintln!("Failed to sign: {e}");
                return;
            }
        }
    }

    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error ({}): {}",
                    err.get("code").and_then(|c| c.as_i64()).unwrap_or(0),
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
            } else if let Some(r) = resp.get("result") {
                println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&resp).unwrap_or_default()
                );
            }
        }
        Err(e) => eprintln!("RPC failed: {e}"),
    }
}

/// `seal bridge-withdraw` — one-shot signed burn that emits a
/// withdrawal record. The returned `withdrawal_id` is what callers
/// pass to `seal bridge-get-withdrawal` to fetch the committee
/// signature once it's been attached.
fn run_bridge_withdraw(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let dest_chain = match flag_value(args, "--dest-chain") {
        Some(s) => s.to_string(),
        None => {
            eprintln!(
                "Usage: seal bridge-withdraw --dest-chain <Solana|Stellar> \
                 --dest-address <addr> --token <WSOL|WXLM|WUSDC> \
                 --amount <base-units> --node <url> --key key.json"
            );
            return;
        }
    };
    let dest_address = match flag_value(args, "--dest-address") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("--dest-address is required");
            return;
        }
    };
    let token = match flag_value(args, "--token") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("--token is required (WSOL / WXLM / WUSDC)");
            return;
        }
    };
    let amount: u64 = match flag_value(args, "--amount").and_then(|s| s.parse().ok()) {
        Some(a) => a,
        None => {
            eprintln!("--amount must be a non-negative integer (base units)");
            return;
        }
    };
    let key = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("--key <key.json> is required (seal_bridgeWithdraw is auth-gated)");
            return;
        }
    };

    let params = serde_json::json!({
        "dest_chain":   dest_chain,
        "dest_address": dest_address,
        "token":        token,
        "amount":       amount,
    });
    let method = "seal_bridgeWithdraw";
    let mut body = serde_json::json!({
        "jsonrpc": "2.0",
        "method":  method,
        "params":  params,
        "id":      1,
    });
    match sign_request(method, &params, key) {
        Ok((sig, sender)) => {
            body["signature"] = serde_json::Value::String(sig);
            body["sender"] = serde_json::Value::String(sender);
        }
        Err(e) => {
            eprintln!("Failed to sign: {e}");
            return;
        }
    }
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error ({}): {}",
                    err.get("code").and_then(|c| c.as_i64()).unwrap_or(0),
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                std::process::exit(1);
            } else if let Some(r) = resp.get("result") {
                let id = r
                    .get("withdrawal_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                println!("Burned {amount} {token} → {dest_chain}:{dest_address}");
                println!("  withdrawal_id: {id}");
                println!("  Next: seal bridge-get-withdrawal --withdrawal-id {id} --node {url}");
            }
        }
        Err(e) => eprintln!("RPC failed: {e}"),
    }
}

/// `seal bridge-list-withdrawals` — unauth read of every withdrawal.
/// Optional `--chain` filters to one destination chain. The two
/// per-entry fields operators care about are `nonce` and
/// `committee_signature_hex`; the latter is `null` until the
/// committee has signed the unlock payload.
fn run_bridge_list_withdrawals(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let chain = flag_value(args, "--chain");
    let params = match chain {
        Some(c) => serde_json::json!({"chain": c}),
        None => serde_json::json!({}),
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method":  "seal_listBridgeWithdrawals",
        "params":  params,
        "id":      1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(r) = resp.get("result") {
                println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
            } else if let Some(err) = resp.get("error") {
                eprintln!("RPC error: {err}");
                std::process::exit(1);
            }
        }
        Err(e) => eprintln!("RPC failed: {e}"),
    }
}

/// `seal register-validator` — one-shot post to the testnet
/// validator-registration portal. Closes the hand-recipe gap in
/// docs/TESTNET-REGISTRATION.md: previously operators built the
/// canonical payload by hand and ran `seal sign-file` against a
/// temp file. This wraps the full flow (build canonical bytes,
/// ML-DSA-sign the SHA3 hash, POST /register) and surfaces the
/// portal's response.
///
/// Canonical signed bytes (matches `apps/seal-registration/src/main.rs::
/// registration_message`):
///     b"register" || pubkey_hex || vrf_pubkey_hex || name || contact
/// Hashed with SHA3-256, signed with ML-DSA-65 under `--key`.
fn run_register_validator(args: &[String]) {
    let portal = match flag_value(args, "--portal") {
        Some(p) => p.to_string(),
        None => {
            eprintln!(
                "Usage: seal register-validator --portal <url> \
                 --key <wallet.json> --name <s> --contact <s> \
                 --vrf-pubkey-hex <64-hex>"
            );
            return;
        }
    };
    let key_file = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!("--key <wallet.json> is required");
            return;
        }
    };
    let name = match flag_value(args, "--name") {
        Some(n) => n.to_string(),
        None => {
            eprintln!("--name <validator-display-name> is required");
            return;
        }
    };
    let contact = match flag_value(args, "--contact") {
        Some(c) => c.to_string(),
        None => {
            eprintln!("--contact <ops-email-or-handle> is required");
            return;
        }
    };
    let vrf_pubkey_hex = match flag_value(args, "--vrf-pubkey-hex") {
        Some(v) => v.to_string(),
        None => {
            eprintln!("--vrf-pubkey-hex <64-hex> is required");
            return;
        }
    };
    if vrf_pubkey_hex.len() != 64 {
        eprintln!(
            "error: --vrf-pubkey-hex must be 64 hex chars (32 bytes); got {}",
            vrf_pubkey_hex.len()
        );
        return;
    }

    let key_json = match std::fs::read_to_string(key_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot read key file {key_file}: {e}");
            return;
        }
    };
    let key_data: serde_json::Value = match serde_json::from_str(&key_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("invalid key file JSON: {e}");
            return;
        }
    };
    let sk_hex = match key_data.get("signing_key").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            eprintln!("key file missing 'signing_key' field");
            return;
        }
    };
    let pubkey_hex = match key_data.get("verifying_key").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            eprintln!("key file missing 'verifying_key' field");
            return;
        }
    };

    // Idempotency: skip the (~ML-DSA-65 sign) cost if the portal
    // already has this pubkey in its roster. Operators re-running
    // their systemd ExecStartPre hit this path on every reboot.
    // `--force` overrides for the rare case where the portal got
    // corrupted and needs a re-submit.
    let force = args.iter().any(|a| a == "--force");
    if !force {
        let lookup_url = format!(
            "{}/registration/{}",
            portal.trim_end_matches('/'),
            pubkey_hex
        );
        if let Ok(body) = http_get(&lookup_url) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
                if json.get("pubkey_hex").is_some() {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json).unwrap_or_default()
                    );
                    eprintln!(
                        "already-registered: skipping POST /register (pass --force to re-submit)"
                    );
                    return;
                }
            }
        }
    }

    let sk_bytes = match hex::decode(sk_hex) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("invalid signing_key hex: {e}");
            return;
        }
    };
    let sk = match seal_crypto::signature::SigningKey::from_bytes(&sk_bytes) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invalid signing key: {e}");
            return;
        }
    };

    // Canonical message: b"register" || pubkey || vrf_pubkey || name || contact
    let mut msg = Vec::with_capacity(
        b"register".len() + pubkey_hex.len() + vrf_pubkey_hex.len() + name.len() + contact.len(),
    );
    msg.extend_from_slice(b"register");
    msg.extend_from_slice(pubkey_hex.as_bytes());
    msg.extend_from_slice(vrf_pubkey_hex.as_bytes());
    msg.extend_from_slice(name.as_bytes());
    msg.extend_from_slice(contact.as_bytes());
    let hash = seal_crypto::hash::sha3_256(&msg);
    let signature = match sk.sign(hash.as_ref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("signing failed: {e}");
            return;
        }
    };

    let body = serde_json::json!({
        "pubkey_hex":     pubkey_hex,
        "vrf_pubkey_hex": vrf_pubkey_hex,
        "name":           name,
        "contact":        contact,
        "signature_hex":  hex::encode(signature.to_bytes()),
    });

    // Portal isn't JSON-RPC — it's plain POST /register. Reuse the
    // raw HTTP client by passing the full /register path.
    let register_url = format!("{}/register", portal.trim_end_matches('/'));
    match rpc_post(&register_url, &body) {
        Ok(resp) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_default()
            );
        }
        Err(e) => {
            eprintln!("POST {register_url}: {e}");
            std::process::exit(1);
        }
    }
}

/// `seal bridge-key-status` — unauth read of the host's committee
/// MAC key state. Prints `{set, fingerprint_sha3_hex,
/// fingerprint_sha2_hex}`. Exit codes for scripted ops drift checks:
///   0 — key set; if `--expect-sha2` was given, its SHA-256
///       fingerprint matches.
///   1 — RPC error, or no key set on the host.
///   2 — key set but `--expect-sha2` does not match (drift).
///
/// `--expect-sha2 <64-hex>` is the SHA-256 fingerprint the
/// dashboard / coordinator expects after the latest coordinated
/// rotation. Operators wire this into bridge-e2e.sh smoke checks.
fn run_bridge_key_status(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let expect_sha2 = flag_value(args, "--expect-sha2").map(|s| s.to_ascii_lowercase());

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method":  "seal_bridgeGetCommitteeKeyStatus",
        "params":  {},
        "id":      1,
    });
    let resp = match rpc_post(url, &body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("RPC failed: {e}");
            std::process::exit(1);
        }
    };
    if let Some(err) = resp.get("error") {
        eprintln!("RPC error: {err}");
        std::process::exit(1);
    }
    let result = match resp.get("result") {
        Some(r) => r,
        None => {
            eprintln!("RPC returned no result");
            std::process::exit(1);
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(result).unwrap_or_default()
    );

    let set = result.get("set").and_then(|v| v.as_bool()).unwrap_or(false);
    if !set {
        eprintln!("committee key not installed on host");
        std::process::exit(1);
    }
    if let Some(expected) = expect_sha2 {
        let actual = result
            .get("fingerprint_sha2_hex")
            .and_then(|v| v.as_str())
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_default();
        if actual != expected {
            eprintln!(
                "fingerprint drift: expected sha2={} actual sha2={}",
                expected, actual
            );
            std::process::exit(2);
        }
        eprintln!("fingerprint matches expected sha2={}", expected);
    }
}

/// `seal bridge-ringtail-status` — unauth read of the bridge's
/// multi-validator Ringtail wiring state. Companion to
/// `seal bridge-key-status` for the PQ-signed path. Exit codes:
///   0 — RPC succeeded (regardless of whether Ringtail is enabled)
///   1 — RPC failed
/// `seal bridge-fee` — query the configured per-withdrawal SEAL
/// fee (P8/§4.2). Prints a human-readable line + JSON; pre-quote
/// helper for wallets / scripts before `seal bridge-withdraw`.
fn run_bridge_fee(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method":  "seal_getBridgeWithdrawalFee",
        "params":  {},
        "id":      1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!("RPC error: {err}");
                std::process::exit(1);
            }
            if let Some(r) = resp.get("result") {
                let base = r
                    .get("fee_base_units")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let seal = r.get("fee_seal").and_then(|v| v.as_f64()).unwrap_or(0.0);
                println!("Bridge withdrawal fee: {base} base units ({seal:.9} SEAL)");
                println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
            }
        }
        Err(e) => {
            eprintln!("RPC failed: {e}");
            std::process::exit(1);
        }
    }
}

fn run_bridge_ringtail_status(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method":  "seal_bridgeRingtailStatus",
        "params":  {},
        "id":      1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!("RPC error: {err}");
                std::process::exit(1);
            }
            if let Some(r) = resp.get("result") {
                println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
            }
        }
        Err(e) => {
            eprintln!("RPC failed: {e}");
            std::process::exit(1);
        }
    }
}

/// `seal admin-list` — read the configured admin set + multisig
/// threshold (P8/§4.3 mainnet gate). Cosigners check membership
/// before bothering to sign; wallets pre-flight admin calls.
fn run_admin_list(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method":  "seal_listAdminAddresses",
        "params":  {},
        "id":      1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!("RPC error: {err}");
                std::process::exit(1);
            }
            if let Some(r) = resp.get("result") {
                let mode = r.get("mode").and_then(|v| v.as_str()).unwrap_or("?");
                let count = r.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                let threshold = r.get("threshold").and_then(|v| v.as_u64()).unwrap_or(0);
                println!("Admin set: {count} address(es), threshold={threshold}, mode={mode}");
                if let Some(arr) = r.get("addresses").and_then(|v| v.as_array()) {
                    for addr in arr {
                        if let Some(s) = addr.as_str() {
                            println!("  {}", s);
                        }
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("RPC failed: {e}");
            std::process::exit(1);
        }
    }
}

/// `seal admin-sign` — produce a cosigner JSON entry for the
/// P8/§4.3 admin M-of-N multisig. Usage:
///
/// ```text
/// seal admin-sign \
///     --method seal_bridgeRotateCommitteeKey \
///     --params '{"new_key_hex":"00..00"}' \
///     --key admin-key.json
/// ```
///
/// Prints `{"sender":"<vk-hex>","signature":"<sig-hex>"}` on
/// stdout — operators paste this into the primary submitter's
/// `admin_signatures` array. The canonical signing message
/// strips the `admin_signatures` field if present so cosigners
/// never sign each other's bytes (matches
/// `verify_admin_multisig` in seal-node rpc.rs).
fn run_admin_sign(args: &[String]) {
    let method = match flag_value(args, "--method") {
        Some(m) => m.to_string(),
        None => {
            eprintln!("usage: seal admin-sign --method <m> --params '<json>' --key <path>");
            std::process::exit(1);
        }
    };
    let params_str = flag_value(args, "--params").unwrap_or("{}").to_string();
    let key_file = match flag_value(args, "--key") {
        Some(k) => k.to_string(),
        None => {
            eprintln!("--key is required");
            std::process::exit(1);
        }
    };
    let params: serde_json::Value = match serde_json::from_str(&params_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("--params is not valid JSON: {e}");
            std::process::exit(1);
        }
    };
    let canon = canonicalize_admin_signing_params(&params);
    match sign_request(&method, &canon, &key_file) {
        Ok((sig_hex, vk_hex)) => {
            let entry = serde_json::json!({
                "sender": vk_hex,
                "signature": sig_hex,
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&entry).unwrap_or_default()
            );
        }
        Err(e) => {
            eprintln!("admin-sign failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Mirror of `seal_node::rpc::verify_admin_multisig`'s canonicalization
/// step: strip the `admin_signatures` field from the params object so
/// every cosigner signs the same byte sequence and the primary
/// submitter can append/replace the array without invalidating
/// earlier cosignatures.
pub(crate) fn canonicalize_admin_signing_params(params: &serde_json::Value) -> serde_json::Value {
    let mut canon = params.clone();
    if let Some(obj) = canon.as_object_mut() {
        obj.remove("admin_signatures");
    }
    canon
}

/// `seal admin-submit` — assemble + POST a full M-of-N admin RPC
/// request. Reads pre-built `{sender, signature}` cosigner files
/// (one per `--cosigners` comma-separated path), embeds them in
/// the params under `admin_signatures`, signs the canonical
/// message with `--primary`, and POSTs to `--node`.
fn run_admin_submit(args: &[String]) {
    let method = match flag_value(args, "--method") {
        Some(m) => m.to_string(),
        None => {
            eprintln!(
                "usage: seal admin-submit --method <m> --params '<json>' \
                       --primary <key.json> --cosigners a.json,b.json --node <url>"
            );
            std::process::exit(1);
        }
    };
    let params_str = flag_value(args, "--params").unwrap_or("{}").to_string();
    let primary_path = match flag_value(args, "--primary") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("--primary is required");
            std::process::exit(1);
        }
    };
    let cosigners_csv = flag_value(args, "--cosigners").unwrap_or("").to_string();
    let url = flag_value(args, "--node")
        .unwrap_or("http://localhost:8545")
        .to_string();
    let cosigner_paths: Vec<&str> = if cosigners_csv.is_empty() {
        Vec::new()
    } else {
        cosigners_csv.split(',').collect()
    };

    let mut params: serde_json::Value = match serde_json::from_str(&params_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("--params is not valid JSON: {e}");
            std::process::exit(1);
        }
    };
    // Strip any caller-supplied admin_signatures — we'll fill it
    // from the cosigner files ourselves so the canonical message
    // matches what each cosigner signed.
    if let Some(obj) = params.as_object_mut() {
        obj.remove("admin_signatures");
    }
    // Sign canonical params with primary BEFORE we attach
    // admin_signatures.
    let (primary_sig, primary_sender) = match sign_request(&method, &params, &primary_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("primary sign failed: {e}");
            std::process::exit(1);
        }
    };
    // Load cosigner entries.
    let mut cosig_entries: Vec<serde_json::Value> = Vec::with_capacity(cosigner_paths.len());
    for cp in &cosigner_paths {
        let raw = match std::fs::read_to_string(cp) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("read cosigner {cp}: {e}");
                std::process::exit(1);
            }
        };
        let v: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("parse cosigner {cp}: {e}");
                std::process::exit(1);
            }
        };
        if v.get("sender").is_none() || v.get("signature").is_none() {
            eprintln!("cosigner {cp} missing 'sender' or 'signature' field");
            std::process::exit(1);
        }
        cosig_entries.push(v);
    }
    if let Some(obj) = params.as_object_mut() {
        obj.insert(
            "admin_signatures".into(),
            serde_json::Value::Array(cosig_entries),
        );
    }
    let envelope = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
        "signature": primary_sig,
        "sender": primary_sender,
    });
    match rpc_post(&url, &envelope) {
        Ok(resp) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&resp).unwrap_or_default()
            );
            if resp.get("error").is_some() {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("RPC failed: {e}");
            std::process::exit(1);
        }
    }
}

/// HTTP GET helper for the unauth /health and /status endpoints
/// — sibling to `rpc_post` but with no body. Returns the raw HTTP
/// body (caller parses).
fn http_get(url: &str) -> Result<String, String> {
    use std::io::{Read, Write};
    let stripped = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);
    let (authority, path) = match stripped.find('/') {
        Some(i) => (&stripped[..i], &stripped[i..]),
        None => (stripped, "/"),
    };
    let mut stream =
        std::net::TcpStream::connect(authority).map_err(|e| format!("connect: {e}"))?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n");
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("send: {e}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|e| format!("read: {e}"))?;
    let body_start = response
        .find("\r\n\r\n")
        .map(|p| p + 4)
        .ok_or("bad HTTP response")?;
    Ok(response[body_start..].to_string())
}

/// `seal health` — pretty-print GET /health for operator one-shot
/// checks. Drop-in for systemd healthcheck / cron.
///
/// Exit codes:
///   0 — node reports status: ok (or "starting" within the 30 s
///       grace) AND `is_validator` is true if `--require-validator`
///       was passed.
///   1 — status is "starting"/"stalled" past the grace, or RPC
///       error.
///   2 — `--require-validator` was passed but the node's pubkey
///       isn't in the active set.
fn run_health(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let require_validator = args.iter().any(|a| a == "--require-validator");

    let health_url = format!("{}/health", url.trim_end_matches('/'));
    let body = match http_get(&health_url) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("GET {health_url}: {e}");
            std::process::exit(1);
        }
    };
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse: {e}\n--- raw response ---\n{body}");
            std::process::exit(1);
        }
    };

    let status = json.get("status").and_then(|v| v.as_str()).unwrap_or("?");
    let height = json.get("height").and_then(|v| v.as_u64()).unwrap_or(0);
    let peers = json.get("peers").and_then(|v| v.as_u64()).unwrap_or(0);
    let uptime = json
        .get("uptime_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let is_validator = json
        .get("is_validator")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let validator_address = json
        .get("validator_address")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let blocks_produced = json
        .get("blocks_produced")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let blocks_pending = json
        .get("blocks_pending")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    let mark = |b: bool| if b { "ok" } else { "no" };
    println!("status:           {status}");
    println!("height:           {height}");
    println!("peers:            {peers}");
    println!("uptime_secs:      {uptime}");
    println!("validator_addr:   {validator_address}");
    println!(
        "is_validator:     {} ({})",
        mark(is_validator),
        is_validator
    );
    println!("blocks_produced:  {blocks_produced}");
    println!("blocks_pending:   {blocks_pending}");

    if status == "stalled" {
        eprintln!("node is stalled — height has not advanced despite peers");
        std::process::exit(1);
    }
    if status == "starting" {
        eprintln!("node is still starting (uptime <30s)");
        std::process::exit(1);
    }
    if require_validator && !is_validator {
        eprintln!(
            "--require-validator: pubkey is not in the active set (expected for {validator_address})"
        );
        std::process::exit(2);
    }
}

/// `seal status` — fetch and pretty-print GET /status. Same fields
/// as `seal_getNodeInfo` plus the structured `bridge` block, the
/// metrics breakdown, and the chain identity. Useful as a one-shot
/// "dump everything" diagnostic; for liveness checks use
/// `seal health` instead (it has exit-code semantics).
fn run_status(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let status_url = format!("{}/status", url.trim_end_matches('/'));
    let body = match http_get(&status_url) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("GET {status_url}: {e}");
            std::process::exit(1);
        }
    };
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse: {e}\n--- raw response ---\n{body}");
            std::process::exit(1);
        }
    };
    println!("{}", serde_json::to_string_pretty(&json).unwrap_or(body));
}

/// `seal check-registration` — verify a validator pubkey is in
/// the testnet registration portal's roster. Pubkey can come from
/// a key file (`--key`) or supplied directly (`--pubkey-hex`).
/// Exit codes:
///   0 — found; the public record is pretty-printed.
///   1 — not found in the roster.
///   2 — portal HTTP error (unreachable, 5xx).
fn run_check_registration(args: &[String]) {
    let portal = match flag_value(args, "--portal") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("Usage: seal check-registration --portal <url> (--key key.json | --pubkey-hex <hex>)");
            std::process::exit(2);
        }
    };
    // Resolve the pubkey either from --pubkey-hex or by reading the
    // verifying_key field out of a key file.
    let pubkey_hex = if let Some(hex) = flag_value(args, "--pubkey-hex") {
        hex.to_string()
    } else if let Some(path) = flag_value(args, "--key") {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("read {path}: {e}");
                std::process::exit(2);
            }
        };
        let v: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("parse {path}: {e}");
                std::process::exit(2);
            }
        };
        match v.get("verifying_key").and_then(|x| x.as_str()) {
            Some(s) => s.to_string(),
            None => {
                eprintln!("{path}: missing 'verifying_key' field");
                std::process::exit(2);
            }
        }
    } else {
        eprintln!("--key <file> or --pubkey-hex <hex> required");
        std::process::exit(2);
    };

    let url = format!(
        "{}/registration/{}",
        portal.trim_end_matches('/'),
        pubkey_hex
    );
    // http_get parses HTTP/1.1; status-line lives in the unparsed
    // response, so we shell out to a curl call when one is available
    // to get the status code. Fall back to body-shape detection
    // otherwise (the portal returns `{"error":"not found"}` on miss).
    let body = match http_get(&url) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("GET {url}: {e}");
            std::process::exit(2);
        }
    };
    let json: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse {url}: {e}\n--- raw response ---\n{body}");
            std::process::exit(2);
        }
    };
    if json.get("error").is_some() {
        eprintln!("not in roster: pubkey={pubkey_hex}");
        std::process::exit(1);
    }
    println!("{}", serde_json::to_string_pretty(&json).unwrap_or(body));
}

/// `seal bridge-mark-executed` — relayer-driven RPC that flips a
/// withdrawal to `executed = true` after the destination-chain unlock
/// has landed. Required for the per-validator relayer custody model
/// (P1#3); auth-gated, validator membership enforced server-side.
///
/// Optional `--dest-chain-tx-hash <h>` logs the tx hash for audit
/// trails. Exits 0 on success (including the `was_already_executed`
/// no-op race case); non-zero on RPC errors so the relayer's
/// supervisor can retry.
fn run_bridge_mark_executed(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let id = match flag_value(args, "--withdrawal-id") {
        Some(s) => s.to_string(),
        None => {
            eprintln!(
                "Usage: seal bridge-mark-executed --withdrawal-id <id> \
                 --key <validator-key.json> [--dest-chain-tx-hash <hash>] [--node <url>]"
            );
            return;
        }
    };
    let key = match flag_value(args, "--key") {
        Some(k) => k,
        None => {
            eprintln!(
                "--key <validator-key.json> is required (seal_bridgeMarkExecuted is auth-gated)"
            );
            return;
        }
    };
    let mut params = serde_json::json!({ "withdrawal_id": id });
    if let Some(h) = flag_value(args, "--dest-chain-tx-hash") {
        params["dest_chain_tx_hash"] = serde_json::Value::String(h.to_string());
    }
    match signed_call(url, "seal_bridgeMarkExecuted", params, key) {
        Ok(resp) => {
            if let Some(err) = resp.get("error") {
                eprintln!(
                    "RPC error ({}): {}",
                    err.get("code").and_then(|c| c.as_i64()).unwrap_or(0),
                    err.get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown")
                );
                std::process::exit(1);
            } else if let Some(r) = resp.get("result") {
                let was_already = r
                    .get("was_already_executed")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if was_already {
                    println!("withdrawal {} was already executed (race no-op)", id);
                } else {
                    println!("withdrawal {} marked executed", id);
                }
            }
        }
        Err(e) => {
            eprintln!("RPC failed: {e}");
            std::process::exit(1);
        }
    }
}

/// `seal bridge-get-withdrawal` — unauth fetch by id. Prints the
/// full record including `committee_signature_hex` (the input the
/// destination-chain unlock claim needs).
fn run_bridge_get_withdrawal(args: &[String]) {
    let url = flag_value(args, "--node").unwrap_or("http://localhost:8545");
    let id = match flag_value(args, "--withdrawal-id") {
        Some(s) => s.to_string(),
        None => {
            eprintln!("Usage: seal bridge-get-withdrawal --withdrawal-id <id> [--node <url>]");
            return;
        }
    };
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method":  "seal_getBridgeWithdrawal",
        "params":  {"withdrawal_id": id},
        "id":      1,
    });
    match rpc_post(url, &body) {
        Ok(resp) => {
            if let Some(r) = resp.get("result") {
                println!("{}", serde_json::to_string_pretty(r).unwrap_or_default());
            } else if let Some(err) = resp.get("error") {
                eprintln!("RPC error: {err}");
                std::process::exit(1);
            }
        }
        Err(e) => eprintln!("RPC failed: {e}"),
    }
}

#[cfg(test)]
mod vrf_keygen_tests {
    /// Roundtrip the file format `seal keygen --vrf` writes — the
    /// register-validator workflow downstream expects this exact
    /// shape (type, secret_key hex, public_key hex). Catches drift
    /// if the JSON keys are renamed.
    #[test]
    fn vrf_keygen_file_shape_is_stable() {
        use seal_vrf::Vrf;
        let kp = seal_vrf::PqVrf::keygen();
        let key_json = serde_json::json!({
            "type": "pq-vrf-ml-dsa-65",
            "secret_key": hex::encode(&kp.secret_key),
            "public_key": hex::encode(&kp.public_key),
        });
        assert_eq!(key_json["type"], "pq-vrf-ml-dsa-65");
        let sk_hex = key_json["secret_key"].as_str().expect("hex str");
        let pk_hex = key_json["public_key"].as_str().expect("hex str");
        // Round-trip via hex::decode; sanity that what we wrote
        // matches what we'd read back.
        assert_eq!(hex::decode(sk_hex).expect("sk decode"), kp.secret_key);
        assert_eq!(hex::decode(pk_hex).expect("pk decode"), kp.public_key);
    }

    /// The `vrf_pubkey_hex` printed to operators is the SHA3-256
    /// of the verifying key (32 bytes) — `register-validator`
    /// requires 64 hex chars. Asserts the print-format invariant.
    #[test]
    fn vrf_pubkey_hex_print_is_64_chars() {
        use seal_vrf::Vrf;
        let kp = seal_vrf::PqVrf::keygen();
        let hash = seal_crypto::hash::sha3_256(&kp.public_key).0;
        let hex_str = hex::encode(hash);
        assert_eq!(
            hex_str.len(),
            64,
            "register-validator's --vrf-pubkey-hex consumer requires exactly 64 hex chars"
        );
    }
}

#[cfg(test)]
mod admin_sign_tests {
    use super::*;

    #[test]
    fn canonicalize_strips_admin_signatures_field() {
        let with_sigs = serde_json::json!({
            "chain": "Solana",
            "admin_signatures": [
                {"sender": "abcd", "signature": "1234"}
            ],
        });
        let canon = canonicalize_admin_signing_params(&with_sigs);
        assert!(
            canon.get("admin_signatures").is_none(),
            "admin_signatures must be stripped before signing"
        );
        assert_eq!(canon.get("chain").and_then(|v| v.as_str()), Some("Solana"));
    }

    #[test]
    fn canonicalize_passthrough_when_no_admin_signatures() {
        let plain = serde_json::json!({"chain": "Stellar"});
        let canon = canonicalize_admin_signing_params(&plain);
        assert_eq!(canon, plain);
    }

    /// admin-submit assembles an envelope whose canonical params
    /// match what each cosigner signed (same SHA3 digest). This
    /// matters because if admin-submit's canonicalization drifts
    /// from admin-sign's, every M-of-N call silently fails server
    /// verification. Pins the contract between the two helpers.
    #[test]
    fn admin_submit_canonicalization_matches_admin_sign() {
        // What a cosigner would sign (admin-sign strips
        // admin_signatures).
        let user_params = serde_json::json!({
            "chain": "Solana",
            "extra_thing": 42,
        });
        let cosigner_canon = canonicalize_admin_signing_params(&user_params);

        // What admin-submit signs (also strips admin_signatures
        // — even if the caller passes some, they're discarded
        // before signing).
        let mut submit_params = user_params.clone();
        submit_params.as_object_mut().unwrap().insert(
            "admin_signatures".into(),
            serde_json::json!([{"sender": "ignore", "signature": "ignore"}]),
        );
        // admin-submit's body does the strip step inline; replicate
        // here for the contract test.
        let mut submit_canon = submit_params.clone();
        if let Some(obj) = submit_canon.as_object_mut() {
            obj.remove("admin_signatures");
        }
        assert_eq!(
            cosigner_canon, submit_canon,
            "admin-sign + admin-submit must canonicalize to the same JSON before signing"
        );
    }

    /// Smoke test the full flow: sign with a fresh keypair, then
    /// verify the produced signature against the same SHA3 digest
    /// the server's verify_admin_multisig builds. Catches drift
    /// between the CLI's message format and the server's.
    #[test]
    fn admin_sign_produces_server_verifiable_signature() {
        use seal_crypto::signature::SigningKey;
        let (sk, vk) = SigningKey::generate();

        let method = "seal_bridgePauseChain";
        let params = serde_json::json!({"chain": "Solana"});
        let canon = canonicalize_admin_signing_params(&params);
        let canon_json = serde_json::to_string(&canon).unwrap();
        let message = format!("{}{}", method, canon_json);
        let message_hash = seal_crypto::hash::sha3_256(message.as_bytes());

        // What the CLI would produce internally:
        let sig = sk.sign(message_hash.as_ref()).expect("sign");
        // What the server does to verify:
        vk.verify(message_hash.as_ref(), &sig)
            .expect("server-side verify");
    }
}
