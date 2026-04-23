//! Seal DAO Node
//!
//! Usage:
//!   cargo run -p seal-node                                              # 10 slots, mDNS discovery
//!   cargo run -p seal-node -- --slots 0                                 # Run forever
//!   cargo run -p seal-node -- --slots 0 --port 4001                     # Listen on port 4001
//!   cargo run -p seal-node -- --slots 0 --bootstrap-peers /dns4/ajax/tcp/4001
//!   cargo run -p seal-node -- --slots 0 --rpc-port 8545                 # Enable JSON-RPC
//!   cargo run -p seal-node -- --no-network                              # Local only

use libp2p::Multiaddr;
use seal_consensus::config::ConsensusConfig;
use seal_node::disk::DiskStore;
use seal_node::network_node::NetworkNode;
use seal_node::rpc::{self, RpcConfig};
use seal_p2p::node::NodeConfig;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    let no_network = args.iter().any(|a| a == "--no-network");
    let dev_faucet = args.iter().any(|a| a == "--dev-faucet");
    // Node defaults to testnet addresses (sealt1…) so the HRP matches
    // what `cargo run -p seal-cli -- wallet` creates by default. Pass
    // `--mainnet` for a `seal1…`-HRP node. Mixing the two across
    // wallet and node makes authenticated transfers silently debit a
    // ghost account.
    let mainnet = args.iter().any(|a| a == "--mainnet");
    let slots = parse_arg(&args, "--slots").unwrap_or(10);
    let port = parse_arg::<u16>(&args, "--port").unwrap_or(4001);
    let rpc_port = parse_arg::<u16>(&args, "--rpc-port").unwrap_or(0);
    let bootstrap_peers = parse_multi_arg(&args, "--bootstrap-peers");
    let serve_namespaces = parse_multi_string(&args, "--serve");
    let data_dir = parse_arg::<String>(&args, "--data-dir")
        .unwrap_or_else(|| "seal-data".into());

    println!("=== Seal DAO Node ===\n");

    if no_network {
        run_local().await;
    } else {
        run_networked(
            slots,
            port,
            rpc_port,
            bootstrap_peers,
            serve_namespaces,
            data_dir,
            dev_faucet,
            mainnet,
        )
        .await;
    }
}

fn parse_arg<T: std::str::FromStr>(args: &[String], flag: &str) -> Option<T> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok())
}

fn parse_multi_string(args: &[String], flag: &str) -> HashSet<String> {
    let mut result = HashSet::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(val) = args.get(i + 1) {
                result.insert(val.clone());
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    result
}

fn parse_multi_arg(args: &[String], flag: &str) -> Vec<Multiaddr> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(val) = args.get(i + 1) {
                if let Ok(addr) = val.parse() {
                    result.push(addr);
                } else {
                    eprintln!("Invalid multiaddr: {}", val);
                }
                i += 2;
                continue;
            }
        }
        i += 1;
    }
    result
}

async fn run_networked(
    slots: u64,
    port: u16,
    rpc_port: u16,
    bootstrap_peers: Vec<Multiaddr>,
    serve_namespaces: HashSet<String>,
    data_dir: String,
    dev_faucet: bool,
    mainnet: bool,
) {
    let config = ConsensusConfig::default();
    let slot_duration = config.slot_duration;

    let node_config = NodeConfig {
        listen_port: port,
        bootstrap_peers,
        pq_encryption: false,
    };

    let mut node = match NetworkNode::start(config, node_config).await {
        Ok(n) => n,
        Err(e) => {
            eprintln!("Failed to start network node: {}", e);
            return;
        }
    };

    let peer_id = node.peer_id;

    // Initialize genesis balances (30/20/15/15/10/10 distribution)
    {
        use seal_token::params;
        let balances = &mut node.runner.balances;
        let _ = balances.mint("seal1validators", params::genesis::VALIDATOR_POOL);
        let _ = balances.mint("seal1treasury", params::genesis::COMMUNITY_TREASURY);
        let _ = balances.mint("seal1team", params::genesis::TEAM_ALLOCATION);
        let _ = balances.mint("seal1ecosystem", params::genesis::ECOSYSTEM_FUND);
        let _ = balances.mint("seal1public", params::genesis::PUBLIC_DISTRIBUTION);
        let _ = balances.mint("seal1reserve", params::genesis::RESERVE);
        println!("Genesis: {} SEAL minted ({} accounts)",
            balances.total_supply() / 1_000_000_000,
            balances.account_count());
    }

    let node = Arc::new(Mutex::new(node));

    println!("Peer ID: {}", peer_id);
    println!("P2P port: {}", port);
    if rpc_port > 0 {
        println!("RPC: http://127.0.0.1:{} (localhost only)", rpc_port);
    }
    if !serve_namespaces.is_empty() {
        println!("Serving: {:?}", serve_namespaces);
    }
    println!("Data dir: {}", data_dir);
    println!("Listening for peers via mDNS...");
    if slots == 0 {
        println!("Running indefinitely (Ctrl+C to stop)\n");
    } else {
        println!("Running for {} slots\n", slots);
    }

    // Start RPC server if enabled
    if rpc_port > 0 {
        if dev_faucet {
            println!(
                "Dev faucet enabled: POST seal_faucet {{\"address\":\"seal1…\"}} — do NOT enable on mainnet."
            );
        }
        let rpc_node = Arc::clone(&node);
        let rpc_config = RpcConfig {
            served_namespaces: serve_namespaces,
            dev_faucet,
            testnet: !mainnet,
            ..RpcConfig::default()
        };
        tokio::spawn(async move {
            rpc::start_rpc_server(rpc_node, rpc_config, rpc_port).await;
        });
    }

    // Open disk store for persistence. If prior blocks exist we replay
    // them FIRST and skip the demo seed — otherwise the seed's
    // `CREATE TABLE users` collides with block 1's already-recorded
    // schema, and the replay dies at block 1 with
    // `SQL replay failed: table already exists: users`.
    let (disk_store, had_prior_chain) = match DiskStore::open(&PathBuf::from(&data_dir)) {
        Ok(store) => {
            let stored_height = store.latest_height().unwrap_or(0);
            let mut replayed_any = false;
            if stored_height > 0 {
                println!("Found {} blocks on disk, replaying...", stored_height);
                let mut n = node.lock().await;
                let mut replayed = 0u64;
                for h in 1..=stored_height {
                    match store.get_block(h) {
                        Ok(Some(block)) => {
                            match n.runner.replay_block(&block) {
                                Ok(_) => replayed += 1,
                                Err(e) => {
                                    eprintln!("Replay failed at block {}: {}", h, e);
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            eprintln!("Block {} missing from disk, stopping replay", h);
                            break;
                        }
                        Err(e) => {
                            eprintln!("Failed to read block {}: {}", h, e);
                            break;
                        }
                    }
                }
                if replayed > 0 {
                    println!(
                        "Replayed {} blocks, height={}, state={}",
                        replayed,
                        n.height(),
                        n.state_root()
                    );
                    replayed_any = true;
                }
                drop(n);
            }
            (Some(store), replayed_any)
        }
        Err(e) => {
            eprintln!("Warning: disk persistence disabled ({})", e);
            (None, false)
        }
    };

    // Demo seed: only on a fresh chain. Block 1 records this tx; on
    // subsequent runs the replay above reconstitutes the same state.
    if !had_prior_chain {
        let mut n = node.lock().await;
        if let Err(e) = n.submit_sql(
            "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL, balance BIGINT)",
        ) {
            eprintln!("Failed to create table: {}", e);
            return;
        }
        if let Err(e) =
            n.submit_sql("INSERT INTO users (id, name, balance) VALUES (1, 'alice', 1000)")
        {
            eprintln!("Failed to insert user alice: {}", e);
            return;
        }
        if let Err(e) =
            n.submit_sql("INSERT INTO users (id, name, balance) VALUES (2, 'bob', 500)")
        {
            eprintln!("Failed to insert user bob: {}", e);
            return;
        }
        println!("Deployed schema + inserted 2 users");
    }

    // Run consensus
    println!("\n--- Running consensus ---");
    let mut slot: u64 = 0;
    loop {
        if slots > 0 && slot >= slots {
            break;
        }
        {
            let mut n = node.lock().await;
            if let Some(block) = n.tick().await {
                println!(
                    "Slot {}: Block #{} produced ({} txs, state: {})",
                    slot,
                    block.block.header.height,
                    block.block.transactions.len(),
                    block.block.header.state_root,
                );
                // Persist block to disk
                if let Some(ref store) = disk_store {
                    if let Err(e) = store.put_block(&block.block) {
                        eprintln!("Warning: failed to persist block: {}", e);
                    }
                }
            }
        }
        tokio::time::sleep(slot_duration).await;
        slot = slot.wrapping_add(1);
    }

    // Query (only when slots are finite)
    let n = node.lock().await;
    println!("\n--- Query results ---");
    // Need to drop and reacquire for mutable access
    drop(n);
    let mut n = node.lock().await;
    match n.query_sql("SELECT * FROM users") {
        Ok(result) => {
            println!("users: {} rows", result.rows.len());
            for row in &result.rows {
                println!("  {:?}", row.values);
            }
        }
        Err(e) => {
            eprintln!("Failed to query users: {}", e);
        }
    }

    println!("\nChain height: {}", n.height());
    println!("State root: {}", n.state_root());
    println!(
        "Received blocks from peers: {}",
        n.received_block_count()
    );
    println!("\n=== Done ===");
}

async fn run_local() {
    use seal_node::state::NodeState;

    let mut node = NodeState::new();
    println!(
        "Node address: {} (local mode, no P2P)\n",
        node.node_address()
    );

    if let Err(e) = node.execute_sql(
        "CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL, balance BIGINT)",
    ) {
        eprintln!("Failed to create table: {}", e);
        return;
    }
    if let Err(e) =
        node.execute_sql("INSERT INTO users (id, name, balance) VALUES (1, 'alice', 1000)")
    {
        eprintln!("Failed to insert user alice: {}", e);
        return;
    }
    if let Err(e) =
        node.execute_sql("INSERT INTO users (id, name, balance) VALUES (2, 'bob', 500)")
    {
        eprintln!("Failed to insert user bob: {}", e);
        return;
    }

    let block = node.produce_block();
    println!(
        "Block #{}: {} txs, state: {}",
        block.header.height,
        block.transactions.len(),
        block.header.state_root
    );

    match node.execute_sql("SELECT * FROM users") {
        Ok(result) => println!("users: {} rows", result.rows.len()),
        Err(e) => eprintln!("Failed to query users: {}", e),
    }

    println!("\n=== Done ===");
}
