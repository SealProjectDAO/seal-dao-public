# Seal DAO — Architecture

## Crate Dependency Graph

```
                        seal-app (REPL)
                            │
                        seal-cli (CLI tools)
                            │
                        seal-node ──────────────────────────────┐
                       /    │    \         \         \          │
              seal-p2p  seal-sql  seal-consensus  seal-zk  seal-token
                │      /    │    \      │    \        │         │
                │     /     │     \     │     \       │         │
            seal-storage  seal-merkle   │  seal-vrf   │    seal-bridge
                │           │           │     │       │         │
                └───────────┴───────────┴─────┘       │    seal-tee
                            │                         │
                        seal-crypto ──────────────────┘
                       (libcrux ML-DSA, ML-KEM, SHA3)

        seal-threshold ─── seal-crypto
        seal-wallet ────── seal-crypto
```

## Layer Architecture

```
┌────────────────────────────────────────────────────────┐
│ Layer 4: Applications                                  │
│   seal-app (REPL)  │  seal-cli (CLI tools)             │
├────────────────────────────────────────────────────────┤
│ Layer 3: Node Integration                              │
│   seal-node                                            │
│   ├── state.rs         (single-node state management)  │
│   ├── consensus_runner (VRF election + block pipeline) │
│   ├── network_node     (P2P + consensus integration)   │
│   ├── disk             (sled-backed --data-dir store)  │
│   ├── persistent       (legacy block-store + replay)   │
│   ├── snapshot_bootstrap (--bootstrap-from-snapshot)   │
│   ├── fees             (burn-and-mint economics)       │
│   ├── governance       (proposals, voting, timelocks)  │
│   └── delegation       (vote weight forwarding)        │
├────────────────────────────────────────────────────────┤
│ Layer 2: Protocol Services                             │
│   seal-consensus  (VRF election, epochs, validators)   │
│   seal-threshold  (committee threshold signatures)     │
│   seal-zk         (ZK proof generation/verification)   │
│   seal-token      (balances, transfers, staking)       │
│   seal-bridge     (Solana/Stellar lock-and-mint)       │
│   seal-tee        (TEE attestation, AI inference)      │
│   seal-wallet     (multi-chain key management)         │
├────────────────────────────────────────────────────────┤
│ Layer 1: Core Infrastructure                           │
│   seal-sql        (PostgreSQL SQL engine + RLS)        │
│   seal-merkle     (content-addressed B-tree)           │
│   seal-storage    (sled persistent KV + block store)   │
│   seal-p2p        (libp2p GossipSub + mDNS)           │
├────────────────────────────────────────────────────────┤
│ Layer 0: Cryptographic Foundation                      │
│   seal-crypto     (libcrux ML-DSA, ML-KEM, SHA3)      │
│   (formally verified with hax + F* by Cryspen)        │
└────────────────────────────────────────────────────────┘
```

## Data Flow: Transaction Lifecycle

```
User                    Node                      Network
 │                       │                          │
 │ SQL: INSERT INTO...   │                          │
 │──────────────────────>│                          │
 │                       │ 1. Execute SQL            │
 │                       │    (seal-sql engine)      │
 │                       │ 2. Sign with ML-DSA       │
 │                       │    (seal-crypto)          │
 │                       │ 3. Add to pending pool    │
 │                       │                          │
 │                       │ [Slot timer fires]        │
 │                       │                          │
 │                       │ 4. VRF election           │
 │                       │    (seal-vrf + consensus) │
 │                       │                          │
 │                       │ If elected proposer:      │
 │                       │ 5. Produce block           │
 │                       │    - Take pending txs     │
 │                       │    - Process fees (burn)  │
 │                       │    - Compute state root   │
 │                       │      (seal-merkle)        │
 │                       │    - Generate ZK proof    │
 │                       │      (seal-zk)            │
 │                       │    - Threshold sign       │
 │                       │      (seal-threshold)     │
 │                       │ 6. Broadcast block        │
 │                       │────────────────────────>  │
 │                       │                     GossipSub
 │                       │                          │
 │                       │ Other nodes:             │
 │                       │ 7. Receive block          │
 │                       │ 8. Verify:                │
 │                       │    - Height sequential    │
 │                       │    - Parent hash matches  │
 │                       │    - Replay txs → check   │
 │                       │      state root matches   │
 │                       │ 9. Apply to local state   │
 │                       │                          │
 │ Query: SELECT...      │                          │
 │──────────────────────>│                          │
 │                       │ Local read (free, no tx) │
 │<──────────────────────│                          │
 │ Results               │                          │
```

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| PostgreSQL SQL dialect | Most widely known query language; easy migration from existing apps |
| Algorand-style consensus | VRF-based secret leader election provides DDoS resistance; fits PQC (see CONSENSUS-COMPARISON.md) |
| libcrux for crypto | Formally verified ML-DSA/ML-KEM; seed-deterministic keygen |
| Merkle B-tree state | Content-addressed; deterministic roots; supports proofs |
| Burn-and-mint fees | Anchors token demand to usage; deflationary under growth |
| STARK proofs (no SNARK) | Post-quantum secure; no trusted setup; ~200KB acceptable for own L1 |
| Ringtail threshold sigs | 96% signature reduction (13.4KB vs 330KB); 2-round interactive |
