# Bridge Contract Implementation Plan

Testnet-first approach. No rush for production networks.

## 1. Solana Bridge (Testnet/Devnet)

### Prerequisites
```bash
# Install Solana CLI (devnet)
sh -c "$(curl -sSfL https://release.solana.com/v1.18.0/install)"
solana config set --url devnet

# Install Anchor framework
cargo install --git https://github.com/coral-xyz/anchor anchor-cli

# Create wallet for testing
solana-keygen new --outfile ~/.config/solana/devnet.json
solana airdrop 2  # Get devnet SOL
```

### Contract Design

```
┌─────────────────────────────────────────┐
│          Solana Devnet                   │
│                                         │
│  seal-lock program (Anchor)             │
│  ├── LockAccount (PDA per deposit)      │
│  │   ├── owner: Pubkey                  │
│  │   ├── amount: u64 (lamports)         │
│  │   ├── seal_recipient: String         │
│  │   ├── released: bool                 │
│  │   └── nonce: u64                     │
│  │                                      │
│  ├── lock() → creates LockAccount       │
│  │   emit LockEvent { id, amount, ... } │
│  │                                      │
│  └── release(threshold_sig) → pays out  │
│      verify validators' threshold sig   │
│      transfer from PDA to recipient     │
└─────────────────────────────────────────┘
         │
         │ LockEvent observed via Solana RPC
         ▼
┌─────────────────────────────────────────┐
│          Seal Testnet                    │
│                                         │
│  BridgeManager                          │
│  ├── observe_deposit(LockEvent)         │
│  ├── confirm_deposit(validator sigs)    │
│  └── process_deposit() → mint wSOL      │
└─────────────────────────────────────────┘
```

### Implementation Steps

1. **Anchor project setup** (1 day)
   ```bash
   cd contracts/solana
   anchor init seal-lock
   ```

2. **LockAccount struct + lock instruction** (1 day)
   - PDA derived from depositor pubkey + nonce
   - Transfer SOL from depositor to PDA
   - Emit `LockEvent` with Seal recipient address

3. **Release instruction** (1 day)
   - Accept serialized threshold signature
   - Verify signature (initially: simple multisig of N known validators)
   - Transfer SOL from PDA to recipient
   - Mark as released

4. **Seal-side observer** (2 days)
   - Poll Solana RPC for `LockEvent` logs
   - Create `BridgeDeposit` in `BridgeManager`
   - Validators confirm
   - Process → mint wSOL on Seal

5. **Withdrawal flow** (2 days)
   - User burns wSOL on Seal
   - Validators sign release message
   - Submit release tx to Solana
   - SOL unlocked to recipient

6. **Testing** (1 day)
   - End-to-end: lock on Solana devnet → observe → mint on Seal testnet
   - Reverse: burn on Seal → release on Solana devnet

**Total: ~8 days for testnet**

### Testnet-Specific Simplifications
- Multisig instead of threshold sigs (simpler)
- Fixed validator set (no dynamic rotation)
- No fee collection on bridge ops
- Manual observer (CLI tool, not automated)

---

## 2. Stellar Bridge (Testnet)

### Prerequisites
```bash
# Install Soroban CLI
cargo install --locked soroban-cli

# Configure for testnet
soroban network add testnet \
  --rpc-url https://soroban-testnet.stellar.org \
  --network-passphrase "Test SDF Network ; September 2015"

# Create test identity
soroban keys generate alice --network testnet
soroban keys fund alice --network testnet
```

### Contract Design

Same pattern as Solana but adapted for Soroban:

```
┌─────────────────────────────────────────┐
│         Stellar Testnet                  │
│                                         │
│  seal-lock contract (Soroban)           │
│  ├── LockRecord (persistent storage)    │
│  │   ├── owner: Address                 │
│  │   ├── amount: i128                   │
│  │   ├── asset: Address (XLM/USDC)      │
│  │   ├── seal_recipient: String         │
│  │   └── released: bool                 │
│  │                                      │
│  ├── lock(asset, amount, seal_recip)    │
│  └── release(lock_id, threshold_sig)    │
└─────────────────────────────────────────┘
         │
         │ Events observed via Stellar Horizon API
         ▼
┌─────────────────────────────────────────┐
│          Seal Testnet                    │
│  (same BridgeManager as Solana)         │
└─────────────────────────────────────────┘
```

### Implementation Steps

1. **Soroban project setup** (1 day)
   ```bash
   cd contracts/stellar
   soroban contract init seal-lock
   ```

2. **Lock function** (1 day)
   - Accept XLM or USDC (SAC token)
   - Store lock record in persistent storage
   - Emit event for Seal observers

3. **Release function** (1 day)
   - Verify multisig from Seal validators
   - Transfer tokens back to recipient

4. **Seal-side observer** (1 day)
   - Reuse most of Solana observer code
   - Different RPC (Stellar Horizon instead of Solana RPC)

5. **Testing** (1 day)
   - End-to-end: lock XLM on testnet → mint wXLM on Seal
   - Reverse: burn wXLM → release XLM

**Total: ~5 days for testnet**

### Stellar-Specific Notes
- Soroban uses `i128` for amounts (not `u64`)
- Stellar has native USDC (Circle) — test with testnet USDC
- TTL management: extend persistent storage TTL periodically
- Resource limits: Soroban has tight resource budgets (CPU, memory, I/O)

---

## 3. Shared Components

Both bridges share:
- `BridgeManager` (already implemented in `seal-bridge`)
- `BridgeDeposit` / `BridgeWithdrawal` types
- Invariant: `minted ≤ locked` (verified by Kani + TLA+)
- Validator confirmation mechanism

### Observer Architecture
```rust
// Shared observer trait
trait BridgeObserver {
    async fn poll_events(&self) -> Vec<LockEvent>;
    async fn submit_release(&self, release: ReleaseRequest) -> Result<TxHash, Error>;
}

// Implementations
struct SolanaObserver { rpc_url: String, program_id: Pubkey }
struct StellarObserver { horizon_url: String, contract_id: String }
```

---

## 4. PQC Considerations for Bridges

| Component | PQC Status | Notes |
|-----------|-----------|-------|
| Lock tx on Solana | ❌ Ed25519 | Solana uses Ed25519, we can't change |
| Lock tx on Stellar | ❌ Ed25519 | Stellar uses Ed25519 |
| Lock event observation | ✅ N/A | Read-only, no crypto needed |
| Seal-side mint | ✅ ML-DSA | Seal transactions are PQ-secure |
| Release threshold sig | ⚠️ Depends | Use ML-DSA multisig on Seal side, Ed25519 on Solana side |
| Bridge invariant | ✅ N/A | Mathematical, no crypto |

**Risk**: Bridge funds on Solana/Stellar are protected by Ed25519 (not PQ).
If quantum computers break Ed25519, locked funds could be stolen.

**Mitigation**: Users should bridge small amounts for active use.
Long-term holdings should stay on the Seal chain (PQ-secure).
