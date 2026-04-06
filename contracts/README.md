# Seal DAO — Bridge Contracts

## Solana Lock Program (`contracts/solana/`)

Anchor program for locking SOL/SPL tokens on Solana.

### Flow
1. User calls `lock_tokens(amount, seal_recipient)`
2. SOL transferred to lock PDA
3. Seal validators observe via Solana RPC
4. Seal chain mints wSOL to `seal_recipient`

### Withdrawal
1. User burns wSOL on Seal
2. Seal validators produce threshold signature
3. `release_tokens(lock_id, recipient, threshold_sig)` called
4. SOL released from PDA to `recipient`

### Build
```bash
cargo install --git https://github.com/coral-xyz/anchor anchor-cli
cd contracts/solana
anchor build
anchor deploy
```

## Stellar Lock Contract (`contracts/stellar/`)

Soroban contract for locking XLM/USDC on Stellar.

### Flow
Same as Solana but using Soroban SDK.

### Build
```bash
cargo install --locked soroban-cli
cd contracts/stellar
soroban contract build
soroban contract deploy --wasm target/wasm32-unknown-unknown/release/seal_lock.wasm
```

## Security

Both contracts use the same security model:
- Lock: anyone can lock tokens (permissionless)
- Release: requires threshold signature from Seal validator committee
- Invariant: `total_minted_on_seal <= total_locked_on_source` (verified by TLA+)
