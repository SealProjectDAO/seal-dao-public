# Seal DAO <-> Stellar Bridge (Soroban)

**Status: SKELETON** -- Not production-ready. Proof verification is stubbed.

## Overview

This Soroban smart contract locks XLM on Stellar and emits events that Seal DAO
relayers monitor. When tokens are burned on the Seal side, the committee produces
a Ringtail threshold signature proof that authorizes unlocking XLM on Stellar.

## Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Soroban CLI](https://soroban.stellar.org/docs/getting-started/setup) >= 21
- `wasm32-unknown-unknown` target:
  ```bash
  rustup target add wasm32-unknown-unknown
  ```

## Setup

```bash
# Build the contract
cargo build --target wasm32-unknown-unknown --release

# Run tests
cargo test

# Optimize the WASM binary (optional, for deployment)
soroban contract optimize \
  --wasm target/wasm32-unknown-unknown/release/seal_bridge_stellar.wasm
```

## Contract Interface

| Function            | Description                                      |
|---------------------|--------------------------------------------------|
| `initialize`        | Set admin address and Seal committee public key  |
| `lock_xlm`          | Lock XLM, emit lock event for relayers           |
| `unlock_xlm`        | Verify proof from Seal committee, release XLM    |
| `get_total_locked`  | View: total XLM currently locked                 |
| `get_nonce`         | View: current lock nonce                         |
| `is_nonce_processed`| View: check if an unlock nonce was already used  |

### Events

| Topic    | Data                                              |
|----------|---------------------------------------------------|
| `lock`   | LockInfo { sender, amount, seal_address, ts, nonce } |
| `unlock` | (recipient, amount, nonce)                        |

### Errors

| Code | Name                | Description                        |
|------|---------------------|------------------------------------|
| 1    | AlreadyInitialized  | Contract already set up            |
| 2    | NotInitialized      | Contract not yet initialized       |
| 3    | Unauthorized        | Caller lacks permission            |
| 4    | AlreadyProcessed    | Nonce replay detected              |
| 5    | InsufficientBalance | Not enough locked XLM              |
| 6    | InvalidProof        | Threshold signature check failed   |
| 7    | InvalidAmount       | Amount must be positive            |

## Deployment

```bash
# Deploy to Stellar testnet
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/seal_bridge_stellar.wasm \
  --network testnet \
  --source <YOUR_SECRET_KEY>

# Resolve the SAC address for native XLM on this network
XLM_SAC=$(stellar contract id asset --asset native --network testnet)

# Initialize the contract
soroban contract invoke \
  --id <CONTRACT_ID> \
  --network testnet \
  --source <YOUR_SECRET_KEY> \
  -- initialize \
  --admin <ADMIN_ADDRESS> \
  --seal_bridge_key <32_BYTE_HEX_KEY> \
  --xlm_sac "$XLM_SAC"
```

The `xlm_sac` address is the Stellar Asset Contract for the asset the
bridge operates on. For native XLM it's derived from the network
passphrase via `stellar contract id asset --asset native`; for a
non-native asset (e.g. USDC) use
`stellar contract id asset --asset USDC:<issuer>`. The contract uses
this SAC to do real `transfer` calls on `lock_xlm` / `unlock_xlm`.

## TODO

- [x] Committee MAC signature verify (HMAC-SHA-256 via
      `Env::crypto().sha256`) — `verify_proof`. Not a full algebraic
      Ringtail verify; see B4 in `bridges/DEPLOYMENT.md` for the
      long-form upgrade path.
- [x] Committee-key rotation (`rotate_committee_key`, admin-only).
- [x] Integrate Stellar Asset Contract (SAC) for actual XLM transfers (B5).
- [ ] Full algebraic Ringtail verify in Soroban (48-bit prime NTT
      polynomial ops; ~10M instructions estimated).
- [x] Add pause/unpause admin functionality (`set_pause` ix, admin-only;
      `paused` instance-storage flag; `lock_xlm` and `unlock_xlm`
      reject with `Paused` while set; `is_paused` view; pause event
      emitted). Defence-in-depth on top of the Seal-side per-chain
      pause (`seal_bridgePauseChain`, 2/3 Technical Council).
- [ ] Add fee collection mechanism
- [ ] Add rate limiting / daily caps
- [ ] Integration tests with Seal DAO testnet relayer
- [ ] Security audit
