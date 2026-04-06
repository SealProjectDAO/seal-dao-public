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

# Initialize the contract
soroban contract invoke \
  --id <CONTRACT_ID> \
  --network testnet \
  --source <YOUR_SECRET_KEY> \
  -- initialize \
  --admin <ADMIN_ADDRESS> \
  --seal_bridge_key <32_BYTE_HEX_KEY>
```

## TODO

- [ ] Implement ML-DSA threshold signature verification (Ringtail)
- [ ] Integrate Stellar Asset Contract (SAC) for actual XLM transfers
- [ ] Add pause/unpause admin functionality
- [ ] Add fee collection mechanism
- [ ] Add rate limiting / daily caps
- [ ] Integration tests with Seal DAO testnet relayer
- [ ] Security audit
