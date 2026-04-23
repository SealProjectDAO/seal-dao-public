# Seal DAO <-> Solana Bridge (Anchor)

**Status: SKELETON** -- Not production-ready. Signature verification is stubbed.

## Overview

This Anchor program locks SOL/SPL tokens on Solana and emits events that Seal DAO
relayers monitor. When tokens are burned on the Seal side, the committee produces
a Ringtail threshold signature that authorizes unlocking on Solana.

## Prerequisites

- [Rust](https://rustup.rs/) (stable)
- [Solana CLI](https://docs.solana.com/cli/install-solana-cli-tools) >= 1.18
- [Anchor CLI](https://www.anchor-lang.com/docs/installation) >= 0.30
- [Node.js](https://nodejs.org/) >= 18
- [Yarn](https://yarnpkg.com/)

## Setup

```bash
# Install JS dependencies
yarn install

# Build the program
anchor build

# Run local validator and deploy
anchor localnet

# Run tests
anchor test
```

## Program Architecture

```
programs/seal-bridge/src/lib.rs
  +-- initialize        Create bridge state PDA, set authority
  +-- lock_tokens       Lock SPL tokens, emit LockEvent with seal_address
  +-- unlock_tokens     Verify threshold signature, release tokens
```

### Accounts

| Account       | Description                                          |
|---------------|------------------------------------------------------|
| BridgeState   | PDA storing authority, total_locked, nonce, bump     |
| LockRecord    | Per-lock PDA with sender, amount, seal_address, etc. |

### Events

| Event       | Fields                                          |
|-------------|-------------------------------------------------|
| LockEvent   | sender, amount, seal_address, nonce, timestamp  |
| UnlockEvent | recipient, amount, nonce, timestamp             |

### Errors

| Code                | Description                           |
|---------------------|---------------------------------------|
| InvalidSignature    | Threshold signature verification fail |
| InsufficientBalance | Not enough tokens for the operation   |
| AlreadyProcessed    | Nonce already used                    |

## Deployment

```bash
# Deploy to devnet
solana config set --url devnet
anchor deploy --provider.cluster devnet

# Update program ID in Anchor.toml and lib.rs after first deploy
```

## TODO

- [x] Committee MAC signature verify (HMAC-SHA-256 via `sol_sha256`
      syscall) — `verify_committee_sig`. Not a full algebraic
      Ringtail verify yet; see B3 in `bridges/DEPLOYMENT.md` for the
      long-form upgrade path once lattice arithmetic is ported to BPF.
- [x] Committee-key rotation ix (`rotate_committee_key`, admin-only).
- [ ] Full algebraic Ringtail verify in BPF (48-bit prime, sparse
      polynomial ops; ~150-200K CU budget estimate).
- [ ] Add nonce replay protection (bitmap or set)
- [ ] Add pause/unpause admin functionality
- [ ] Add fee collection mechanism
- [ ] Add rate limiting
- [ ] Integration tests with Seal DAO testnet relayer
- [ ] Security audit
