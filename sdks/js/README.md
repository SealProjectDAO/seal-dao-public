# @seal-dao/sdk

JavaScript/TypeScript SDK for [Seal DAO](https://github.com/SealProjectDAO/seal-dao-master) -- a PQC-native L1 blockchain with a distributed SQL database layer.

> **Status: Scaffold.** This SDK provides the type definitions and client interface. Method implementations will be connected once the Seal node's JSON-RPC interface is finalized.

## Install

```bash
npm install @seal-dao/sdk
```

## Quick start

```typescript
import { SealClient } from "@seal-dao/sdk";

const client = new SealClient("http://localhost:9944");
await client.connect();

// Query the on-chain SQL database (PostgreSQL-compatible)
const result = await client.submitSql("SELECT * FROM users LIMIT 10");
console.log(result.rows);

// Fetch a block
const block = await client.getBlock(0);
console.log(`Genesis hash: ${block.hash}`);

// Check balance (returns micro-SEAL as bigint)
const balance = await client.getBalance("seal1...");
console.log(`Balance: ${balance} micro-SEAL`);

// Transfer tokens
const txHash = await client.transfer("seal1...", 1_000_000_000n);
console.log(`Transfer tx: ${txHash}`);

// Get network info
const info = await client.getNetworkInfo();
console.log(`Chain: ${info.chainId}, height: ${info.latestHeight}`);

await client.disconnect();
```

## Types

The SDK exports TypeScript types that mirror the Rust structs:

- `Block` -- a block in the Seal blockchain
- `Transaction` -- a transaction (transfer or SQL)
- `QueryResult` -- result of a SQL query with columns and rows
- `SealValue` -- a tagged union of SQL value types
- `NetworkInfo` -- current chain status
- `TxHash` -- a SHA3-256 transaction hash (hex string)
- `Address` -- a bech32m-encoded Seal address

## WASM bindings

This SDK can use the WASM bindings from `sdks/wasm/` for client-side cryptographic operations (SHA3-256 hashing, ML-DSA-65 signing/verification, SQL parsing). Build the WASM package first:

```bash
cd ../wasm
wasm-pack build --target web
```

## Architecture

- **Post-quantum cryptography**: All signatures use ML-DSA-65 (FIPS 204). Key encapsulation uses ML-KEM-768 (FIPS 203). Hashing uses SHA3-256 (FIPS 202).
- **SQL layer**: The on-chain database supports a PostgreSQL-compatible SQL subset with row-level security policies.
- **Consensus**: Algorand-style VRF-based leader election with single-slot finality.

## License

Apache-2.0
