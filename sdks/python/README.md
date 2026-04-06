# seal-sdk

Python SDK for [Seal DAO](https://github.com/SealProjectDAO/seal-dao-master) -- a PQC-native L1 blockchain with a distributed SQL database layer.

> **Status: Scaffold.** This SDK provides the type definitions and client interface. Method implementations will be connected once the Seal node's JSON-RPC interface is finalized.

## Install

```bash
pip install seal-sdk
```

Or for development:

```bash
pip install -e ".[dev]"
```

## Quick start

```python
import asyncio
from seal_sdk import SealClient

async def main():
    client = SealClient("http://localhost:9944")
    await client.connect()

    # Query the on-chain SQL database (PostgreSQL-compatible)
    result = await client.submit_sql("SELECT * FROM users LIMIT 10")
    print(result.rows)

    # Fetch a block
    block = await client.get_block(0)
    print(f"Genesis hash: {block.hash}")

    # Check balance (returns micro-SEAL as int)
    balance = await client.get_balance("seal1...")
    print(f"Balance: {balance} micro-SEAL")

    # Transfer tokens
    tx_hash = await client.transfer("seal1...", 1_000_000_000)
    print(f"Transfer tx: {tx_hash}")

    # Get network info
    info = await client.get_network_info()
    print(f"Chain: {info.chain_id}, height: {info.latest_height}")

    await client.disconnect()

asyncio.run(main())
```

## Types

The SDK exports dataclasses that mirror the Rust structs:

- `Block` -- a block in the Seal blockchain
- `Transaction` -- a transaction (transfer or SQL)
- `QueryResult` -- result of a SQL query with columns and rows
- `ColumnDef` -- a column definition with name, type, and constraints
- `NetworkInfo` -- current chain status

## Architecture

- **Post-quantum cryptography**: All signatures use ML-DSA-65 (FIPS 204). Key encapsulation uses ML-KEM-768 (FIPS 203). Hashing uses SHA3-256 (FIPS 202).
- **SQL layer**: The on-chain database supports a PostgreSQL-compatible SQL subset with row-level security policies.
- **Consensus**: Algorand-style VRF-based leader election with single-slot finality.

## Requirements

- Python >= 3.9
- aiohttp >= 3.9

## License

Apache-2.0
