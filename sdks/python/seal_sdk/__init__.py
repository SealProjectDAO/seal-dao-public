"""
Seal DAO Python SDK — PQC-native L1 blockchain with distributed SQL.

This package provides a client for interacting with Seal DAO nodes over
JSON-RPC. All cryptographic operations use post-quantum algorithms
(ML-DSA-65, ML-KEM-768, SHA3-256).

NOTE: This is a scaffold. Method implementations will be connected once the
Seal node's JSON-RPC interface is finalized.

Example::

    from seal_sdk import SealClient

    client = SealClient("http://localhost:9944")
    await client.connect()
    result = await client.submit_sql("SELECT * FROM users LIMIT 10")
    await client.disconnect()
"""

from seal_sdk.client import SealClient
from seal_sdk.types import Block, QueryResult, Transaction

__all__ = [
    "SealClient",
    "Block",
    "Transaction",
    "QueryResult",
]

__version__ = "0.1.0"
