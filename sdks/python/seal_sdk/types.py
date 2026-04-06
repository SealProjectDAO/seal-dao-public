"""
Type definitions for the Seal DAO SDK.

These dataclasses mirror the Rust structs in the seal-consensus, seal-token,
and seal-sql crates. See SPEC.md for the full protocol specification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class ColumnDef:
    """A column definition (mirrors seal_sql::types::Column)."""

    name: str
    data_type: str  # One of the SealType values (e.g., "TEXT", "BIGINT")
    nullable: bool = True
    primary_key: bool = False


@dataclass
class Row:
    """A row of query results."""

    values: List[Any] = field(default_factory=list)


@dataclass
class QueryResult:
    """Result of a SQL query execution.

    Attributes:
        columns: Column definitions for the result set.
        rows: Rows returned by the query.
        rows_affected: Number of rows affected (for INSERT/UPDATE/DELETE).
        execution_time_ms: Execution time in milliseconds.
    """

    columns: List[ColumnDef] = field(default_factory=list)
    rows: List[Row] = field(default_factory=list)
    rows_affected: int = 0
    execution_time_ms: float = 0.0


@dataclass
class Transaction:
    """A transaction within a block.

    Attributes:
        hash: Transaction hash (SHA3-256, hex-encoded).
        from_address: Sender address (bech32m).
        to_address: Recipient address (bech32m), if applicable.
        amount: Transfer amount in micro-SEAL (9 decimal places).
        sql: SQL statement, if this is a data transaction.
        signature: ML-DSA-65 signature (hex-encoded).
        nonce: Transaction nonce.
        fee: Fee paid in micro-SEAL.
    """

    hash: str = ""
    from_address: str = ""
    to_address: Optional[str] = None
    amount: int = 0
    sql: Optional[str] = None
    signature: str = ""
    nonce: int = 0
    fee: int = 0


@dataclass
class Block:
    """A block in the Seal blockchain.

    Attributes:
        height: Block height (0-indexed).
        hash: Block hash (SHA3-256, hex-encoded).
        parent_hash: Parent block hash.
        state_root: Merkle root of the state after this block.
        tx_root: Merkle root of the transactions in this block.
        timestamp: Block timestamp (microseconds since epoch).
        epoch: Epoch number.
        slot: Slot within the epoch.
        proposer: Proposer address (VRF-elected leader).
        transactions: Transactions included in this block.
    """

    height: int = 0
    hash: str = ""
    parent_hash: str = ""
    state_root: str = ""
    tx_root: str = ""
    timestamp: int = 0
    epoch: int = 0
    slot: int = 0
    proposer: str = ""
    transactions: List[Transaction] = field(default_factory=list)


@dataclass
class NetworkInfo:
    """Network information.

    Attributes:
        chain_id: Chain identifier.
        latest_height: Latest block height.
        latest_hash: Latest block hash.
        current_epoch: Current epoch number.
        validator_count: Number of active validators.
    """

    chain_id: str = ""
    latest_height: int = 0
    latest_hash: str = ""
    current_epoch: int = 0
    validator_count: int = 0
