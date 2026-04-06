/**
 * Type definitions for the Seal DAO SDK.
 *
 * These types mirror the Rust structs in the seal-consensus, seal-token,
 * and seal-sql crates. See SPEC.md for the full protocol specification.
 */

/** A SHA3-256 transaction hash, hex-encoded (64 characters). */
export type TxHash = string;

/** A Seal address in bech32m format. */
export type Address = string;

/** Supported SQL column types (mirrors seal_sql::types::SealType). */
export type SealType =
  | "SMALLINT"
  | "INTEGER"
  | "BIGINT"
  | "REAL"
  | "DOUBLE_PRECISION"
  | "NUMERIC"
  | "TEXT"
  | "BYTEA"
  | "BOOLEAN"
  | "TIMESTAMP"
  | "TIMESTAMPTZ"
  | "INTERVAL"
  | "UUID"
  | "JSONB"
  | "SEAL_ADDRESS"
  | "SEAL_AMOUNT";

/** A column definition (mirrors seal_sql::types::Column). */
export interface ColumnDef {
  name: string;
  dataType: SealType;
  nullable: boolean;
  primaryKey: boolean;
}

/** A runtime SQL value (mirrors seal_sql::types::SealValue). */
export type SealValue =
  | { type: "null" }
  | { type: "smallint"; value: number }
  | { type: "integer"; value: number }
  | { type: "bigint"; value: bigint }
  | { type: "real"; value: number }
  | { type: "double_precision"; value: number }
  | { type: "numeric"; value: string }
  | { type: "text"; value: string }
  | { type: "bytea"; value: Uint8Array }
  | { type: "boolean"; value: boolean }
  | { type: "timestamp"; value: bigint }
  | { type: "uuid"; value: string }
  | { type: "jsonb"; value: unknown }
  | { type: "seal_address"; value: string }
  | { type: "seal_amount"; value: bigint };

/** A row of query results. */
export interface Row {
  values: SealValue[];
}

/** Result of a SQL query execution. */
export interface QueryResult {
  /** Column definitions for the result set. */
  columns: ColumnDef[];
  /** Rows returned by the query. */
  rows: Row[];
  /** Number of rows affected (for INSERT/UPDATE/DELETE). */
  rowsAffected: number;
  /** Execution time in milliseconds. */
  executionTimeMs: number;
}

/** A transaction within a block. */
export interface Transaction {
  /** Transaction hash (SHA3-256, hex-encoded). */
  hash: TxHash;
  /** Sender address (bech32m). */
  from: Address;
  /** Recipient address (bech32m), if applicable. */
  to: Address | null;
  /** Transfer amount in micro-SEAL (9 decimal places). */
  amount: bigint;
  /** SQL statement, if this is a data transaction. */
  sql: string | null;
  /** ML-DSA-65 signature (hex-encoded). */
  signature: string;
  /** Transaction nonce. */
  nonce: bigint;
  /** Fee paid in micro-SEAL. */
  fee: bigint;
}

/** A block in the Seal blockchain. */
export interface Block {
  /** Block height (0-indexed). */
  height: number;
  /** Block hash (SHA3-256, hex-encoded). */
  hash: string;
  /** Parent block hash. */
  parentHash: string;
  /** Merkle root of the state after this block. */
  stateRoot: string;
  /** Merkle root of the transactions in this block. */
  txRoot: string;
  /** Block timestamp (microseconds since epoch). */
  timestamp: bigint;
  /** Epoch number. */
  epoch: number;
  /** Slot within the epoch. */
  slot: number;
  /** Proposer address (VRF-elected leader). */
  proposer: Address;
  /** Transactions included in this block. */
  transactions: Transaction[];
}

/** Network information. */
export interface NetworkInfo {
  /** Chain identifier. */
  chainId: string;
  /** Latest block height. */
  latestHeight: number;
  /** Latest block hash. */
  latestHash: string;
  /** Current epoch number. */
  currentEpoch: number;
  /** Number of active validators. */
  validatorCount: number;
}

/** Error returned by the Seal RPC. */
export class SealError extends Error {
  constructor(
    message: string,
    public readonly code: number,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "SealError";
  }
}
