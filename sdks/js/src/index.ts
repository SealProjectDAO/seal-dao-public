/**
 * @seal-dao/sdk — JavaScript/TypeScript SDK for Seal DAO
 *
 * Seal DAO is a PQC-native L1 blockchain with a distributed SQL database layer.
 * This SDK provides a client for interacting with Seal nodes over JSON-RPC.
 *
 * NOTE: This is a scaffold. Method implementations will be connected to a live
 * Seal node RPC once the node's JSON-RPC interface is finalized.
 *
 * @example
 * ```typescript
 * import { SealClient } from "@seal-dao/sdk";
 *
 * const client = new SealClient("http://localhost:9944");
 * await client.connect();
 *
 * const block = await client.getBlock(0);
 * const balance = await client.getBalance("seal1...");
 * const result = await client.submitSql("SELECT * FROM users LIMIT 10");
 *
 * await client.disconnect();
 * ```
 */

export {
  type TxHash,
  type Address,
  type SealType,
  type ColumnDef,
  type SealValue,
  type Row,
  type QueryResult,
  type Transaction,
  type Block,
  type NetworkInfo,
  SealError,
} from "./types.js";

import type {
  TxHash,
  Block,
  QueryResult,
  NetworkInfo,
} from "./types.js";
import { SealError } from "./types.js";

/**
 * Client for interacting with a Seal DAO node.
 *
 * Communicates over JSON-RPC with the node's HTTP endpoint.
 * All cryptographic operations use post-quantum algorithms (ML-DSA-65, SHA3-256).
 */
export class SealClient {
  private readonly rpcUrl: string;
  private connected: boolean = false;

  /**
   * Create a new Seal client.
   *
   * @param rpcUrl - The URL of the Seal node's JSON-RPC endpoint
   *                 (e.g., "http://localhost:9944").
   */
  constructor(rpcUrl: string) {
    if (!rpcUrl) {
      throw new SealError("rpcUrl is required", -1);
    }
    this.rpcUrl = rpcUrl.replace(/\/+$/, ""); // strip trailing slashes
  }

  /**
   * Connect to the Seal node and verify reachability.
   *
   * @throws {SealError} If the node is unreachable.
   */
  async connect(): Promise<void> {
    // TODO: Perform a health-check RPC call (e.g., seal_getNetworkInfo)
    // to verify the node is reachable and compatible.
    this.connected = true;
  }

  /**
   * Disconnect from the Seal node and release resources.
   */
  async disconnect(): Promise<void> {
    this.connected = false;
  }

  /** Whether the client is currently connected. */
  get isConnected(): boolean {
    return this.connected;
  }

  /**
   * Submit a SQL statement for execution on the Seal database layer.
   *
   * Supports PostgreSQL-compatible syntax: SELECT, INSERT, UPDATE, DELETE,
   * CREATE TABLE, CREATE POLICY, CREATE INDEX, ALTER TABLE.
   *
   * @param sql - The SQL statement to execute.
   * @returns The query result including columns, rows, and execution metadata.
   * @throws {SealError} If the SQL is invalid or execution fails.
   */
  async submitSql(sql: string): Promise<QueryResult> {
    this.ensureConnected();
    return this.rpcCall<QueryResult>("seal_submitSql", { sql });
  }

  /**
   * Fetch a block by height.
   *
   * @param height - The block height (0-indexed).
   * @returns The block at the given height.
   * @throws {SealError} If the block does not exist.
   */
  async getBlock(height: number): Promise<Block> {
    this.ensureConnected();
    return this.rpcCall<Block>("seal_getBlock", { height });
  }

  /**
   * Get the SEAL token balance of an address.
   *
   * Balances are in micro-SEAL (9 decimal places).
   * 1 SEAL = 1_000_000_000 micro-SEAL.
   *
   * @param address - The bech32m-encoded Seal address.
   * @returns The balance in micro-SEAL.
   */
  async getBalance(address: string): Promise<bigint> {
    this.ensureConnected();
    const result = await this.rpcCall<{ balance: string }>(
      "seal_getBalance",
      { address },
    );
    return BigInt(result.balance);
  }

  /**
   * Transfer SEAL tokens to another address.
   *
   * The transaction is signed locally with ML-DSA-65 and submitted to the node.
   *
   * @param to - The recipient's bech32m-encoded Seal address.
   * @param amount - The amount to transfer in micro-SEAL.
   * @returns The transaction hash (SHA3-256, hex-encoded).
   * @throws {SealError} If the transfer fails (insufficient balance, invalid address, etc.).
   */
  async transfer(to: string, amount: bigint): Promise<TxHash> {
    this.ensureConnected();
    const result = await this.rpcCall<{ txHash: string }>(
      "seal_transfer",
      { to, amount: amount.toString() },
    );
    return result.txHash;
  }

  /**
   * Get network information (chain ID, latest block, epoch, validators).
   *
   * @returns Current network status.
   */
  async getNetworkInfo(): Promise<NetworkInfo> {
    this.ensureConnected();
    return this.rpcCall<NetworkInfo>("seal_getNetworkInfo", {});
  }

  // ---- Internal helpers ----

  private ensureConnected(): void {
    if (!this.connected) {
      throw new SealError(
        "Not connected. Call connect() first.",
        -1,
      );
    }
  }

  /**
   * Make a JSON-RPC call to the Seal node.
   *
   * @internal
   */
  private async rpcCall<T>(method: string, params: unknown): Promise<T> {
    // TODO: Replace this stub with a real fetch-based JSON-RPC call once the
    // Seal node's RPC interface is implemented. The expected wire format is
    // JSON-RPC 2.0 over HTTP POST.
    //
    // Example request body:
    // {
    //   "jsonrpc": "2.0",
    //   "id": 1,
    //   "method": "seal_getBlock",
    //   "params": { "height": 0 }
    // }
    throw new SealError(
      `RPC method "${method}" is not yet implemented. ` +
      `The Seal node JSON-RPC interface is under development. ` +
      `See SPEC.md for the planned RPC API.`,
      -32601, // Method not found (JSON-RPC standard error code)
      { method, params, rpcUrl: this.rpcUrl },
    );
  }
}
