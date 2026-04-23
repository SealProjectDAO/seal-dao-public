/* tslint:disable */
/* eslint-disable */

/**
 * Parse and validate a PostgreSQL-compatible SQL statement.
 *
 * Returns a JSON string containing the parsed statement strings on success,
 * or an error message if the SQL is invalid. This uses the same parser as
 * the Seal node.
 *
 * Supported statements: SELECT, INSERT, UPDATE, DELETE, CREATE TABLE,
 * CREATE POLICY, CREATE INDEX, ALTER TABLE.
 *
 * # Example (JavaScript)
 * ```js
 * import { sql_parse } from "seal-dao-wasm";
 * const ast = sql_parse("SELECT * FROM users WHERE id = 1");
 * console.log(ast); // JSON string
 * ```
 *
 * # Errors
 *
 * Returns an error string if the SQL cannot be parsed.
 * Generate a new ML-DSA-65 keypair.
 *
 * Returns a JSON string with signing_key (hex), verifying_key (hex), and address.
 */
export function generate_keypair(testnet: boolean): string;

/**
 * Import a wallet from a hex seed (64 chars).
 */
export function import_from_hex(seed_hex: string, testnet: boolean): string;

/**
 * Import a wallet from a BIP-39 mnemonic (24 words).
 * Returns the same JSON as generate_keypair.
 */
export function import_from_mnemonic(words: string, testnet: boolean): string;

/**
 * Compute SHA3-256 hash of the input bytes.
 *
 * Returns a 32-byte hash digest as a `Uint8Array`.
 *
 * # Example (JavaScript)
 * ```js
 * import { sha3_256 } from "seal-dao-wasm";
 * const hash = sha3_256(new TextEncoder().encode("hello"));
 * console.log(hash); // Uint8Array(32)
 * ```
 */
export function sha3_256(data: Uint8Array): Uint8Array;

/**
 * Sign a message using ML-DSA-65 (FIPS 204).
 *
 * Takes a signing key (4032 bytes) and a message, returns the detached
 * signature (3309 bytes) as a `Uint8Array`.
 *
 * # Errors
 *
 * Returns an error string if the signing key is invalid.
 */
export function sign(signing_key_bytes: Uint8Array, message: Uint8Array): Uint8Array;

export function sql_parse(sql: string): string;

/**
 * Verify an ML-DSA-65 signature (FIPS 204).
 *
 * Takes a verifying key (1952 bytes), a message, and a signature (3309 bytes).
 * Returns `true` if the signature is valid, `false` otherwise.
 *
 * # Errors
 *
 * Returns an error string if the verifying key is malformed.
 */
export function verify(verifying_key_bytes: Uint8Array, message: Uint8Array, signature_bytes: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly sha3_256: (a: number, b: number) => [number, number];
    readonly sign: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
    readonly generate_keypair: (a: number) => [number, number];
    readonly import_from_mnemonic: (a: number, b: number, c: number) => [number, number, number, number];
    readonly import_from_hex: (a: number, b: number, c: number) => [number, number, number, number];
    readonly sql_parse: (a: number, b: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
