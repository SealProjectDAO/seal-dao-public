/* tslint:disable */
/* eslint-disable */
export const memory: WebAssembly.Memory;
export const sha3_256: (a: number, b: number) => [number, number];
export const sign: (a: number, b: number, c: number, d: number) => [number, number, number, number];
export const verify: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
export const generate_keypair: (a: number) => [number, number];
export const import_from_mnemonic: (a: number, b: number, c: number) => [number, number, number, number];
export const import_from_hex: (a: number, b: number, c: number) => [number, number, number, number];
export const sql_parse: (a: number, b: number) => [number, number, number, number];
export const __wbindgen_exn_store: (a: number) => void;
export const __externref_table_alloc: () => number;
export const __wbindgen_externrefs: WebAssembly.Table;
export const __wbindgen_free: (a: number, b: number, c: number) => void;
export const __wbindgen_malloc: (a: number, b: number) => number;
export const __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
export const __externref_table_dealloc: (a: number) => void;
export const __wbindgen_start: () => void;
