# ADR-001 — Smart-contract execution model: SQL stored procedures (default) + WASM procedures (opt-in)

- Status: Accepted — 2026-04-19
- Deciders: Seal DAO core (user decision)
- Supersedes: open question in TODO.md lines 125–126 and TODOS.md line 96–97

## Context

Seal DAO's state is a collection of PostgreSQL-compatible SQL databases (SPEC §4.1).
"Smart contracts" in this model are schemas with tables, RLS policies, and triggers.
Until now the execution model for the *code* side of contracts — the logic inside
triggers and callable procedures — was an open question. The candidates were:

1. **SQL stored procedures** in the style of PostgreSQL PL/pgSQL.
2. **WASM VM** with a custom host ABI.
3. **A custom DSL.**
4. **Both SQL and WASM**, side-by-side, as PostgreSQL offers PL/pgSQL + PL/Python
   + PL/Perl + C functions behind a single `LANGUAGE` clause.

## Decision

**Default to SQL stored procedures. Allow WASM procedures as an opt-in second
language behind a `LANGUAGE` clause.**

PostgreSQL's multi-language `CREATE FUNCTION ... LANGUAGE <lang>` design is the
source of inspiration. A proc declares its language at creation; the engine
dispatches to the right interpreter. Both languages share one surface:

```sql
CREATE FUNCTION <name>(<args>) RETURNS <type>
    LANGUAGE sql | wasm
AS $$ <body> $$;

CREATE PROCEDURE <name>(<args>)
    LANGUAGE sql | wasm
AS $$ <body> $$;

CREATE TRIGGER <name> ... EXECUTE FUNCTION <name>();
```

### Tier 1 — `LANGUAGE sql` (default)

- Control flow: `IF`, `CASE`, `LOOP`, `WHILE`, `FOR`, `RETURN`.
- Variable declarations: `DECLARE v INT := 0;`
- Embedded SQL: any `SELECT`/`INSERT`/`UPDATE`/`DELETE` the caller is
  authorized to run under RLS.
- Deterministic by construction — the SQL engine is already deterministic
  and gas-metered.
- No host I/O, no clocks beyond `block.time`, no RNG beyond `block.seed`.

### Tier 2 — `LANGUAGE wasm` (opt-in)

- Precompiled WASM module uploaded alongside the `CREATE FUNCTION`.
- Executed in a deterministic sandbox (wasmtime / wasmer, floats disabled
  or canonicalized, no SIMD non-determinism, no threads, no host clock).
- Host ABI is intentionally minimal — only the procedure's own namespace's
  SQL surface:
  - `sql_exec(query, args) -> rows`
  - `sql_query(query, args) -> rows`
  - `block_height() -> u64`
  - `block_time() -> i64`
  - `block_seed() -> [u8; 32]`
  - `caller() -> address`
  - `log(msg)` — event log for the receipt
- Gas metering on WASM instructions + on every host call.
- Module hash is part of the on-chain code; re-deploy = new hash.

### Why both

Most contracts are CRUD with a few guards — PL/pgSQL-style SQL procs are
the right tool for that. A minority of contracts need heavier logic
(matching engines, cryptographic checks beyond what SQL offers, sealed-bid
auctions) and benefit from a proper language compiled to WASM. Forcing
everyone through either one is hostile: PL/pgSQL hits a ceiling fast, and
WASM is overkill for a permission check.

Postgres made the same call decades ago and it has aged well.

## Consequences

### Positive

- SQL-first: 80% of contracts stay in familiar territory, no new toolchain.
- WASM escape hatch is real but optional — it doesn't pollute the base UX.
- Aligns with the PostgreSQL-compatibility promise (SPEC §4.2).
- Deterministic execution for both tiers is enforceable and auditable.
- Triggers (SPEC §4.1) now have a concrete implementation strategy.

### Negative / costs

- Two interpreters to maintain; two gas schedules to calibrate; two fuzzers.
- WASM sandbox hardening is non-trivial — must block every source of
  non-determinism (floats, SIMD, threads, randomness, time, memory layout).
- Cross-language calls (SQL proc calling a WASM proc or vice versa)
  need careful transaction / gas / re-entry semantics.

### Migration impact

- SPEC §13.3 row "Stored procedures — Error: rewrite as app logic or Seal
  triggers" is now out of date: stored procedures ARE supported natively.
  Updating SPEC in the same commit as this ADR.

## Implementation sketch (not binding)

1. Extend `seal-sql` parser to accept `CREATE FUNCTION` / `CREATE PROCEDURE` /
   `CREATE TRIGGER` with a `LANGUAGE` clause. Store body + language in the
   on-chain code namespace.
2. New crate `seal-procs` with a `ProcedureEngine` trait; two impls:
   - `SqlProcEngine` — walks a parsed PL/pgSQL AST.
   - `WasmProcEngine` — wraps wasmtime with deterministic config + gas meter.
3. Gas schedule: publish alongside `params.rs`; treat as a governance param.
4. Determinism test harness: run each proc 100× on 100 different validators'
   machines; hash the result trace; assert equality.
5. Kani harness for the dispatcher; Miri on the host ABI; fuzz target for
   the WASM sandbox edges.

## Out of scope

- Language choice for the WASM *source* (Rust, AssemblyScript, C, Zig) —
  users ship bytecode, we don't pick the source language.
- Cross-contract calls across different namespaces — separate ADR.
- Upgrade semantics (governance-gated proc replacement) — separate ADR.
