# RLS write-path + engine user context — design note (item 14)

Date: 2026-10-08 · Status: **design-first, implementation DEFERRED** (same treatment as
item 13 / DEX T2). The RLS *store and predicate evaluator* exist and are unit-tested in
isolation; the defect is that they are **wired to nothing in the execution choke point**.

## 1. What exists, and where it is inert

`RlsManager` (`crates/seal-sql/src/rls.rs`) is a correct-in-isolation component:
- `check_access(table, action, user, row_owner)` (rls.rs:174) evaluates `USING` predicates,
  applies the injected `TokenBalanceChecker`, and matches owner. Thoroughly unit-tested
  (rls.rs:275-430) and exercised through `AppNamespace::execute_as`.
- `Policy { using_expr, with_check_expr: Option<String> }` (rls.rs:44-57).

The gaps, validated against primary source (2026-10-08):

1. **`Engine::execute` has no user** (`engine.rs:100` — `pub fn execute(&mut self, sql: &str)`).
   The engine — the object that actually runs every statement — has **no notion of a caller**, so
   it cannot apply RLS. RLS is applied only by the *optional* wrapper `AppNamespace::execute_as`
   (namespace.rs:62), which is a best-effort convenience, not the execution choke point.

2. **The consensus transition bypasses RLS entirely.** `apply_block_transition_impl`'s SQL arm
   (`consensus_runner.rs:1327-1332`) calls `self.sql_engine.execute(sql)` directly with **no user**.
   Every on-chain `SqlExec`/`CreateApp`/`AlterSchema` write lands with zero user context, so RLS
   policies are inert for the state that actually enters the chain. The `sql_root` covers
   post-write rows; it does not cover *who* wrote them.

3. **`with_check_expr` is stored but never evaluated.** `execute_create_policy` parses and stores
   it (`engine.rs:804` → `with_check.map(|s| s.to_string())`), but a whole-workspace search finds no
   evaluation path — every other occurrence is a `None` test fixture or the doc comment. So a
   policy's `WITH CHECK` clause (the INSERT/UPDATE guard) is **inert**: a row that would violate
   `WITH CHECK` is written and committed.

4. **`row_owner` is derived from the caller.** `execute_as` passes `Some(user)` as *both* the
   actor and the row owner (namespace.rs:96); the SELECT filter keys on a hardcoded `"owner"`
   column (namespace.rs:133). There is no independent row-owner concept (e.g. a table column or
   a session-derived owner), so the owner check is only as good as the `user` string the caller
   supplies.

5. **Bypasses.** `execute_as` short-circuits DDL (CREATE/ALTER/DROP) to `engine.execute` with no
   RLS (namespace.rs:70-75); `CALL` and any statement not matching the `SELECT`/`INSERT`/`UPDATE`/
   `DELETE` prefix fall through to `engine.execute` unguarded.

## 2. The crux — RLS needs a context at the choke point, but the transition has none

The F3-hardened transition is the single choke point every on-block SQL goes through, and it is
**sync, user-less, and proposer-signed**: a node is applying a committed block, not serving an
interactive user. That is the same structural tension as the token on-chain apply (item 13): the
thing that *must* be applied deterministically on every node has no per-caller identity to
enforce RLS against. Two coherent designs:

- **(B1) Explicit context, transition = privileged/bypass.** Introduce a `SessionContext` (or
  `Option<&str>` user) into the execution path: `None` = **privileged / RLS-bypass** (system,
  DDL, and the **transition**), `Some(user)` = **RLS-enforced** (app-facing RPC, `execute_as`,
  `cross_app_query`). This makes today's "transition bypasses RLS" behavior *explicit and
  documented* instead of accidental, and lets the app-facing path enforce RLS end-to-end —
  **including a real `WITH CHECK` evaluation** on INSERT/UPDATE and closing the DDL/CALL bypasses
  by gating on the context's capability, not on a statement-prefix match. Bounded; still touches
  the engine core.

- **(B2) On-chain RLS — carry a verified actor in the SQL tx.** Each SQL tx already carries
  `tx.sender`; the transition would apply RLS **under that actor's context**, so on-chain writes
  are RLS-gated identically on every node. This makes RLS a consensus-enforced invariant, but
  then `USING`/`WITH CHECK` evaluation becomes **part of the root-covered transition**: a
  non-deterministic or divergent predicate is a **fork**, and it changes *which blocks are valid*
  (a block whose SQL violates a policy is rejected by replays). That is an F3-class consensus-state
  change, not a local hardening.

## 3. Sub-fixes (required under either design)

1. **Evaluate `WITH CHECK`** per-row on INSERT/UPDATE (against the row being written), so the
   stored predicate is no longer inert.
2. **Per-row owner extraction** — derive the row owner from the row's data (a designated owner
   column or the table's row-identity), not from the caller's `user` string.
3. **Close the bypasses** — DDL, `CALL`, and unscoped statements gate on the `SessionContext`
   capability, not a `starts_with` prefix.
4. **Determinism** — any predicate evaluation that lands in the transition (B2) must be pure and
   identical on every node (no wall-clock, no environment reads), covered by a determinism
   regression.

## 4. Recommendation

- **Now-ish (bounded follow-up): B1** — thread an explicit `SessionContext` through `Engine::execute`
  (new `execute_as_user`), transition = privileged-bypass (documented), app path = RLS-enforced with
  a real `WITH CHECK` eval and the bypasses closed. Non-consensus-breaking (the transition's
  effective behavior is unchanged; it just stops being an accident), but touches the engine core so
  it is not a trivial swap.
- **Deferred: B2** — on-chain RLS under `tx.sender`. F3-class (validity + fork surface); requires the
  determinism proof in §3.4. Revisit once the on-chain actor model is deliberate rather than the
  transition's user-less default.

## 5. Status

Design-first; **implementation deferred**. The corrected framing (RLS is a correctly-built store +
evaluator wired to nothing at the choke point; the transition is sync and user-less; `WITH CHECK`
is inert; `row_owner` is caller-derived) is the deliverable. Revisit with a regression-first
implementation pass for B1 (context + `WITH CHECK` + bypass-closes), B2 after.
