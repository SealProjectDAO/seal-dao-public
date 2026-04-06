# Rocq/Coq — State Machine Verification

## What is Rocq?

Rocq (formerly Coq) is a **theorem prover** based on the Calculus of Inductive
Constructions. You define data types, write functions, and prove properties
about them using tactics. If a proof compiles, it is mathematically correct.

## Why Rocq (not Lean)?

We use BOTH — for different things:
- **Lean 4**: Cryptographic algorithm properties (Mathlib, VCVio)
- **Rocq**: State machine correctness (mature ecosystem, coq-of-rust for automatic
  Rust→Rocq extraction, strong inductive type support)

For state machines and token arithmetic, Rocq's tactic system (`lia`, `nia`,
`omega`) makes arithmetic proofs very concise.

## What we prove

| File | Property | Proven? |
|------|----------|---------|
| `Balance.v` | Credit-debit roundtrip | Yes (fully proven) |
| `Balance.v` | Transfer conserves total supply | Yes (fully proven) |
| `Balance.v` | Stake-unstake preserves total | Yes (fully proven) |
| `Balance.v` | Well-formedness preserved by all operations | Yes (fully proven) |
| `StateMachine.v` | Transition determinism | Yes (trivially) |
| `StateMachine.v` | Transfer conserves pair balance | Yes (fully proven) |
| `StateMachine.v` | Invalid transfers don't modify state | Yes (fully proven) |
| `StateMachine.v` | Mint increases supply correctly | Yes (fully proven) |
| `StateMachine.v` | Burn decreases supply correctly | Yes (fully proven) |

## Installation

### macOS
```bash
# Via Homebrew:
brew install coq

# Or via opam (OCaml package manager):
brew install opam
opam init
opam install coq

# Verify:
coqc --version
```

### Linux (Debian/Ubuntu)
```bash
# Via apt (may be older version):
sudo apt install coq

# Or via opam (recommended for latest version):
sudo apt install opam
opam init
eval $(opam env)
opam install coq

# Verify:
coqc --version
```

## How to build

```bash
cd formal/rocq
coq_makefile -f _CoqProject -o Makefile
make
```

If all proofs are correct, `make` succeeds silently.
If a proof is wrong, you get an error at the failing theorem.

## File-by-file explanation

### `Balance.v` — Token balance conservation

**Purpose**: Prove that SEAL token operations never create or destroy tokens
(except mint/burn).

**Structure**:
```
Record Balance = { available, staked, total }  ← mirrors Rust Balance struct
well_formed: total = available + staked        ← invariant

credit(b, amount): available += amount, total += amount
debit(b, amount): available -= amount, total -= amount
stake(b, amount): available -= amount, staked += amount, total unchanged
unstake(b, amount): staked -= amount, available += amount, total unchanged

THEOREM credit_debit_roundtrip:
  credit then debit of same amount = identity
  (PROVEN: lia tactic solves it automatically)

THEOREM transfer_conserves:
  debit(A, amt) + credit(B, amt) → total_A + total_B unchanged
  (PROVEN: lia tactic)

THEOREM stake_unstake_roundtrip:
  stake then unstake of same amount = identity
  (PROVEN: lia tactic)
```

### `StateMachine.v` — State transition correctness

**Purpose**: Prove that the blockchain state machine is deterministic, that
transfers conserve balances, and that invalid transactions are rejected.

**Structure**:
```
State = Address → nat            ← map from address to balance
Transaction = Transfer | Mint | Burn

apply_tx(state, tx) → option State
  Transfer: debit sender, credit receiver (None if insufficient)
  Mint: credit recipient
  Burn: debit sender (None if insufficient)

THEOREM transition_deterministic:
  apply_tx is a pure function (same input → same output)

THEOREM transfer_conserves_pair:
  After Transfer(from, to, amount):
    state'(from) + state'(to) = state(from) + state(to)

THEOREM invalid_transfer_no_change:
  If amount > balance → apply_tx returns None (state unchanged)
```

## Relationship to Rust code

```
Rocq (this directory)            Rust (crates/)
===========================      ==========================
Balance.credit              ↔    Balance::credit()
Balance.debit               ↔    Balance::debit()
Balance.stake               ↔    Balance::stake()
Balance.unstake             ↔    Balance::unstake()
credit_debit_roundtrip      ↔    Kani: credit_debit_roundtrip
transfer_conserves          ↔    test_transfer_preserves_total_supply
stake_unstake_roundtrip     ↔    Kani: stake_unstake_preserves_total
apply_tx (Transfer)         ↔    transfer::transfer()
apply_tx (Mint)             ↔    BalanceStore::mint()
apply_tx (Burn)             ↔    BalanceStore::burn()
```

## Future work

1. **coq-of-rust**: Automatically extract the Rust seal-token code to Rocq
   and prove it matches this specification.
2. **Access control proofs**: Prove that RLS policies are complete and
   non-bypassable.
3. **State transition**: Prove that SQL write operations produce correct
   state diffs (requires modeling the SQL engine).
