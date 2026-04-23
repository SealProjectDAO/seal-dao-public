# forms.seal — browser frontend

Minimal HTML/JS demo of the encrypted-survey app.

## Run locally

```bash
# 1. Serve the directory (any static file server works)
cd examples/seal-forms/web
python3 -m http.server 5174

# 2. Open
open http://localhost:5174
```

The page expects a Seal node at `http://localhost:8545` (configurable
in the UI). Spin one up with:

```bash
cargo run -p seal-node
```

## Build the SDK

The page imports `sdks/wasm/pkg/seal_dao_wasm.js` for ML-KEM
encapsulation + SHA3 hashing. Build it with:

```bash
cd sdks/wasm
./build.sh
```

If the SDK module is missing the page falls back to read-only mode
and disables the encrypt / submit buttons.

## What the demo shows

1. **Encrypted answers.** The form's ML-KEM-768 public key is fetched
   from the on-chain `forms` table. Your answer is encapsulated against
   it; only the owner (who holds the corresponding secret key) can
   decrypt.

2. **Trace chain.** Each response's `trace_hash` chains off the
   previous one. Auditors can replay the chain from the genesis hash
   to confirm no answer was suppressed or reordered, without ever
   seeing the cleartext.

3. **AEAD wrapping.** Optional — see
   `examples/seal-forms/src/aead.rs` for the wire format. The web
   client doesn't enable it by default so the trace-chain demo stays
   focused; production deployments would.

4. **MPC sum aggregation.** Numeric questions can use the additive-
   sharing variant in `src/mpc_sum.rs` so the form owner only learns
   the survey total.

5. **ZK statistics commitments.** `src/zk_stats.rs` posts a SHA3-based
   commitment to the per-row witness; future work swaps in a real
   risc0/sp1 proof so auditors can verify the sum without seeing the
   transcript.
