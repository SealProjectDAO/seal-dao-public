# Integration request — quantum multi-repo extension (OPTIONAL / not on critical path)

> Deferred and optional. Master plan: `../../../quantum/future/PLAN-AHEAD.md`;
> full asks: `../../../quantum/future/requests/REQUESTS.md`.

**Decision (2026-06-04):** the `llm-inference-tune` harness will **not** take a direct dependency on
`seal-dao-master`. It is a PQC *blockchain* monorepo; the only thing relevant here was crypto utils,
which are already covered by **libcrux** (upstream ML-KEM/ML-DSA) and `service-network::sn-crypto` /
`sn-identity`.

**If** a seal-specific helper is ever needed (e.g. the hybrid ML-KEM+X25519 combiner in
`crates/seal-crypto/src/hybrid_kem.rs`), the agreed approach is to **extract that one file into a
tiny standalone crate** — not to `path`-dep this repo. No action required here.
