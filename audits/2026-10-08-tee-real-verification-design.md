# Real TEE attestation verification — design note

Date: 2026-10-08 · Status: **research-grade, design-doc + scaffold only; implementation DEFERRED.**
The attestation path is **fail-closed by construction** (item 11): the three `AttestationBackend`
stubs reject every non-empty report, so no TEE gate can be *bypassed* — but nothing real is
verified yet. This note designs what real verification would plug into.

## 1. Current state (validated against primary source, 2026-10-08)

Two separate, non-wired TEE subsystems:

**(A) `crates/seal-tee/` — the fail-closed backend stubs (the item-11 target).**
- `AttestationBackend` trait (`lib.rs:38-48`): `backend_name()`, `is_available()`,
  `verify_report(&[u8]) -> Result<Verdict, TeeError>`.
- Three backends, **all fail-closed** (`tee.rs`): `TdxVerifier` (Intel TDX, `tee.rs:162-182`),
  `SevSnpVerifier` (AMD SEV-SNP, `tee.rs:195-215`), `NvTdaVerifier` (NVIDIA NV-TDA, `tee.rs:228-248`).
  Each: empty report → `TeeError::EmptyReport`; **any non-empty report → `TeeError::VerificationFailed`**
  (`VerificationStatus::Failed`, "TEE not configured"). `is_available()` returns `false` for all.
- Report **schemas exist but are unverified**: `TdxReport { report_data, rtmr[4], misc_select }`
  (`types.rs:36-45`), `SevSnpReport { report_data, policy_version, policy }` (`types.rs:100-108`),
  `NvTdaReport { report_data, policy, attestation, device_identity }` (`types.rs:164-172`). All carry
  a `[0u8;64] report_data` field and placeholder policy/rtmr. `VerificationStatus` (`report.rs:113`)
  has `Pending/Success/Failed`.

**(B) `crates/seal-node/src/tee.rs` — the (dormant) node enclave.**
- `TeeEnclave` (`tee.rs:27-70`): `is_tee_enclave` hardcoded `false`, `tee_measurement`/`tee_report`
  empty, `is_trusted` = `is_tee_enclave`. **Never constructed by consensus; no production verifier
  consumes it.** It is the natural integration point for a real attestation generator.

**Absent (the real-verification gaps):** no DCAP/SEV-SNP/NV-TDA chain-of-trust verification, no
reference-measurement (expected MRENCLAVE/rtmr) store, no IAS/AMD/NVIDIA attestation-service
integration, no `report_data` binding to node identity. The only production caller is the
attestation RPC (`attestation.rs:260-293`), which is test-only; **consensus never consults TEE**
(`network_node.rs:700-766` verifies VRF + committee sig + state root only).

## 2. Real verification design

Each backend replaces its fail-closed stub with a real quote/report verification:

1. **Intel TDX (DCAP):** parse the TDX quote (v4/v5), verify the ECDSA P-384 signature chain up to
   the pinned Intel root CA, check `report_data` (binds the workload), and compare `MRENCLAVE`/
   `MRSIGNER`/`RTMR[0..4]` against a reference measurement.
2. **AMD SEV-SNP (VCK):** parse the report, verify the signature chain to the pinned AMD root,
   check `report_data`, `policy` version, and the measured guest hash against a reference.
3. **NVIDIA NV-TDA:** parse the report, verify the NVIDIA CA chain, check `report_data`, `policy`,
   and the `device_identity` attestation against a reference device roster.

Cross-cutting:
- **Reference-value store (the biggest missing piece):** a signed, versioned registry of expected
  measurements per attested workload (MRENCLAVE/rtmr/guest-hash + acceptable `report_data` policy).
  Verification is "quote valid *and* measurement matches a pinned reference" — a valid quote of the
  wrong workload must fail.
- **Root-of-trust pinning:** pin the vendor root CAs (do not blindly trust a remote attestation
  service's verdict); if using IAS/AMD/`nvidia`, verify the *attestation document's own signature*
  against the pinned root, not just accept its `valid` flag.
- **`report_data` binding + anti-replay:** `report_data` must bind the node's identity/epoch (e.g.
  a node nonce the verifier challenges) so a quote cannot be replayed across nodes or epochs.
- **Integration:** `TeeEnclave` populates a real `tee_report`/`tee_measurement` on startup; the
  dormant attestation RPC (`attestation.rs`) becomes the node-join gate; optionally the consensus
  path requires attestation for a privileged op set (off by default until real backends exist).
- **Fail-closed default preserved:** when no real backend + reference store is configured, keep the
  current reject-everything behavior as the safe default (a misconfigured node attests nothing).

## 3. Failure modes

Quote parse/length errors; chain-of-trust mis-pinning (trusting an untrusted CA); reference-value
staleness (a legit workload update fails until the reference registry is re-signed); `report_data`
replay; attestation-service availability (mitigate by self-verifying the quote signature locally and
treating the service as advisory).

## 4. Status

Research-grade; **design-doc + scaffold only, implementation deferred**. Deliverable is the corrected
framing (two subsystems, both dormant/fail-closed; report schemas exist; **no reference-measurement
store, no chain-of-trust, no report_data binding**; integration point is `TeeEnclave` + the dormant
attestation RPC). Revisit with a regression-first implementation per backend (§2), starting from the
reference-value store, keeping the fail-closed default when unconfigured.
