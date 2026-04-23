# Metal-Accelerated STARK Proving — Current State & Path Forward

Status as of 2026-04-18 (RISC Zero 5.0.0-rc.1, vendored).

## TL;DR

On an Apple Silicon Mac with full Xcode 16 + the `MetalToolchain`
component, we can:

- compile the `risc0-zkvm/metal` feature,
- produce a real `metal_kernels_zkp.metallib` (~117 KB),
- run `RISC0_DEV_MODE=0` end-to-end prove + verify successfully.

But we **do not yet get a segment-prover speed-up** from Metal. Upstream
risc0 wires Metal into the *recursion* HAL only; the *segment* HAL
(where 90%+ of wall-time lives for typical guests) has CPU and CUDA
branches only. The C++ Metal HAL for the segment prover actually exists
in vendored sources but is commented out in the build script. This doc
lays out what's there, what's missing, and the realistic DIY paths.

## What lives where

| Piece | Location | Metal-ready? |
|---|---|---|
| risc0-zkp Metal primitives (NTT, MSM, Poseidon, SHA) | `vendor/risc0-zkp/src/core/hash/sha/*.rs` + kernels shipped by risc0-sys | ✅ present, `.metallib` built on every macOS build |
| Recursion-circuit Metal HAL | `vendor/risc0-circuit-recursion/src/prove/hal/metal.rs` | ✅ wired via `risc0-zkvm/metal` feature |
| **Segment (RV32IM) Metal HAL** — C++ | `vendor/risc0-circuit-rv32im-sys/cxx/hal/metal/hal.cpp` (609 lines) | ⚠ source present, **not compiled** — see "Upstream gap" below |
| Segment prover FFI entry points | `vendor/risc0-circuit-rv32im-sys/cxx/rv32im/ffi.cpp:254-266` | Only `new_cpu` and `new_cuda`; no `new_metal` |
| Segment prover Rust selection | `vendor/risc0-circuit-rv32im/src/prove.rs:193-199` | `cfg_if!` branches CPU ↔ CUDA only |
| Our own GPU abstraction | `crates/seal-zk/src/gpu.rs` | Backend enum + env plumbing only; no kernels |

## Host we validated on

- Apple Silicon (M-series, 10 cores, 16 GB)
- Xcode 16 at `/Applications/Xcode.app`
- `MetalToolchain` 17A324 (downloaded via `xcodebuild -downloadComponent MetalToolchain`)
- `xcrun metal --version` → `Apple metal version 32023.830`
- `r0vm 5.0.0-rc.1` on PATH

Activation command we used (all one line):

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  cargo build -p seal-zk --features "risc0 local-prover risc0-zkvm/metal" --release
```

Test result: prove OK, verify OK, 205 842-byte receipt. Wall-time
was ~17 s vs ~10.9 s for the CPU-only build — the ~6 s is Metal-device
/ library-load overhead that's not amortised on a tiny guest.

## Upstream gap (why Metal doesn't accelerate the segment prove today)

### 1. `segment_prover` has no Metal branch

`vendor/risc0-circuit-rv32im/src/prove.rs:192-201`:

```rust
pub fn segment_prover(po2: usize) -> Result<ProverContext> {
    cfg_if! {
        if #[cfg(feature = "cuda")] {
            let segment_prover = ProverContext::new_cuda(po2)?;
        } else {
            let segment_prover = ProverContext::new_cpu(po2)?;
        }
    }
    Ok(segment_prover)
}
```

No `#[cfg(feature = "metal")]` arm.

### 2. FFI has no `new_metal`

`vendor/risc0-circuit-rv32im-sys/cxx/rv32im/ffi.cpp:254-266`:

```cpp
ProverContext* risc0_circuit_rv32im_m3_prover_new_cpu(size_t po2)  { ... getCpuHal() ... }
ProverContext* risc0_circuit_rv32im_m3_prover_new_cuda(size_t po2) { ... getGpuHal() ... }
// no risc0_circuit_rv32im_m3_prover_new_metal
```

`getGpuHal()` is defined in both `hal/cuda/hal.cpp:507` and
`hal/metal/hal.cpp:608`, so at the C++ level the symbol would resolve
to whichever `hal.cpp` is compiled in. But:

### 3. The build script leaves Metal out

`vendor/risc0-circuit-rv32im-sys/build.rs:24-26, 93-96, 238-…` — the
`PLATFORM_METAL`, `is_metal()`, and the "compile `cxx/hal/metal/hal.cpp`
+ metal kernels" block are all **commented out**:

```rust
// const PLATFORM_METAL: Platform = Platform::new("metal", "metal", "hal/metal/kernels");
...
// if is_metal() {
//     build
//         .file("cxx/hal/metal/hal.cpp")
//         .files(glob_paths("cxx/hal/metal/kernel/*.metal"));
// } else
if is_cuda() {
    ...
}
...
// fn is_metal() -> bool { ... }
```

So even though `hal.cpp` has a 609-line `MetalHal`, the C++ isn't
compiled, no symbol ever ships, and enabling `risc0-zkvm/metal` at the
top-level only affects the recursion HAL.

The commented-out state is almost certainly because the segment
Metal HAL isn't feature-complete upstream (some kernels incomplete,
or divergence between Metal Shading Language capabilities and what
the CUDA kernels do). It's plausible code-reading work to close the
gap, not a greenfield port.

## How we'd add real segment Metal support

Three tiers of ambition, pick based on time budget.

### Option A — minimal: fork `risc0-circuit-rv32im-sys`, un-comment the Metal path

Low-risk baseline that validates whether upstream's half-done Metal HAL
already works.

1. In a Seal-owned fork of `risc0-circuit-rv32im-sys` (we already vendor
   it — just edit in place or hold a local patch in `vendor-patches/`):
   - Uncomment `PLATFORM_METAL`, `is_metal()`, and the Metal `build`
     block in `build.rs`.
   - Gate `is_metal()` on a new `metal` Cargo feature (add it to that
     crate's `[features]`).
   - Add a `risc0_circuit_rv32im_m3_prover_new_metal(po2)` FFI entry
     in `cxx/rv32im/ffi.cpp` mirroring `new_cuda` but calling
     `getGpuHal()` (which on macOS resolves to the Metal impl).
   - Export it in `src/lib.rs` extern block.

2. In a Seal-owned fork of `risc0-circuit-rv32im`:
   - Add `metal = ["risc0-circuit-rv32im-sys/metal"]` feature.
   - Extend the `cfg_if!` in `prove.rs:193` with a Metal arm calling
     `ProverContext::new_metal(po2)`.

3. In our `risc0-zkvm` vendored copy: wire `metal = [...]` through the
   same way `cuda` is wired.

4. In `crates/seal-zk/Cargo.toml`: make `gpu-metal` actually pull
   `risc0-zkvm/metal` (we currently keep it detached because the
   unified feature resolver tried to resolve `cust` which isn't in
   vendor — adding an owned `metal` feature that doesn't chain through
   `cuda` avoids that).

**Expected outcome**: one of
- kernels already work → instant wins, run the benchmark and merge;
- a subset of kernels is stubbed → compile error or runtime assert
  pinpointing exactly which stage needs a Metal shader written (next
  tier).

**Cost**: ~1 day if kernels are complete; ~1 week if we hit missing
kernels and have to write them.

### Option B — medium: write the missing Metal kernels ourselves

If Option A's forked build errors out on a missing Metal Shading
Language file, write each one. The kernel set used by the segment
prover is small and well-defined (NTT, eltwise, FRI fold, Poseidon2,
SHA, mix, zk). The CUDA versions live at
`vendor/risc0-sys/kernels/zkp/cuda/{eltwise.cu,fri_prove.cu,ntt supra/ntt.cu,poseidon2.cu,sha.cu,...}`
and the recursion-side Metal versions at
`vendor/risc0-sys/kernels/zkp/metal/{eltwise,fri,mix,ntt,poseidon2,sha,zk}.metal`
are a good template.

Per-kernel workflow:

1. Open the CUDA `.cu` file, extract the core kernel (compute grid,
   memory accesses, per-thread work).
2. Translate to MSL: replace `__global__` with `kernel`,
   `threadIdx.x` with `[[thread_position_in_threadgroup]]`, CUDA
   texture/shared memory with MTLBuffer / threadgroup memory.
3. Compile with `xcrun -sdk macosx metal -c` and link into the
   `metal_kernels_rv32im.metallib` output.
4. Match it into the C++ HAL's kernel dispatch table (names must line
   up with what `hal.cpp` expects — grep for the corresponding
   `loadKernel("...")` call).
5. Cross-check numeric output against the CPU HAL on a BabyBear field
   element test (this is what `vendor/risc0-circuit-rv32im-sys/cxx/hal/test/test.cpp`
   already does for CPU vs CUDA — we just add a Metal column).

The BabyBear prime (2^31 − 2^27 + 1) fits in 32-bit words, so MSL
native u32 arithmetic is fine. No bignum/carry plumbing, unlike the
elliptic-curve MSMs used by Groth16 provers (which would actually need
multi-word arithmetic in MSL).

**Cost**: ~3–6 weeks for one engineer familiar with GPU proving. Eltwise
and SHA are almost mechanical ports; the NTT and FRI kernels are the
two real pieces of work.

### Option C — max: run GPU-accelerated field arithmetic as a drop-in
"Metal backend" under `seal-zk`

Instead of forking vendor crates, let risc0 keep running CPU for the
prover itself and offload just the hot inner loops (NTT, MSM over
BabyBear) to Metal from within our own crate. This is what
`crates/seal-zk/src/gpu.rs::metal_accel` already sketches (currently
estimate-only, lines 847–894).

Approach:

1. Add `metal` crate (0.29 — already a dep of risc0-circuit-recursion)
   to `seal-zk`'s `[target.'cfg(target_os = "macos")'.dependencies]`.
2. Write a `seal-zk/src/metal_ntt.rs` module with `forward_ntt`,
   `inverse_ntt`, `elementwise_mul` over the BabyBear field, each
   backed by a MSL shader we ship in `crates/seal-zk/metal/*.metal`.
3. Provide a `trait FieldAccel` and have the host-side prover code
   route NTT calls through it when `SEAL_GPU_BACKEND=metal` is set.

**This doesn't speed up risc0's prover** — risc0 uses its own NTT path
that we can't intercept without forking. But it would accelerate
*our own* pre/post-processing, and it gives us a local testbed for
Metal Shading Language without forking anything.

**Cost**: ~1 week for the plumbing + one NTT kernel; low risk, but
also lower payoff than Option A/B.

## Recommendation

1. **First do Option A.** It's a day of work and it tells us whether
   upstream's commented-out Metal HAL is simply WIP or deliberately
   broken. If it works, we get Metal segment proving for free.

2. **If Option A surfaces missing kernels, evaluate whether we need
   them.** For Seal's workloads the guest is small (≈80-byte journal,
   a handful of tx iterations). A 6× segment speed-up on a 10-second
   CPU prove is a 1.7s proof — nice, but not urgent compared to the
   MPC/Ringtail audit backlog.

3. **Revisit after RISC Zero 5.1.** Upstream may land the Metal segment
   HAL without us, since the C++ is already there. Check release notes
   at each vendor-update cycle (`scripts/vendor-update.sh`).

4. **Keep CUDA as the first-class GPU path.** The rv32im segment prover
   already supports CUDA end-to-end; it's the only `cfg_if` branch that
   lights up today. A single NVIDIA dev box is a better investment than
   polishing Metal until upstream catches up.

## Validation bench

Once real Metal support lands, validate with:

```bash
# Before:
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  SEAL_RUN_REAL_RISC0=1 RISC0_DEV_MODE=0 RUST_MIN_STACK=33554432 \
  /usr/bin/time -l cargo test -p seal-zk \
    --features "risc0 local-prover" --release \
    test_risc0_real_prove_and_verify -- --nocapture

# After:
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  SEAL_RUN_REAL_RISC0=1 RISC0_DEV_MODE=0 RUST_MIN_STACK=33554432 \
  /usr/bin/time -l cargo test -p seal-zk \
    --features "risc0 local-prover risc0-zkvm/metal" --release \
    test_risc0_real_prove_and_verify -- --nocapture
```

Success criterion: wall-time after < wall-time before, and `VERIFY`
still passes. Expected ballpark on M-series with a real Metal segment
HAL: 2–4× speed-up on a guest large enough to hide device-setup
overhead (≥10 s CPU baseline). For our current 10.9 s baseline we
should see ≤5 s if Metal is genuinely engaged.
