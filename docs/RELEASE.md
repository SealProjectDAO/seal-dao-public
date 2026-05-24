# Releasing Seal DAO

The release pipeline is `scripts/release.sh` plus the ML-DSA-65
signing primitives in `seal-cli` (`sign-file` / `verify-file`).
There are no GitHub Actions workflows — releases run as a shell
script, the same way as the rest of CI (per `CLAUDE.md`).

## What a release contains

For version `${VERSION}` (e.g. `v0.1.0`), under `dist/`:

| Artifact                                            | Contents                                             |
| --------------------------------------------------- | ---------------------------------------------------- |
| `seal-node-${VERSION}-linux-x86_64`                 | Linux glibc binary (cross-built in `rust:1.94`)      |
| `seal-node-${VERSION}-linux-aarch64`                | Linux ARM64 binary (cross-built `--platform=linux/arm64`) |
| `seal-node-${VERSION}-darwin-aarch64`               | macOS ARM64 binary (host-built; only on Apple Silicon) |
| `SHA256SUMS`                                        | One SHA-256 line per binary, filenames sorted        |
| `SHA256SUMS.sig`                                    | ML-DSA-65 detached signature over `SHA256SUMS`'s SHA3 hash |
| `SHA256SUMS.sig.pubkey`                             | Verifying-key hex matching the signing key          |
| `seal-node-${VERSION}.tar.gz`                       | Tarball of all of the above for one-shot upload      |

Plus a Docker image tagged `ghcr.io/seal-dao/seal-node:${VERSION}`.

## Why ML-DSA, not minisign / cosign / sigstore

Per `CLAUDE.md` the project is **post-quantum first**: classical
crypto is only allowed in bridge modules. Using a classical-only
sigstore flow for our own release signatures would contradict
that policy. The signing primitive
(`crates/seal-crypto::SigningKey`) is the same ML-DSA-65 the
chain itself uses — operators verifying a release run the same
verifier (`seal verify-file`) that any consensus participant
already has on their host.

`SHA256SUMS` itself stays SHA-256 because (a) it's a content
manifest, not a signature, and (b) `shasum -a 256` is universal
on every BSD / Linux box. The PQ commitment lives in
`SHA256SUMS.sig`.

## Prerequisites

- Docker daemon running. Linux cross-builds run inside
  `rust:1.94-bookworm` containers per `scripts/release.sh`, so the
  host toolchain only needs to compile the macOS binary (when run
  on Apple Silicon). There is no `rust-toolchain.toml` in the
  workspace today — the version pin lives inside the release script.
- A release keypair generated with `seal keygen`. **Back it up.**
  Losing it means future releases can't sign under the same
  identity, so existing downstream consumers will start seeing
  pubkey-mismatch errors.

```bash
cargo run -p seal-cli -- keygen --output release-key.json
# back release-key.json up to a hardware-secured location;
# operator team policy is to keep it offline between releases.
```

## Cutting a release

```bash
# Dry run — produces dist/ artifacts, builds the Docker image
# locally, but does NOT push to ghcr.io.
./scripts/release.sh --version v0.1.0 --key release-key.json
```

The script:

1. Builds three binaries (Linux x86_64 / Linux ARM64 / macOS
   ARM64-on-host) with `target-dir` set to per-target
   subdirectories so the host `target/` cache stays usable.
2. Writes `SHA256SUMS` (filenames sorted, line format matching
   `sha256sum`).
3. ML-DSA-signs `SHA256SUMS` via `seal sign-file`, immediately
   re-verifies via `seal verify-file`, and refuses to ship a
   signature that doesn't verify against its own pubkey.
4. Builds `dist/seal-node-${VERSION}.tar.gz` containing
   binaries + sums + sig + sig.pubkey for one-shot upload to
   a release channel.
5. Builds the Docker image `ghcr.io/seal-dao/seal-node:${VERSION}`.
6. Prints the verifier recipe a downloader runs.

## Pushing to ghcr.io

The default mode is dry-run. To publish:

```bash
RELEASE_PUBLISH=1 ./scripts/release.sh --version v0.1.0 --key release-key.json
```

This is the only operation the script does that's externally
visible — until `RELEASE_PUBLISH=1` is set, nothing leaves the
host. CI / cron / a stray `bash scripts/release.sh` shortcut
all stay safe.

## Verifying a release as a downloader

```bash
# 1. sums match
shasum -a 256 -c SHA256SUMS

# 2. ML-DSA signature on SHA256SUMS verifies against
#    the project's release pubkey
cargo run -p seal-cli -- verify-file SHA256SUMS \
    --pubkey-hex "$(cat SHA256SUMS.sig.pubkey)" \
    --sig-file SHA256SUMS.sig
```

Step 2 returns exit 0 + "OK ..." on success, exit 1 + "FAIL ..."
on a tampered file or wrong pubkey. CI consumers should pin the
expected pubkey rather than trusting `SHA256SUMS.sig.pubkey`
out of the same archive: a malicious upstream could swap both
the sig and the pubkey but a pinned pubkey detects this.

## Pinning the release pubkey

The first release establishes the public-key identity. After
that, downstream consumers should pin the hex once and verify
all future releases against it:

```bash
RELEASE_PUBKEY="<hex from the first release>"
cargo run -p seal-cli -- verify-file SHA256SUMS \
    --pubkey-hex "$RELEASE_PUBKEY" \
    --sig-file SHA256SUMS.sig
```

Rotating the release key is a deliberate, announced operation
— same shape as a CA root rotation. Document the new pubkey
prominently in the release notes that change it.

## What this script doesn't do (yet)

- **No GitHub release creation.** The `dist/` tarball is ready
  for upload; the actual "publish to release channel" step is
  manual today (the same way `bridge-testnet-demo.sh` is
  manual). The hook to call `gh release create` is a one-line
  follow-up under the `RELEASE_PUBLISH=1` branch.
- **No reproducible-build attestation.** The Docker-cross
  builds are byte-deterministic in practice today (same Rust
  image, same source tree, same target directories), but we
  don't yet emit a SLSA-style provenance file. Open issue
  for the next mainnet-prerequisite push.
- **No multi-signer / threshold release signing.** The current
  signature is from a single ML-DSA key. Using
  `seal-threshold`'s scheme to require N-of-M operator
  signatures on the release manifest is a future hardening —
  out of scope for testnet readiness.

## Files

- `scripts/release.sh` — driver
- `crates/seal-cli/src/main.rs::run_sign_file` — ML-DSA detached signing
- `crates/seal-cli/src/main.rs::run_verify_file` — verifier
- `Dockerfile` — the multi-stage container image used in step 5
