# Seal DAO Node — Multi-stage Dockerfile
#
# Build: docker build -t seal-node .
# Run:   docker run -it seal-node
# Multi-node: docker-compose up (see docker-compose.yml)

# Match the host dev env (`rustc --version` → 1.94.1). The MSRV from
# the dependency graph keeps rising — `vendor/risc0-groth16-5.0.0-rc.1`
# needs `edition = "2024"` (Rust 1.85+) and the transitive `icu_*`
# family (via `idna`/`url`) bumps that to 1.86+. Pinning to the
# workspace's actual Rust (1.94.1 per STATUS.md) keeps Docker builds
# byte-identical to what we ship locally and absorbs future MSRV
# bumps without Dockerfile churn.
FROM rust:1.94-bookworm AS builder

WORKDIR /app
COPY . .
# seal-cli is built alongside seal-node so the entrypoint can run
# `seal keygen` to materialize a persistent --validator-key on
# first boot when one isn't already mounted in. The bin name is
# `seal` (per seal-cli's [[bin]] declaration), not `seal-cli`.
# seal-registration is built so docker-compose can stand up the
# validator-onboarding portal as a sibling service. seal-faucet
# is also built but requires a funded key the compose can't
# bootstrap on first boot — operators run it out-of-band.
RUN cargo build --release -p seal-node -p seal-cli -p seal-registration -p seal-faucet

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/seal-node /usr/local/bin/seal-node
COPY --from=builder /app/target/release/seal /usr/local/bin/seal
COPY --from=builder /app/target/release/seal-registration /usr/local/bin/seal-registration
COPY --from=builder /app/target/release/seal-faucet /usr/local/bin/seal-faucet

# Entrypoint script keeps validator identity stable across container
# restarts. If SEAL_VALIDATOR_KEY is set and the file doesn't exist
# yet, run `seal keygen` to create it. Then exec seal-node with the
# original args plus `--validator-key <path>` appended.
#
# Operators who supply their own keyfile via a bind mount get
# detected (the file already exists) and skip the keygen path.
COPY --from=builder /app/docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 4001

ENTRYPOINT ["entrypoint.sh"]
