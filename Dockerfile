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
RUN cargo build --release -p seal-node

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/seal-node /usr/local/bin/seal-node

EXPOSE 4001

ENTRYPOINT ["seal-node"]
