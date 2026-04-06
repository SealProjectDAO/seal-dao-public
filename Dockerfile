# Seal DAO Node — Multi-stage Dockerfile
#
# Build: docker build -t seal-node .
# Run:   docker run -it seal-node
# Multi-node: docker-compose up (see docker-compose.yml)

FROM rust:1.82 AS builder

WORKDIR /app
COPY . .
RUN cargo build --release -p seal-node

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/seal-node /usr/local/bin/seal-node

EXPOSE 4001

ENTRYPOINT ["seal-node"]
