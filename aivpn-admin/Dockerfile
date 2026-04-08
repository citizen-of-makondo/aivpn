FROM rust:1.86-slim AS builder

WORKDIR /app

COPY . .

RUN cargo build --release --bin aivpn-admin

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/aivpn-admin /usr/local/bin/aivpn-admin

EXPOSE 8081

ENTRYPOINT ["/usr/local/bin/aivpn-admin"]
