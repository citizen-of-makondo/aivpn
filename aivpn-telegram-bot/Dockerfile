FROM rust:1.86-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml ./
COPY aivpn-common aivpn-common/
COPY aivpn-server aivpn-server/
COPY aivpn-client aivpn-client/
COPY aivpn-android-core aivpn-android-core/
COPY aivpn-admin aivpn-admin/
COPY aivpn-telegram-bot aivpn-telegram-bot/
COPY aivpn-windows aivpn-windows/

RUN cargo build --release --bin aivpn-telegram-bot

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/aivpn-telegram-bot /usr/local/bin/aivpn-telegram-bot

ENTRYPOINT ["/usr/local/bin/aivpn-telegram-bot"]
