FROM rust:1.85-slim as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y libsqlite3-0 ca-certificates && rm -rf /var/lib/apt/lists/*

CMD touch ./forbidden.txt && ./honeypot_dns

COPY --from=builder /app/target/release/DNS_honeypot /app/honeypot_dns

RUN chmod +x /app/honeypot_dns

EXPOSE 53/udp
EXPOSE 53/tcp

# Uruchamiamy bezpośrednio
CMD ["./honeypot_dns"]