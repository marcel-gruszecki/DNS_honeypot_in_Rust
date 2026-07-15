# DNS Honeypot

A high-performance, asynchronous DNS honeypot written in Rust. It listens for DNS queries over both UDP and TCP, logs every request to a SQLite database, and automatically classifies traffic patterns associated with common attack techniques.

## Features

- **Dual-protocol support** — handles DNS over UDP and TCP simultaneously
- **Persistent logging** — every query is stored in SQLite with full metadata (client IP, port, query type, timestamp)
- **Automatic attack classification** — a background job runs hourly and categorises collected traffic into threat classes
- **Deceptive responses** — returns plausible-looking but fake records to slow down reconnaissance
- **Containerised** — ships as a two-container Docker Compose stack with a built-in web UI for the database

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Rust (edition 2024) |
| Async runtime | Tokio |
| DNS parsing | hickory-server |
| Database | SQLite via SQLx |
| Containerisation | Docker / Docker Compose |
| DB viewer | sqlite-web |

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │           DNS Honeypot              │
UDP :53 ──────────▶ │  udp_module  ──┐                    │
                    │                ├──▶  dns.rs         │
TCP :53 ──────────▶ │  tcp_module  ──┘   (parse & spoof)  │
                    │                        │            │
                    │               database.rs           │
                    │          (log + hourly analysis)    │
                    └──────────────┬──────────────────────┘
                                   │
                              SQLite DB
                                   │
                    ┌──────────────▼──────────────────────┐
                    │  sqlite-web  :8080  (read-only UI)  │
                    └─────────────────────────────────────┘
```

## Database Schema

### `logs` — raw request log

| Column | Description |
|---|---|
| `id` | Auto-incremented primary key |
| `timestamp` | Event time with millisecond precision |
| `day` | Date in `YYYY-MM-DD` format (for aggregation) |
| `question` | Domain name queried by the client |
| `question_length` | Length of the queried domain in characters |
| `response` | Spoofed response data returned by the honeypot |
| `server_ip` | Local interface address that received the packet |
| `server_port` | Listening port (default: 53) |
| `client_ip` | Source IP of the querying host |
| `client_port` | Source port of the querying host |
| `q_type` | DNS record type (A, AAAA, TXT, AXFR, …) |

### `daily_summary` — aggregated threat report

| Column | Description |
|---|---|
| `day` | Date covered by this summary (primary key) |
| `by_class` | Threat class name (primary key) |
| `total_events` | Total incidents of this class on the given day |
| `first_seen` | Timestamp of the first event |
| `last_seen` | Timestamp of the most recent event |

## Attack Classification

The analysis engine runs every hour and writes results to `daily_summary`:

| Class | Detection criteria |
|---|---|
| **Flood Attack** | More than 60 queries per minute from a single IP |
| **Zone Transfer** | Queries with type `AXFR`, `IXFR`, or `SOA` |
| **DNS Tunneling** | Queried domain name longer than 60 characters |
| **Amplification Attempt** | Queries with type `ANY` or `TXT` |
| **Forbidden Domain** | Domain listed in `data/forbidden_domains.txt` |

Logs older than 3 days are purged automatically to keep the database small.

## Quick Start

### Prerequisites

- Docker and Docker Compose

### 1. Prepare data directory

```bash
mkdir -p data
touch data/forbidden_domains.txt   # add one domain per line to track
```

### 2. Start the stack

```bash
sudo docker compose up -d --build
```

### 3. View collected data

Open the database UI in your browser:

```
http://localhost:8080
```

### 4. Check logs

```bash
docker compose logs -f honeypot
```

### 5. Stop and remove

```bash
sudo docker compose down -v
```

## Testing

Send various DNS query types against the honeypot to generate test data:

```bash
TARGET="127.0.0.1"
PORT="53"

# Zone Transfer attempt
dig @$TARGET -p $PORT example.com AXFR
dig @$TARGET -p $PORT example.com IXFR

# DNS Tunneling (query > 60 characters)
LONG="v1-a5b6c7d8e9f0g1h2i3j4k5l6m7n8o9p0q1r2s3t4u5v6w7x8y9z0.example.com"
dig @$TARGET -p $PORT $LONG A

# Amplification attempt
dig @$TARGET -p $PORT google.com ANY
dig @$TARGET -p $PORT google.com TXT

# Forbidden domain (add the domain to data/forbidden_domains.txt first)
dig @$TARGET -p $PORT forbidden.example.com A

# Flood simulation (triggers at 60 req/min)
for i in {1..65}; do
    dig @$TARGET -p $PORT flood-test-$i.com A +short > /dev/null 2>&1
done
```

## License

MIT — see [LICENSE](LICENSE) for details.
