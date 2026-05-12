# Cyber Security Audit Tool

A lightweight HTTP security event collector and threat analyzer written in **Go** (standard library only — no external router).

## Tech Stack
- **Language**: Go 1.22+
- **Framework**: `net/http` (stdlib)
- **Architecture**: Clean layered (cmd → internal/api → internal/audit)
- **Concurrency**: `sync.RWMutex` for thread-safe event store

## Getting Started

```bash
# Download dependencies
go mod tidy

# Run (default port 9000)
go run ./cmd/server

# Build binary
go build -o bin/cyber-audit ./cmd/server
./bin/cyber-audit
```

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Service health check |
| `POST` | `/api/events` | Ingest a security event |
| `GET` | `/api/events` | List all collected events |
| `GET` | `/api/threats` | Run threat analysis |
| `GET` | `/api/report` | Full audit report |

## Ingesting an Event

```bash
curl -X POST http://localhost:9000/api/events \
  -H "Content-Type: application/json" \
  -d '{
    "type": "LOGIN_ATTEMPT",
    "source_ip": "192.168.1.100",
    "severity": "WARNING",
    "payload": "Failed auth for user admin"
  }'
```

## Threat Detection Rules

| Threat | Trigger |
|--------|---------|
| `BRUTE_FORCE` | >10 `LOGIN_ATTEMPT` from same IP within 60 seconds |
| `PORT_SCAN` | >5 `PORT_SCAN` events from same IP |

## Project Structure

```
cmd/server/         # Entrypoint (main.go)
internal/
├── api/            # HTTP handlers
└── audit/          # Domain: types, store, analyzer
```

## Author
Emmanuel García — [emmanuelg@allcognition.com](mailto:emmanuelg@allcognition.com)
