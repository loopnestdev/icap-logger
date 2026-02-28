# icap-logger

A **production-ready ICAP (Internet Content Adaptation Protocol) server** written in Go that logs incoming request and response bodies to a file in structured JSON format. It is intended for traffic inspection and debugging — it never modifies content and always responds with `204 No Modifications`.

---

## Features

- Parses `REQMOD` and `RESPMOD` ICAP requests
- Decodes chunked HTTP bodies
- **Smart body logging** — prints plain text payloads as-is; replaces binary data, file uploads, and blobs with safe metadata summaries
- Structured JSON logging to stdout via `log/slog`
- Built-in log rotation (no external dependencies)
- Graceful shutdown on `SIGTERM` / `SIGINT`
- HTTP health check endpoint (`/healthz`)
- Fully configurable via environment variables and CLI flags
- Non-root hardened Docker image
- Read-only container filesystem
- Resource limits via Docker Compose

---

## How It Works

1. Listens on TCP port `1344` (configurable via `ICAP_PORT`) for incoming connections
2. Parses each ICAP request (`REQMOD` / `RESPMOD`)
3. Extracts ICAP headers, encapsulated HTTP headers, and chunked body content
4. Sanitises the body before logging — text payloads are printed; binary/file content is replaced with metadata
5. Writes a structured JSON log entry to `/var/log/icap_bodies.log` (configurable via `LOG_FILE`)
6. Responds with `ICAP/1.0 204 No Modifications`
7. Exposes `/healthz` on port `8080` (configurable via `HEALTH_PORT`)

### Log entry format

```json
{
  "timestamp": "2026-02-27T10:00:00Z",
  "icap_method": "REQMOD",
  "icap_url": "icap://proxy/reqmod",
  "icap_headers": { "Host": "proxy", "Encapsulated": "req-hdr=0, req-body=47" },
  "req_method": "POST",
  "req_path": "/submit",
  "destination_url": "http://example.com/submit",
  "req_headers": { "Host": "example.com", "Content-Length": "5" },
  "req_body": "hello",
  "resp_status": "200 OK",
  "resp_headers": { "Content-Type": "text/plain" },
  "resp_body": "world"
}
```

### Body logging behaviour

The `req_body` and `resp_body` fields follow these rules:

| Body type | Example `Content-Type` | Logged as |
|---|---|---|
| Plain text (JSON, XML, form data) | `application/json`, `text/plain` | ✅ Full content |
| Binary blob (image, PDF, zip, exe) | `image/jpeg`, `application/zip` | `[binary: 8192 bytes]` |
| Multipart file upload — file part | `multipart/form-data` | `[file: "report.pdf", content-type: "application/pdf", 204800 bytes]` |
| Multipart file upload — text field | `multipart/form-data` | `[field: "username" = "alice"]` |
| Multipart file upload — binary field | `multipart/form-data` | `[field: "data", binary, 1024 bytes]` |

Binary detection samples the first 512 bytes — if more than 10% are non-printable, the body is treated as binary.

---

## Prerequisites

### Running locally (Go)

| Requirement | Version | Install |
|---|---|---|
| Go | 1.24+ | `brew install go` |
| macOS / Linux | — | — |
| Write access to `/var/log/` | — | Required in production |

```bash
go version
```

### Running with Docker

| Requirement | Install |
|---|---|
| Docker | [docs.docker.com](https://docs.docker.com/get-docker/) |
| Docker Compose | Included with Docker Desktop |

```bash
docker --version
docker compose version
```

---

## Environment Variables

All settings are configurable via environment variables. CLI flags `--port=` and `--log=` take precedence over env vars.

| Variable | Default | CLI Flag | Description |
|---|---|---|---|
| `ICAP_PORT` | `1344` | `--port=` | ICAP server listen port |
| `LOG_FILE` | `/var/log/icap_bodies.log` | `--log=` | JSON log output file |
| `LOG_ROTATE_SIZE_MB` | `25` | `--log-rotate-size=` | Rotate log file after this many MB |
| `MAX_BODY_SIZE` | `10485760` | — | Max request body size in bytes (10 MB) |
| `READ_TIMEOUT_SEC` | `30` | — | TCP read timeout in seconds |
| `WRITE_TIMEOUT_SEC` | `10` | — | TCP write timeout in seconds |
| `HEALTH_PORT` | `8080` | — | HTTP health check listen port |

---

## Project Structure

```
icap-logger/
├── main.go             # Entry point — main(), signal handling, server bootstrap
├── config.go           # Config struct, loadConfig(), getEnv(), getEnvInt()
├── server.go           # handleConn() — reads, parses, logs, responds
├── parser.go           # parseICAP(), splitEncapsulated(), headersToMap()
├── logger.go           # rotatingWriter — size-based log rotation (stdlib only)
├── body.go             # sanitizeBody(), isBinary(), parseMultipartBody(), decodeChunked()
├── types.go            # Config, icapInfo, logEntry struct definitions
├── main_test.go        # Unit tests for ICAP parsing (13 tests)
├── go.mod              # Go module (no external dependencies)
├── Dockerfile          # Multi-stage hardened Alpine build
├── docker-compose.yml  # Full production Compose config
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

> **No external dependencies.** Log rotation, binary detection, and multipart parsing are all implemented using the Go standard library only.

---

## Build

### Go binary

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/icap-logger.git
cd icap-logger

# Build the binary
go build -o icap-logger .
```

### Docker image

```bash
docker build -t icap-logger:1.0.0 .
```

---

## Run

### Option 1 — Go binary

#### Production (requires sudo — binds to port 1344, writes to /var/log/)

```bash
sudo ./icap-logger
```

#### Local dev with custom port, log file, and rotation size (no sudo needed)

```bash
go run main.go --port=11344 --log=/tmp/icap.log --log-rotate-size=10
```

#### Via environment variables

```bash
ICAP_PORT=11344 LOG_FILE=/tmp/icap.log LOG_ROTATE_SIZE_MB=10 go run main.go
```

#### Available flags

| Flag | Default | Description |
|---|---|---|
| `--port=` | `1344` | TCP port to listen on |
| `--log=` | `/var/log/icap_bodies.log` | Path to the log output file |
| `--log-rotate-size=` | `25` | Rotate log file after N MB |

---

### Option 2 — Docker Compose (recommended)

The provided `docker-compose.yml` runs the server on a custom port (`11344`) and maps the log file to a local `./logs/` directory on the host.

```bash
# Start in background
docker compose up -d

# Tail the log directly on your host
tail -f ./logs/icap_bodies.log

# Check health
curl http://localhost:8080/healthz

# Stop
docker compose down

# Rebuild after code changes
docker compose up -d --build
```

The `docker-compose.yml` is pre-configured with:
- **ICAP Port**: `11344` (host) → `11344` (container)
- **Health Port**: `8080` (host) → `8080` (container)
- **Log file**: `/var/log/icap_bodies.log` inside the container → `./logs/` on the host
- **Log rotation**: every `25` MB (configurable via `LOG_ROTATE_SIZE_MB`)
- **Restart policy**: `unless-stopped`
- **Health check**: polls `/healthz` every 30 seconds
- **Resource limits**: 256 MB RAM, 0.5 CPU
- **Security**: non-root user, `no-new-privileges`, read-only filesystem, tmpfs `/tmp`

---

### Option 3 — Docker run (manual)

```bash
# Custom port, log path and rotation size
docker run -d \
  --name icap-logger \
  -p 11344:11344 \
  -p 8080:8080 \
  -e ICAP_PORT=11344 \
  -e LOG_FILE=/var/log/icap_bodies.log \
  -e LOG_ROTATE_SIZE_MB=25 \
  -e MAX_BODY_SIZE=10485760 \
  -e HEALTH_PORT=8080 \
  -v $(pwd)/logs:/var/log \
  --read-only \
  --tmpfs /tmp \
  icap-logger:1.0.0
```

---

## Test Without a Proxy (using `nc`)

Start the server on a non-privileged port:

```bash
go run main.go --port=11344 --log=/tmp/icap.log
```

In a second terminal, tail the log:

```bash
tail -f /tmp/icap.log
```

### Send a REQMOD request with a plain text body

```bash
printf "REQMOD icap://localhost/reqmod ICAP/1.0\r\nHost: localhost\r\nEncapsulated: req-hdr=0, req-body=47\r\n\r\nPOST /submit HTTP/1.1\r\nHost: example.com\r\n\r\n5\r\nhello\r\n0\r\n\r\n" | nc localhost 11344
```

### Send a RESPMOD request with a plain text body

```bash
printf "RESPMOD icap://localhost/respmod ICAP/1.0\r\nHost: localhost\r\nEncapsulated: res-hdr=0, res-body=38\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n5\r\nworld\r\n0\r\n\r\n" | nc localhost 11344
```

### Expected server response

```
ICAP/1.0 204 No Modifications
Connection: close
```

---

## Run Tests

```bash
# Run all tests
go test ./...

# Run all tests with verbose output
go test ./... -v

# Run a single test by name
go test ./... -run TestParseICAP_ReqMod_WithBody

# Run with race detector and coverage
go test ./... -race -coverprofile=coverage.out

# View coverage in browser
go tool cover -html=coverage.out
```

### Test coverage areas

| Test | Description |
|---|---|
| `TestParseICAP_Empty` | Handles empty input gracefully |
| `TestParseICAP_RequestLine` | Parses ICAP method and URL |
| `TestParseICAP_ICAPHeaders` | Parses ICAP-level headers |
| `TestParseICAP_ReqMod_WithHTTPRequest` | Parses encapsulated HTTP request headers |
| `TestParseICAP_ReqMod_WithBody` | Decodes chunked request body |
| `TestParseICAP_RespMod_WithHTTPResponse` | Parses encapsulated HTTP response headers |
| `TestParseICAP_RespMod_WithBody` | Decodes chunked response body |
| `TestParseICAP_DestinationURL` | Constructs full destination URL |
| `TestParseICAP_ChunkedBodyMultipleChunks` | Handles multi-chunk bodies |
| `TestParseICAP_MissingHTTPSection` | Handles ICAP with no encapsulated HTTP |
| `TestParseICAP_MultipleICAPHeaders` | Handles repeated ICAP headers |

---

## Notes

- This server **never modifies** content — it always returns `204 No Modifications`
- **Only plain text payloads are printed** — binary data, file uploads, and blobs are replaced with safe metadata summaries
- Built-in log rotation — no external dependencies; the entire project uses the Go standard library only
- Log rotation renames the active file with a timestamp suffix (e.g. `icap_bodies.log.20260227-103045`) and opens a fresh file
- Structured JSON server events go to **stdout** (suitable for container log collection); ICAP data goes to the **log file**
- Graceful shutdown drains in-flight connections on `SIGTERM` / `SIGINT` with a 15-second timeout
- All connections are handled **concurrently** via goroutines with read/write timeouts
- The `./logs/` directory is excluded from git via `.gitignore`
