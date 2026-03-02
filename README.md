# icap-logger

A **production-ready ICAP (Internet Content Adaptation Protocol) server** written in Go that logs incoming request and response data to a rotating JSON log file. It is intended for traffic inspection and debugging — it never modifies content and always responds with `204 No Modifications`.

---

## Features

- Full `REQMOD` and `RESPMOD` ICAP request handling
- `OPTIONS` request support — Squid probes are answered immediately with correct capability headers
- RFC 3507 offset-based encapsulated section parsing (`req-hdr`, `res-hdr`, `req-body`, `res-body`, `null-body`)
- Non-blocking ICAP message reading — reads complete messages without waiting for EOF (required for Squid compatibility)
- Chunked HTTP body decoding
- **Smart body logging** — plain text logged as-is; binary, file uploads, and blobs replaced with safe metadata summaries
- **Tunnel detection** — `CONNECT` (HTTPS tunnel) requests are flagged with `"tunneled": true` and an explanatory note
- Millisecond-precision timestamps in local timezone
- ICAP `Date` header reformatted from GMT to container local timezone
- Structured JSON logging to stdout via `log/slog`
- Built-in log rotation — no external dependencies
- Graceful shutdown on `SIGTERM` / `SIGINT` with 15-second drain
- HTTP health check endpoint (`/healthz`)
- Fully configurable via environment variables and CLI flags
- Non-root hardened multi-stage Docker image
- Read-only container filesystem with tmpfs `/tmp`
- Resource limits via Docker Compose

---

## How It Works

1. Listens on TCP port `11344` (configurable via `ICAP_PORT`) for incoming connections
2. Reads one complete ICAP message without waiting for EOF — critical for Squid which holds connections open
3. Answers `OPTIONS` probes immediately so Squid marks the service as up
4. Parses `REQMOD` / `RESPMOD` using RFC 3507 byte offsets from the `Encapsulated` header
5. Extracts ICAP headers, encapsulated HTTP request/response headers, and chunked body
6. Sanitises the body before logging — text payloads are printed; binary/file content is replaced with metadata
7. Writes a structured JSON log entry to `/var/log/icap/icap_logger.log` (configurable via `LOG_FILE`)
8. Responds with `ICAP/1.0 204 No Modifications`
9. Exposes `/healthz` on port `8080` (configurable via `HEALTH_PORT`)

---

## Log Entry Format

### Regular request with body (HTTP)

```json
{
  "timestamp": "2026-03-02T17:02:56.123+11:00",
  "icap_method": "REQMOD",
  "icap_url": "icap://<ICAP_SERVER_IP>:11344/reqmod",
  "icap_headers": {
    "Allow": "204, trailers",
    "Date": "2026-03-02T17:02:56.000+11:00",
    "Encapsulated": "req-hdr=0, req-body=143",
    "Host": "<ICAP_SERVER_IP>:11344",
    "X-Client-Ip": "<CLIENT_IP>"
  },
  "req_method": "POST",
  "req_path": "/submit",
  "destination_url": "http://example.com/submit",
  "req_headers": {
    "Content-Type": "application/json",
    "Content-Length": "36",
    "User-Agent": "curl/7.76.1"
  },
  "req_body": "{\"key1\": \"value1\", \"key2\": \"value2\"}"
}
```

### Bodyless request (GET with `null-body`)

```json
{
  "timestamp": "2026-03-02T17:02:56.456+11:00",
  "icap_method": "REQMOD",
  "icap_url": "icap://<ICAP_SERVER_IP>:11344/reqmod",
  "icap_headers": {
    "Encapsulated": "req-hdr=0, null-body=124",
    "X-Client-Ip": "<CLIENT_IP>"
  },
  "req_method": "GET",
  "req_path": "/index.html",
  "destination_url": "http://example.com/index.html",
  "req_headers": {
    "User-Agent": "Go-http-client/1.1"
  }
}
```

### HTTPS tunnel (CONNECT — body not inspectable)

```json
{
  "timestamp": "2026-03-02T17:02:56.789+11:00",
  "icap_method": "REQMOD",
  "icap_url": "icap://<ICAP_SERVER_IP>:11344/reqmod",
  "icap_headers": {
    "Encapsulated": "req-hdr=0, null-body=112",
    "X-Client-Ip": "<CLIENT_IP>"
  },
  "req_method": "CONNECT",
  "req_path": "/",
  "destination_url": "http://login.microsoftonline.com:443/",
  "tunneled": true,
  "req_body": "[tunneled: HTTPS traffic, body not inspectable]",
  "req_headers": {
    "User-Agent": "curl/7.76.1"
  }
}
```

### Body logging behaviour

| Body type | Example `Content-Type` | Logged as |
|---|---|---|
| Plain text, JSON, XML, form data | `application/json`, `text/plain` | ✅ Full content |
| Binary blob (image, PDF, zip, exe) | `image/jpeg`, `application/zip` | `[binary: 8192 bytes]` |
| Multipart file upload — file part | `multipart/form-data` | `[file: "report.pdf", content-type: "application/pdf", 204800 bytes]` |
| Multipart file upload — text field | `multipart/form-data` | `[field: "username" = "alice"]` |
| Multipart file upload — binary field | `multipart/form-data` | `[field: "data", binary, 1024 bytes]` |
| HTTPS tunnel (CONNECT) | — | `[tunneled: HTTPS traffic, body not inspectable]` |

> Binary detection samples the first 512 bytes — if more than 10% are non-printable the body is treated as binary.

> HTTPS traffic sent through a `CONNECT` tunnel is end-to-end encrypted. No ICAP server can inspect its body without Squid SSL Bump (TLS interception) configured on the proxy.

---

## Prerequisites

### Running locally (Go)

| Requirement | Version | Install |
|---|---|---|
| Go | 1.24+ | `brew install go` |
| macOS / Linux | — | — |
| Write access to log directory | — | Required in production |

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

All settings are configurable via environment variables. CLI flags take precedence over env vars.

| Variable | Default | CLI Flag | Description |
|---|---|---|---|
| `ICAP_PORT` | `11344` | `--port=` | ICAP server listen port |
| `LOG_FILE` | `/var/log/icap/icap_logger.log` | `--log=` | JSON log output file |
| `LOG_ROTATE_SIZE_MB` | `25` | `--log-rotate-size=` | Rotate log file after this many MB |
| `MAX_BODY_SIZE` | `10485760` | — | Max bytes read per connection (10 MB) |
| `READ_TIMEOUT_SEC` | `30` | — | TCP read timeout in seconds |
| `WRITE_TIMEOUT_SEC` | `10` | — | TCP write timeout in seconds |
| `HEALTH_PORT` | `8080` | — | HTTP health check listen port |
| `TZ` | system default | — | Container timezone (e.g. `Australia/ACT`) |

---

## Project Structure

```
icap-logger/
├── main.go             # Entry point — main(), signal handling, server bootstrap
├── config.go           # Config struct, loadConfig(), getEnv(), getEnvInt()
├── server.go           # readICAPMessage(), handleConn(), icapOptionsResponse()
├── parser.go           # parseICAP(), splitEncapsulated(), headersToMap()
├── logger.go           # rotatingWriter — size-based log rotation (stdlib only)
├── body.go             # sanitizeBody(), isBinary(), parseMultipartBody(), decodeChunked()
├── types.go            # Config, icapInfo, logEntry struct definitions
├── main_test.go        # Unit tests (19 tests)
├── go.mod              # Go module — zero external dependencies
├── Dockerfile          # Multi-stage hardened Alpine build
├── docker-compose.yml  # Full production Compose config
├── .gitignore          # Git ignore rules
└── README.md           # This file
```

> **Zero external dependencies.** Log rotation, binary detection, and multipart parsing are all implemented using the Go standard library only.

---

## Build

### Go binary

```bash
git clone https://github.com/<YOUR_GITHUB_USERNAME>/icap-logger.git
cd icap-logger
go build -o icap-logger .
```

### Docker image

```bash
docker build -t icap-logger:1.1.1 .
```

---

## Run

### Option 1 — Go binary

```bash
# Production (port 1344 needs elevated privileges on Linux)
sudo ./icap-logger

# Local dev — custom port, log file, rotation size
go run . --port=11344 --log=/tmp/icap.log --log-rotate-size=10

# Via environment variables
ICAP_PORT=11344 LOG_FILE=/tmp/icap.log TZ=Australia/ACT go run .
```

| Flag | Default | Description |
|---|---|---|
| `--port=` | `11344` | TCP port to listen on |
| `--log=` | `/var/log/icap/icap_logger.log` | Path to the JSON log file |
| `--log-rotate-size=` | `25` | Rotate log after N MB |

---

### Option 2 — Docker Compose (recommended)

```bash
# Start in background
docker compose up -d

# Tail the log on the host
tail -f ./logs/icap_logger.log

# Pretty-print with jq
tail -f ./logs/icap_logger.log | jq .

# Check health
curl http://localhost:8080/healthz

# Stop
docker compose down

# Rebuild after code changes
docker compose up -d --build
```

The `docker-compose.yml` is pre-configured with:

| Setting | Value |
|---|---|
| ICAP port | `11344` (host) → `11344` (container) |
| Health port | `8080` (host) → `8080` (container) |
| Log file | `./logs/icap_logger.log` on host → `/var/log/icap/icap_logger.log` in container |
| Log rotation | every `25` MB |
| Timezone | `Australia/ACT` (set via `TZ` env var) |
| Restart policy | `unless-stopped` |
| Health check | polls `/healthz` every 30 s |
| RAM limit | 256 MB |
| CPU limit | 0.5 cores |
| Security | non-root user, `no-new-privileges`, read-only filesystem, tmpfs `/tmp` |

---

### Option 3 — Docker run (manual)

```bash
docker run -d \
  --name icap-logger \
  -p 11344:11344 \
  -p 8080:8080 \
  -e ICAP_PORT=11344 \
  -e LOG_FILE=/var/log/icap/icap_logger.log \
  -e LOG_ROTATE_SIZE_MB=25 \
  -e MAX_BODY_SIZE=10485760 \
  -e HEALTH_PORT=8080 \
  -e TZ=Australia/ACT \
  -v $(pwd)/logs:/var/log/icap \
  --read-only \
  --tmpfs /tmp \
  icap-logger:1.1.1
```

---

## Squid Configuration

Point Squid at icap-logger by adding the following to `squid.conf`:

```
# ICAP service declaration
icap_enable on
icap_service icap_logger reqmod_precache bypass=1 icap://<ICAP_SERVER_IP>:11344/reqmod

# Apply to all requests
adaptation_access icap_logger allow all
```

> **HTTPS body logging** requires Squid SSL Bump (TLS interception). Without it, `CONNECT` requests are logged with `"tunneled": true` and the body is not available — this is a fundamental TLS property, not a limitation of icap-logger.

---

## Test Without a Proxy

Start the server locally:

```bash
go run . --port=11344 --log=/tmp/icap.log
```

In a second terminal, tail the log:

```bash
tail -f /tmp/icap.log | jq .
```

### Test OPTIONS (Squid probe)

```bash
printf "OPTIONS icap://localhost:11344/reqmod ICAP/1.0\r\nHost: localhost\r\n\r\n" \
  | nc localhost 11344
```

Expected response:
```
ICAP/1.0 200 OK
Methods: REQMOD
Service: icap-logger/1.0
...
```

### Test REQMOD with body (HTTP POST)

```bash
printf "REQMOD icap://localhost:11344/reqmod ICAP/1.0\r\nHost: localhost\r\nEncapsulated: req-hdr=0, req-body=68\r\n\r\nPOST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n" \
  | nc localhost 11344
```

### Test REQMOD without body (HTTP GET with null-body)

```bash
printf "REQMOD icap://localhost:11344/reqmod ICAP/1.0\r\nHost: localhost\r\nEncapsulated: req-hdr=0, null-body=49\r\n\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n" \
  | nc localhost 11344
```

### Test via Squid proxy (HTTP — body visible)

```bash
curl -v -x <SQUID_IP>:4128 http://httpbin.org/post \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"key1": "value1", "key2": "value2"}'
```

### Test via Squid proxy (HTTPS — tunnel, body not inspectable without SSL Bump)

```bash
curl -v -x <SQUID_IP>:4128 https://login.microsoftonline.com \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"key1": "value1"}'
# Log will show: "tunneled": true
```

---

## Run Tests

```bash
# Run all tests
go test ./...

# Verbose output
go test ./... -v

# With race detector and coverage
go test ./... -race -coverprofile=coverage.out

# View coverage in browser
go tool cover -html=coverage.out
```

### Test coverage

| Test | Description |
|---|---|
| `TestParseICAP_Empty` | Handles empty input gracefully |
| `TestParseICAP_RequestLine` | Parses ICAP method and URL |
| `TestParseICAP_ICAPHeaders` | Parses ICAP-level headers |
| `TestParseICAP_NullBody` | Parses `req-hdr` when `Encapsulated` is `req-hdr=0, null-body=N` |
| `TestParseICAP_ReqMod_WithHTTPRequest` | Parses encapsulated HTTP request headers |
| `TestParseICAP_ReqMod_WithBody` | Decodes chunked request body |
| `TestParseICAP_RespMod_WithHTTPResponse` | Parses encapsulated HTTP response headers |
| `TestParseICAP_RespMod_WithBody` | Decodes chunked response body |
| `TestParseICAP_DestinationURL` | Constructs full destination URL |
| `TestParseICAP_ChunkedBodyMultipleChunks` | Handles multi-chunk bodies |
| `TestParseICAP_MissingHTTPSection` | Handles ICAP with no encapsulated HTTP section |
| `TestSplitEncapsulated_NullBody` | Offset-based split with `null-body` marker |
| `TestSplitEncapsulated_ReqHdrAndReqBody` | Offset-based split with req-hdr + req-body |
| `TestSplitEncapsulated_Empty` | Empty data returns empty map |
| `TestDecodeChunked_Single` | Single-chunk body decoded correctly |
| `TestDecodeChunked_Multiple` | Multi-chunk body concatenated correctly |
| `TestDecodeChunked_Empty` | Terminating zero-chunk returns empty string |
| `TestIsBinary_PlainText` | Plain text not flagged as binary |
| `TestIsBinary_BinaryData` | Binary data correctly detected |

---

## Notes

- This server **never modifies** content — it always returns `204 No Modifications`
- **Only plain text payloads are logged in full** — binary data, file uploads, and blobs are replaced with safe metadata summaries
- `CONNECT` (HTTPS tunnel) requests are logged with `"tunneled": true`; the body is unavailable by design unless Squid SSL Bump is configured
- Timestamps use millisecond precision in the container's local timezone (`"2026-03-02T17:02:56.123+11:00"`)
- The ICAP `Date` header (sent by Squid in GMT) is converted to local timezone in the log
- Log rotation renames the active file with a timestamp suffix (e.g. `icap_logger.log.20260302-170256`) and opens a fresh file
- Structured JSON server events go to **stdout** (suitable for container log collectors); ICAP data goes to the **rotating log file**
- All connections are handled **concurrently** via goroutines with per-connection read/write deadlines
- Zero external Go dependencies — the entire project uses the standard library only
- The `./logs/` directory is excluded from git via `.gitignore`


---
