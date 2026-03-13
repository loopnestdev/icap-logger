# icap-logger

A **production-ready ICAP (Internet Content Adaptation Protocol) server** written in Go that logs incoming request and response data to a rotating JSON log file. It is intended for traffic inspection and debugging — it never modifies content and always responds with `204 No Modifications`.

---

## Features

- Full `REQMOD` and `RESPMOD` ICAP request handling
- `OPTIONS` request support — Squid probes are answered immediately with correct capability headers
- RFC 3507 offset-based encapsulated section parsing (`req-hdr`, `res-hdr`, `req-body`, `res-body`, `null-body`)
- Non-blocking ICAP message reading — reads complete messages without waiting for EOF (required for Squid compatibility)
- Chunked HTTP body decoding
- **Smart body logging** — plain text logged as-is; binary, file uploads, and Base64-encoded file payloads inside JSON replaced with safe metadata summaries; JSON bodies with non-JSON `Content-Type` headers (e.g. `application/octet-stream`) are content-sniffed so Base64 redaction still applies
- **Token redaction** — OAuth2/OIDC token values (`access_token`, `refresh_token`, `id_token`, etc.) in JSON response and request bodies are replaced with `[redacted: token]`
- **Tunnel detection** — `CONNECT` (HTTPS tunnel) requests are flagged with `"tunneled": true` and an explanatory note
- Millisecond-precision timestamps in local timezone
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
6. Sends `ICAP/1.0 204 No Modifications` immediately after reading the message — before any parsing or I/O — so large payloads never delay the response and cause client timeouts
7. Parses and sanitises the request asynchronously — text payloads are logged in full; binary/file content is replaced with safe metadata
8. Writes a structured JSON log entry to `/var/log/icap/icap_logger.log` (configurable via `LOG_FILE`)
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

### OAuth2 token response (RESPMOD)

```json
{
  "timestamp": "2026-03-13T16:13:24.224+11:00",
  "icap_method": "RESPMOD",
  "icap_url": "icap://<ICAP_SERVER_IP>:11344/respmod",
  "req_method": "GET",
  "req_path": "/oauth2/token",
  "destination_url": "https://login.microsoftonline.com/oauth2/token",
  "req_headers": {
    "Authorization": "[redacted]"
  },
  "resp_status": "200 OK",
  "resp_headers": {
    "Content-Type": "application/json; charset=utf-8"
  },
  "resp_body": "{\"access_token\":\"[redacted: token]\",\"refresh_token\":\"[redacted: token]\",\"token_type\":\"Bearer\",\"expires_in\":3600}"
}
```

### Body logging behaviour

| Body type | Example `Content-Type` | Logged as |
|---|---|---|
| Plain text, JSON, XML, form data | `application/json`, `text/plain` | ✅ Full content |
| Binary blob (image, PDF, zip, exe) | `image/jpeg`, `application/zip` | `[binary: 8192 bytes]` |
| JSON field containing Base64-encoded file | `application/json` | `[redacted: base64 payload ~4194488 bytes]` |
| JSON body with non-JSON Content-Type (e.g. AzCopy, Azure SDK) | `application/octet-stream` | Base64 fields redacted as above (content-sniffed) |
| OAuth2/OIDC token field in JSON body | `application/json` | `[redacted: token]` |
| Multipart file upload — file part | `multipart/form-data` | `[file: "report.pdf", content-type: "application/pdf", 204800 bytes]` |
| Multipart file upload — text field | `multipart/form-data` | `[field: "username" = "alice"]` |
| Multipart file upload — binary field | `multipart/form-data` | `[field: "data", binary, 1024 bytes]` |
| HTTPS tunnel (CONNECT) | — | `[tunneled: HTTPS traffic, body not inspectable]` |

> Binary detection samples the first 512 bytes — if more than 10% are non-printable the body is treated as binary.

> Base64 detection walks every JSON string field and redacts any value longer than 512 chars whose characters are entirely within the Base64 alphabet (standard `+/`, URL-safe `-_`, or MIME-wrapped with `\r\n` line breaks) and that passes a decode probe. The `raw` field value is never printed regardless of the underlying file type.

> Content-sniff fallback: if the declared `Content-Type` is not `application/json` but the body parses as JSON (e.g. `application/octet-stream` from AzCopy / Azure SDKs), Base64 field redaction is still applied.

> Token redaction walks every JSON field whose name equals or ends with `token` (e.g. `access_token`, `refresh_token`, `id_token`, `device_token`, `refreshToken`) and replaces the value with `[redacted: token]`. `token_type` is intentionally preserved. Controlled by `REDACT_TOKENS` (default `true`).

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
| `REDACT_AUTH_HEADER` | `true` | — | Redact `Authorization` and `Proxy-Authorization` header values. Set `false` to log raw values (debug only). |
| `REDACT_TOKENS` | `true` | — | Redact OAuth2/OIDC token values from JSON bodies. Matches any JSON field whose name ends with `token` (e.g. `access_token`, `refresh_token`, `id_token`, `device_token`). Set `false` to log raw token values (debug only). |
| `LOG_FILE_RETENTION` | `60` | — | Maximum number of compressed (`.gz`) archive files to retain. When exceeded, the oldest archives are deleted. Set `0` for unlimited. |

---

## Project Structure

```
icap-logger/
├── main.go             # Entry point — main(), signal handling, server bootstrap
├── config.go           # Config struct, loadConfig(), getEnv(), getEnvInt()
├── server.go           # readICAPMessage(), handleConn(), icapOptionsResponse()
├── parser.go           # parseICAP(), splitEncapsulated(), headersToMap()
├── logger.go           # rotatingWriter — size-based log rotation (stdlib only)
├── body.go             # sanitizeBody(), isBinary(), parseMultipartBody(), decodeChunked(), redactTokenBody()
├── types.go            # Config, icapInfo, logEntry struct definitions
├── main_test.go        # Unit tests (25 tests)
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

### REQMOD only (log outbound requests)

Add the following to `squid.conf`:

```squid
icap_enable on

icap_service req_logger reqmod_precache bypass=on icap://<ICAP_SERVER_IP>:11344/reqmod

adaptation_access req_logger allow all
```

### REQMOD + RESPMOD (log requests and responses)

This is the recommended configuration for full visibility including `resp_status`, `resp_headers`, and `resp_body`:

```squid
icap_enable on

icap_service req_logger  reqmod_precache  bypass=on icap://<ICAP_SERVER_IP>:11344/reqmod
icap_service resp_logger respmod_precache bypass=on icap://<ICAP_SERVER_IP>:11344/respmod

adaptation_access req_logger  allow all
adaptation_access resp_logger allow all
```

### With ClamAV (or another ICAP scanner) in the same chain

When chaining icap-logger with an antivirus or DLP scanner, use `adaptation_service_chain` so both services run sequentially. **Do not use two separate `adaptation_access` rules for the same direction** — Squid treats them as a service set (one-of) and only calls one.

```squid
icap_enable on
icap_send_client_ip on

# ── ICAP services ──────────────────────────────────────────────────────────────
icap_service service_avi_req  reqmod_precache  bypass=off icap://<SCANNER_IP>:1344/squidclamav
icap_service service_avi_resp respmod_precache bypass=off icap://<SCANNER_IP>:1344/squidclamav
icap_service req_logger       reqmod_precache  bypass=on  icap://<ICAP_SERVER_IP>:11344/reqmod
icap_service resp_logger      respmod_precache bypass=on  icap://<ICAP_SERVER_IP>:11344/respmod

# ── Sequential chains: scanner first, then logger ─────────────────────────────
adaptation_service_chain req_chain  service_avi_req  req_logger
adaptation_service_chain resp_chain service_avi_resp resp_logger

# ── Apply chains to all traffic ────────────────────────────────────────────────
adaptation_access req_chain  allow all
adaptation_access resp_chain allow all
```

> **Chain order matters:** if the scanner blocks a request (returns `403`), the chain is interrupted and icap-logger does not fire for that transaction — which is the correct behaviour.

> **`bypass=on` vs `bypass=off`:** use `bypass=on` for icap-logger (fail open — traffic continues if the logger is down) and `bypass=off` for security scanners (fail closed — block traffic if the scanner is unreachable).

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

```text
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
| `TestSanitizeBody_OctetStreamJSONBase64Redacted` | JSON+Base64 body with `application/octet-stream` Content-Type is still redacted (content-sniff fallback) |
| `TestSanitizeBody_EmptyContentTypeJSONBase64Redacted` | JSON+Base64 body with absent Content-Type is redacted |
| `TestSanitizeBody_TextPlainJSONBase64Redacted` | JSON+Base64 body with `text/plain` Content-Type is redacted via content-sniff |
| `TestRedactTokenBody_AccessToken` | `access_token` JWT value redacted in RESPMOD body |
| `TestRedactTokenBody_MultipleTokenFields` | All token fields redacted; `token_type` and `expires_in` preserved |
| `TestRedactTokenBody_NestedTokenField` | Token field inside nested JSON object is redacted |
| `TestRedactTokenBody_NotJSON` | Non-JSON body markers pass through unchanged |
| `TestIsTokenKey` | Key matching rules: ends-with-token matched, `token_type` excluded |

---

## Notes

- This server **never modifies** content — it always returns `204 No Modifications`
- **Only plain text payloads are logged in full** — binary data, file uploads, and blobs are replaced with safe metadata summaries
- **JSON bodies are content-sniffed** — Base64 field redaction applies regardless of the declared `Content-Type` (catches `application/octet-stream` uploads from AzCopy, Azure SDKs, etc.)
- **OAuth2/OIDC tokens are redacted by default** — any JSON field whose name ends with `token` is replaced with `[redacted: token]` in both request and response bodies; disable with `REDACT_TOKENS=false`
- `CONNECT` (HTTPS tunnel) requests are logged with `"tunneled": true`; the body is unavailable by design unless Squid SSL Bump is configured
- Timestamps use millisecond precision in the container's local timezone (`"2026-03-02T17:02:56.123+11:00"`)
- The ICAP `Date` header sent by Squid is intentionally omitted from `icap_headers` — it is the same moment as the top-level `timestamp` field
- `204 No Modifications` is sent to the client **immediately** after reading the ICAP message; all parsing, sanitisation, and file I/O happens asynchronously in a goroutine so large payloads (e.g. 4 MB file uploads) never cause `ERR_ICAP_FAILURE` timeouts
- Log rotation renames the active file with a timestamp suffix (e.g. `icap_logger.log.20260302-170256`) and opens a fresh file
- Structured JSON server events go to **stdout** (suitable for container log collectors); ICAP data goes to the **rotating log file**
- All connections are handled **concurrently** via goroutines with per-connection read/write deadlines
- Zero external Go dependencies — the entire project uses the standard library only
- The `./logs/` directory is excluded from git via `.gitignore`
