# CLAUDE.md — icap-logger

This file is read automatically by Claude Code before every response.
It captures all architectural decisions, constraints, and conventions for this project.
**Never delete or shorten this file. Append new decisions as the project evolves.**

---

## Project Purpose

An ICAP (RFC 3507) server written in Go that acts as a logging proxy for Squid.
- Receives REQMOD / RESPMOD requests from Squid
- Logs structured JSON to a rotating file
- Never modifies content — always responds 204 No Modifications
- Answers OPTIONS probes so Squid marks the service as UP

---

## Hard Constraints

1. **Zero external dependencies** — stdlib only. No lumberjack, no zerolog, no cobra.
2. **Single Go package** (`package main`) — no subdirectories, no internal packages.
3. **File-per-concern layout** — one file per responsibility (see File Layout below).
4. **No `io.ReadAll` on TCP connections** — Squid holds connections open; ReadAll blocks forever.
   Use `readICAPMessage()` in server.go which reads until the protocol boundary.
5. **Timestamps in local timezone** — use `time.Now()` never `time.Now().UTC()`.
   TZ is set via environment variable and /etc/localtime in the Docker image.
6. **RFC 3507 offset-based parsing** — splitEncapsulated() MUST use the byte offsets
   from the Encapsulated header, NOT heuristic \r\n\r\n splitting.
7. **null-body is a marker, not a section** — when Encapsulated contains null-body,
   still read req-hdr bytes from the TCP stream. Only skip the chunked body read.

---

## File Layout

| File | Single Responsibility |
|---|---|
| `main.go` | Entry point only: loadConfig, signal handling, listener, health server |
| `config.go` | Config struct, loadConfig(), getEnv(), getEnvInt(), CLI flag parsing |
| `types.go` | icapInfo, logEntry, Config struct definitions |
| `server.go` | readICAPMessage(), handleConn(), icapOptionsResponse() |
| `parser.go` | parseICAP(), splitEncapsulated(), headersToMap() |
| `body.go` | `decodeChunked()`, `isChunkedBody()`, `isBinary()`, `sanitizeBody()`, `parseMultipartBody()`, `redactTokenBody()`, `isTokenKey()` |
| `logger.go` | rotatingWriter struct and methods |
| `main_test.go` | All tests — no _test packages, uses package main |

---

## ICAP Protocol Decisions

### OPTIONS handling
Squid sends OPTIONS before using the service. Must respond ICAP/1.0 200 OK with:
- Methods: REQMOD (or RESPMOD)
- Options-TTL: 3600
- Allow: 204
- Encapsulated: null-body=0
OPTIONS are never logged.

### Encapsulated header parsing (RFC 3507 §4.4.1)
- "req-hdr=0, null-body=106"        → slice req-hdr[0:106], no body
- "req-hdr=0, req-body=47"          → slice req-hdr[0:47], req-body[47:end]
- "res-hdr=0, res-body=38"          → slice res-hdr[0:38], res-body[38:end]
The null-body key is SKIPPED in the parts slice — it carries no bytes.

### readICAPMessage() reading order
1. Read ICAP request line + ICAP headers until blank line
2. If encapsulatedVal == "" → return (bare OPTIONS)
3. If contains "req-hdr" → read lines until blank line (even if null-body present)
4. If contains "res-hdr" → read lines until blank line
5. If contains "req-body" or "res-body" AND NOT null-body → read chunked body

### Body sanitization
- Plain text → log as-is
- Binary (>10% non-printable in first 512 bytes) → `[binary: N bytes]`
- multipart/form-data → per-part summary
- CONNECT (tunnel) → `[tunneled: HTTPS traffic, body not inspectable]`
- **Base64-in-JSON payloads** — `isBinary()` never fires on Base64 because all chars are
  printable ASCII. `sanitizeBody()` JSON-parses the body and calls `looksLikeBase64()`
  on every string value, redacting any that exceed 512 chars and pass the alphabet + decode probe.
  Three Base64 variants are detected:
  - Standard Base64 (RFC 4648 §4): `+` and `/`
  - URL-safe Base64 (RFC 4648 §5): `-` and `_` (used by JWT, many REST APIs)
  - MIME-wrapped Base64 (RFC 2045): `\r\n` every 76 chars (Java `getMimeEncoder`, email)
  The Base64 prefix varies by file type (`LS1Z` = multipart `--`, `JVBE` = PDF, `iVBO` = PNG, `UEsD` = ZIP).
  No specific prefix is assumed — the check is alphabet + decode probe only.
- **Content-sniff JSON fallback** — `sanitizeBody()` tries JSON parsing for ALL Content-Types
  after the `isBinary()` check. Clients like AzCopy and Azure SDKs declare
  `application/octet-stream` even when the body is a JSON document. Without this
  fallback the Base64 field redaction is bypassed entirely.
  Decision tree:
  1. Content-Encoding compressed → `[binary: N bytes, content-encoding: X]`
  2. multipart/* → per-part summary
  3. application/json or *+json or empty CT → JSON Base64 redaction
  4. isBinary() → `[binary: N bytes]`
  5. any remaining body that parses as JSON → JSON Base64 redaction (content-sniff)
  6. everything else → plain text
- **Token redaction** — after `sanitizeBody()` and Base64 redaction, if `REDACT_TOKENS=true`
  `redactTokenBody()` walks the JSON tree again and replaces any string value whose key
  satisfies `isTokenKey()` with `"[redacted: token]"`. Matching rule: lowercased key equals
  `token` or ends with `_token` or `token` (camelCase: `refreshToken`, snake: `refresh_token`).
  `token_type` is intentionally excluded — its value is the harmless string `"Bearer"`.
  Applied to both `req_body` and `resp_body` in the logging goroutine.

### Response timing

- `204 No Modifications` is sent **immediately** after `readICAPMessage()` returns,
  before `parseICAP()`, `json.Marshal()`, or any file I/O.
- All logging runs in a `go func()` goroutine so large payloads (e.g. 4 MB file uploads)
  never delay the ICAP response and cause `ERR_ICAP_FAILURE` on the client.

### Date header

- The ICAP `Date` header is deleted from `icap_headers` after map construction.
  It is the same moment as the top-level `timestamp` field — logging it twice is redundant.

---

## Docker / Deployment Decisions

- Base image: alpine:3.23 (NOT distroless — needs wget for healthcheck, tzdata for TZ)
- Timezone: Australia/ACT hardcoded in Dockerfile; also passed as TZ env var
- Non-root user: icap:icap (uid created in Dockerfile)
- Read-only filesystem with tmpfs /tmp
- Log volume: ./logs → /var/log/icap inside container
- ICAP port: 11344 (not 1344 — avoids needing root)
- Health port: 8080

---

## Known Pitfalls (Lessons Learned)

1. **Squid null-body bug** — The biggest gotcha. Squid sends `req-hdr=0, null-body=N`
   for GET requests. Early return on null-body before reading req-hdr = empty log entries.
   Fix: always read req-hdr/res-hdr sections regardless of null-body.

2. **UTC timestamp bug** — `time.Now().UTC()` ignores TZ env var. Use `time.Now()`.

3. **io.ReadAll deadlock** — Squid keeps TCP connection open waiting for response.
   io.ReadAll blocks until timeout. Use line-by-line reading with protocol boundaries.

4. **Heuristic body splitting** — Splitting on \r\n\r\n fails when req-hdr offset != 0.
   Always use splitEncapsulated() with Encapsulated header offsets.

5. **OPTIONS returns 204** — Original bug. Squid marks service [down,!opt].
   OPTIONS must return 200 OK with capability headers.

6. **Base64-in-JSON payloads cause silent data leakage** — A client embedding a 4 MB file
   as Base64 in a JSON string field (e.g. `{"raw":"LS1Z..."}`) passes `isBinary()` because
   Base64 output is all printable ASCII. Fix: `sanitizeJSONBody()` walks the parsed JSON tree
   and redacts any string value that passes `looksLikeBase64()`. Covers standard, URL-safe,
   and MIME-wrapped variants. The redaction marker shows estimated decoded size.

7. **ERR_ICAP_FAILURE 500 on large payloads** — `json.Marshal` + file write after reading a
   4 MB body can exceed Squid's ICAP response deadline. Fix: send `204` immediately after
   `readICAPMessage()` returns, then parse and log asynchronously in a goroutine.

8. **Duplicate timestamp in icap_headers.Date** — Squid sends a `Date` header in every ICAP
   request. It represents the same moment as the top-level `timestamp`. Fix: `delete()`
   the `Date` key from `icap_headers` after building the map.

9. **Non-JSON Content-Type bypasses Base64 redaction** — AzCopy and Azure SDKs upload JSON
   bodies with `Content-Type: application/octet-stream`. The explicit JSON branch in
   `sanitizeBody()` checks `ct == "application/json"` and was skipped, logging the raw 7 MB
   Base64 string. Fix: add a content-sniff fallback after `isBinary()` that tries
   `sanitizeJSONBody()` regardless of Content-Type. `sanitizeJSONBody()` returns `""`
   for non-JSON input so plain text still falls through unchanged.

10. **OAuth2 tokens in response bodies** — Services like Azure Container Registry return
    `access_token`, `refresh_token`, `id_token` etc. in JSON response bodies (`/oauth2/token`).
    These are security credentials and must not be logged in full. Fix: `redactTokenBody()`
    walks the parsed JSON tree and replaces any string value whose key name ends with `token`.
    Controlled by `REDACT_TOKENS` env var (default `true`). Applied to both `req_body` and
    `resp_body` in the async logging goroutine after `parseICAP()`.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| ICAP_PORT | 11344 | TCP listen port |
| LOG_FILE | /var/log/icap/icap_logger.log | JSON log path |
| LOG_ROTATE_SIZE_MB | 25 | Rotate after N MB |
| LOG_FILE_RETENTION | 60 | Max compressed (.gz) archive files to keep. Oldest deleted first. 0 = unlimited. |
| MAX_BODY_SIZE | 25MB | Max body bytes per connection |
| READ_TIMEOUT_SEC | 30 | TCP read timeout |
| WRITE_TIMEOUT_SEC | 10 | TCP write timeout |
| HEALTH_PORT | 8080 | Health check HTTP port |
| TZ | Australia/ACT | Container timezone |
| REDACT_AUTH_HEADER | true | Redact Authorization / Proxy-Authorization headers. Set false to log raw values (debug only). |
| REDACT_TOKENS | true | Redact OAuth2/OIDC token values from JSON response/request bodies. Matches any JSON field whose name equals or ends with `token` (access_token, refresh_token, id_token, device_token, etc.). token_type is intentionally excluded. Set false to log raw token values (debug only). |

## Log Rotation Behaviour

1. Active file exceeds `LOG_ROTATE_SIZE_MB` → renamed with timestamp suffix
   e.g. `icap_logger.log.20260311-165838`
2. Renamed file compressed to `.gz` in a background goroutine
   (never blocks the ICAP write path)
3. Uncompressed renamed file deleted after successful compression
4. If `.gz` count exceeds `LOG_FILE_RETENTION`, oldest archives deleted first
   (lexicographic sort on `YYYYMMDD-HHMMSS` suffix = chronological order)
5. If the file is not compressed, it is removed after the rotation
6. If the file is compressed, it is removed after the `.gz` is confirmed written and synced
7. If compression fails the raw file is kept
8. Retention is enforced by `pruneOldArchives()` in the same goroutine

---

## Test Strategy

- All tests in main_test.go (package main)
- buildICAP() helper constructs raw ICAP bytes for unit tests
- Every parser code path has a test — especially the null-body case
- Tests use itoa() helper to avoid strconv import
- Run: `go test ./... -v -race -coverprofile=coverage.out`