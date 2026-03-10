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
| `body.go` | decodeChunked(), isChunkedBody(), isBinary(), sanitizeBody(), parseMultipartBody() |
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
- Binary (>10% non-printable in first 512 bytes) → "[binary: N bytes]"
- multipart/form-data → per-part summary
- CONNECT (tunnel) → "[tunneled: HTTPS traffic, body not inspectable]"

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

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| ICAP_PORT | 11344 | TCP listen port |
| LOG_FILE | /var/log/icap/icap_logger.log | JSON log path |
| LOG_ROTATE_SIZE_MB | 25 | Rotate after N MB |
| MAX_BODY_SIZE | 10485760 | Max body bytes (10 MB) |
| READ_TIMEOUT_SEC | 30 | TCP read timeout |
| WRITE_TIMEOUT_SEC | 10 | TCP write timeout |
| HEALTH_PORT | 8080 | Health check HTTP port |
| TZ | Australia/ACT | Container timezone |

---

## Test Strategy

- All tests in main_test.go (package main)
- buildICAP() helper constructs raw ICAP bytes for unit tests
- Every parser code path has a test — especially the null-body case
- Tests use itoa() helper to avoid strconv import
- Run: `go test ./... -v -race -coverprofile=coverage.out`