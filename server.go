package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

// icapOptionsResponse returns a valid ICAP OPTIONS response for the given
// service URL. Squid reads this on startup to confirm the service is alive
// and to learn its capabilities (methods, TTL, preview size, etc.).
func icapOptionsResponse(serviceURL string) string {
	method := "REQMOD"
	if strings.Contains(strings.ToLower(serviceURL), "respmod") {
		method = "RESPMOD"
	}
	return strings.Join([]string{
		"ICAP/1.0 200 OK",
		"Methods: " + method,
		"Service: icap-logger/1.0",
		`ISTag: "icap-logger-1.0"`,
		"Encapsulated: null-body=0",
		"Max-Connections: 100",
		"Options-TTL: 3600",
		"Allow: 204",
		"Connection: close",
		"\r\n",
	}, "\r\n")
}

// readICAPMessage reads exactly one complete ICAP message from r without
// waiting for EOF. This is critical for Squid compatibility: Squid keeps
// the TCP connection open after sending OPTIONS/REQMOD (it waits for a
// response), so io.ReadAll would block forever until ReadTimeout fires.
//
// Reading strategy:
//  1. Read ICAP request line + ICAP headers line-by-line until the blank line.
//  2. Read encapsulated HTTP headers (req-hdr, res-hdr) until their blank line.
//     This is done even when null-body is present — null-body only means there
//     is no chunked body section, not that req-hdr is absent.
//  3. Read chunked body (req-body / res-body) until "0\r\n\r\n".
//     Skipped when null-body is present.
func readICAPMessage(r *bufio.Reader, maxSize int64) ([]byte, error) {
	var buf bytes.Buffer
	var total int64

	// ── Step 1: ICAP request line + ICAP headers ─────────────────────────────
	encapsulatedVal := ""
	for {
		line, err := r.ReadString('\n')
		total += int64(len(line))
		if total > maxSize {
			return buf.Bytes(), fmt.Errorf("ICAP message exceeds max size")
		}
		buf.WriteString(line)
		if err != nil {
			return buf.Bytes(), err
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break // blank line = end of ICAP headers
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "encapsulated:") {
			encapsulatedVal = lower
		}
	}

	// Nothing encapsulated at all — done (e.g. bare OPTIONS).
	if encapsulatedVal == "" {
		return buf.Bytes(), nil
	}

	// ── Step 2: encapsulated HTTP request headers (req-hdr) ──────────────────
	// Read these even when null-body is present; null-body only signals that
	// there is no body section — the header section is still there.
	if strings.Contains(encapsulatedVal, "req-hdr") {
		for {
			line, err := r.ReadString('\n')
			total += int64(len(line))
			if total > maxSize {
				return buf.Bytes(), fmt.Errorf("ICAP message exceeds max size")
			}
			buf.WriteString(line)
			if err != nil {
				return buf.Bytes(), err
			}
			if strings.TrimRight(line, "\r\n") == "" {
				break // blank line = end of HTTP request headers
			}
		}
	}

	// ── Step 3: encapsulated HTTP response headers (res-hdr) ─────────────────
	if strings.Contains(encapsulatedVal, "res-hdr") {
		for {
			line, err := r.ReadString('\n')
			total += int64(len(line))
			if total > maxSize {
				return buf.Bytes(), fmt.Errorf("ICAP message exceeds max size")
			}
			buf.WriteString(line)
			if err != nil {
				return buf.Bytes(), err
			}
			if strings.TrimRight(line, "\r\n") == "" {
				break // blank line = end of HTTP response headers
			}
		}
	}

	// ── Step 4: chunked body (req-body or res-body) ───────────────────────────
	// Skipped entirely when null-body is present — there is no body to read.
	hasBody := strings.Contains(encapsulatedVal, "req-body") ||
		strings.Contains(encapsulatedVal, "res-body")
	hasNullBody := strings.Contains(encapsulatedVal, "null-body")

	if hasBody && !hasNullBody {
		for {
			sizeLine, err := r.ReadString('\n')
			total += int64(len(sizeLine))
			buf.WriteString(sizeLine)
			if err != nil {
				return buf.Bytes(), err
			}
			sizeStr := strings.TrimSpace(sizeLine)
			// Strip chunk extensions: "5;ext=val" → "5"
			if idx := strings.IndexByte(sizeStr, ';'); idx >= 0 {
				sizeStr = sizeStr[:idx]
			}
			size, err := strconv.ParseInt(sizeStr, 16, 64)
			if err != nil || size == 0 {
				// Terminating chunk — consume trailing \r\n
				trail, _ := r.ReadString('\n')
				buf.WriteString(trail)
				break
			}
			if total+size > maxSize {
				break
			}
			// Read chunk data + trailing \r\n
			chunk := make([]byte, size+2)
			n, readErr := io.ReadFull(r, chunk)
			total += int64(n)
			buf.Write(chunk[:n])
			if readErr != nil {
				break
			}
		}
	}

	return buf.Bytes(), nil
}

// allow204 reports whether the ICAP request permits a "204 No Modifications"
// response.  RFC 3507 §4.6 prohibits sending 204 unless the ICAP client's
// Allow header explicitly carries the "204" token.
//
// In a service chain (e.g. SquidClamav → icap-logger), Squid strips the
// Allow: 204 token from the forwarded request when the upstream ICAP service
// returned 200 OK with the full body — signalling that subsequent services
// must echo the content back, not short-circuit with 204.
func allow204(buf []byte) bool {
	reader := bufio.NewReader(bytes.NewReader(buf))
	reader.ReadString('\n') // skip the ICAP request line
	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || err != nil {
			break
		}
		if idx := strings.IndexByte(trimmed, ':'); idx != -1 {
			if strings.EqualFold(strings.TrimSpace(trimmed[:idx]), "Allow") {
				val := strings.TrimSpace(trimmed[idx+1:])
				for _, token := range strings.Split(val, ",") {
					if strings.TrimSpace(token) == "204" {
						return true
					}
				}
			}
		}
	}
	return false
}

// buildICAPEchoResponse constructs an ICAP/1.0 200 OK response that echoes
// the encapsulated HTTP section from the request buffer back to Squid unchanged.
//
// This is required when the ICAP client did not advertise Allow: 204 (RFC 3507
// §4.6).  The server must not send 204 in that case, so it returns 200 OK with
// the original request/response headers and body so the chain can continue
// forwarding to the upstream server.
//
// The Encapsulated header offset values are preserved verbatim because the
// encapsulated section bytes are echoed in the same order and at the same
// relative offsets as they arrived.
func buildICAPEchoResponse(buf []byte) []byte {
	// Extract the Encapsulated header value from the ICAP request headers.
	encapsulatedVal := ""
	reader := bufio.NewReader(bytes.NewReader(buf))
	reader.ReadString('\n') // skip the ICAP request line
	for {
		line, err := reader.ReadString('\n')
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || err != nil {
			break
		}
		if idx := strings.IndexByte(trimmed, ':'); idx != -1 {
			if strings.EqualFold(strings.TrimSpace(trimmed[:idx]), "Encapsulated") {
				encapsulatedVal = strings.TrimSpace(trimmed[idx+1:])
			}
		}
	}

	// Locate the end of the ICAP headers — the first \r\n\r\n boundary.
	// Everything after it is the encapsulated HTTP content to echo back.
	sep := []byte("\r\n\r\n")
	icapHdrEnd := bytes.Index(buf, sep)
	if icapHdrEnd < 0 {
		// Malformed request — return a safe minimal response.
		return []byte("ICAP/1.0 200 OK\r\nConnection: close\r\nEncapsulated: null-body=0\r\n\r\n")
	}
	encapsulatedSection := buf[icapHdrEnd+len(sep):]

	if encapsulatedVal == "" {
		encapsulatedVal = "null-body=0"
	}

	var resp bytes.Buffer
	resp.WriteString("ICAP/1.0 200 OK\r\n")
	resp.WriteString("Connection: close\r\n")
	resp.WriteString("Encapsulated: " + encapsulatedVal + "\r\n")
	resp.WriteString("\r\n")
	resp.Write(encapsulatedSection)
	return resp.Bytes()
}

// handleConn reads one complete ICAP request, parses it, writes a structured
// JSON log entry, and responds appropriately.
// OPTIONS requests are handled immediately and never logged.
func handleConn(conn net.Conn, logger *log.Logger, cfg Config) {
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout)); err != nil {
		return
	}

	reader := bufio.NewReaderSize(conn, 64*1024)
	buf, err := readICAPMessage(reader, cfg.MaxBodySize)
	if err != nil || len(buf) == 0 {
		return
	}

	// Detect OPTIONS — respond immediately without logging
	firstLine := strings.SplitN(string(buf), "\r\n", 2)[0]
	if strings.HasPrefix(strings.TrimSpace(firstLine), "OPTIONS ") {
		parts := strings.Fields(firstLine)
		serviceURL := ""
		if len(parts) >= 2 {
			serviceURL = parts[1]
		}
		slog.Debug("ICAP OPTIONS received", "url", serviceURL)
		if err := conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout)); err != nil {
			return
		}
		_, _ = conn.Write([]byte(icapOptionsResponse(serviceURL)))
		return
	}

	// ── Respond: 204 if the client permits it; 200 OK echo otherwise ───────────
	// RFC 3507 §4.6: a 204 response is ONLY legal when the ICAP request's
	// Allow header contains the token "204".  In a service chain, Squid strips
	// Allow: 204 after ClamAV returns 200 OK with the full body — signalling
	// that subsequent chain members must echo the content rather than
	// short-circuit.  Sending 204 without Allow: 204 causes Squid to return
	// ERR_ICAP_FAILURE (Cache-Status: detail=mismatch) to the client.
	if err := conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout)); err != nil {
		slog.Warn("failed to set write deadline", "err", err)
		return
	}
	var icapResp []byte
	if allow204(buf) {
		icapResp = []byte("ICAP/1.0 204 No Modifications\r\nConnection: close\r\n\r\n")
	} else {
		icapResp = buildICAPEchoResponse(buf)
	}
	if _, err := conn.Write(icapResp); err != nil {
		logger.Println(`{"error":"failed to write ICAP response"}`)
		return
	}

	// ── Log asynchronously so we never block the ICAP response path ──────────
	go func() {
		info := parseICAP(buf)
		reqBody, respBody := selectBodies(info, cfg)

		const tsFormat = "2006-01-02T15:04:05.000Z07:00"
		entry := logEntry{
			Timestamp:      time.Now().Format(tsFormat),
			ICAPMethod:     info.icapMethod,
			ICAPURL:        info.icapURL,
			ReqMethod:      info.reqMethod,
			ReqPath:        info.reqPath,
			DestinationURL: info.destinationURL,
			Tunneled:       info.reqMethod == "CONNECT",
			ReqBody:        reqBody,
			RespStatus:     info.respStatus,
			RespBody:       respBody,
		}

		if len(info.icapHeaders) > 0 {
			entry.ICAPHeaders = headersToMap(info.icapHeaders)
			// "Date" in icap_headers duplicates the top-level "timestamp" field.
			// Drop it to keep the log compact and unambiguous.
			delete(entry.ICAPHeaders, "Date")
		}
		if len(info.reqHeaders) > 0 {
			entry.ReqHeaders = headersToMap(info.reqHeaders)
			if cfg.RedactAuthHeader {
				redactAuthHeaders(entry.ReqHeaders)
			}
		}
		if len(info.respHeaders) > 0 {
			entry.RespHeaders = headersToMap(info.respHeaders)
			if cfg.RedactAuthHeader {
				redactAuthHeaders(entry.RespHeaders)
			}
		}

		data, err := json.Marshal(entry)
		if err != nil {
			errEntry, _ := json.Marshal(map[string]string{
				"error": fmt.Sprintf("failed to marshal log entry: %v", err),
			})
			logger.Println(string(errEntry))
		} else {
			logger.Println(string(data))
		}
	}()
}

// selectBodies returns the req and resp body strings that should appear in the
// log entry, respecting the LogReqBody / LogRespBody flags and applying token
// redaction only for bodies that will actually be logged.
//
//   - cfg.LogReqBody=false (default) → reqBody is always ""
//   - cfg.LogRespBody=false (default) → respBody is always ""
//   - CONNECT (HTTPS tunnel) requests receive the standard tunneled marker
//     only when LogReqBody is true and the parsed body is empty.
func selectBodies(info icapInfo, cfg Config) (reqBody, respBody string) {
	if cfg.LogReqBody {
		reqBody = info.reqBody
		if cfg.RedactTokens {
			reqBody = redactTokenBody(reqBody)
		}
		if info.reqMethod == "CONNECT" && reqBody == "" {
			reqBody = "[tunneled: HTTPS traffic, body not inspectable]"
		}
	}
	if cfg.LogRespBody {
		respBody = info.respBody
		if cfg.RedactTokens {
			respBody = redactTokenBody(respBody)
		}
	}
	return
}

// redactAuthHeaders replaces the value of any Authorization or
// Proxy-Authorization header with "[redacted]".
func redactAuthHeaders(headers map[string]string) {
	for k := range headers {
		switch strings.ToLower(k) {
		case "authorization", "proxy-authorization":
			headers[k] = "[redacted]"
		}
	}
}
