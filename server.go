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
		"Preview: 0",
		"Transfer-Complete: *",
		"Transfer-Ignore: jpg,jpeg,gif,png,swf,flv,mp3,mp4,avi,mkv,zip,gz,tar,iso",
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

// handleConn reads one complete ICAP request, parses it, writes a structured
// JSON log entry, and responds with 204 No Modifications.
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

	info := parseICAP(buf)

	// A CONNECT request establishes an opaque TLS tunnel — Squid forwards
	// only the CONNECT line to ICAP (null-body), so no request body is ever
	// available regardless of what the client sends through the tunnel.
	tunneled := info.reqMethod == "CONNECT"

	reqBody := info.reqBody
	if tunneled && reqBody == "" {
		reqBody = "[tunneled: HTTPS traffic, body not inspectable]"
	}

	// "2006-01-02T15:04:05.000Z07:00" is RFC3339 with exactly 3ms digits.
	const tsFormat = "2006-01-02T15:04:05.000Z07:00"

	entry := logEntry{
		Timestamp:      time.Now().Format(tsFormat),
		ICAPMethod:     info.icapMethod,
		ICAPURL:        info.icapURL,
		ReqMethod:      info.reqMethod,
		ReqPath:        info.reqPath,
		DestinationURL: info.destinationURL,
		Tunneled:       tunneled,
		ReqBody:        reqBody,
		RespStatus:     info.respStatus,
		RespBody:       info.respBody,
	}

	if len(info.icapHeaders) > 0 {
		entry.ICAPHeaders = headersToMap(info.icapHeaders)
		// Squid sets Date in RFC 1123 / GMT. Reformat to local timezone so
		// all timestamps in the log entry are consistent.
		if dateStr, ok := entry.ICAPHeaders["Date"]; ok {
			// RFC 1123 carries no sub-second precision; parse it and reformat
			// with milliseconds using the same tsFormat as the timestamp field.
			if t, err := time.Parse(time.RFC1123, dateStr); err == nil {
				entry.ICAPHeaders["Date"] = t.Local().Format(tsFormat)
			}
		}
	}
	if len(info.reqHeaders) > 0 {
		entry.ReqHeaders = headersToMap(info.reqHeaders)
	}
	if len(info.respHeaders) > 0 {
		entry.RespHeaders = headersToMap(info.respHeaders)
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

	if err := conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout)); err != nil {
		slog.Warn("failed to set write deadline", "err", err)
		return
	}
	if _, err := conn.Write([]byte("ICAP/1.0 204 No Modifications\r\nConnection: close\r\n\r\n")); err != nil {
		logger.Println(`{"error":"failed to write ICAP response"}`)
	}
}
