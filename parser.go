package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// parseICAP parses a raw ICAP request byte slice and extracts relevant fields.
func parseICAP(raw []byte) icapInfo {
	info := icapInfo{}
	reader := bufio.NewReader(bytes.NewReader(raw))

	// Parse ICAP request line: e.g. "REQMOD icap://host/service ICAP/1.0"
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return info
	}
	requestLine = strings.TrimSpace(requestLine)
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) >= 2 {
		info.icapMethod = parts[0]
		info.icapURL = parts[1]
	}

	// Parse ICAP headers until blank line
	info.icapHeaders = make(http.Header)
	encapsulatedHeader := ""
	for {
		line, err := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" || err != nil {
			break
		}
		if idx := strings.IndexByte(line, ':'); idx != -1 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			info.icapHeaders.Add(key, val)
			// Capture the Encapsulated header for offset-based splitting
			if strings.EqualFold(key, "Encapsulated") {
				encapsulatedHeader = val
			}
		}
	}

	// The remainder after the ICAP header blank line is the encapsulated HTTP data
	remaining, _ := io.ReadAll(reader)

	// Use RFC 3507 offset-based splitting
	sections := splitEncapsulated(remaining, encapsulatedHeader)

	// --- req-hdr ---
	if reqBytes, ok := sections["req-hdr"]; ok && len(reqBytes) > 0 {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(reqBytes)))
		if err == nil {
			info.reqMethod = req.Method
			info.reqHeaders = req.Header
			if req.URL != nil {
				info.reqPath = req.URL.RequestURI()
			}
			host := req.Host
			if host == "" {
				host = req.Header.Get("Host")
			}
			scheme := "http"
			if req.Header.Get("X-Forwarded-Proto") == "https" {
				scheme = "https"
			}
			requestURI := ""
			if req.URL != nil {
				requestURI = req.URL.RequestURI()
			}
			if host != "" {
				info.destinationURL = fmt.Sprintf("%s://%s%s", scheme, host, requestURI)
			}
		}
	}

	// --- res-hdr ---
	if respBytes, ok := sections["res-hdr"]; ok && len(respBytes) > 0 {
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(respBytes)), nil)
		if err == nil {
			info.respStatus = resp.Status
			info.respHeaders = resp.Header
			if resp.Body != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}
	}

	// --- req-body ---
	if bodyBytes, ok := sections["req-body"]; ok && len(bodyBytes) > 0 {
		decoded := decodeChunked(bodyBytes)
		ct := ""
		if info.reqHeaders != nil {
			ct = info.reqHeaders.Get("Content-Type")
		}
		info.reqBody = sanitizeBody(decoded, ct)
	}

	// --- res-body ---
	if bodyBytes, ok := sections["res-body"]; ok && len(bodyBytes) > 0 {
		decoded := decodeChunked(bodyBytes)
		ct := ""
		if info.respHeaders != nil {
			ct = info.respHeaders.Get("Content-Type")
		}
		info.respBody = sanitizeBody(decoded, ct)
	}

	return info
}

// splitEncapsulated parses the Encapsulated header value and uses byte offsets
// to slice the data buffer into named sections per RFC 3507 §4.4.1.
//
// Examples:
//
//	"req-hdr=0, null-body=106"             → req-hdr[0:106]
//	"req-hdr=0, req-body=47"               → req-hdr[0:47], req-body[47:end]
//	"res-hdr=0, res-body=38"               → res-hdr[0:38], res-body[38:end]
//	"req-hdr=0, res-hdr=210, res-body=294" → three sections
func splitEncapsulated(data []byte, encHeader string) map[string][]byte {
	sections := make(map[string][]byte)
	if encHeader == "" || len(data) == 0 {
		return sections
	}

	type part struct {
		name   string
		offset int
	}

	var parts []part
	for _, token := range strings.Split(encHeader, ",") {
		token = strings.TrimSpace(token)
		kv := strings.SplitN(token, "=", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(strings.ToLower(kv[0]))
		// null-body is a marker only — no bytes to slice
		if name == "null-body" {
			continue
		}
		offset := 0
		fmt.Sscanf(strings.TrimSpace(kv[1]), "%d", &offset)
		parts = append(parts, part{name, offset})
	}

	for i, p := range parts {
		start := p.offset
		end := len(data)
		if i+1 < len(parts) {
			end = parts[i+1].offset
		}
		if start >= len(data) {
			continue
		}
		if end > len(data) {
			end = len(data)
		}
		buf := make([]byte, end-start)
		copy(buf, data[start:end])
		sections[p.name] = buf
	}

	return sections
}

// headersToMap converts http.Header to a flat map[string]string,
// joining multiple values with ", ".
func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vs := range h {
		m[k] = strings.Join(vs, ", ")
	}
	return m
}
