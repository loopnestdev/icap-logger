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

	// Parse ICAP headers
	info.icapHeaders = make(http.Header)
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
		}
	}

	// The remainder contains encapsulated HTTP request/response headers
	remaining, _ := io.ReadAll(reader)
	sections := splitEncapsulated(remaining)

	if reqBytes, ok := sections["req-hdr"]; ok {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(reqBytes)))
		if err == nil {
			info.reqMethod = req.Method
			info.reqHeaders = req.Header
			if req.URL != nil {
				info.reqPath = req.URL.Path
			}
			scheme := "http"
			if req.TLS != nil {
				scheme = "https"
			}
			host := req.Host
			if host == "" {
				host = req.Header.Get("Host")
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

	if respBytes, ok := sections["res-hdr"]; ok {
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

	if bodyBytes, ok := sections["req-body"]; ok {
		decoded := decodeChunked(bodyBytes)
		info.reqBody = sanitizeBody(decoded, info.reqHeaders.Get("Content-Type"))
	}
	if bodyBytes, ok := sections["res-body"]; ok {
		decoded := decodeChunked(bodyBytes)
		info.respBody = sanitizeBody(decoded, info.respHeaders.Get("Content-Type"))
	}

	return info
}

// splitEncapsulated splits the encapsulated body of an ICAP message into named
// sections (req-hdr, res-hdr, req-body, res-body) using a heuristic based on
// blank-line-separated HTTP messages.
func splitEncapsulated(data []byte) map[string][]byte {
	sections := make(map[string][]byte)
	if len(data) == 0 {
		return sections
	}

	parts := bytes.SplitN(data, []byte("\r\n\r\n"), 3)

	for i, part := range parts {
		if len(part) == 0 {
			continue
		}
		firstLine := strings.SplitN(string(part), "\r\n", 2)[0]
		firstLineUpper := strings.ToUpper(firstLine)
		partCopy := make([]byte, len(part))
		copy(partCopy, part)
		block := append(partCopy, []byte("\r\n\r\n")...)
		switch {
		case strings.HasPrefix(firstLineUpper, "HTTP/"):
			sections["res-hdr"] = block
		case isChunkedBody(part):
			if _, exists := sections["req-body"]; !exists && sections["req-hdr"] != nil {
				sections["req-body"] = part
			} else if _, exists := sections["res-body"]; !exists {
				sections["res-body"] = part
			}
		case i == 0 || strings.ContainsAny(firstLineUpper[:minInt(4, len(firstLineUpper))], "ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
			if _, exists := sections["req-hdr"]; !exists {
				sections["req-hdr"] = block
			}
		}
	}
	return sections
}

// headersToMap converts http.Header to a flat map[string]string joining multiple values with ", ".
func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vs := range h {
		m[k] = strings.Join(vs, ", ")
	}
	return m
}
