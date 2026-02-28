package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"
)

// decodeChunked decodes a chunked-transfer-encoded body and returns it as a string.
func decodeChunked(data []byte) string {
	var result bytes.Buffer
	reader := bufio.NewReader(bytes.NewReader(data))
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		size, err := strconv.ParseInt(line, 16, 64)
		if err != nil || size == 0 {
			break
		}
		chunk := make([]byte, size)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			break
		}
		result.Write(chunk)
		reader.ReadString('\n') // consume trailing \r\n after chunk data
	}
	return result.String()
}

// isChunkedBody returns true if data looks like a chunked-encoded body
// (i.e. the first line is a valid hex chunk size).
func isChunkedBody(data []byte) bool {
	line := strings.SplitN(string(data), "\r\n", 2)[0]
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	_, err := strconv.ParseInt(line, 16, 64)
	return err == nil
}

// isBinary returns true if more than 10% of the first 512 bytes are non-printable
// (excluding tab, newline, carriage return). This reliably identifies binary blobs
// such as images, PDFs, compressed archives, and executables.
func isBinary(data []byte) bool {
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	if len(sample) == 0 {
		return false
	}
	nonPrintable := 0
	for _, b := range sample {
		if b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f {
			nonPrintable++
		}
	}
	return nonPrintable*100/len(sample) > 10
}

// parseMultipartBody parses a multipart/form-data body and returns a human-readable
// summary of each part. File parts are replaced with [file: "name", N bytes],
// binary fields with [field: "name", binary, N bytes], and text fields are inlined.
func parseMultipartBody(body, boundary string) string {
	mr := multipart.NewReader(strings.NewReader(body), boundary)
	var parts []string
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		data, _ := io.ReadAll(part)
		filename := part.FileName()
		fieldName := part.FormName()
		ct := part.Header.Get("Content-Type")
		if ct == "" {
			ct = "application/octet-stream"
		}
		if filename != "" {
			// File upload part — never log content, just metadata
			parts = append(parts, fmt.Sprintf(`[file: %q, content-type: %q, %d bytes]`, filename, ct, len(data)))
		} else if isBinary(data) {
			parts = append(parts, fmt.Sprintf(`[field: %q, binary, %d bytes]`, fieldName, len(data)))
		} else {
			parts = append(parts, fmt.Sprintf(`[field: %q = %q]`, fieldName, string(data)))
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("[multipart: 0 parts, %d bytes]", len(body))
	}
	return strings.Join(parts, "; ")
}

// sanitizeBody inspects a decoded body string and returns a safe log-friendly
// representation:
//   - multipart/form-data → per-part summary (filename, size, content-type)
//   - binary content      → [binary: N bytes]
//   - plain text          → returned as-is
func sanitizeBody(body, contentType string) string {
	if body == "" {
		return ""
	}
	if contentType != "" {
		ct, params, err := mime.ParseMediaType(contentType)
		if err == nil && strings.HasPrefix(ct, "multipart/") {
			if boundary, ok := params["boundary"]; ok {
				return parseMultipartBody(body, boundary)
			}
		}
	}
	if isBinary([]byte(body)) {
		return fmt.Sprintf("[binary: %d bytes]", len(body))
	}
	return body
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
