package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strconv"
	"strings"
	"unicode/utf8"
)

// largeStringThreshold — JSON string values longer than this are checked for
// Base64 content and redacted if they look like encoded binary/file payloads.
const largeStringThreshold = 512

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

// isChunkedBody returns true if data looks like a chunked-encoded body.
func isChunkedBody(data []byte) bool {
	line := strings.SplitN(string(data), "\r\n", 2)[0]
	line = strings.TrimSpace(line)
	if line == "" {
		return false
	}
	_, err := strconv.ParseInt(line, 16, 64)
	return err == nil
}

// isBinary returns true if data appears to be binary rather than human-readable
// text. Two signals are checked in order:
//
//  1. Invalid UTF-8 — valid text (including multi-byte UTF-8 for non-ASCII
//     languages) is always valid UTF-8. Compressed data (gzip, deflate, brotli)
//     and raw binary formats almost always contain byte sequences that violate
//     UTF-8 encoding rules. gzip for example starts with 0x1F 0x8B — the second
//     byte is a UTF-8 continuation byte with no leading byte, which is invalid.
//
//  2. Non-printable ASCII ratio — even for valid UTF-8 content, if more than
//     10% of the first 512 bytes are ASCII control characters the body is
//     treated as binary.
func isBinary(data []byte) bool {
	sample := data
	if len(sample) > 512 {
		sample = sample[:512]
	}
	if len(sample) == 0 {
		return false
	}
	// Signal 1: invalid UTF-8 → binary.
	// This catches gzip, deflate, brotli, JPEG, PNG, ZIP, PDF and any other
	// format whose bytes don't form valid UTF-8 sequences.
	if !utf8.Valid(sample) {
		return true
	}
	// Signal 2: high density of ASCII control characters.
	nonPrintable := 0
	for _, b := range sample {
		if b < 0x09 || (b > 0x0d && b < 0x20) || b == 0x7f {
			nonPrintable++
		}
	}
	return nonPrintable*100/len(sample) > 10
}

// looksLikeBase64 returns true if s is a large Base64-encoded payload.
//
// Three encoding variants are recognised:
//   - Standard Base64      (RFC 4648 §4): alphabet A-Za-z0-9+/=
//   - URL-safe Base64      (RFC 4648 §5): alphabet A-Za-z0-9-_=  (used by JWT, many REST APIs)
//   - MIME-wrapped Base64  (RFC 2045):    standard alphabet with \r\n every 76 chars
//     (used by Java Base64.getMimeEncoder, email attachments, some PDF encoders)
//
// The Base64 prefix depends entirely on the first bytes of the original file, so
// it varies by file type (e.g. PDF → "JVBE", PNG → "iVBO", ZIP → "UEsD").
// No specific prefix is assumed.
func looksLikeBase64(s string) bool {
	if len(s) < largeStringThreshold {
		return false
	}

	// Strip MIME line-wrap whitespace (\r\n) to support MIME-wrapped Base64.
	// Only allocate a new string when line-wrap characters are actually present
	// (the common case for non-MIME-wrapped Base64 avoids the allocation entirely).
	stripped := s
	if strings.ContainsAny(s, "\r\n") {
		stripped = strings.Map(func(r rune) rune {
			if r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, s)
		if len(stripped) < largeStringThreshold {
			return false
		}
	}

	// Detect which Base64 alphabet is in use and pick the right decoder.
	// URL-safe Base64 uses '-' and '_'; standard uses '+' and '/'.
	// Both may use '=' padding.
	urlSafe := false
	for i := 0; i < len(stripped); i++ {
		c := stripped[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '=' {
			continue
		}
		if c == '-' || c == '_' {
			urlSafe = true
			continue
		}
		if c == '+' || c == '/' {
			continue
		}
		// Character outside all known Base64 alphabets → not Base64.
		return false
	}

	// Decode a sample prefix to confirm structural validity.
	sample := stripped
	if len(sample) > 64 {
		sample = stripped[:64]
	}
	if pad := len(sample) % 4; pad != 0 {
		sample += strings.Repeat("=", 4-pad)
	}
	if urlSafe {
		_, err := base64.URLEncoding.DecodeString(sample)
		return err == nil
	}
	_, err := base64.StdEncoding.DecodeString(sample)
	return err == nil
}

// redactJSONLargeStrings walks a decoded JSON value tree and replaces any string
// value that exceeds largeStringThreshold AND looks like Base64 with a safe
// redaction marker. All other values are returned unchanged.
func redactJSONLargeStrings(v any) any {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			val[k] = redactJSONLargeStrings(child)
		}
		return val
	case []any:
		for i, child := range val {
			val[i] = redactJSONLargeStrings(child)
		}
		return val
	case string:
		if looksLikeBase64(val) {
			// Estimate decoded size: Base64 encodes 3 bytes per 4 chars
			decoded := len(val) * 3 / 4
			return fmt.Sprintf("[redacted: base64 payload ~%d bytes]", decoded)
		}
		return val
	default:
		return v
	}
}

// sanitizeJSONBody parses a JSON body, redacts large Base64 string fields,
// optionally redacts token fields, and re-serializes.
// Returns "" if parsing fails (not valid JSON).
func sanitizeJSONBody(body string, redactTokens bool) string {
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		// Not valid JSON — fall through to binary/text check
		return ""
	}
	v = redactJSONLargeStrings(v)
	if redactTokens {
		v = redactTokenFields(v)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return string(out)
}

// parseMultipartBody parses a multipart/form-data body and returns a human-readable
// summary of each part.
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

// isCompressedEncoding returns true when the HTTP Content-Encoding header
// indicates the body has been compressed at the transport layer.
// Such bodies are always binary after ICAP chunked-decoding and must never
// be logged as text regardless of Content-Type.
func isCompressedEncoding(contentEncoding string) bool {
	for _, token := range strings.Split(contentEncoding, ",") {
		switch strings.TrimSpace(strings.ToLower(token)) {
		case "gzip", "x-gzip", "deflate", "br", "zstd", "compress", "x-compress":
			return true
		}
	}
	return false
}

// sanitizeBody inspects a decoded body string and returns a safe log-friendly
// representation:
//   - compressed (Content-Encoding: gzip/deflate/br/zstd) → [binary: N bytes, content-encoding: X]
//   - multipart/form-data                                  → per-part summary
//   - application/json (or +json)                          → JSON with Base64 + token fields redacted
//   - binary content (invalid UTF-8 or high control-char density) → [binary: N bytes]
//   - any other non-binary body that parses as JSON        → JSON with Base64 + token fields redacted
//     (content-sniff fallback — catches application/octet-stream uploads, e.g.
//     AzCopy / Azure SDK, that carry a JSON body but declare a non-JSON Content-Type)
//   - plain text                                           → returned as-is
//
// redactTokens controls whether JSON token fields are redacted in the same pass.
func sanitizeBody(body, contentType, contentEncoding string, redactTokens bool) string {
	if body == "" {
		return ""
	}

	// ── Content-Encoding fast path ─────────────────────────────────────────────
	// If the HTTP client compressed the body, the ICAP payload bytes are raw
	// compressed data — definitively binary, never human-readable.
	if isCompressedEncoding(contentEncoding) {
		ce := strings.TrimSpace(strings.ToLower(contentEncoding))
		return fmt.Sprintf("[binary: %d bytes, content-encoding: %s]", len(body), ce)
	}

	ct := ""
	var params map[string]string
	if contentType != "" {
		var err error
		ct, params, err = mime.ParseMediaType(contentType)
		if err != nil {
			ct = ""
		}
	}

	// ── multipart ──────────────────────────────────────────────────────────────
	if strings.HasPrefix(ct, "multipart/") {
		if boundary, ok := params["boundary"]; ok {
			return parseMultipartBody(body, boundary)
		}
	}

	// ── binary blob ────────────────────────────────────────────────────────────
	if isBinary([]byte(body)) {
		return fmt.Sprintf("[binary: %d bytes]", len(body))
	}

	// ── JSON (declared or content-sniffed) ─────────────────────────────────────
	// Applies to: application/json, *+json, empty CT, or any CT where the body
	// actually parses as JSON (content-sniff for AzCopy octet-stream etc.).
	// Both Base64-field and token redaction happen in a single unmarshal/marshal pass.
	if sanitized := sanitizeJSONBody(body, redactTokens); sanitized != "" {
		return sanitized
	}

	// Plain text — return as-is.
	return body
}

// isTokenKey returns true when a JSON key name indicates a security token
// value.  Matching rule: the lowercased key ends with "token" — this catches
// access_token, refresh_token, id_token, device_token, session_token, token,
// etc.  It intentionally does NOT match "token_type" (ends with "type") whose
// value is the harmless string "Bearer".
func isTokenKey(key string) bool {
	l := strings.ToLower(key)
	return l == "token" || strings.HasSuffix(l, "_token") || strings.HasSuffix(l, "token")
}

// redactTokenFields walks a decoded JSON value tree and replaces any string
// value whose key name matches isTokenKey with "[redacted: token]".
func redactTokenFields(v any) any {
	switch val := v.(type) {
	case map[string]any:
		for k, child := range val {
			if s, ok := child.(string); ok && isTokenKey(k) && s != "" {
				val[k] = "[redacted: token]"
			} else {
				val[k] = redactTokenFields(child)
			}
		}
		return val
	case []any:
		for i, child := range val {
			val[i] = redactTokenFields(child)
		}
		return val
	default:
		return v
	}
}

// redactTokenBody parses body as JSON and replaces any token-named string
// field with "[redacted: token]".  Returns the original body unchanged when
// it is not valid JSON (e.g. a [binary: N bytes] marker or plain text).
func redactTokenBody(body string) string {
	if body == "" {
		return body
	}
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return body // not JSON — leave as-is
	}
	v = redactTokenFields(v)
	out, err := json.Marshal(v)
	if err != nil {
		return body
	}
	return string(out)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
