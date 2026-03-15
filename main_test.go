package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// itoa is a test helper for int-to-string conversion.
func itoa(n int) string { return strconv.Itoa(n) }

// parseICAPMeta is a test helper that feeds raw bytes through readICAPMessage
// and returns the resulting icapMeta. It panics on errors other than io.EOF
// (which is normal when reading from a fixed buffer) so test bodies stay concise.
func parseICAPMeta(raw []byte) icapMeta {
	_, meta, err := readICAPMessage(bufio.NewReader(bytes.NewReader(raw)), 1<<30)
	if err != nil && err.Error() != "EOF" {
		panic("parseICAPMeta: " + err.Error())
	}
	return meta
}

// buildICAP is a test helper that assembles a raw ICAP byte slice from parts.
func buildICAP(requestLine, icapHeaders, encapsulated string) []byte {
	msg := requestLine + "\r\n" + icapHeaders
	if !strings.HasSuffix(icapHeaders, "\r\n\r\n") {
		msg += "\r\n"
	}
	msg += encapsulated
	return []byte(msg)
}

// ── parseICAP unit tests ──────────────────────────────────────────────────────

func TestParseICAP_Empty(t *testing.T) {
	info := parseICAP([]byte{})
	if info.icapMethod != "" {
		t.Errorf("expected empty method, got %q", info.icapMethod)
	}
}

func TestParseICAP_RequestLine(t *testing.T) {
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: null-body=0\r\n",
		"",
	)
	info := parseICAP(raw)
	if info.icapMethod != "REQMOD" {
		t.Errorf("expected REQMOD, got %q", info.icapMethod)
	}
	if info.icapURL != "icap://localhost/reqmod" {
		t.Errorf("unexpected icapURL: %q", info.icapURL)
	}
}

func TestParseICAP_ICAPHeaders(t *testing.T) {
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Host: localhost\r\nX-Client-Ip: 10.0.0.1\r\nEncapsulated: null-body=0\r\n",
		"",
	)
	info := parseICAP(raw)
	if info.icapHeaders.Get("Host") != "localhost" {
		t.Errorf("expected Host=localhost, got %q", info.icapHeaders.Get("Host"))
	}
	if info.icapHeaders.Get("X-Client-Ip") != "10.0.0.1" {
		t.Errorf("expected X-Client-Ip=10.0.0.1, got %q", info.icapHeaders.Get("X-Client-Ip"))
	}
}

// TestParseICAP_NullBody verifies that req-hdr IS parsed when Encapsulated
// is "req-hdr=0, null-body=N" — the pattern Squid sends for bodyless requests.
func TestParseICAP_NullBody(t *testing.T) {
	httpReq := "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TestAgent/1.0\r\n\r\n"
	encHeader := "req-hdr=0, null-body=" + itoa(len(httpReq))

	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: "+encHeader+"\r\n",
		httpReq,
	)
	info := parseICAP(raw)

	if info.reqMethod != "GET" {
		t.Errorf("expected GET, got %q", info.reqMethod)
	}
	if info.reqPath != "/index.html" {
		t.Errorf("expected /index.html, got %q", info.reqPath)
	}
	if info.reqHeaders.Get("User-Agent") != "TestAgent/1.0" {
		t.Errorf("expected User-Agent header, got %q", info.reqHeaders.Get("User-Agent"))
	}
	if info.reqBody != "" {
		t.Errorf("expected empty body for null-body, got %q", info.reqBody)
	}
}

func TestParseICAP_ReqMod_WithHTTPRequest(t *testing.T) {
	httpReq := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
	encHeader := "req-hdr=0, null-body=" + itoa(len(httpReq))

	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: "+encHeader+"\r\n",
		httpReq,
	)
	info := parseICAP(raw)

	if info.reqMethod != "POST" {
		t.Errorf("expected POST, got %q", info.reqMethod)
	}
	if info.reqPath != "/submit" {
		t.Errorf("expected /submit, got %q", info.reqPath)
	}
}

func TestParseICAP_ReqMod_WithBody(t *testing.T) {
	httpReqHdr := "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n"
	chunkedBody := "5\r\nhello\r\n0\r\n\r\n"
	encHeader := "req-hdr=0, req-body=" + itoa(len(httpReqHdr))

	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: "+encHeader+"\r\n",
		httpReqHdr+chunkedBody,
	)
	info := parseICAP(raw)

	if info.reqBody != "hello" {
		t.Errorf("expected body=hello, got %q", info.reqBody)
	}
}

func TestParseICAP_RespMod_WithHTTPResponse(t *testing.T) {
	httpReqHdr := "GET /page HTTP/1.1\r\nHost: example.com\r\n\r\n"
	httpRespHdr := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"
	encHeader := "req-hdr=0, res-hdr=" + itoa(len(httpReqHdr)) +
		", null-body=" + itoa(len(httpReqHdr)+len(httpRespHdr))

	raw := buildICAP(
		"RESPMOD icap://localhost/respmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: "+encHeader+"\r\n",
		httpReqHdr+httpRespHdr,
	)
	info := parseICAP(raw)

	if info.respStatus != "200 OK" {
		t.Errorf("expected 200 OK, got %q", info.respStatus)
	}
	if info.respHeaders.Get("Content-Type") != "text/html" {
		t.Errorf("expected Content-Type=text/html, got %q", info.respHeaders.Get("Content-Type"))
	}
}

func TestParseICAP_RespMod_WithBody(t *testing.T) {
	httpRespHdr := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
	chunkedBody := "5\r\nworld\r\n0\r\n\r\n"
	encHeader := "res-hdr=0, res-body=" + itoa(len(httpRespHdr))

	raw := buildICAP(
		"RESPMOD icap://localhost/respmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: "+encHeader+"\r\n",
		httpRespHdr+chunkedBody,
	)
	info := parseICAP(raw)

	if info.respBody != "world" {
		t.Errorf("expected body=world, got %q", info.respBody)
	}
}

func TestParseICAP_DestinationURL(t *testing.T) {
	httpReq := "GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"
	encHeader := "req-hdr=0, null-body=" + itoa(len(httpReq))

	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: "+encHeader+"\r\n",
		httpReq,
	)
	info := parseICAP(raw)

	want := "http://example.com/path?q=1"
	if info.destinationURL != want {
		t.Errorf("expected destinationURL=%q, got %q", want, info.destinationURL)
	}
}

func TestParseICAP_ChunkedBodyMultipleChunks(t *testing.T) {
	httpReqHdr := "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\n\r\n"
	chunkedBody := "5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n"
	encHeader := "req-hdr=0, req-body=" + itoa(len(httpReqHdr))

	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: "+encHeader+"\r\n",
		httpReqHdr+chunkedBody,
	)
	info := parseICAP(raw)

	if info.reqBody != "helloworld" {
		t.Errorf("expected helloworld, got %q", info.reqBody)
	}
}

func TestParseICAP_MissingHTTPSection(t *testing.T) {
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Host: localhost\r\nEncapsulated: null-body=0\r\n",
		"",
	)
	info := parseICAP(raw)
	// Should not panic; method and URL must still be parsed
	if info.icapMethod != "REQMOD" {
		t.Errorf("expected REQMOD, got %q", info.icapMethod)
	}
	if info.reqMethod != "" {
		t.Errorf("expected empty reqMethod, got %q", info.reqMethod)
	}
}

// ── splitEncapsulated unit tests ─────────────────────────────────────────────

func TestSplitEncapsulated_NullBody(t *testing.T) {
	data := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	sections := splitEncapsulated(data, "req-hdr=0, null-body=38")
	if _, ok := sections["req-hdr"]; !ok {
		t.Error("expected req-hdr section")
	}
	if _, ok := sections["null-body"]; ok {
		t.Error("null-body should not appear as a section key")
	}
}

func TestSplitEncapsulated_ReqHdrAndReqBody(t *testing.T) {
	hdr := []byte("POST /x HTTP/1.1\r\nHost: h\r\n\r\n")
	body := []byte("5\r\nhello\r\n0\r\n\r\n")
	data := append(hdr, body...)
	sections := splitEncapsulated(data, "req-hdr=0, req-body="+itoa(len(hdr)))

	if string(sections["req-hdr"]) != string(hdr) {
		t.Errorf("req-hdr mismatch: %q", sections["req-hdr"])
	}
	if string(sections["req-body"]) != string(body) {
		t.Errorf("req-body mismatch: %q", sections["req-body"])
	}
}

func TestSplitEncapsulated_Empty(t *testing.T) {
	sections := splitEncapsulated([]byte{}, "req-hdr=0")
	if len(sections) != 0 {
		t.Errorf("expected empty sections, got %v", sections)
	}
}

// ── decodeChunked unit tests ──────────────────────────────────────────────────

func TestDecodeChunked_Single(t *testing.T) {
	input := []byte("5\r\nhello\r\n0\r\n\r\n")
	if got := decodeChunked(input); got != "hello" {
		t.Errorf("expected hello, got %q", got)
	}
}

func TestDecodeChunked_Multiple(t *testing.T) {
	input := []byte("5\r\nhello\r\n5\r\nworld\r\n0\r\n\r\n")
	if got := decodeChunked(input); got != "helloworld" {
		t.Errorf("expected helloworld, got %q", got)
	}
}

func TestDecodeChunked_Empty(t *testing.T) {
	input := []byte("0\r\n\r\n")
	if got := decodeChunked(input); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ── isBinary unit tests ───────────────────────────────────────────────────────

func TestIsBinary_PlainText(t *testing.T) {
	if isBinary([]byte("hello world\nthis is text\n")) {
		t.Error("plain text should not be binary")
	}
}

func TestIsBinary_BinaryData(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if !isBinary(data) {
		t.Error("binary data should be detected as binary")
	}
}

// ── looksLikeBase64 unit tests ────────────────────────────────────────────────

func TestLooksLikeBase64_ShortString(t *testing.T) {
	if looksLikeBase64("abc") {
		t.Error("short string should not be flagged as base64")
	}
}

func TestLooksLikeBase64_RegularText(t *testing.T) {
	// Regular JSON text with spaces/punctuation — NOT base64
	s := strings.Repeat("hello world this is plain text. ", 20)
	if looksLikeBase64(s) {
		t.Error("plain text should not be flagged as base64")
	}
}

func TestLooksLikeBase64_ActualBase64(t *testing.T) {
	// Encode a realistic multipart body (same pattern as production 'raw' field)
	// This produces a "LS1Z..." prefix because the content starts with "--YYYY".
	payload := "--YYYY\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"3MB Text.txt\"\r\nContent-Type: text/plain\r\n\r\n" +
		strings.Repeat("examplefile.com | Your Example Files.\r\n", 100)
	encoded := base64Encode([]byte(payload))
	if !looksLikeBase64(encoded) {
		t.Error("standard base64-encoded payload should be detected")
	}
}

func TestLooksLikeBase64_URLSafe(t *testing.T) {
	// URL-safe Base64 uses '-' and '_' instead of '+' and '/'.
	// Used by JWT, many REST APIs, and some file upload services.
	payload := strings.Repeat("binary\x00\xff\xfe data for url-safe test\n", 50)
	encoded := base64.URLEncoding.EncodeToString([]byte(payload))
	if !looksLikeBase64(encoded) {
		t.Error("URL-safe base64 payload should be detected")
	}
}

func TestLooksLikeBase64_MIMEWrapped(t *testing.T) {
	// MIME-wrapped Base64 inserts \r\n every 76 chars.
	// Used by Java Base64.getMimeEncoder(), email attachments, some PDF encoders.
	payload := strings.Repeat("mime encoded file content for testing purposes\n", 50)
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	// Simulate MIME line-wrapping at 76 chars
	var wrapped strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		wrapped.WriteString(encoded[i:end])
		wrapped.WriteString("\r\n")
	}
	if !looksLikeBase64(wrapped.String()) {
		t.Error("MIME-wrapped base64 payload should be detected")
	}
}

func TestLooksLikeBase64_PNGPrefix(t *testing.T) {
	// PNG magic bytes: 0x89 0x50 0x4E 0x47 → Base64 prefix "iVBO"
	pngMagic := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	payload := append(pngMagic, []byte(strings.Repeat("fake png body data\n", 40))...)
	encoded := base64.StdEncoding.EncodeToString(payload)
	if !looksLikeBase64(encoded) {
		t.Error("Base64-encoded PNG payload should be detected (prefix: iVBO)")
	}
}

func TestLooksLikeBase64_ZIPPrefix(t *testing.T) {
	// ZIP magic bytes: 0x50 0x4B 0x03 0x04 → Base64 prefix "UEsD"
	zipMagic := []byte{0x50, 0x4B, 0x03, 0x04}
	payload := append(zipMagic, []byte(strings.Repeat("fake zip body data\n", 40))...)
	encoded := base64.StdEncoding.EncodeToString(payload)
	if !looksLikeBase64(encoded) {
		t.Error("Base64-encoded ZIP payload should be detected (prefix: UEsD)")
	}
}

// ── sanitizeBody JSON redaction tests ─────────────────────────────────────────

func TestSanitizeBody_JSONBase64FieldRedacted(t *testing.T) {
	// Reproduce the exact production case: PUT with JSON body containing
	// a 'raw' field that holds a Base64-encoded multipart file attachment.
	payload := "--YYYY\r\nContent-Disposition: form-data; name=\"files[]\"; filename=\"3MB Text.txt\"\r\nContent-Type: text/plain\r\n\r\n" +
		strings.Repeat("examplefile.com | Your Example Files.\r\n", 1000)
	encoded := base64Encode([]byte(payload))

	body := `{"sys_id":"abc123","snow_id":"def456","last_update":1773208633000,"raw":"` + encoded + `"}`

	got := sanitizeBody(body, "application/json", "", false)

	if strings.Contains(got, encoded[:50]) {
		t.Fatalf("Base64 payload must be redacted, got raw base64 in: %.200s", got)
	}
	if !strings.Contains(got, "[redacted: base64 payload") {
		t.Fatalf("expected redaction marker, got: %.200s", got)
	}
	// Other fields must be preserved
	if !strings.Contains(got, "abc123") {
		t.Fatalf("sys_id field must be preserved, got: %.200s", got)
	}
}

func TestSanitizeBody_JSONNonBase64Preserved(t *testing.T) {
	body := `{"key":"value","number":42,"nested":{"a":"b"}}`
	got := sanitizeBody(body, "application/json", "", false)
	if !strings.Contains(got, "value") {
		t.Fatalf("non-base64 JSON fields must be preserved, got: %s", got)
	}
}

func TestSanitizeBody_JSONEmptyBody(t *testing.T) {
	got := sanitizeBody("", "application/json", "", false)
	if got != "" {
		t.Errorf("empty body should return empty, got %q", got)
	}
}

// ── Content-Encoding / compressed body tests ──────────────────────────────────

func TestSanitizeBody_GzipContentEncoding(t *testing.T) {
	// Reproduce the exact production case: git client sends a gzip-compressed
	// body with Content-Encoding: gzip. The body bytes are raw gzip and must
	// never be logged as text.
	gzipMagic := string([]byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03}) +
		strings.Repeat("x", 200)
	got := sanitizeBody(gzipMagic, "application/x-git-upload-pack-request", "gzip", false)
	if !strings.HasPrefix(got, "[binary:") {
		t.Errorf("gzip body must be redacted, got: %q", got)
	}
	if !strings.Contains(got, "content-encoding: gzip") {
		t.Errorf("redaction marker must mention encoding, got: %q", got)
	}
}

func TestSanitizeBody_BrContentEncoding(t *testing.T) {
	body := strings.Repeat("brotli compressed", 20)
	got := sanitizeBody(body, "text/html", "br", false)
	if !strings.HasPrefix(got, "[binary:") {
		t.Errorf("br-encoded body must be redacted, got: %q", got)
	}
}

func TestSanitizeBody_MultipleEncodings(t *testing.T) {
	// Content-Encoding can be a comma-separated list, e.g. "gzip, identity"
	body := strings.Repeat("data", 50)
	got := sanitizeBody(body, "application/octet-stream", "gzip, identity", false)
	if !strings.HasPrefix(got, "[binary:") {
		t.Errorf("multi-value content-encoding with gzip must be redacted, got: %q", got)
	}
}

func TestSanitizeBody_NoContentEncoding(t *testing.T) {
	// Empty/absent Content-Encoding must not suppress normal JSON parsing.
	body := `{"key":"value"}`
	got := sanitizeBody(body, "application/json", "", false)
	if !strings.Contains(got, "value") {
		t.Errorf("plain JSON with no content-encoding must be logged, got: %q", got)
	}
}
func TestSanitizeBody_OctetStreamJSONBase64Redacted(t *testing.T) {
	// Reproduce the exact AzCopy / Azure SDK production case:
	// Content-Type is application/octet-stream but the body is a JSON document
	// with a large Base64-encoded 'raw' field.  The field must still be redacted.
	payload := strings.Repeat("A", 600) // >512-byte value that passes looksLikeBase64
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))

	body := `{"name":"test.bin","raw":"` + encoded + `"}`

	got := sanitizeBody(body, "application/octet-stream", "", false)

	if strings.Contains(got, encoded[:50]) {
		t.Fatalf("Base64 payload in octet-stream body must be redacted, got raw base64 in: %.200s", got)
	}
	if !strings.Contains(got, "[redacted: base64 payload") {
		t.Fatalf("expected redaction marker, got: %.200s", got)
	}
	if !strings.Contains(got, "test.bin") {
		t.Fatalf("non-base64 fields must be preserved, got: %.200s", got)
	}
}

func TestSanitizeBody_EmptyContentTypeJSONBase64Redacted(t *testing.T) {
	// No Content-Type header at all (ct == "") — must hit the explicit JSON
	// branch (step 4 in sanitizeBody) and still redact Base64 fields.
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("B", 600)))
	body := `{"file":"` + encoded + `"}`

	got := sanitizeBody(body, "", "", false)

	if strings.Contains(got, encoded[:50]) {
		t.Fatalf("Base64 payload with empty Content-Type must be redacted, got: %.200s", got)
	}
	if !strings.Contains(got, "[redacted: base64 payload") {
		t.Fatalf("expected redaction marker, got: %.200s", got)
	}
}

func TestSanitizeBody_TextPlainJSONBase64Redacted(t *testing.T) {
	// Content-Type: text/plain but the body is a JSON document containing a
	// large Base64-encoded field.  text/plain skips the explicit JSON branch
	// (step 4) but the content-sniff fallback (step 6) must catch it.
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("C", 600)))
	body := `{"attachment":"` + encoded + `"}`

	got := sanitizeBody(body, "text/plain", "", false)

	if strings.Contains(got, encoded[:50]) {
		t.Fatalf("Base64 payload with text/plain Content-Type must be redacted, got: %.200s", got)
	}
	if !strings.Contains(got, "[redacted: base64 payload") {
		t.Fatalf("expected redaction marker, got: %.200s", got)
	}
}
func TestIsBinary_GzipBytes(t *testing.T) {
	// gzip magic: 0x1F 0x8B — 0x8B is a UTF-8 continuation byte without a
	// leading byte, making the sequence invalid UTF-8. isBinary must catch this.
	gzipHeader := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03}
	gzipBody := append(gzipHeader, []byte(strings.Repeat("abcdefgh", 60))...)
	if !isBinary(gzipBody) {
		t.Error("gzip bytes must be detected as binary via utf8.Valid check")
	}
}

func TestIsBinary_UTF8NonASCIIText(t *testing.T) {
	// Valid UTF-8 text with non-ASCII characters (Chinese) must NOT be binary.
	text := strings.Repeat("你好世界 Hello World\n", 30)
	if isBinary([]byte(text)) {
		t.Error("valid UTF-8 non-ASCII text must not be flagged as binary")
	}
}

func TestIsCompressedEncoding(t *testing.T) {
	cases := []struct {
		ce   string
		want bool
	}{
		{"gzip", true},
		{"x-gzip", true},
		{"deflate", true},
		{"br", true},
		{"zstd", true},
		{"compress", true},
		{"GZIP", true},           // case-insensitive
		{"gzip, identity", true}, // comma-separated
		{"identity", false},
		{"", false},
		{"chunked", false},
	}
	for _, c := range cases {
		if got := isCompressedEncoding(c.ce); got != c.want {
			t.Errorf("isCompressedEncoding(%q) = %v, want %v", c.ce, got, c.want)
		}
	}
}

// base64Encode is a test helper (avoids import in main test file).
func base64Encode(src []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	for i := 0; i < len(src); i += 3 {
		b0 := src[i]
		var b1, b2 byte
		if i+1 < len(src) {
			b1 = src[i+1]
		}
		if i+2 < len(src) {
			b2 = src[i+2]
		}
		sb.WriteByte(alphabet[b0>>2])
		sb.WriteByte(alphabet[((b0&0x3)<<4)|(b1>>4)])
		if i+1 < len(src) {
			sb.WriteByte(alphabet[((b1&0xf)<<2)|(b2>>6)])
		} else {
			sb.WriteByte('=')
		}
		if i+2 < len(src) {
			sb.WriteByte(alphabet[b2&0x3f])
		} else {
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

// ── redactTokenBody unit tests ────────────────────────────────────────────────

func TestRedactTokenBody_AccessToken(t *testing.T) {
	// Exact production case: Azure Container Registry /oauth2/token response.
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.signature"
	body := `{"access_token":"` + jwt + `"}`
	got := redactTokenBody(body)
	if strings.Contains(got, jwt) {
		t.Fatalf("access_token value must be redacted, got: %s", got)
	}
	if !strings.Contains(got, "[redacted: token]") {
		t.Fatalf("expected redaction marker, got: %s", got)
	}
}

func TestRedactTokenBody_MultipleTokenFields(t *testing.T) {
	// refresh_token, id_token and access_token must all be redacted.
	body := `{"access_token":"aaa","refresh_token":"bbb","id_token":"ccc","token_type":"Bearer","expires_in":3600}`
	got := redactTokenBody(body)
	for _, secret := range []string{"aaa", "bbb", "ccc"} {
		if strings.Contains(got, secret) {
			t.Fatalf("token value %q must be redacted, got: %s", secret, got)
		}
	}
	// token_type value must NOT be redacted
	if !strings.Contains(got, "Bearer") {
		t.Fatalf("token_type=Bearer must be preserved, got: %s", got)
	}
	// Non-token fields must be preserved
	if !strings.Contains(got, "3600") {
		t.Fatalf("expires_in must be preserved, got: %s", got)
	}
}

func TestRedactTokenBody_NestedTokenField(t *testing.T) {
	// Token inside a nested object must also be redacted.
	body := `{"auth":{"access_token":"secret","scope":"read"}}`
	got := redactTokenBody(body)
	if strings.Contains(got, "secret") {
		t.Fatalf("nested access_token must be redacted, got: %s", got)
	}
	if !strings.Contains(got, "read") {
		t.Fatalf("non-token nested field must be preserved, got: %s", got)
	}
}

func TestRedactTokenBody_NotJSON(t *testing.T) {
	// Non-JSON body (marker, plain text) must pass through unchanged.
	for _, body := range []string{
		"[binary: 1024 bytes]",
		"[redacted: base64 payload ~5000 bytes]",
		"plain text response",
		"",
	} {
		got := redactTokenBody(body)
		if got != body {
			t.Errorf("non-JSON body must be unchanged: input=%q got=%q", body, got)
		}
	}
}

func TestIsTokenKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"access_token", true},
		{"refresh_token", true},
		{"id_token", true},
		{"device_token", true},
		{"session_token", true},
		{"token", true},
		{"AccessToken", true},  // camelCase
		{"refreshToken", true}, // camelCase
		{"token_type", false},  // must NOT match — value is "Bearer"
		{"expires_in", false},
		{"scope", false},
		{"client_id", false},
	}
	for _, c := range cases {
		if got := isTokenKey(c.key); got != c.want {
			t.Errorf("isTokenKey(%q) = %v, want %v", c.key, got, c.want)
		}
	}
}

// ── allow204 unit tests ───────────────────────────────────────────────────────

func TestAllow204_Present(t *testing.T) {
	// Exact CONNECT case from production: Allow: 204, trailers
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Allow: 204, trailers\r\nEncapsulated: null-body=0\r\n",
		"",
	)
	if !allow204(parseICAPMeta(raw)) {
		t.Error("expected allow204=true when Allow header contains 204 token")
	}
}

func TestAllow204_Absent(t *testing.T) {
	// Exact PUT case from production: Allow: trailers (no 204 token)
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Allow: trailers\r\nEncapsulated: req-body=0\r\n",
		"",
	)
	if allow204(parseICAPMeta(raw)) {
		t.Error("expected allow204=false when Allow header does not contain 204 token")
	}
}

func TestAllow204_NoHeader(t *testing.T) {
	// No Allow header at all
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Encapsulated: req-body=0\r\n",
		"",
	)
	if allow204(parseICAPMeta(raw)) {
		t.Error("expected allow204=false when no Allow header present")
	}
}

func TestAllow204_CaseInsensitive(t *testing.T) {
	// Header name casing must not matter
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"ALLOW: 204, trailers\r\nEncapsulated: null-body=0\r\n",
		"",
	)
	if !allow204(parseICAPMeta(raw)) {
		t.Error("expected allow204=true for ALLOW header with 204 token (case-insensitive)")
	}
}

func TestAllow204_NoPartialMatch(t *testing.T) {
	// "2048" must NOT match the "204" token
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Allow: 2048, trailers\r\nEncapsulated: null-body=0\r\n",
		"",
	)
	if allow204(parseICAPMeta(raw)) {
		t.Error("expected allow204=false: '2048' must not match '204' token")
	}
}

// ── buildICAPEchoResponse unit tests ─────────────────────────────────────────

func TestBuildICAPEchoResponse_ReqMod(t *testing.T) {
	// Simulate the exact production PUT case: Allow: trailers, no 204
	httpHdr := "PUT /blob HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\n"
	chunkedBody := "5\r\nhello\r\n0\r\n\r\n"
	encHeader := "req-hdr=0, req-body=" + itoa(len(httpHdr))
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Allow: trailers\r\nEncapsulated: "+encHeader+"\r\n",
		httpHdr+chunkedBody,
	)
	resp := buildICAPEchoResponse(raw, parseICAPMeta(raw))
	respStr := string(resp)

	if !strings.HasPrefix(respStr, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("response must start with ICAP/1.0 200 OK, got: %.80s", respStr)
	}
	if !strings.Contains(respStr, "Encapsulated: "+encHeader) {
		t.Errorf("response must preserve Encapsulated header value, got: %.200s", respStr)
	}
	if !strings.Contains(respStr, httpHdr) {
		t.Error("response must echo the original HTTP request headers")
	}
	if !strings.Contains(respStr, chunkedBody) {
		t.Error("response must echo the original chunked body")
	}
}

func TestBuildICAPEchoResponse_NullBody(t *testing.T) {
	httpHdr := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	encHeader := "req-hdr=0, null-body=" + itoa(len(httpHdr))
	raw := buildICAP(
		"REQMOD icap://localhost/reqmod ICAP/1.0",
		"Allow: trailers\r\nEncapsulated: "+encHeader+"\r\n",
		httpHdr,
	)
	resp := buildICAPEchoResponse(raw, parseICAPMeta(raw))
	respStr := string(resp)

	if !strings.HasPrefix(respStr, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("response must start with ICAP/1.0 200 OK, got: %.80s", respStr)
	}
	if !strings.Contains(respStr, "Encapsulated: "+encHeader) {
		t.Errorf("expected Encapsulated header preserved, got: %.200s", respStr)
	}
	if !strings.Contains(respStr, httpHdr) {
		t.Error("response must echo the HTTP headers")
	}
}

func TestBuildICAPEchoResponse_Malformed(t *testing.T) {
	// No \r\n\r\n boundary — must return a safe fallback response, not panic.
	raw := []byte("REQMOD icap://localhost ICAP/1.0\r\nAllow: trailers")
	resp := buildICAPEchoResponse(raw, parseICAPMeta(raw))
	if !strings.HasPrefix(string(resp), "ICAP/1.0 200 OK") {
		t.Errorf("malformed input must return a safe 200 OK response, got: %q", resp)
	}
}

func TestBuildICAPEchoResponse_RespMod(t *testing.T) {
	// Production RESPMOD case: Allow: trailers (no 204), req-hdr + res-hdr + res-body.
	// The echo response must NOT include req-hdr — RFC 3507 §4.9.2.
	reqHdr := "GET /file.gz HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resHdr := "HTTP/1.1 200 OK\r\nContent-Type: application/gzip\r\nContent-Length: 5\r\n\r\n"
	chunkedBody := "5\r\nhello\r\n0\r\n\r\n"
	resHdrOff := len(reqHdr)
	resBodyOff := resHdrOff + len(resHdr)
	encHeader := fmt.Sprintf("req-hdr=0, res-hdr=%d, res-body=%d", resHdrOff, resBodyOff)

	raw := buildICAP(
		"RESPMOD icap://localhost/respmod ICAP/1.0",
		"Allow: trailers\r\nEncapsulated: "+encHeader+"\r\n",
		reqHdr+resHdr+chunkedBody,
	)
	resp := buildICAPEchoResponse(raw, parseICAPMeta(raw))
	respStr := string(resp)

	if !strings.HasPrefix(respStr, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("response must start with ICAP/1.0 200 OK, got: %.80s", respStr)
	}
	// Encapsulated must be res-hdr=0, res-body=<len(resHdr)>
	wantEnc := fmt.Sprintf("Encapsulated: res-hdr=0, res-body=%d", len(resHdr))
	if !strings.Contains(respStr, wantEnc) {
		t.Errorf("expected %q in response, got: %.300s", wantEnc, respStr)
	}
	// Must NOT include the HTTP request headers
	if strings.Contains(respStr, "GET /file.gz") {
		t.Error("RESPMOD echo must not include the original HTTP request headers (req-hdr)")
	}
	// Must include the HTTP response headers and body
	if !strings.Contains(respStr, resHdr) {
		t.Error("response must echo the HTTP response headers")
	}
	if !strings.Contains(respStr, chunkedBody) {
		t.Error("response must echo the chunked body")
	}
}

func TestBuildICAPEchoResponse_RespMod_NullBody(t *testing.T) {
	// RESPMOD with null-body (HEAD request or redirect — no response body).
	reqHdr := "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	resHdr := "HTTP/1.1 302 Found\r\nLocation: /new\r\n\r\n"
	resHdrOff := len(reqHdr)
	nullBodyOff := resHdrOff + len(resHdr)
	encHeader := fmt.Sprintf("req-hdr=0, res-hdr=%d, null-body=%d", resHdrOff, nullBodyOff)

	raw := buildICAP(
		"RESPMOD icap://localhost/respmod ICAP/1.0",
		"Allow: trailers\r\nEncapsulated: "+encHeader+"\r\n",
		reqHdr+resHdr,
	)
	resp := buildICAPEchoResponse(raw, parseICAPMeta(raw))
	respStr := string(resp)

	if !strings.HasPrefix(respStr, "ICAP/1.0 200 OK\r\n") {
		t.Errorf("response must start with ICAP/1.0 200 OK, got: %.80s", respStr)
	}
	wantEnc := fmt.Sprintf("Encapsulated: res-hdr=0, null-body=%d", len(resHdr))
	if !strings.Contains(respStr, wantEnc) {
		t.Errorf("expected %q in response, got: %.300s", wantEnc, respStr)
	}
	if strings.Contains(respStr, "HEAD /") {
		t.Error("RESPMOD echo must not include the original HTTP request headers")
	}
}

func TestTrimReqHdrSection_WithBody(t *testing.T) {
	reqHdr := "GET / HTTP/1.1\r\nHost: x\r\n\r\n" // 26 bytes
	resHdr := "HTTP/1.1 200 OK\r\n\r\n"           // 19 bytes
	body := "5\r\nhello\r\n0\r\n\r\n"
	section := []byte(reqHdr + resHdr + body)
	encVal := fmt.Sprintf("req-hdr=0, res-hdr=%d, res-body=%d", len(reqHdr), len(reqHdr)+len(resHdr))

	gotEnc, gotSec := trimReqHdrSection(encVal, section)

	wantEnc := fmt.Sprintf("res-hdr=0, res-body=%d", len(resHdr))
	if gotEnc != wantEnc {
		t.Errorf("encVal: want %q, got %q", wantEnc, gotEnc)
	}
	if string(gotSec) != resHdr+body {
		t.Errorf("section: want res-hdr+body, got %q", gotSec)
	}
}

func TestTrimReqHdrSection_NullBody(t *testing.T) {
	reqHdr := "HEAD / HTTP/1.1\r\nHost: x\r\n\r\n" // 27 bytes
	resHdr := "HTTP/1.1 200 OK\r\n\r\n"            // 19 bytes
	section := []byte(reqHdr + resHdr)
	encVal := fmt.Sprintf("req-hdr=0, res-hdr=%d, null-body=%d", len(reqHdr), len(reqHdr)+len(resHdr))

	gotEnc, gotSec := trimReqHdrSection(encVal, section)

	wantEnc := fmt.Sprintf("res-hdr=0, null-body=%d", len(resHdr))
	if gotEnc != wantEnc {
		t.Errorf("encVal: want %q, got %q", wantEnc, gotEnc)
	}
	if string(gotSec) != resHdr {
		t.Errorf("section: want resHdr only, got %q", gotSec)
	}
}

func TestTrimReqHdrSection_NoResHdr(t *testing.T) {
	// If there's no res-hdr (shouldn't happen for RESPMOD, but must not panic).
	section := []byte("some bytes")
	encVal := "req-hdr=0, null-body=10"
	gotEnc, gotSec := trimReqHdrSection(encVal, section)
	if gotEnc != encVal || string(gotSec) != "some bytes" {
		t.Error("no res-hdr: should return original encVal and section unchanged")
	}
}

// ── selectBodies unit tests ───────────────────────────────────────────────────

func TestSelectBodies_BothDisabled(t *testing.T) {
	// Default config (false/false) — neither body must appear in the log entry.
	info := icapInfo{reqBody: "sensitive request data", respBody: "sensitive response data"}
	cfg := Config{LogReqBody: false, LogRespBody: false}
	req, resp := selectBodies(info, cfg)
	if req != "" {
		t.Errorf("req body must be empty when LogReqBody=false, got %q", req)
	}
	if resp != "" {
		t.Errorf("resp body must be empty when LogRespBody=false, got %q", resp)
	}
}

func TestSelectBodies_ReqBodyEnabled(t *testing.T) {
	info := icapInfo{reqBody: "hello", respBody: "world"}
	cfg := Config{LogReqBody: true, LogRespBody: false}
	req, resp := selectBodies(info, cfg)
	if req != "hello" {
		t.Errorf("expected req=hello, got %q", req)
	}
	if resp != "" {
		t.Errorf("resp must be empty when LogRespBody=false, got %q", resp)
	}
}

func TestSelectBodies_RespBodyEnabled(t *testing.T) {
	info := icapInfo{reqBody: "hello", respBody: "world"}
	cfg := Config{LogReqBody: false, LogRespBody: true}
	req, resp := selectBodies(info, cfg)
	if req != "" {
		t.Errorf("req must be empty when LogReqBody=false, got %q", req)
	}
	if resp != "world" {
		t.Errorf("expected resp=world, got %q", resp)
	}
}

func TestSelectBodies_BothEnabled(t *testing.T) {
	info := icapInfo{reqBody: "hello", respBody: "world"}
	cfg := Config{LogReqBody: true, LogRespBody: true}
	req, resp := selectBodies(info, cfg)
	if req != "hello" {
		t.Errorf("expected req=hello, got %q", req)
	}
	if resp != "world" {
		t.Errorf("expected resp=world, got %q", resp)
	}
}

func TestSelectBodies_TunneledMarkerSet(t *testing.T) {
	// CONNECT with LogReqBody=true and no body → must produce the tunneled marker.
	info := icapInfo{reqMethod: "CONNECT", reqBody: ""}
	cfg := Config{LogReqBody: true, LogRespBody: false}
	req, _ := selectBodies(info, cfg)
	const want = "[tunneled: HTTPS traffic, body not inspectable]"
	if req != want {
		t.Errorf("CONNECT with LogReqBody=true must set tunneled marker, got %q", req)
	}
}

func TestSelectBodies_TunneledMarkerDisabled(t *testing.T) {
	// CONNECT with LogReqBody=false → req body must be empty (marker suppressed).
	info := icapInfo{reqMethod: "CONNECT", reqBody: ""}
	cfg := Config{LogReqBody: false, LogRespBody: false}
	req, _ := selectBodies(info, cfg)
	if req != "" {
		t.Errorf("CONNECT with LogReqBody=false must return empty body, got %q", req)
	}
}

func TestSelectBodies_TokenRedactionApplied(t *testing.T) {
	// Token redaction must fire when LogReqBody=true and RedactTokens=true.
	info := icapInfo{reqBody: `{"access_token":"eyJsecretToken"}`, respBody: ""}
	cfg := Config{LogReqBody: true, LogRespBody: false, RedactTokens: true}
	req, _ := selectBodies(info, cfg)
	if strings.Contains(req, "eyJsecretToken") {
		t.Errorf("access_token value must be redacted, got %q", req)
	}
	if !strings.Contains(req, "[redacted: token]") {
		t.Errorf("expected [redacted: token] marker, got %q", req)
	}
}

func TestSelectBodies_TokenRedactionSkippedWhenBodyDisabled(t *testing.T) {
	// When LogReqBody=false the body must be empty — redactTokenBody must not
	// even be called (the body is never processed or logged).
	info := icapInfo{reqBody: `{"access_token":"eyJsecretToken"}`, respBody: ""}
	cfg := Config{LogReqBody: false, LogRespBody: false, RedactTokens: true}
	req, _ := selectBodies(info, cfg)
	if req != "" {
		t.Errorf("req body must be empty when LogReqBody=false, got %q", req)
	}
}

// ── redactAuthHeaders unit tests ──────────────────────────────────────────────

func TestRedactAuthHeaders_Redacts(t *testing.T) {
	headers := map[string]string{
		"Authorization":       "Basic dXNlcjpwYXNz",
		"Proxy-Authorization": "Bearer token123",
		"Content-Type":        "application/json",
	}
	redactAuthHeaders(headers)
	if headers["Authorization"] != "[redacted]" {
		t.Errorf("Authorization must be redacted, got %q", headers["Authorization"])
	}
	if headers["Proxy-Authorization"] != "[redacted]" {
		t.Errorf("Proxy-Authorization must be redacted, got %q", headers["Proxy-Authorization"])
	}
	if headers["Content-Type"] != "application/json" {
		t.Errorf("Content-Type must be unchanged, got %q", headers["Content-Type"])
	}
}

func TestRedactAuthHeaders_EmptyMap(t *testing.T) {
	headers := map[string]string{}
	redactAuthHeaders(headers) // must not panic
}

func TestGetEnvBool_Defaults(t *testing.T) {
	t.Setenv("REDACT_AUTH_HEADER", "")
	if !getEnvBool("REDACT_AUTH_HEADER", true) {
		t.Error("empty env var should return fallback true")
	}
}

func TestGetEnvBool_False(t *testing.T) {
	t.Setenv("REDACT_AUTH_HEADER", "false")
	if getEnvBool("REDACT_AUTH_HEADER", true) {
		t.Error("env var=false should return false")
	}
}

func TestGetEnvBool_True(t *testing.T) {
	t.Setenv("REDACT_AUTH_HEADER", "1")
	if !getEnvBool("REDACT_AUTH_HEADER", false) {
		t.Error("env var=1 should return true")
	}
}

// ── rotatingWriter unit tests ─────────────────────────────────────────────────

// TestRotatingWriter_RotatesOnSizeThreshold verifies that once the size threshold
// is crossed a new active file is created and the rotated file exists.
func TestRotatingWriter_RotatesOnSizeThreshold(t *testing.T) {
	dir := t.TempDir()
	logFile := filepath.Join(dir, "test.log")

	// 1-byte threshold so any write forces rotation.
	w, err := newRotatingWriter(logFile, 0 /* 0 MB = 0 bytes max */, 60)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	defer w.Close()

	// Force size > 0 so the threshold check fires.
	w.mu.Lock()
	w.maxSize = 10 // 10 bytes
	w.mu.Unlock()

	// Write a first chunk so size > 0 (rotation requires size > 0 to prevent
	// triggering on the very first write to a fresh empty file).
	if _, err := w.Write([]byte("hi")); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	// Second write pushes total (2 + 12 = 14) over maxSize (10) → rotation fires.
	payload := []byte("hello world!") // 12 bytes; 2+12=14 > 10
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Give the background goroutine time to rename + compress.
	time.Sleep(300 * time.Millisecond)

	// Active log file must exist.
	if _, err := os.Stat(logFile); err != nil {
		t.Errorf("active log file missing after rotation: %v", err)
	}

	// At least one .gz archive must exist.
	entries, _ := os.ReadDir(dir)
	var gzFiles []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			gzFiles = append(gzFiles, e.Name())
		}
	}
	if len(gzFiles) == 0 {
		t.Error("expected at least one .gz archive after rotation")
	}
}

// TestRotatingWriter_PrunesOldArchives verifies that archives beyond the
// fileRetention limit are removed oldest-first.
func TestRotatingWriter_PrunesOldArchives(t *testing.T) {
	dir := t.TempDir()
	baseName := filepath.Join(dir, "icap_logger.log")

	// Create 5 fake .gz archives with distinct timestamps (oldest first).
	timestamps := []string{
		"20260101-000000",
		"20260102-000000",
		"20260103-000000",
		"20260104-000000",
		"20260105-000000",
	}
	for _, ts := range timestamps {
		path := baseName + "." + ts + ".gz"
		if err := os.WriteFile(path, []byte("fake gz content"), 0644); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}

	// Prune to max 3 — the 2 oldest must be removed.
	pruneOldArchives(baseName, 3)

	entries, _ := os.ReadDir(dir)
	var remaining []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			remaining = append(remaining, e.Name())
		}
	}

	if len(remaining) != 3 {
		t.Errorf("expected 3 archives after pruning, got %d: %v", len(remaining), remaining)
	}

	// The 3 newest must survive.
	sort.Strings(remaining)
	wantSuffixes := []string{"20260103-000000.gz", "20260104-000000.gz", "20260105-000000.gz"}
	for i, want := range wantSuffixes {
		if !strings.HasSuffix(remaining[i], want) {
			t.Errorf("archive[%d]: want suffix %q, got %q", i, want, remaining[i])
		}
	}
}

// TestCompressFile_RoundTrip verifies that compressFile produces a valid gzip
// archive that decompresses to the original content.
func TestCompressFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "input.log")
	dst := filepath.Join(dir, "input.log.gz")

	want := strings.Repeat("icap log line\n", 100)
	if err := os.WriteFile(src, []byte(want), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := compressFile(src, dst); err != nil {
		t.Fatalf("compressFile: %v", err)
	}

	// Open and decompress.
	f, err := os.Open(dst)
	if err != nil {
		t.Fatalf("open gz: %v", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()

	got, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("ReadAll gz: %v", err)
	}

	if string(got) != want {
		t.Errorf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(want))
	}
}

// TestPruneOldArchives_WithinLimit verifies that no files are deleted when the
// archive count is at or below the limit.
func TestPruneOldArchives_WithinLimit(t *testing.T) {
	dir := t.TempDir()
	baseName := filepath.Join(dir, "icap_logger.log")

	for _, ts := range []string{"20260101-000000", "20260102-000000"} {
		path := baseName + "." + ts + ".gz"
		if err := os.WriteFile(path, []byte("gz"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	pruneOldArchives(baseName, 5) // limit=5, only 2 exist — nothing deleted

	entries, _ := os.ReadDir(dir)
	count := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected 2 archives (within limit), got %d", count)
	}
}

// TestPruneOldArchives_Unlimited verifies that fileRetention=0 never prunes.
func TestPruneOldArchives_Unlimited(t *testing.T) {
	dir := t.TempDir()
	baseName := filepath.Join(dir, "icap_logger.log")

	for _, ts := range []string{"20260101-000000", "20260102-000000", "20260103-000000"} {
		path := baseName + "." + ts + ".gz"
		if err := os.WriteFile(path, []byte("gz"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	pruneOldArchives(baseName, 0) // 0 = unlimited

	entries, _ := os.ReadDir(dir)
	count := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gz") {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected all 3 archives to survive with fileRetention=0, got %d", count)
	}
}
