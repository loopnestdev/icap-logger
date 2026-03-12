package main

import (
	"compress/gzip"
	"encoding/base64"
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

	got := sanitizeBody(body, "application/json")

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
	got := sanitizeBody(body, "application/json")
	if !strings.Contains(got, "value") {
		t.Fatalf("non-base64 JSON fields must be preserved, got: %s", got)
	}
}

func TestSanitizeBody_JSONEmptyBody(t *testing.T) {
	got := sanitizeBody("", "application/json")
	if got != "" {
		t.Errorf("empty body should return empty, got %q", got)
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

	// Write enough to trigger rotation.
	payload := []byte("hello world!") // 12 bytes > 10
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
