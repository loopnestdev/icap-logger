package main

import (
	"strings"
	"testing"
)

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

// ── helper ────────────────────────────────────────────────────────────────────

// itoa converts an int to its decimal string — avoids importing strconv in tests.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}