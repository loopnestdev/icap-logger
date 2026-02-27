package main

import (
	"strings"
	"testing"
)

func TestParseICAP_Empty(t *testing.T) {
	info := parseICAP([]byte{})
	if info.icapMethod != "" || info.icapURL != "" {
		t.Errorf("expected empty info for empty input, got %+v", info)
	}
}

func TestParseICAP_RequestLine(t *testing.T) {
	raw := "REQMOD icap://example.com/service ICAP/1.0\r\n\r\n"
	info := parseICAP([]byte(raw))
	if info.icapMethod != "REQMOD" {
		t.Errorf("expected icapMethod=REQMOD, got %q", info.icapMethod)
	}
	if info.icapURL != "icap://example.com/service" {
		t.Errorf("expected icapURL=icap://example.com/service, got %q", info.icapURL)
	}
}

func TestParseICAP_ICAPHeaders(t *testing.T) {
	raw := "REQMOD icap://example.com/service ICAP/1.0\r\nHost: example.com\r\nISTag: \"tag123\"\r\n\r\n"
	info := parseICAP([]byte(raw))
	if info.icapHeaders.Get("Host") != "example.com" {
		t.Errorf("expected Host header=example.com, got %q", info.icapHeaders.Get("Host"))
	}
	if info.icapHeaders.Get("Istag") != "\"tag123\"" {
		t.Errorf("expected ISTag header, got %q", info.icapHeaders.Get("Istag"))
	}
}

func TestParseICAP_ReqMod_WithHTTPRequest(t *testing.T) {
	httpReq := "GET /path/to/resource HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: TestAgent\r\n\r\n"
	raw := "REQMOD icap://proxy.example.com/reqmod ICAP/1.0\r\nEncapsulated: req-hdr=0\r\n\r\n" + httpReq
	info := parseICAP([]byte(raw))
	if info.reqMethod != "GET" {
		t.Errorf("expected reqMethod=GET, got %q", info.reqMethod)
	}
	if info.reqPath != "/path/to/resource" {
		t.Errorf("expected reqPath=/path/to/resource, got %q", info.reqPath)
	}
	if info.reqHeaders.Get("User-Agent") != "TestAgent" {
		t.Errorf("expected User-Agent=TestAgent, got %q", info.reqHeaders.Get("User-Agent"))
	}
}

func TestParseICAP_DestinationURL(t *testing.T) {
	httpReq := "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n"
	raw := "REQMOD icap://proxy/reqmod ICAP/1.0\r\n\r\n" + httpReq
	info := parseICAP([]byte(raw))
	if info.destinationURL == "" {
		t.Error("expected non-empty destinationURL")
	}
	if !strings.Contains(info.destinationURL, "www.example.com") {
		t.Errorf("expected destinationURL to contain www.example.com, got %q", info.destinationURL)
	}
}

func TestParseICAP_ReqMod_WithBody(t *testing.T) {
	body := "5\r\nhello\r\n0\r\n\r\n"
	httpReq := "POST /submit HTTP/1.1\r\nHost: www.example.com\r\nContent-Length: 5\r\n\r\n"
	raw := "REQMOD icap://proxy/reqmod ICAP/1.0\r\n\r\n" + httpReq + body
	info := parseICAP([]byte(raw))
	if info.reqBody != "hello" {
		t.Errorf("expected reqBody=hello, got %q", info.reqBody)
	}
}

func TestParseICAP_RespMod_WithHTTPResponse(t *testing.T) {
	httpResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n"
	raw := "RESPMOD icap://proxy/respmod ICAP/1.0\r\n\r\n" + httpResp
	info := parseICAP([]byte(raw))
	if info.respStatus != "200 OK" {
		t.Errorf("expected respStatus=200 OK, got %q", info.respStatus)
	}
	if info.respHeaders.Get("Content-Type") != "text/html" {
		t.Errorf("expected Content-Type=text/html, got %q", info.respHeaders.Get("Content-Type"))
	}
}

func TestParseICAP_RespMod_WithBody(t *testing.T) {
	body := "5\r\nworld\r\n0\r\n\r\n"
	httpResp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n"
	raw := "RESPMOD icap://proxy/respmod ICAP/1.0\r\n\r\n" + httpResp + body
	info := parseICAP([]byte(raw))
	if info.respBody != "world" {
		t.Errorf("expected respBody=world, got %q", info.respBody)
	}
}

func TestParseICAP_ICAPMethod_REQMOD(t *testing.T) {
	raw := "REQMOD icap://host/mod ICAP/1.0\r\n\r\n"
	info := parseICAP([]byte(raw))
	if info.icapMethod != "REQMOD" {
		t.Errorf("expected REQMOD, got %q", info.icapMethod)
	}
}

func TestParseICAP_ICAPMethod_RESPMOD(t *testing.T) {
	raw := "RESPMOD icap://host/mod ICAP/1.0\r\n\r\n"
	info := parseICAP([]byte(raw))
	if info.icapMethod != "RESPMOD" {
		t.Errorf("expected RESPMOD, got %q", info.icapMethod)
	}
}

func TestParseICAP_MissingHTTPSection(t *testing.T) {
	raw := "REQMOD icap://host/mod ICAP/1.0\r\nHost: host\r\n\r\n"
	info := parseICAP([]byte(raw))
	// No encapsulated HTTP, so req fields should be empty
	if info.reqMethod != "" {
		t.Errorf("expected empty reqMethod, got %q", info.reqMethod)
	}
	if info.reqPath != "" {
		t.Errorf("expected empty reqPath, got %q", info.reqPath)
	}
}

func TestParseICAP_MultipleICAPHeaders(t *testing.T) {
	raw := "REQMOD icap://host/mod ICAP/1.0\r\nX-Custom: value1\r\nX-Custom: value2\r\n\r\n"
	info := parseICAP([]byte(raw))
	vals := info.icapHeaders["X-Custom"]
	if len(vals) != 2 {
		t.Errorf("expected 2 values for X-Custom, got %d", len(vals))
	}
}

func TestParseICAP_ChunkedBodyMultipleChunks(t *testing.T) {
	body := "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	httpReq := "POST /data HTTP/1.1\r\nHost: example.com\r\n\r\n"
	raw := "REQMOD icap://proxy/mod ICAP/1.0\r\n\r\n" + httpReq + body
	info := parseICAP([]byte(raw))
	if info.reqBody != "hello world" {
		t.Errorf("expected reqBody='hello world', got %q", info.reqBody)
	}
}