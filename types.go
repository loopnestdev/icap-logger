package main

import (
	"net/http"
	"time"
)

// icapMeta holds the lightweight metadata extracted from the ICAP request
// headers during readICAPMessage. It is cheap to produce (no heap allocs
// beyond the two strings) and lets allow204 / buildICAPEchoResponse avoid
// re-scanning the buffer with a second bufio.Reader.
type icapMeta struct {
	// allow204 is true when the ICAP request's Allow header contains the "204" token.
	allow204 bool
	// isRespMod is true when the ICAP method is RESPMOD.
	isRespMod bool
	// encapsulated is the verbatim value of the Encapsulated header (e.g.
	// "req-hdr=0, res-hdr=226, res-body=1244"). Empty for bare OPTIONS.
	encapsulated string
	// icapHdrLen is the byte length of the ICAP header section including the
	// trailing \r\n\r\n. Used by buildICAPEchoResponse to locate the encapsulated
	// section without a second bytes.Index scan.
	icapHdrLen int
}

// Config holds all runtime configuration loaded from environment variables,
// with optional CLI flag overrides (--port=, --log=, --log-rotate-size=).
type Config struct {
	Port             string
	LogFile          string
	LogRotateSizeMB  int64
	MaxFileRetention int    // LOG_FILE_RETENTION env var — default 60
	MaxBodySize      int64
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	HealthPort       string
	RedactAuthHeader bool // REDACT_AUTH_HEADER env var — default true
	RedactTokens     bool // REDACT_TOKENS env var — default true
	LogReqBody       bool // LOG_REQ_BODY env var — default false
	LogRespBody      bool // LOG_RESP_BODY env var — default false
}

// icapInfo holds parsed information from an ICAP request.
type icapInfo struct {
	icapMethod     string
	icapURL        string
	icapHeaders    http.Header
	reqMethod      string
	reqPath        string
	destinationURL string
	reqHeaders     http.Header
	reqBody        string
	respStatus     string
	respHeaders    http.Header
	respBody       string
}

// logEntry is the JSON structure written to the log file.
type logEntry struct {
	Timestamp      string            `json:"timestamp"`
	ICAPMethod     string            `json:"icap_method,omitempty"`
	ICAPURL        string            `json:"icap_url,omitempty"`
	ICAPHeaders    map[string]string `json:"icap_headers,omitempty"`
	ReqMethod      string            `json:"req_method,omitempty"`
	ReqPath        string            `json:"req_path,omitempty"`
	DestinationURL string            `json:"destination_url,omitempty"`
	Tunneled       bool              `json:"tunneled,omitempty"`
	ReqHeaders     map[string]string `json:"req_headers,omitempty"`
	ReqBody        string            `json:"req_body,omitempty"`
	RespStatus     string            `json:"resp_status,omitempty"`
	RespHeaders    map[string]string `json:"resp_headers,omitempty"`
	RespBody       string            `json:"resp_body,omitempty"`
}
