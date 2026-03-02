package main

import (
	"net/http"
	"time"
)

// Config holds all runtime configuration loaded from environment variables,
// with optional CLI flag overrides (--port=, --log=, --log-rotate-size=).
type Config struct {
	Port            string
	LogFile         string
	LogRotateSizeMB int64
	MaxBodySize     int64
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	HealthPort      string
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
