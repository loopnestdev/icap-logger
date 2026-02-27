// Package main implements a minimal ICAP (Internet Content Adaptation Protocol)
// server that logs request bodies to a file.
//
// The server listens on port 1344 (the standard ICAP port) and handles incoming
// connections concurrently. For each connection, it reads the full request body,
// logs it with a timestamp to /var/log/icap_bodies.log, and responds with an
// ICAP 204 No Modifications response.
//
// Usage:
//
//	Run the binary with sufficient permissions to write to /var/log/icap_bodies.log
//	and listen on port 1344.
//
// Log format:
//
//	JSON object with timestamp and ICAP request details
//
// Note: This implementation is intentionally minimal and is intended for logging
// and debugging purposes only. It always returns 204 No Modifications, meaning
// it never modifies the content of the requests it receives.

// main initializes the log file at /var/log/icap_bodies.log and starts the ICAP
// server on port 1344. Incoming connections are handled concurrently via goroutines.

// handleConn reads the full content of an incoming ICAP connection, logs it with
// a RFC3339 timestamp using the provided logger, and responds with a
// "204 No Modifications" ICAP response before closing the connection.
//
// Parameters:
//   - conn:   The net.Conn representing the incoming ICAP connection.
//   - logger: A *log.Logger instance used to write the request body to the log file.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config holds all runtime configuration loaded from environment variables,
// with optional CLI flag overrides (--port=, --log=).
type Config struct {
	Port             string
	LogFile          string
	LogRotateSizeMB  int64
	MaxBodySize      int64
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	HealthPort       string
}

// loadConfig builds a Config from environment variables with hardcoded defaults.
// CLI flags --port= and --log= take precedence over env vars.
func loadConfig() Config {
	cfg := Config{
		Port:            getEnv("ICAP_PORT", "1344"),
		LogFile:         getEnv("LOG_FILE", "/var/log/icap_bodies.log"),
		LogRotateSizeMB: int64(getEnvInt("LOG_ROTATE_SIZE_MB", 25)),
		MaxBodySize:     int64(getEnvInt("MAX_BODY_SIZE", 10*1024*1024)),
		ReadTimeout:     time.Duration(getEnvInt("READ_TIMEOUT_SEC", 30)) * time.Second,
		WriteTimeout:    time.Duration(getEnvInt("WRITE_TIMEOUT_SEC", 10)) * time.Second,
		HealthPort:      getEnv("HEALTH_PORT", "8080"),
	}
	for _, arg := range os.Args[1:] {
		switch {
		case strings.HasPrefix(arg, "--port="):
			cfg.Port = strings.TrimPrefix(arg, "--port=")
		case strings.HasPrefix(arg, "--log="):
			cfg.LogFile = strings.TrimPrefix(arg, "--log=")
		case strings.HasPrefix(arg, "--log-rotate-size="):
			if n, err := strconv.ParseInt(strings.TrimPrefix(arg, "--log-rotate-size="), 10, 64); err == nil && n > 0 {
				cfg.LogRotateSizeMB = n
			}
		}
	}
	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// Minimal ICAP server that logs request bodies
func main() {
	cfg := loadConfig()

	// Structured JSON logger for server events → stdout
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// Log-rotating writer for ICAP request data → file
	logWriter, err := newRotatingWriter(cfg.LogFile, cfg.LogRotateSizeMB)
	if err != nil {
		slog.Error("failed to open log file", "path", cfg.LogFile, "err", err)
		os.Exit(1)
	}

	// ICAP data logger writes raw JSON lines to the rotated file
	icapLogger := log.New(logWriter, "", 0)

	// Graceful shutdown — handle SIGINT / SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Health check HTTP server
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})
	healthSrv := &http.Server{
		Addr:    ":" + cfg.HealthPort,
		Handler: healthMux,
	}
	go func() {
		slog.Info("health check listening", "port", cfg.HealthPort)
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health server error", "err", err)
		}
	}()

	// ICAP TCP listener
	ln, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		slog.Error("failed to listen", "port", cfg.Port, "err", err)
		os.Exit(1)
	}
	slog.Info("ICAP logger started",
		"icap_port", cfg.Port,
		"health_port", cfg.HealthPort,
		"log_file", cfg.LogFile,
		"log_rotate_size_mb", cfg.LogRotateSizeMB,
		"max_body_size", cfg.MaxBodySize,
		"read_timeout", cfg.ReadTimeout.String(),
	)

	// Accept loop in goroutine so we can select on ctx.Done
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					slog.Warn("accept error", "err", err)
					continue
				}
			}
			go handleConn(conn, icapLogger, cfg)
		}
	}()

	// Block until shutdown signal
	<-ctx.Done()
	slog.Info("shutdown signal received, draining...")
	ln.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	healthSrv.Shutdown(shutdownCtx)
	logWriter.Close()
	slog.Info("shutdown complete")
}

// rotatingWriter is an io.WriteCloser that rotates the log file when it
// exceeds maxSize bytes. The rotated file is renamed with a timestamp suffix.
type rotatingWriter struct {
	mu       sync.Mutex
	filename string
	maxSize  int64
	file     *os.File
	size     int64
}

func newRotatingWriter(filename string, maxSizeMB int64) (*rotatingWriter, error) {
	w := &rotatingWriter{
		filename: filename,
		maxSize:  maxSizeMB * 1024 * 1024,
	}
	if err := w.openFile(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingWriter) openFile() error {
	f, err := os.OpenFile(w.filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	w.file = f
	w.size = fi.Size()
	return nil
}

func (w *rotatingWriter) rotate() error {
	if w.file != nil {
		w.file.Close()
		w.file = nil
	}
	newName := w.filename + "." + time.Now().Format("20060102-150405")
	_ = os.Rename(w.filename, newName)
	return w.openFile()
}

func (w *rotatingWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.size+int64(len(p)) > w.maxSize && w.size > 0 {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err = w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
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
	ReqHeaders     map[string]string `json:"req_headers,omitempty"`
	ReqBody        string            `json:"req_body,omitempty"`
	RespStatus     string            `json:"resp_status,omitempty"`
	RespHeaders    map[string]string `json:"resp_headers,omitempty"`
	RespBody       string            `json:"resp_body,omitempty"`
}

func handleConn(conn net.Conn, logger *log.Logger, cfg Config) {
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(cfg.ReadTimeout)); err != nil {
		return
	}

	limitedReader := io.LimitReader(conn, cfg.MaxBodySize)
	buf, err := io.ReadAll(limitedReader)
	if err != nil {
		return
	}
	info := parseICAP(buf)

	entry := logEntry{
		Timestamp:      time.Now().Format(time.RFC3339),
		ICAPMethod:     info.icapMethod,
		ICAPURL:        info.icapURL,
		ReqMethod:      info.reqMethod,
		ReqPath:        info.reqPath,
		DestinationURL: info.destinationURL,
		ReqBody:        info.reqBody,
		RespStatus:     info.respStatus,
		RespBody:       info.respBody,
	}

	if len(info.icapHeaders) > 0 {
		entry.ICAPHeaders = headersToMap(info.icapHeaders)
	}
	if len(info.reqHeaders) > 0 {
		entry.ReqHeaders = headersToMap(info.reqHeaders)
	}
	if len(info.respHeaders) > 0 {
		entry.RespHeaders = headersToMap(info.respHeaders)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		// Use %s with a pre-built string to avoid format-string injection
		errEntry, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("failed to marshal log entry: %v", err)})
		logger.Println(string(errEntry))
	} else {
		logger.Println(string(data))
	}

	if err := conn.SetWriteDeadline(time.Now().Add(cfg.WriteTimeout)); err != nil {
		return
	}
	if _, err := conn.Write([]byte("ICAP/1.0 204 No Modifications\r\nConnection: close\r\n\r\n")); err != nil {
		logger.Println(`{"error":"failed to write ICAP response"}`)
	}
}

// headersToMap converts http.Header to a flat map[string]string joining multiple values with ", ".
func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, vs := range h {
		m[k] = strings.Join(vs, ", ")
	}
	return m
}

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
			// Build destination URL safely
			scheme := "http"
			if req.TLS != nil {
				scheme = "https"
			}
			host := req.Host
			if host == "" {
				host = req.Header.Get("Host")
			}
			// req.RequestURI may be absolute or "*"; use URL.RequestURI() for a safe relative form
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
			// Always drain and close the response body to avoid resource leak
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
// sections (req-hdr, res-hdr, req-body, res-body) by reading chunked boundaries.
// It relies on the Encapsulated header parsed earlier to determine offsets, but
// here we use a simpler heuristic: split on blank-line-separated HTTP messages.
func splitEncapsulated(data []byte) map[string][]byte {
	sections := make(map[string][]byte)
	if len(data) == 0 {
		return sections
	}

	// Heuristic: detect HTTP request vs response by first line
	parts := bytes.SplitN(data, []byte("\r\n\r\n"), 3)

	for i, part := range parts {
		if len(part) == 0 {
			continue
		}
		firstLine := strings.SplitN(string(part), "\r\n", 2)[0]
		firstLineUpper := strings.ToUpper(firstLine)
		// Copy part into a new slice before appending to avoid corrupting
		// the shared underlying array from bytes.SplitN
		partCopy := make([]byte, len(part))
		copy(partCopy, part)
		block := append(partCopy, []byte("\r\n\r\n")...)
		switch {
		case strings.HasPrefix(firstLineUpper, "HTTP/"):
			sections["res-hdr"] = block
		case isChunkedBody(part):
			// Chunked body: assign to req-body or res-body depending on context
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
	// Check for multipart content type with boundary
	if contentType != "" {
		ct, params, err := mime.ParseMediaType(contentType)
		if err == nil && strings.HasPrefix(ct, "multipart/") {
			if boundary, ok := params["boundary"]; ok {
				return parseMultipartBody(body, boundary)
			}
		}
	}
	// Fall back to binary detection
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