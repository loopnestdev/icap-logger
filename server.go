package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// handleConn reads the full content of an incoming ICAP connection, parses it,
// writes a structured JSON log entry, and responds with 204 No Modifications.
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
		errEntry, _ := json.Marshal(map[string]string{
			"error": fmt.Sprintf("failed to marshal log entry: %v", err),
		})
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
