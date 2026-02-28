// Package main implements a production-ready ICAP (Internet Content Adaptation
// Protocol) logging server.
//
// Usage:
//
//	./icap-logger [--port=PORT] [--log=PATH] [--log-rotate-size=MB]
package main

import (
	"context"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg := loadConfig()

	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	logWriter, err := newRotatingWriter(cfg.LogFile, cfg.LogRotateSizeMB)
	if err != nil {
		slog.Error("failed to open log file", "path", cfg.LogFile, "err", err)
		os.Exit(1)
	}

	icapLogger := log.New(logWriter, "", 0)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start health-check HTTP server.
	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	healthSrv := &http.Server{Addr: ":" + cfg.HealthPort, Handler: healthMux}
	go func() {
		slog.Info("health check listening", "port", cfg.HealthPort)
		if err := healthSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("health server error", "err", err)
		}
	}()

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

	<-ctx.Done()
	slog.Info("shutdown signal received, draining...")
	_ = ln.Close()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = healthSrv.Shutdown(shutdownCtx)

	_ = logWriter.Close()
	slog.Info("shutdown complete")
}
