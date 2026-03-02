package main

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// loadConfig builds a Config from environment variables with hardcoded defaults.
// CLI flags --port=, --log=, and --log-rotate-size= take precedence over env vars.
func loadConfig() Config {
	cfg := Config{
		Port:            getEnv("ICAP_PORT", "11344"),
		LogFile:         getEnv("LOG_FILE", "/var/log/icap/icap_logger.log"),
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
