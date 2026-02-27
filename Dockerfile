# Multi-stage build: compile with Go, run on hardened Alpine image
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Cache dependencies before copying full source
COPY go.mod ./
RUN go mod download

# Copy source and build a fully static, stripped binary
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o icap-logger .

FROM alpine:3.20
WORKDIR /app

# Install wget for health checks; create non-root user and log directory
RUN apk add --no-cache wget && \
    addgroup -S icap && \
    adduser -S -G icap icap && \
    mkdir -p /var/log && \
    chown icap:icap /var/log

COPY --from=builder /app/icap-logger .

# ICAP port + health check port
EXPOSE 1344 8080

USER icap

ENTRYPOINT ["./icap-logger"]