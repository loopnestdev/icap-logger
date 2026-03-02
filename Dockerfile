# Multi-stage build: compile with Go, run on hardened Alpine image
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Cache dependencies before copying full source
COPY go.mod ./
RUN go mod download

# Copy source and build a fully static, stripped binary
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o icap-logger .

FROM --platform=linux/amd64 alpine:3.23
WORKDIR /app

# Install wget for health checks; create non-root user and log directory
RUN apk update --no-check-certificate && \
    apk upgrade --no-check-certificate && \
    apk add --no-cache --no-check-certificate \
      bind-tools \
      ca-certificates \
      curl \
      jq \
      nss-tools \
      logrotate \
      tzdata \
      wget && \
    rm -rf /var/cache/apk/* /tmp/* && \
    update-ca-certificates && \
    cp -R /usr/share/zoneinfo/Australia/ACT /etc/localtime && \
    echo "Australia/ACT" > /etc/timezone && \
    addgroup -S icap && \
    adduser -S -G icap icap && \
    mkdir -p /var/log/icap && \
    chown icap:icap /var/log/icap

COPY --from=builder /app/icap-logger .

# ICAP port + health check port
EXPOSE 1344 8080

USER icap

ENTRYPOINT ["./icap-logger"]