package main

import (
    "fmt"
    "io"
    "log"
    "net"
    "os"
    "time"
)

// Minimal ICAP server that logs request bodies
func main() {
    f, _ := os.OpenFile("/var/log/icap_bodies.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    logger := log.New(f, "", 0)

    ln, _ := net.Listen("tcp", ":1344")
    log.Println("ICAP logger listening on :1344")
    for {
        conn, err := ln.Accept()
        if err != nil { continue }
        go handleConn(conn, logger)
    }
}

func handleConn(conn net.Conn, logger *log.Logger) {
    defer conn.Close()
    buf, _ := io.ReadAll(conn)
    logger.Printf("[%s] %s\n", time.Now().Format(time.RFC3339), string(buf))
    conn.Write([]byte("ICAP/1.0 204 No Modifications\r\nConnection: close\r\n\r\n"))
}