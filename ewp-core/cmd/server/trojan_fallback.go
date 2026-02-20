package main

import (
	"io"
	"net"
	"strconv"
	"time"

	log "ewp-core/log"
)

type TrojanFallbackHandler struct {
	addr string
}

func (h *TrojanFallbackHandler) HandleFallback(conn net.Conn, header []byte) error {
	defer conn.Close()

	fallbackConn, err := net.DialTimeout("tcp", h.addr, 10*time.Second)
	if err != nil {
		log.Warn("Fallback dial failed: %v", err)
		h.sendNginxResponse(conn)
		return nil
	}
	defer fallbackConn.Close()

	log.Info("Fallback connection to %s", h.addr)

	if len(header) > 0 {
		if _, err := fallbackConn.Write(header); err != nil {
			return err
		}
	}

	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		io.CopyBuffer(fallbackConn, conn, buf)
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)
		io.CopyBuffer(conn, fallbackConn, buf)
	}()

	<-done
	return nil
}

func (h *TrojanFallbackHandler) sendNginxResponse(conn net.Conn) {
	response := "HTTP/1.1 200 OK\r\n" +
		"Server: nginx/1.18.0\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: " + strconv.Itoa(len(nginxHTML)) + "\r\n" +
		"Connection: close\r\n" +
		"\r\n" +
		nginxHTML
	conn.Write([]byte(response))
}
