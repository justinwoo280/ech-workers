package protocol

import (
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ewp-core/log"
	"ewp-core/transport"
)

var (
	largeBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 32*1024)
		},
	}

	activeConns   int64
	totalUpload   int64
	totalDownload int64
)

type TunnelHandler struct {
	transport transport.Transport
}

func NewTunnelHandler(trans transport.Transport) *TunnelHandler {
	return &TunnelHandler{
		transport: trans,
	}
}

func (h *TunnelHandler) HandleTunnel(conn net.Conn, target string, clientAddr string, initialData []byte, sendSuccessReply func() error) error {
	atomic.AddInt64(&activeConns, 1)
	defer atomic.AddInt64(&activeConns, -1)

	tunnelConn, err := h.transport.Dial()
	if err != nil {
		return err
	}
	defer tunnelConn.Close()

	stopPing := tunnelConn.StartPing(30 * time.Second)
	defer close(stopPing)

	conn.SetDeadline(time.Time{})

	if err := tunnelConn.Connect(target, initialData); err != nil {
		return err
	}

	if err := sendSuccessReply(); err != nil {
		return err
	}

	log.V("[Proxy] %s connected: %s", clientAddr, target)

	done := make(chan bool, 2)

	go func() {
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if err := tunnelConn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
			atomic.AddInt64(&totalUpload, int64(n))
		}
	}()

	go func() {
		buf := largeBufferPool.Get().([]byte)
		defer largeBufferPool.Put(buf)

		for {
			n, err := tunnelConn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if _, err := conn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
			atomic.AddInt64(&totalDownload, int64(n))
		}
	}()

	<-done
	log.V("[Proxy] %s disconnected: %s", clientAddr, target)
	return nil
}

func (h *TunnelHandler) HandleUDPPacket(target string, data []byte, clientAddr string) ([]byte, error) {
	tunnelConn, err := h.transport.Dial()
	if err != nil {
		return nil, err
	}
	defer tunnelConn.Close()

	// Send UDP packet through tunnel using UDP mode
	if err := tunnelConn.ConnectUDP(target, data); err != nil {
		return nil, err
	}

	// Wait for response with timeout
	type readResult struct {
		data []byte
		err  error
	}
	
	resultChan := make(chan readResult, 1)
	
	go func() {
		buf := make([]byte, 65536)
		n, err := tunnelConn.Read(buf)
		if err != nil {
			resultChan <- readResult{nil, err}
			return
		}
		resultChan <- readResult{buf[:n], nil}
	}()
	
	select {
	case result := <-resultChan:
		if result.err != nil {
			return nil, result.err
		}
		log.V("[UDP Tunnel] %s -> %s: sent %d bytes, received %d bytes", clientAddr, target, len(data), len(result.data))
		return result.data, nil
	case <-time.After(5 * time.Second):
		return nil, io.ErrUnexpectedEOF
	}
}

func IsNormalCloseError(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "connection reset by peer") ||
		strings.Contains(errStr, "normal closure")
}

func GetStats() (active, upload, download int64) {
	return atomic.LoadInt64(&activeConns), atomic.LoadInt64(&totalUpload), atomic.LoadInt64(&totalDownload)
}
