package webtransport

import (
	"context"
	"net/http"
	"time"

	"ewp-core/log"
	ewpserver "ewp-core/internal/server"

	wtransport "github.com/quic-go/webtransport-go"
)

// Handler is an HTTP handler that upgrades WebTransport sessions and routes
// each accepted bidi stream as a protocol tunnel connection.
type Handler struct {
	wtServer           *wtransport.Server
	newProtocolHandler func() ewpserver.ProtocolHandler
}

// NewHandler creates a Handler wrapping an existing webtransport.Server.
// The handler must be registered at the path used by clients.
func NewHandler(wtServer *wtransport.Server, newProtocolHandler func() ewpserver.ProtocolHandler) *Handler {
	return &Handler{
		wtServer:           wtServer,
		newProtocolHandler: newProtocolHandler,
	}
}

// ServeHTTP upgrades the HTTP/3 request to a WebTransport session,
// then accepts streams in a loop, each handled in its own goroutine.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sess, err := h.wtServer.Upgrade(w, r)
	if err != nil {
		log.Warn("[WebTransport] Upgrade failed from %s: %v", r.RemoteAddr, err)
		return
	}

	clientIP := r.RemoteAddr
	log.V("[WebTransport] Session opened from %s", clientIP)

	for {
		stream, err := sess.AcceptStream(r.Context())
		if err != nil {
			log.V("[WebTransport] Session closed for %s: %v", clientIP, err)
			return
		}
		go h.handleStream(stream, clientIP)
	}
}

// handleStream processes one bidi stream using the unified ProtocolHandler.
func (h *Handler) handleStream(stream *wtransport.Stream, clientIP string) {
	tr := &wtAdapter{stream: stream}

	handshakeData, err := tr.Read()
	if err != nil {
		log.Warn("[WebTransport] Failed to read handshake from %s: %v", clientIP, err)
		stream.Close()
		return
	}

	opts := ewpserver.TunnelOptions{
		Protocol:  h.newProtocolHandler(),
		Transport: tr,
		ClientIP:  clientIP,
		Timeout:   10 * time.Second,
	}

	if err := ewpserver.EstablishTunnel(context.Background(), handshakeData, opts); err != nil {
		log.Debug("[WebTransport] Tunnel closed for %s: %v", clientIP, err)
	}
}

// wtAdapter wraps a WebTransport stream to implement ewpserver.TransportAdapter.
type wtAdapter struct {
	stream *wtransport.Stream
}

func (a *wtAdapter) Read() ([]byte, error) {
	buf := make([]byte, 32*1024)
	n, err := a.stream.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (a *wtAdapter) Write(data []byte) error {
	_, err := a.stream.Write(data)
	return err
}

func (a *wtAdapter) Close() error {
	return a.stream.Close()
}
