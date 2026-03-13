package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	ewpserver "ewp-core/internal/server"
	"ewp-core/log"
	masqueauth "ewp-core/protocol/masque"
	"ewp-core/transport"

	masquego "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// tcpBufPool provides 64 KiB reusable buffers for TCP tunnel relay goroutines.
// io.CopyBuffer with a pooled buffer eliminates per-connection heap allocations
// and cuts GC pressure significantly under high concurrent TCP load.
var tcpBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 64*1024)
		return &b
	},
}

// Handler is an HTTP/3 request handler that serves the MASQUE protocol.
//
// It handles two request types on the same HTTP/3 server:
//   - HTTP CONNECT (plain):           TCP tunneling — proxies to an arbitrary TCP target.
//   - Extended CONNECT connect-udp:   UDP tunneling — proxies via masquego.Proxy (RFC 9298).
//
// Both require a valid X-Masque-Auth header (see protocol/masque/auth.go).
type Handler struct {
	validUUIDs  [][16]byte
	udpTemplate *uritemplate.Template
	udpProxy    masquego.Proxy
	dialer      net.Dialer // shared, zero-value is valid; avoids per-request alloc

	newProtocolHandler func() ewpserver.ProtocolHandler
}

// NewHandler creates a Handler.
//   - uuids is the list of authorised UUID strings (comma-separated or multiple calls to AddUUID).
//   - udpTemplateStr is the RFC 6570 URI template for UDP proxying,
//     e.g. "https://proxy.example.com/masque/{target_host}/{target_port}".
func NewHandler(udpTemplateStr string, uuids []string, newPH func() ewpserver.ProtocolHandler) (*Handler, error) {
	tmpl, err := uritemplate.New(udpTemplateStr)
	if err != nil {
		return nil, err
	}

	h := &Handler{
		udpTemplate:        tmpl,
		newProtocolHandler: newPH,
	}

	for _, u := range uuids {
		if err := h.AddUUID(u); err != nil {
			return nil, err
		}
	}
	return h, nil
}

// AddUUID registers an additional valid UUID.
func (h *Handler) AddUUID(uuidStr string) error {
	uuid, err := transport.ParseUUID(uuidStr)
	if err != nil {
		return err
	}
	h.validUUIDs = append(h.validUUIDs, uuid)
	return nil
}

// ServeHTTP routes incoming HTTP/3 requests.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect && r.Proto == "connect-udp":
		h.handleUDP(w, r)
	case r.Method == http.MethodConnect:
		h.handleTCP(w, r)
	default:
		http.Error(w, "not found", http.StatusNotFound)
	}
}

// ── TCP CONNECT ──────────────────────────────────────────────────────────────

func (h *Handler) handleTCP(w http.ResponseWriter, r *http.Request) {
	if _, err := masqueauth.ValidateAuthHeader(r.Header, h.validUUIDs); err != nil {
		log.Warn("[MASQUE] TCP auth failed from %s: %v", r.RemoteAddr, err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	target := r.Host
	if target == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	dialCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	remote, err := h.dialer.DialContext(dialCtx, "tcp", target)
	if err != nil {
		log.Warn("[MASQUE] TCP dial %s: %v", target, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.(http.Flusher).Flush()

	str := w.(http3.HTTPStreamer).HTTPStream()

	log.Info("[MASQUE] TCP tunnel: %s -> %s", r.RemoteAddr, target)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bufp := tcpBufPool.Get().(*[]byte)
		io.CopyBuffer(remote, str, *bufp)
		tcpBufPool.Put(bufp)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		bufp := tcpBufPool.Get().(*[]byte)
		io.CopyBuffer(str, remote, *bufp)
		tcpBufPool.Put(bufp)
		str.Close()
	}()
	wg.Wait()
	remote.Close()

	log.Info("[MASQUE] TCP closed: %s -> %s", r.RemoteAddr, target)
}

// ── UDP CONNECT-UDP ──────────────────────────────────────────────────────────

func (h *Handler) handleUDP(w http.ResponseWriter, r *http.Request) {
	if _, err := masqueauth.ValidateAuthHeader(r.Header, h.validUUIDs); err != nil {
		log.Warn("[MASQUE] UDP auth failed from %s: %v", r.RemoteAddr, err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	req, err := masquego.ParseRequest(r, h.udpTemplate)
	if err != nil {
		var perr *masquego.RequestParseError
		if errors.As(err, &perr) {
			http.Error(w, perr.Error(), perr.HTTPStatus)
		} else {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		log.Warn("[MASQUE] UDP parse request from %s: %v", r.RemoteAddr, err)
		return
	}

	log.Info("[MASQUE] UDP tunnel: %s -> %s", r.RemoteAddr, req.Target)

	if err := h.udpProxy.Proxy(w, req); err != nil {
		log.Info("[MASQUE] UDP closed: %s -> %s: %v", r.RemoteAddr, req.Target, err)
	}
}
