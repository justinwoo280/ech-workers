package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"ewp-core/dns"
	"ewp-core/engine"
	"ewp-core/log"
)

// udpResponseWriter is the write-side of a gVisor UDP socket exposed
// to the rest of the package. tunSocket uses it to push reply
// datagrams back into the gVisor stack so they appear on the TUN
// device with the correct (per FakeIP / Real-IP rule) source address.
//
// Signature matches *gonet.UDPConn (net.PacketConn).
type udpResponseWriter interface {
	WriteTo(payload []byte, addr net.Addr) (int, error)
	Close() error
}

// Handler is the v2 TUN dispatcher.
//
// It owns no transport. Instead it bridges every TCP/UDP flow
// observed on the TUN device to the engine.InboundHandler bound by
// BindEngine(); the engine's Router decides which Outbound carries
// the flow.
//
// FakeIP semantics live in tunSocket; this Handler only maps each
// observed (src,dst) into a tunSocket and hands it off.
type Handler struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.RWMutex
	engine  engine.InboundHandler
	fakeIP  *dns.FakeIPPool

	// Per-(src,dst) UDP socket map keeps a stable engine.UDPConn alive
	// for the lifetime of the flow on the TUN side. The key is the
	// (TUN-observed src, TUN-observed dst) tuple; gVisor delivers all
	// inbound packets for that 4-tuple to the same conn instance.
	udpMu sync.Mutex
	udp   map[udpKey]*tunSocket
}

type udpKey struct {
	src netip.AddrPort
	dst netip.AddrPort
}

// NewHandler builds a v2 TUN handler. The Engine must be bound via
// BindEngine before Start; until then HandleTCP/HandleUDP drop flows.
func NewHandler(ctx context.Context) *Handler {
	ctx, cancel := context.WithCancel(ctx)
	return &Handler{
		ctx:    ctx,
		cancel: cancel,
		udp:    make(map[udpKey]*tunSocket),
	}
}

// BindEngine connects the Handler to the engine's InboundHandler.
// Safe to call after Start; flows received before binding are
// dropped.
func (h *Handler) BindEngine(e engine.InboundHandler) {
	h.mu.Lock()
	h.engine = e
	h.mu.Unlock()
}

// SetFakeIPPool installs the shared FakeIP pool. May be nil.
func (h *Handler) SetFakeIPPool(pool *dns.FakeIPPool) {
	h.mu.Lock()
	h.fakeIP = pool
	h.mu.Unlock()
}

// Close stops the handler and tears down per-flow resources.
func (h *Handler) Close() error {
	h.cancel()
	h.udpMu.Lock()
	for k, s := range h.udp {
		_ = s.Close()
		delete(h.udp, k)
	}
	h.udpMu.Unlock()
	return nil
}

// HandleTCP is invoked by the gVisor TCP forwarder per accepted flow.
// We wrap the gVisor conn in a thin engine.TCPConn shim and hand it
// to the engine.
func (h *Handler) HandleTCP(conn *gonet.TCPConn) {
	h.mu.RLock()
	eng := h.engine
	pool := h.fakeIP
	h.mu.RUnlock()
	if eng == nil {
		_ = conn.Close()
		return
	}

	src, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
	dst, _ := netip.ParseAddrPort(conn.LocalAddr().String())
	srcEP := engine.Endpoint{Addr: src, Port: src.Port()}
	dstEP := makeDstEndpoint(dst, pool)

	go func() {
		defer conn.Close()
		if err := eng.HandleTCP(h.ctx, srcEP, dstEP, conn); err != nil {
			log.V("[TUN TCP] %s -> %s: %v", src, dst, err)
		}
	}()
}

// HandleUDP is invoked by the gVisor UDP forwarder for every packet.
// It reuses one tunSocket per (src,dst) so multiple datagrams of the
// same flow end up on the same engine.UDPConn (and therefore the
// same outbound sub-session).
func (h *Handler) HandleUDP(conn udpResponseWriter, payload []byte, src netip.AddrPort, dst netip.AddrPort) {
	h.mu.RLock()
	eng := h.engine
	pool := h.fakeIP
	h.mu.RUnlock()
	if eng == nil {
		return
	}

	srcEP := engine.Endpoint{Addr: src, Port: src.Port()}
	dstEP := makeDstEndpoint(dst, pool)

	key := udpKey{src: src, dst: dst}
	h.udpMu.Lock()
	sock, ok := h.udp[key]
	if !ok {
		sock = newTunSocket(conn, src, dst, dstEP, pool)
		h.udp[key] = sock
		h.udpMu.Unlock()
		go func() {
			err := eng.HandleUDP(h.ctx, srcEP, dstEP, sock)
			h.udpMu.Lock()
			delete(h.udp, key)
			h.udpMu.Unlock()
			if err != nil && err != io.EOF {
				log.V("[TUN UDP] %s -> %s: %v", src, dst, err)
			}
		}()
	} else {
		h.udpMu.Unlock()
	}
	sock.feedFromTUN(payload, src)
}

// makeDstEndpoint converts a TUN-observed dst into an engine.Endpoint,
// performing FakeIP reverse lookup so the outbound DNS policy applies.
func makeDstEndpoint(dst netip.AddrPort, pool *dns.FakeIPPool) engine.Endpoint {
	ep := engine.Endpoint{Addr: dst, Port: dst.Port()}
	if pool != nil {
		if name, ok := pool.LookupByIP(dst.Addr()); ok {
			ep.Domain = name
		}
	}
	return ep
}
