package tun

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	commpool "ewp-core/common/bufferpool"
	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/transport"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// udpSession represents a proxy tunnel connection for a specific local UDP socket
type udpSession struct {
	tunnelConn transport.TunnelConn
	remoteAddr netip.AddrPort // the remote server addr (responses appear to come FROM here)
	lastActive atomic.Int64  // UnixNano; updated on every packet, read by cleanup goroutine
}

// UDPWriter allows the handler to write responses back to the TUN virtual device
type UDPWriter interface {
	WriteTo(p []byte, src netip.AddrPort, dst netip.AddrPort) error
	ReleaseConn(src netip.AddrPort, dst netip.AddrPort)
}

type Handler struct {
	transport   transport.Transport
	ctx         context.Context
	dnsResolver *dns.TunnelDNSResolver

	udpWriter   UDPWriter
	udpSessions sync.Map // map[string]*udpSession (key is localAddr string)
}

func NewHandler(ctx context.Context, trans transport.Transport, udpWriter UDPWriter) *Handler {
	h := &Handler{
		transport: trans,
		ctx:       ctx,
		udpWriter: udpWriter,
	}

	// Start UDP Session Cleanup coroutine (Full Cone NAT state tracking)
	go h.cleanupUDPSessions()

	return h
}

// SetDNSResolver sets the tunnel DNS resolver for handling DNS queries (port 53).
func (h *Handler) SetDNSResolver(resolver *dns.TunnelDNSResolver) {
	h.dnsResolver = resolver
}

func (h *Handler) HandleTCP(conn *gonet.TCPConn) {
	dstAddr := conn.LocalAddr().(*net.TCPAddr)
	srcAddr := conn.RemoteAddr().(*net.TCPAddr)

	target := dstAddr.String()
	log.V("[TUN TCP] New connection: %s -> %s", srcAddr, target)

	tunnelConn, err := h.transport.Dial()
	if err != nil {
		log.Printf("[TUN TCP] Tunnel dial failed: %v", err)
		conn.Close()
		return
	}
	defer tunnelConn.Close()
	defer conn.Close()

	stopPing := tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	if err := tunnelConn.Connect(target, nil); err != nil {
		log.Printf("[TUN TCP] CONNECT failed: %v", err)
		return
	}

	log.V("[TUN TCP] Connected: %s", target)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		b := commpool.GetLarge()
		defer commpool.PutLarge(b)
		for {
			n, err := conn.Read(b)
			if err != nil {
				tunnelConn.Close()
				return
			}
			if err := tunnelConn.Write(b[:n]); err != nil {
				conn.Close()
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		b := commpool.GetLarge()
		defer commpool.PutLarge(b)
		for {
			n, err := tunnelConn.Read(b)
			if err != nil {
				conn.Close()
				return
			}
			if _, err := conn.Write(b[:n]); err != nil {
				tunnelConn.Close()
				return
			}
		}
	}()

	wg.Wait()
	log.V("[TUN TCP] Disconnected: %s", target)
}

func (h *Handler) HandleUDP(payload []byte, src netip.AddrPort, dst netip.AddrPort) {
	// DNS interception: resolve port 53 queries locally
	if dst.Port() == 53 && h.dnsResolver != nil {
		log.V("[TUN DNS] Intercepted DNS query: %s -> %s", src, dst)
		h.handleDNS(payload, src, dst)
		return
	}

	// Get or Create UDP tunnel session for the source IP:Port (NAT binding)
	// Use netip.AddrPort directly as map key (comparable value type, zero allocation)
	val, ok := h.udpSessions.Load(src)
	var session *udpSession

	if !ok {
		// Create a new tunnel connection for this local UDP port
		tunnelConn, err := h.transport.Dial()
		if err != nil {
			log.Printf("[TUN UDP] Tunnel dial failed for %s: %v", src, err)
			return
		}

		session = &udpSession{
			tunnelConn: tunnelConn,
			remoteAddr: dst, // dst is always an IP (from gVisor), safe to store directly
		}
		session.lastActive.Store(time.Now().UnixNano())

		actual, loaded := h.udpSessions.LoadOrStore(src, session)
		if loaded {
			// Another goroutine beat us to it, close the one we just made
			tunnelConn.Close()
			session = actual.(*udpSession)
		} else {
			log.V("[TUN UDP] New session binding: %s -> %s", src, dst)

			// We only `ConnectUDP` once per pseudo-socket to trick Trojan
			// into maintaining a pseudo-socket. The destination passed here
			// is completely arbitrary since UDP mapping sends the actual target
			// inside every WebSocket/transport packet frame anyway.
			// We just arbitrarily use the First Packet's target.
			if err := tunnelConn.ConnectUDP(transport.Endpoint{Addr: dst}, nil); err != nil {
				log.Printf("[TUN UDP] ConnectUDP failed: %v", err)
				tunnelConn.Close()
				h.udpSessions.Delete(src)
				return
			}

			go h.udpReadLoop(src, session)
		}
	} else {
		session = val.(*udpSession)
	}

	session.lastActive.Store(time.Now().UnixNano())

	// Forward UDP payload to the target via the proxy tunnel
	if err := session.tunnelConn.WriteUDP(transport.Endpoint{Addr: dst}, payload); err != nil {
		log.V("[TUN UDP] Packet send failed: %v", err)
	}
}

// udpReadLoop continuously reads UDP responses from the proxy tunnel and writes them back to the TUN Stack.
func (h *Handler) udpReadLoop(tunClientSrc netip.AddrPort, session *udpSession) {
	defer h.udpSessions.Delete(tunClientSrc)
	defer session.tunnelConn.Close()

	// Eagerly release the cached write-side conn when the session ends.
	if h.udpWriter != nil && session.remoteAddr.IsValid() {
		defer h.udpWriter.ReleaseConn(session.remoteAddr, tunClientSrc)
	}

	stopPing := session.tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	buf := commpool.GetLarge()
	defer commpool.PutLarge(buf)

	for {
		n, remoteAddr, err := session.tunnelConn.ReadUDPFrom(buf)
		if err != nil {
			log.V("[TUN UDP] Session read loop closed for %s: %v", tunClientSrc, err)
			return
		}

		if h.udpWriter == nil || h.ctx.Err() != nil {
			return
		}

		actualRemote := remoteAddr
		if !actualRemote.IsValid() {
			actualRemote = session.remoteAddr
		}

		// Inject reply into gVisor:
		//   src = actualRemote  (packet appears to come FROM the remote server)
		//   dst = tunClientSrc   (packet is delivered TO the TUN client)
		if actualRemote.IsValid() {
			if err := h.udpWriter.WriteTo(buf[:n], actualRemote, tunClientSrc); err != nil {
				log.V("[TUN UDP] Write to TUN failed: %v", err)
			}
		} else {
			log.V("[TUN UDP] Dropping reply: actualRemote not valid for session %s", tunClientSrc)
		}
	}
}

func (h *Handler) cleanupUDPSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-5 * time.Minute).UnixNano()
			h.udpSessions.Range(func(key, value interface{}) bool {
				session := value.(*udpSession)
				if session.lastActive.Load() < cutoff {
					log.V("[TUN UDP] Cleaning up inactive NAT session: %s", key)
					session.tunnelConn.Close()
					h.udpSessions.Delete(key)
				}
				return true
			})
		}
	}
}

func (h *Handler) handleDNS(query []byte, src netip.AddrPort, dst netip.AddrPort) {
	if len(query) < 12 {
		log.V("[TUN DNS] Query too short (%d bytes), ignoring", len(query))
		return
	}

	go func(q []byte, tunClient netip.AddrPort, dnsServer netip.AddrPort) {
		response, err := h.dnsResolver.QueryRaw(h.ctx, q)
		if err != nil {
			log.Printf("[TUN DNS] Resolution failed: %v", err)
			return
		}

		if len(response) == 0 {
			log.Printf("[TUN DNS] Empty response")
			return
		}

		// Inject DNS reply into gVisor:
		//   src = dnsServer  (packet appears to come FROM the DNS server)
		//   dst = tunClient  (packet is delivered TO the TUN client app)
		if h.udpWriter != nil && h.ctx.Err() == nil {
			if err := h.udpWriter.WriteTo(response, dnsServer, tunClient); err != nil {
				log.V("[TUN DNS] Failed to write response: %v", err)
			} else {
				log.V("[TUN DNS] Resolved: %d bytes", len(response))
			}
		}
	}(query, src, dst)
}
