package tun

import (
	"context"
	"net"
	"net/netip"
	"strconv"
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
	InjectUDP(p []byte, src netip.AddrPort, dst netip.AddrPort) error
	ReleaseConn(src netip.AddrPort, dst netip.AddrPort)
}

type Handler struct {
	transport  transport.Transport
	ctx        context.Context
	fakeIPPool *dns.FakeIPPool

	udpWriter   UDPWriter
	udpSessions sync.Map // map[netip.AddrPort]*udpSession
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

// SetFakeIPPool sets the FakeIP pool for instant DNS responses.
func (h *Handler) SetFakeIPPool(pool *dns.FakeIPPool) {
	h.fakeIPPool = pool
}

func (h *Handler) HandleTCP(conn *gonet.TCPConn) {
	dstAddr := conn.LocalAddr().(*net.TCPAddr)
	srcAddr := conn.RemoteAddr().(*net.TCPAddr)

	// If destination is a fake IP, reverse-lookup the domain for Connect
	var target string
	if h.fakeIPPool != nil {
		dstIP, _ := netip.AddrFromSlice(dstAddr.IP)
		dstIP = dstIP.Unmap() // convert ::ffff:198.18.x.x → 198.18.x.x
		if domain, ok := h.fakeIPPool.LookupByIP(dstIP); ok {
			target = net.JoinHostPort(domain, strconv.Itoa(dstAddr.Port))
			log.Printf("[TUN TCP] FakeIP reverse: %s -> %s", dstAddr, target)
		} else if h.fakeIPPool.IsFakeIP(dstIP) {
			log.Printf("[TUN TCP] WARNING: FakeIP %s has no mapping!", dstIP)
		}
	}
	if target == "" {
		target = dstAddr.String()
	}
	log.Printf("[TUN TCP] New connection: %s -> %s", srcAddr, target)

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
	// DNS interception: use FakeIP for instant response
	if dst.Port() == 53 && h.fakeIPPool != nil {
		h.handleDNSFakeIP(payload, src, dst)
		return
	}

	// Reverse-lookup fake IP to domain for UDP endpoint
	var endpoint transport.Endpoint
	if h.fakeIPPool != nil {
		unmapped := dst.Addr().Unmap()
		if domain, ok := h.fakeIPPool.LookupByIP(unmapped); ok {
			endpoint = transport.Endpoint{Domain: domain, Port: dst.Port()}
			log.Printf("[TUN UDP] FakeIP reverse: %s -> %s:%d", dst, domain, dst.Port())
		}
	}
	if endpoint.Domain == "" && !endpoint.Addr.IsValid() {
		endpoint = transport.Endpoint{Addr: dst}
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
			if err := tunnelConn.ConnectUDP(endpoint, nil); err != nil {
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
	if err := session.tunnelConn.WriteUDP(endpoint, payload); err != nil {
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

		// Use the FakeIP the app originally connected to (session.remoteAddr) as the
		// response source. This ensures FakeIP transparency: the app sent to a fakeIP
		// and expects responses from that same fakeIP, not the real remote IP.
		actualRemote := session.remoteAddr
		if !actualRemote.IsValid() {
			actualRemote = remoteAddr
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
			cutoff := time.Now().Add(-2 * time.Minute).UnixNano()
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



// handleDNSFakeIP intercepts a DNS query and returns a fake IP instantly.
// No tunnel connection is needed — pure memory operation, < 1ms response.
func (h *Handler) handleDNSFakeIP(query []byte, src netip.AddrPort, dst netip.AddrPort) {
	if len(query) < 12 {
		return
	}

	// Extract the queried domain name
	domain := dns.ParseDNSName(query)
	if domain == "" {
		log.V("[TUN DNS] FakeIP: unable to parse domain from query")
		return
	}

	// Allocate fake IPs for this domain
	fakeIPv4 := h.fakeIPPool.AllocateIPv4(domain)
	fakeIPv6 := h.fakeIPPool.AllocateIPv6(domain)

	// Build DNS response with the fake IP
	response := dns.BuildDNSResponse(query, fakeIPv4, fakeIPv6)
	if response == nil {
		log.V("[TUN DNS] FakeIP: unsupported query for %s", domain)
		return
	}

	// Inject response directly into TUN (bypasses gVisor transport to avoid port conflict)
	if h.udpWriter != nil && h.ctx.Err() == nil {
		if err := h.udpWriter.InjectUDP(response, dst, src); err != nil {
			log.Printf("[TUN DNS] FakeIP: inject response failed: %v", err)
		} else {
			log.Printf("[TUN DNS] FakeIP: %s -> %s", domain, fakeIPv4)
		}
	}
}
