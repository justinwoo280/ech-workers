package tun

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"ewp-core/common/network"
	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/protocol/ewp"
	"ewp-core/transport"
	"ewp-core/transport/packet"
)

// protocolTimeout returns the UDP session timeout for a given destination port.
func protocolTimeout(port uint16) time.Duration {
	switch port {
	case 53:
		return 5 * time.Second
	case 443, 80:
		return 30 * time.Second
	case 123:
		return 10 * time.Second
	default:
		return 2 * time.Minute
	}
}

// dispatchSession represents an active UDP proxy session.
type dispatchSession struct {
	natConn       *NATPacketConn
	tunnelConn    transport.TunnelConn
	packetConn    network.PacketConn
	endpoint      transport.Endpoint
	closeOnce     sync.Once
}

func (s *dispatchSession) close() {
	s.closeOnce.Do(func() {
		if s.packetConn != nil {
			s.packetConn.Close() // This closes TimeoutPacketConn -> TunnelPacketConn -> tunnelConn
		}
		// No need to close tunnelConn again - it's already closed by packetConn.Close()
		s.natConn.Close()
	})
}

// PacketDispatcher is the UDP dispatch center.
type PacketDispatcher struct {
	transport  transport.Transport
	ctx        context.Context
	dnsRouter  *dns.DefaultDNSRouter
	fakeIPPool *dns.FakeIPPool // Legacy: for backward compatibility

	sessions sync.Map
}

// NewPacketDispatcher creates a UDP packet dispatcher.
func NewPacketDispatcher(ctx context.Context, trans transport.Transport) *PacketDispatcher {
	return &PacketDispatcher{
		transport: trans,
		ctx:       ctx,
	}
}

// SetFakeIPPool injects the FakeIP pool (legacy compatibility).
func (d *PacketDispatcher) SetFakeIPPool(pool *dns.FakeIPPool) {
	d.fakeIPPool = pool
}

// SetDNSRouter injects the DNS router.
func (d *PacketDispatcher) SetDNSRouter(router *dns.DefaultDNSRouter) {
	d.dnsRouter = router
}

// Dispatch is the main entry point for UDP packet handling.
func (d *PacketDispatcher) Dispatch(conn udpResponseWriter, payload []byte, src netip.AddrPort, dst netip.AddrPort) {
	if d.ctx.Err() != nil {
		if conn != nil {
			conn.Close()
		}
		return
	}

	// Phase 1: DNS interception
	if dst.Port() == 53 && (d.fakeIPPool != nil || d.dnsRouter != nil) {
		payloadCopy := make([]byte, len(payload))
		copy(payloadCopy, payload)
		go d.handleDNS(conn, payloadCopy, src, dst)
		return
	}

	// Phase 2: FakeIP / ReverseMapping resolution
	endpoint := d.resolveEndpoint(dst)

	// Phase 3: Session routing
	key := udpSessionKey{src: src, dst: dst}

	if val, ok := d.sessions.Load(key); ok {
		session := val.(*dispatchSession)
		if conn != nil {
			conn.Close()
		}
		if err := session.natConn.SendUpstream(payload, src); err != nil {
			log.Printf("[Dispatcher] Failed to send packet to existing session %s->%s: %v", key.src, key.dst, err)
		}
		return
	}

	if conn == nil {
		log.V("[Dispatcher] UDP packet for unknown session and no conn, dropping: %s->%s", src, dst)
		return
	}

	// Create NATPacketConn
	natConn := NewNATPacketConn(dst, endpoint.Domain, endpoint.Port, conn)

	// Dial tunnel
	tunnelConn, err := d.transport.Dial()
	if err != nil {
		log.Printf("[Dispatcher] Tunnel dial failed for %s->%s: %v", src, dst, err)
		conn.Close()
		return
	}

	timeout := protocolTimeout(dst.Port())

	session := &dispatchSession{
		natConn:    natConn,
		tunnelConn: tunnelConn,
		endpoint:   endpoint,
	}

	actual, loaded := d.sessions.LoadOrStore(key, session)
	if loaded {
		tunnelConn.Close()
		conn.Close()
		existing := actual.(*dispatchSession)
		if err := existing.natConn.SendUpstream(payload, src); err != nil {
			log.Printf("[Dispatcher] Failed to send packet to loaded session %s->%s: %v", key.src, key.dst, err)
		}
		return
	}

	log.V("[Dispatcher] New UDP session: %s -> %s (endpoint=%v, timeout=%s)", src, dst, endpoint, timeout)

	// ConnectUDP handshake with initial payload
	if err := tunnelConn.ConnectUDP(endpoint, payload); err != nil {
		log.Printf("[Dispatcher] ConnectUDP failed: %v", err)
		tunnelConn.Close()
		conn.Close()
		d.sessions.Delete(key)
		return
	}

	// Create TunnelPacketConn
	var tunnelPacketConn *packet.TunnelPacketConn
	if tc, ok := tunnelConn.(interface{ UseTrojan() bool }); ok && tc.UseTrojan() {
		tunnelPacketConn = packet.NewTrojanPacketConn(tunnelConn)
	} else {
		globalID := ewp.NewGlobalID()
		var flowState *ewp.FlowState
		if fs, ok := tunnelConn.(interface{ GetFlowState() *ewp.FlowState }); ok {
			flowState = fs.GetFlowState()
		}
		tunnelPacketConn = packet.NewEWPPacketConn(tunnelConn, globalID, flowState)
	}

	// Wrap with timeout
	session.packetConn = network.NewTimeoutPacketConn(tunnelPacketConn, timeout)

	// Start bidirectional copy
	go d.runSession(session, key)
}

// runSession handles bidirectional packet copying for a session.
func (d *PacketDispatcher) runSession(session *dispatchSession, key udpSessionKey) {
	defer func() {
		d.sessions.Delete(key)
		session.close()
		log.V("[Dispatcher] Session closed: %s -> %s", key.src, key.dst)
	}()

	// Start ping for keepalive
	stopPing := session.tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	// Use two goroutines for bidirectional copy
	done := make(chan struct{}, 2)

	// Upstream: NAT → Tunnel
	go func() {
		network.CopyPacket(session.packetConn, session.natConn)
		done <- struct{}{}
	}()

	// Downstream: Tunnel → NAT
	go func() {
		network.CopyPacket(session.natConn, session.packetConn)
		done <- struct{}{}
	}()

	// Wait for either direction to finish
	<-done
}

// handleDNS handles DNS queries asynchronously.
func (d *PacketDispatcher) handleDNS(conn udpResponseWriter, query []byte, src netip.AddrPort, dst netip.AddrPort) {
	if conn != nil {
		defer conn.Close()
	}
	if len(query) < 12 {
		return
	}

	var response []byte
	var err error

	// Use DNSRouter if available
	if d.dnsRouter != nil {
		ctx, cancel := context.WithTimeout(d.ctx, 5*time.Second)
		defer cancel()
		response, err = d.dnsRouter.Exchange(ctx, query)
	} else if d.fakeIPPool != nil {
		// Legacy FakeIP-only mode
		domain := dns.ParseDNSName(query)
		if domain == "" {
			return
		}
		fakeIPv4 := d.fakeIPPool.AllocateIPv4(domain)
		fakeIPv6 := d.fakeIPPool.AllocateIPv6(domain)
		response = dns.BuildDNSResponse(query, fakeIPv4, fakeIPv6)
	}

	if err != nil {
		log.Printf("[Dispatcher] DNS query failed: %v", err)
		return
	}

	if response == nil {
		log.V("[Dispatcher] DNS: unsupported query")
		return
	}

	if conn != nil && d.ctx.Err() == nil {
		if _, err := conn.Write(response); err != nil {
			log.Printf("[Dispatcher] DNS write response failed: %v", err)
		}
	}
}

// resolveEndpoint resolves the destination address to a transport.Endpoint.
func (d *PacketDispatcher) resolveEndpoint(dst netip.AddrPort) transport.Endpoint {
	unmapped := dst.Addr().Unmap()

	// Use DNSRouter if available
	if d.dnsRouter != nil {
		if domain, ok := d.dnsRouter.LookupReverseMapping(unmapped); ok {
			log.V("[Dispatcher] Reverse mapping: %s -> %s:%d", dst, domain, dst.Port())
			return transport.Endpoint{Domain: domain, Port: dst.Port()}
		}
		return transport.Endpoint{Addr: dst}
	}

	// Legacy FakeIP-only mode
	if d.fakeIPPool != nil {
		if domain, ok := d.fakeIPPool.LookupByIP(unmapped); ok {
			log.V("[Dispatcher] FakeIP reverse: %s -> %s:%d", dst, domain, dst.Port())
			return transport.Endpoint{Domain: domain, Port: dst.Port()}
		}
	}

	return transport.Endpoint{Addr: dst}
}

// Close closes the dispatcher and cleans up all sessions.
func (d *PacketDispatcher) Close() {
	d.sessions.Range(func(k, v interface{}) bool {
		v.(*dispatchSession).close()
		d.sessions.Delete(k)
		return true
	})
}
