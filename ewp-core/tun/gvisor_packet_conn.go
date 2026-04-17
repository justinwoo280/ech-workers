package tun

import (
	"net/netip"
	"sync"
	"time"

	"ewp-core/transport"
)

// GVisorPacketConn wraps a gVisor UDP endpoint to implement network.PacketConn.
// It enables bidirectional packet copying with NATPacketConn.
type GVisorPacketConn struct {
	// originDst is the client's perceived destination (FakeIP:Port)
	originDst netip.AddrPort

	// gvisorConn is the gVisor UDP endpoint for writing back to client
	gvisorConn udpResponseWriter

	// upstreamChan receives packets from Dispatch() for upstream (client → tunnel)
	upstreamChan chan packetWithAddr

	// doneChan signals connection closure
	doneChan chan struct{}

	mu     sync.Mutex
	closed bool
}

type packetWithAddr struct {
	payload []byte
	src     netip.AddrPort
}

// NewGVisorPacketConn creates a new GVisorPacketConn.
func NewGVisorPacketConn(originDst netip.AddrPort, conn udpResponseWriter) *GVisorPacketConn {
	return &GVisorPacketConn{
		originDst:    originDst,
		gvisorConn:   conn,
		upstreamChan: make(chan packetWithAddr, 256), // Increased from 64 to reduce packet drops
		doneChan:     make(chan struct{}),
	}
}

// ReadPacket reads a packet from the upstream channel.
// This is called by CopyPacket to get packets from the client.
func (g *GVisorPacketConn) ReadPacket(buf []byte) (int, transport.Endpoint, error) {
	pkt, ok := <-g.upstreamChan
	if !ok {
		return 0, transport.Endpoint{}, ErrClosed
	}

	n := copy(buf, pkt.payload)
	// Return the source address as the endpoint (for logging/debugging)
	return n, transport.Endpoint{Addr: pkt.src}, nil
}

// WritePacket writes a packet to the gVisor endpoint (downstream: tunnel → client).
func (g *GVisorPacketConn) WritePacket(payload []byte, _ transport.Endpoint) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return ErrClosed
	}

	_, err := g.gvisorConn.Write(payload)
	return err
}

// SendUpstream sends a packet to the upstream channel.
// Called by Dispatch() when receiving packets from the client.
func (g *GVisorPacketConn) SendUpstream(payload []byte, src netip.AddrPort) error {
	// Make a copy of the payload since the caller may reuse the buffer
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)

	pkt := packetWithAddr{
		payload: payloadCopy,
		src:     src,
	}

	// Use doneChan to avoid race between Close() and channel send
	select {
	case g.upstreamChan <- pkt:
		return nil
	case <-g.doneChan:
		return ErrClosed
	case <-time.After(5 * time.Second):
		// Timeout: channel is blocked, likely high load
		return ErrClosed
	}
}

// Close closes the connection.
func (g *GVisorPacketConn) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.closed {
		return nil
	}
	g.closed = true
	
	close(g.doneChan)      // Signal all SendUpstream to exit
	close(g.upstreamChan)  // Signal ReadPacket to exit
	
	return g.gvisorConn.Close()
}

// OriginDst returns the client's perceived destination address.
func (g *GVisorPacketConn) OriginDst() netip.AddrPort {
	return g.originDst
}
