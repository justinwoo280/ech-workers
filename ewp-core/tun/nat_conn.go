package tun

import (
	"net/netip"
	"sync"

	"ewp-core/transport"
)

// NATPacketConn implements FakeIP ↔ real address transparent substitution.
// It wraps a GVisorPacketConn and provides address translation for FakeIP scenarios.
//
// Upstream (client → tunnel):
//   Client sends to FakeIP:Port → replaced with real domain:port to tunnel
//
// Downstream (tunnel → client):
//   Tunnel returns data → src rewritten to FakeIP:Port → written back to gVisor conn
type NATPacketConn struct {
	// originDst is the client's perceived destination (FakeIP:Port)
	originDst netip.AddrPort

	// realDomain / realPort are the real target after FakeIP reverse lookup
	realDomain string
	realPort   uint16

	// gvisorConn is the underlying GVisorPacketConn
	gvisorConn *GVisorPacketConn

	mu     sync.Mutex
	closed bool
}

// NewNATPacketConn creates a FakeIP NAT wrapper connection.
//   originDst  — the FakeIP:Port the client wrote to
//   realDomain — the real domain from FakeIP reverse lookup (empty if direct IP)
//   realPort   — the real port
//   conn       — gVisor UDP endpoint for writing back to client
func NewNATPacketConn(
	originDst netip.AddrPort,
	realDomain string,
	realPort uint16,
	conn udpResponseWriter,
) *NATPacketConn {
	return &NATPacketConn{
		originDst:  originDst,
		realDomain: realDomain,
		realPort:   realPort,
		gvisorConn: NewGVisorPacketConn(originDst, conn),
	}
}

// OriginDst returns the client's perceived destination (FakeIP:Port).
func (nc *NATPacketConn) OriginDst() netip.AddrPort {
	return nc.originDst
}

// RealDomain returns the real target domain.
func (nc *NATPacketConn) RealDomain() string {
	return nc.realDomain
}

// RealPort returns the real target port.
func (nc *NATPacketConn) RealPort() uint16 {
	return nc.realPort
}

// IsFakeIP returns whether this connection went through FakeIP substitution.
func (nc *NATPacketConn) IsFakeIP() bool {
	return nc.realDomain != ""
}

// ReadPacket reads a packet from the upstream channel (client → tunnel).
// Implements network.PacketReader interface.
func (nc *NATPacketConn) ReadPacket(buf []byte) (int, transport.Endpoint, error) {
	n, _, err := nc.gvisorConn.ReadPacket(buf)
	if err != nil {
		return n, transport.Endpoint{}, err
	}

	// Return the real endpoint (domain or IP)
	if nc.realDomain != "" {
		return n, transport.Endpoint{Domain: nc.realDomain, Port: nc.realPort}, nil
	}
	// If no domain, return the original destination (which is the real IP if not FakeIP)
	return n, transport.Endpoint{Addr: nc.originDst}, nil
}

// WritePacket writes a packet to the client (tunnel → client).
// Implements network.PacketWriter interface.
func (nc *NATPacketConn) WritePacket(payload []byte, _ transport.Endpoint) error {
	return nc.gvisorConn.WritePacket(payload, transport.Endpoint{})
}

// SendUpstream sends a packet to the upstream channel.
// Called by Dispatch() when receiving packets from the client.
func (nc *NATPacketConn) SendUpstream(payload []byte, src netip.AddrPort) error {
	return nc.gvisorConn.SendUpstream(payload, src)
}

// Close closes the underlying connection.
func (nc *NATPacketConn) Close() error {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	if nc.closed {
		return nil
	}
	nc.closed = true
	return nc.gvisorConn.Close()
}

// WriteToClient writes payload back to TUN client (legacy compatibility).
// Deprecated: Use WritePacket instead.
func (nc *NATPacketConn) WriteToClient(payload []byte) error {
	return nc.WritePacket(payload, transport.Endpoint{})
}
