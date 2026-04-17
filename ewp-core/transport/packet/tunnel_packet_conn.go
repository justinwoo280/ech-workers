package packet

import (
	"fmt"
	"sync"

	"ewp-core/common/network"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
	"ewp-core/transport"
)

// TunnelPacketConn wraps a TunnelConn to implement network.PacketConn.
// It handles EWP and Trojan UDP frame encoding/decoding.
type TunnelPacketConn struct {
	conn         transport.TunnelConn
	useTrojan    bool
	enableFlow   bool
	flowState    *ewp.FlowState
	udpGlobalID  [8]byte
	mu           sync.Mutex
	closed       bool
}

// NewEWPPacketConn creates a PacketConn for EWP protocol.
func NewEWPPacketConn(conn transport.TunnelConn, globalID [8]byte, flowState *ewp.FlowState) *TunnelPacketConn {
	return &TunnelPacketConn{
		conn:        conn,
		useTrojan:   false,
		enableFlow:  flowState != nil,
		flowState:   flowState,
		udpGlobalID: globalID,
	}
}

// NewTrojanPacketConn creates a PacketConn for Trojan protocol.
func NewTrojanPacketConn(conn transport.TunnelConn) *TunnelPacketConn {
	return &TunnelPacketConn{
		conn:      conn,
		useTrojan: true,
	}
}

// ReadPacket reads a UDP packet from the tunnel and decodes it.
func (c *TunnelPacketConn) ReadPacket(buf []byte) (int, transport.Endpoint, error) {
	// Read directly into caller's buffer
	n, err := c.conn.Read(buf)
	if err != nil {
		return 0, transport.Endpoint{}, err
	}
	data := buf[:n]

	// Process flow if enabled
	if c.enableFlow && c.flowState != nil {
		data = c.flowState.ProcessDownlink(data)
		// Copy processed data back to buf if it changed
		if len(data) != n {
			n = copy(buf, data)
			data = buf[:n]
		}
	}

	// Decode based on protocol (in-place)
	if c.useTrojan {
		return c.decodeTrojanPacket(buf, data)
	}
	return c.decodeEWPPacket(buf, data)
}

// WritePacket encodes and writes a UDP packet to the tunnel.
func (c *TunnelPacketConn) WritePacket(payload []byte, addr transport.Endpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("connection closed")
	}

	if c.useTrojan {
		return c.writeTrojanPacket(addr, payload)
	}
	return c.writeEWPPacket(addr, payload)
}

// Close closes the underlying connection.
func (c *TunnelPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.conn.Close()
}

// decodeTrojanPacket decodes a Trojan UDP frame.
func (c *TunnelPacketConn) decodeTrojanPacket(buf []byte, data []byte) (int, transport.Endpoint, error) {
	payload, addr, domain, err := trojan.DecodeUDPPayloadWithAddrAndDomain(data)
	if err != nil {
		return 0, transport.Endpoint{}, err
	}

	n := copy(buf, payload)
	
	// Prefer domain if available
	if domain != "" {
		return n, transport.Endpoint{Domain: domain, Port: addr.Port()}, nil
	}
	return n, transport.Endpoint{Addr: addr}, nil
}

// decodeEWPPacket decodes an EWP UDP frame.
func (c *TunnelPacketConn) decodeEWPPacket(buf []byte, data []byte) (int, transport.Endpoint, error) {
	n, addr, err := ewp.DecodeUDPAddrPayloadTo(data, buf)
	if err != nil {
		return 0, transport.Endpoint{}, err
	}
	return n, transport.Endpoint{Addr: addr}, nil
}

// writeTrojanPacket encodes and writes a Trojan UDP frame.
func (c *TunnelPacketConn) writeTrojanPacket(target transport.Endpoint, data []byte) error {
	length := uint16(len(data))
	addrLen := 7
	if target.Domain != "" {
		addrLen = 1 + 1 + len(target.Domain) + 2
	} else if target.Addr.Addr().Is6() {
		addrLen = 19
	}

	buf := make([]byte, 0, addrLen+4+len(data))
	if target.Domain != "" {
		buf = append(buf, trojan.AddressTypeDomain, byte(len(target.Domain)))
		buf = append(buf, []byte(target.Domain)...)
		buf = append(buf, byte(target.Port>>8), byte(target.Port))
	} else {
		buf = trojan.AppendAddrPort(buf, target.Addr)
	}
	buf = append(buf, byte(length>>8), byte(length))
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, data...)

	return c.conn.Write(buf)
}

// writeEWPPacket encodes and writes an EWP UDP frame.
func (c *TunnelPacketConn) writeEWPPacket(target transport.Endpoint, data []byte) error {
	var buf []byte

	if target.Domain != "" {
		buf = make([]byte, 0, 2+8+1+1+(1+1+len(target.Domain)+2)+2+len(data))
		buf = ewp.AppendUDPDomainFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, target.Domain, target.Port, data)
	} else {
		addrLen := 7
		if target.Addr.IsValid() && target.Addr.Addr().Is6() {
			addrLen = 19
		}
		buf = make([]byte, 0, 2+8+1+1+addrLen+2+len(data))
		buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, target.Addr, data)
	}

	return c.conn.Write(buf)
}

// Ensure TunnelPacketConn implements network.PacketConn
var _ network.PacketConn = (*TunnelPacketConn)(nil)
