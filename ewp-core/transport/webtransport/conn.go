package webtransport

import (
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"

	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
	"ewp-core/transport"

	wtransport "github.com/quic-go/webtransport-go"
)

// Conn implements transport.TunnelConn over a single WebTransport bidi stream.
// Each Dial() opens one stream; TCP and UDP both use the raw byte stream.
type Conn struct {
	stream      *wtransport.Stream
	uuid        [16]byte
	udpGlobalID [8]byte
	mu          sync.Mutex
	leftover    []byte

	// Protocol support
	enableFlow        bool
	useTrojan         bool
	key               [56]byte
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
}

func newConn(stream *wtransport.Stream, uuid [16]byte, password string, enableFlow, useTrojan bool) *Conn {
	c := &Conn{
		stream:     stream,
		uuid:       uuid,
		enableFlow: enableFlow,
		useTrojan:  useTrojan,
	}
	if useTrojan {
		c.key = trojan.GenerateKey(password)
	}
	return c
}

// Connect sends a TCP handshake request.
func (c *Conn) Connect(target string, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojan(target, initialData)
	}
	return c.connectEWP(target, initialData)
}

func (c *Conn) connectEWP(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	if _, err := c.stream.Write(handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	var respBuf [26]byte
	if _, err := io.ReadFull(c.stream, respBuf[:]); err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respBuf[:], req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}
	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	if len(initialData) > 0 {
		return c.Write(initialData)
	}
	return nil
}

func (c *Conn) connectTrojan(target string, initialData []byte) error {
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return err
	}
	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}
	buf := make([]byte, 0, trojan.KeyLength+2+1+len(addrBytes)+2+len(initialData))
	buf = append(buf, c.key[:]...)
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, trojan.CommandTCP)
	buf = append(buf, addrBytes...)
	buf = append(buf, trojan.CRLF...)
	if len(initialData) > 0 {
		buf = append(buf, initialData...)
	}
	var errW error
	if len(buf) > 0 {
		_, errW = c.stream.Write(buf)
	}
	return errW
}

// ConnectUDP handles UDP handshake.
func (c *Conn) ConnectUDP(target transport.Endpoint, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojanUDP(target, initialData)
	}
	return c.connectEWPUDP(target, initialData)
}

func (c *Conn) connectEWPUDP(target transport.Endpoint, initialData []byte) error {
	var addr ewp.Address
	if target.Domain != "" {
		addr = ewp.Address{Type: ewp.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = ewp.AddressFromAddrPort(target.Addr)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)
	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode EWP UDP handshake: %w", err)
	}

	if _, err := c.stream.Write(handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	var respBuf [26]byte
	if _, err := io.ReadFull(c.stream, respBuf[:]); err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respBuf[:], req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}
	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	c.udpGlobalID = ewp.NewGlobalID()
	targetAddr := target.Addr
	bufp := ewp.UDPWriteBufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusNew, targetAddr, initialData)

	_, err = c.stream.Write(buf)
	*bufp = buf
	ewp.UDPWriteBufPool.Put(bufp)
	if err != nil {
		return fmt.Errorf("send UDPStatusNew: %w", err)
	}
	return nil
}

func (c *Conn) connectTrojanUDP(target transport.Endpoint, initialData []byte) error {
	var addr trojan.Address
	if target.Domain != "" {
		addr = trojan.Address{Type: trojan.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = trojan.AddressFromAddrPort(target.Addr)
	}

	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}

	buf := make([]byte, 0, trojan.KeyLength+2+1+len(addrBytes)+2)
	buf = append(buf, c.key[:]...)
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, trojan.CommandUDP)
	buf = append(buf, addrBytes...)
	buf = append(buf, trojan.CRLF...)
	_, err = c.stream.Write(buf)
	if err != nil {
		return err
	}
	return c.WriteUDP(target, initialData)
}

// WriteUDP sends a UDP frame.
func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
	if c.useTrojan {
		return c.writeUDPTrojan(target, data)
	}
	
	targetAddr := target.Addr
	bufp := ewp.UDPWriteBufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, targetAddr, data)

	c.mu.Lock()
	_, err := c.stream.Write(buf)
	c.mu.Unlock()

	*bufp = buf
	ewp.UDPWriteBufPool.Put(bufp)
	return err
}

func (c *Conn) writeUDPTrojan(target transport.Endpoint, data []byte) error {
	var addr trojan.Address
	if target.Domain != "" {
		addr = trojan.Address{Type: trojan.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = trojan.AddressFromAddrPort(target.Addr)
	}

	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}

	payloadLen := len(data)
	bufp := ewp.UDPWriteBufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = append(buf, addrBytes...)
	buf = append(buf, byte(payloadLen>>8), byte(payloadLen))
	buf = append(buf, trojan.CRLF...)
	buf = append(buf, data...)

	c.mu.Lock()
	_, err = c.stream.Write(buf)
	c.mu.Unlock()

	*bufp = buf
	ewp.UDPWriteBufPool.Put(bufp)
	return err
}

func (c *Conn) readTrojanUDP(buf []byte) ([]byte, netip.AddrPort, error) {
	addr, err := trojan.DecodeAddress(c.stream)
	if err != nil {
		return nil, netip.AddrPort{}, err
	}

	var meta [4]byte
	if _, err := io.ReadFull(c.stream, meta[:]); err != nil {
		return nil, netip.AddrPort{}, err
	}
	length := int(meta[0])<<8 | int(meta[1])

	payload := buf
	if payload == nil {
		payload = make([]byte, length)
	} else if len(payload) < length {
		return nil, netip.AddrPort{}, fmt.Errorf("buffer too small: %d < %d", len(payload), length)
	} else {
		payload = payload[:length]
	}

	if _, err := io.ReadFull(c.stream, payload); err != nil {
		return nil, netip.AddrPort{}, err
	}

	ip, err := netip.ParseAddr(addr.Host)
	if err != nil {
		return nil, netip.AddrPort{}, fmt.Errorf("invalid UDP source IP %s: %v", addr.Host, err)
	}

	return payload, netip.AddrPortFrom(ip, addr.Port), nil
}

// ReadUDPFrom reads a UDP frame.
func (c *Conn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	if c.useTrojan {
		payload, addr, err := c.readTrojanUDP(buf)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		return len(payload), addr, nil
	}
	return ewp.DecodeUDPAddrPacketTo(c.stream, buf)
}

// ReadUDP reads a UDP frame and returns the payload.
func (c *Conn) ReadUDP() ([]byte, error) {
	if c.useTrojan {
		payload, _, err := c.readTrojanUDP(nil)
		return payload, err
	}
	pkt, err := ewp.DecodeUDPPacket(c.stream)
	if err != nil {
		return nil, err
	}
	return pkt.Payload, nil
}

// ReadUDPTo reads a UDP frame payload into buf.
func (c *Conn) ReadUDPTo(buf []byte) (int, error) {
	if c.useTrojan {
		payload, _, err := c.readTrojanUDP(buf)
		return len(payload), err
	}
	pkt, err := ewp.DecodeUDPPacket(c.stream)
	if err != nil {
		return 0, err
	}
	return copy(buf, pkt.Payload), nil
}

// Read reads raw bytes.
func (c *Conn) Read(buf []byte) (int, error) {
	if len(c.leftover) > 0 {
		n := copy(buf, c.leftover)
		c.leftover = c.leftover[n:]
		if len(c.leftover) == 0 {
			c.leftover = nil
		}
		return n, nil
	}
	return c.stream.Read(buf)
}

// Write writes raw bytes to the stream (for TCP relay).
func (c *Conn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, err := c.stream.Write(data)
	return err
}

// Close closes the WebTransport stream.
func (c *Conn) Close() error {
	return c.stream.Close()
}

// StartPing returns nil; QUIC keepalives handle liveness.
func (c *Conn) StartPing(_ time.Duration) chan struct{} {
	return nil
}
