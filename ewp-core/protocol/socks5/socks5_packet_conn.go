package socks5

import (
	"net"
	"net/netip"
	"sync"

	"ewp-core/transport"
	"ewp-core/tun"
)

var (
	ErrUnauthorizedSource  = tun.ErrUnauthorizedSource
	ErrInvalidSOCKS5Header = tun.ErrInvalidSOCKS5Header
)

// SOCKS5PacketConn wraps a UDP connection to implement network.PacketConn
// with SOCKS5 UDP header parsing/encoding.
type SOCKS5PacketConn struct {
	udpConn   *net.UDPConn
	clientIP  net.IP
	mu        sync.Mutex
	closed    bool
	lastSender atomicPointer[net.UDPAddr]
}

type atomicPointer[T any] struct {
	ptr *T
	mu  sync.RWMutex
}

func (p *atomicPointer[T]) Load() *T {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.ptr
}

func (p *atomicPointer[T]) Store(val *T) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.ptr = val
}

// NewSOCKS5PacketConn creates a new SOCKS5 PacketConn.
func NewSOCKS5PacketConn(udpConn *net.UDPConn, clientIP net.IP) *SOCKS5PacketConn {
	return &SOCKS5PacketConn{
		udpConn:  udpConn,
		clientIP: clientIP,
	}
}

// ReadPacket reads a UDP packet and parses the SOCKS5 header.
// Returns the payload and the target endpoint.
func (s *SOCKS5PacketConn) ReadPacket(buf []byte) (int, transport.Endpoint, error) {
	n, senderAddr, err := s.udpConn.ReadFromUDP(buf)
	if err != nil {
		return 0, transport.Endpoint{}, err
	}

	// Source validation
	if s.clientIP != nil && !senderAddr.IP.Equal(s.clientIP) {
		return 0, transport.Endpoint{}, ErrUnauthorizedSource // Drop packet from unexpected source
	}

	if n < 10 {
		return 0, transport.Endpoint{}, ErrInvalidSOCKS5Header
	}

	// Check SOCKS5 header: RSV(2) + FRAG(1)
	if buf[0] != 0x00 || buf[1] != 0x00 || buf[2] != 0x00 {
		return 0, transport.Endpoint{}, ErrInvalidSOCKS5Header
	}

	// Store sender for response routing
	s.lastSender.Store(senderAddr)

	// Parse address
	atyp := buf[3]
	var headerLen int
	var endpoint transport.Endpoint

	switch atyp {
	case AddressTypeIPv4:
		if n < 10 {
			return 0, transport.Endpoint{}, ErrInvalidSOCKS5Header
		}
		ip, _ := netip.AddrFromSlice(buf[4:8])
		port := uint16(buf[8])<<8 | uint16(buf[9])
		endpoint = transport.Endpoint{Addr: netip.AddrPortFrom(ip, port)}
		headerLen = 10

	case AddressTypeDomain:
		if n < 5 {
			return 0, transport.Endpoint{}, ErrInvalidSOCKS5Header
		}
		domainLen := int(buf[4])
		if n < 7+domainLen {
			return 0, transport.Endpoint{}, ErrInvalidSOCKS5Header
		}
		host := string(buf[5 : 5+domainLen])
		port := uint16(buf[5+domainLen])<<8 | uint16(buf[6+domainLen])
		endpoint = transport.Endpoint{Domain: host, Port: port}
		headerLen = 7 + domainLen

	case AddressTypeIPv6:
		if n < 22 {
			return 0, transport.Endpoint{}, ErrInvalidSOCKS5Header
		}
		ip, _ := netip.AddrFromSlice(buf[4:20])
		port := uint16(buf[20])<<8 | uint16(buf[21])
		endpoint = transport.Endpoint{Addr: netip.AddrPortFrom(ip, port)}
		headerLen = 22

	default:
		return 0, transport.Endpoint{}, ErrInvalidSOCKS5Header
	}

	// Copy payload to start of buffer
	payloadLen := n - headerLen
	copy(buf, buf[headerLen:n])

	return payloadLen, endpoint, nil
}

// WritePacket writes a UDP packet with SOCKS5 header.
func (s *SOCKS5PacketConn) WritePacket(payload []byte, addr transport.Endpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	sender := s.lastSender.Load()
	if sender == nil {
		return nil
	}

	// Build SOCKS5 header
	header := s.buildSOCKS5Header(addr)

	// Combine header and payload
	response := make([]byte, 0, len(header)+len(payload))
	response = append(response, header...)
	response = append(response, payload...)

	_, err := s.udpConn.WriteToUDP(response, sender)
	return err
}

// buildSOCKS5Header builds a SOCKS5 UDP header for the given endpoint.
func (s *SOCKS5PacketConn) buildSOCKS5Header(addr transport.Endpoint) []byte {
	header := []byte{0x00, 0x00, 0x00} // RSV + FRAG

	if addr.Domain != "" {
		header = append(header, AddressTypeDomain)
		header = append(header, byte(len(addr.Domain)))
		header = append(header, []byte(addr.Domain)...)
		header = append(header, byte(addr.Port>>8), byte(addr.Port))
	} else if addr.Addr.Addr().Is6() {
		header = append(header, AddressTypeIPv6)
		ip := addr.Addr.Addr().As16()
		header = append(header, ip[:]...)
		header = append(header, byte(addr.Addr.Port()>>8), byte(addr.Addr.Port()))
	} else {
		header = append(header, AddressTypeIPv4)
		ip := addr.Addr.Addr().As4()
		header = append(header, ip[:]...)
		header = append(header, byte(addr.Addr.Port()>>8), byte(addr.Addr.Port()))
	}

	return header
}

// Close closes the underlying UDP connection.
func (s *SOCKS5PacketConn) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	return s.udpConn.Close()
}

// LastSender returns the last sender address.
func (s *SOCKS5PacketConn) LastSender() *net.UDPAddr {
	return s.lastSender.Load()
}
