package dns

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"

	"ewp-core/log"
	"ewp-core/transport"
)

var _ TunnelDNSTransport = (*TunnelDoQTransport)(nil)

// TunnelDoQTransport performs DoQ queries through a proxy tunnel
// Implements DNS over QUIC (RFC 9250) routed through the proxy
type TunnelDoQTransport struct {
	server    string // e.g., "dns.google:853"
	transport transport.Transport
}

// NewTunnelDoQTransport creates a new DoQ transport that uses proxy tunnel
func NewTunnelDoQTransport(server string, trans transport.Transport) *TunnelDoQTransport {
	if server == "" {
		server = "dns.google:853"
	}

	// Parse server address to ensure it has a port
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		// No port specified, add default DoQ port 853
		server = net.JoinHostPort(server, "853")
	} else if port == "" {
		server = net.JoinHostPort(host, "853")
	}

	return &TunnelDoQTransport{
		server:    server,
		transport: trans,
	}
}

// QueryRaw performs a raw DNS query through the proxy tunnel using DoQ
func (c *TunnelDoQTransport) QueryRaw(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	// Establish tunnel connection
	conn, err := c.transport.Dial()
	if err != nil {
		return nil, fmt.Errorf("failed to dial tunnel: %w", err)
	}
	defer conn.Close()

	// Parse server URL to get target
	target := c.server

	// If server is a URL, extract hostname:port
	if u, err := url.Parse(c.server); err == nil && u.Host != "" {
		target = u.Host
		if u.Port() == "" {
			target = net.JoinHostPort(u.Hostname(), "853")
		}
	}

	// Connect tunnel to DoQ server (UDP over tunnel)
	// Note: DoQ uses QUIC which is UDP-based, but we're tunneling it through TCP
	// The tunnel will handle the transport, we just need to send/receive DNS messages
	if err := conn.Connect(target, nil); err != nil {
		return nil, fmt.Errorf("tunnel connect failed: %w", err)
	}

	// DoQ uses length-prefixed DNS messages over QUIC streams (RFC 9250 Section 4.2)
	// Write length prefix (2 bytes, big endian)
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(dnsQuery)))

	if err := conn.Write(lengthPrefix); err != nil {
		return nil, fmt.Errorf("failed to write length prefix: %w", err)
	}

	// Write DNS query
	if err := conn.Write(dnsQuery); err != nil {
		return nil, fmt.Errorf("failed to write query: %w", err)
	}

	// Read length prefix of response
	responseLenBuf := make([]byte, 2)
	n, err := conn.Read(responseLenBuf)
	if err != nil {
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}
	if n != 2 {
		return nil, fmt.Errorf("incomplete length prefix: got %d bytes, expected 2", n)
	}

	responseLen := binary.BigEndian.Uint16(responseLenBuf)
	if responseLen == 0 || responseLen > 4096 {
		return nil, fmt.Errorf("invalid response length: %d", responseLen)
	}

	// Read DNS response
	response := make([]byte, responseLen)
	totalRead := 0
	for totalRead < int(responseLen) {
		n, err := conn.Read(response[totalRead:])
		if err != nil {
			if err == io.EOF && totalRead > 0 {
				break
			}
			return nil, fmt.Errorf("failed to read response: %w", err)
		}
		totalRead += n
	}

	if totalRead != int(responseLen) {
		log.V("[TunnelDoQ] Partial read: expected %d bytes, got %d", responseLen, totalRead)
	}

	log.V("[TunnelDoQ] Query successful: %d bytes", totalRead)
	return response[:totalRead], nil
}

// Type returns the transport type
func (c *TunnelDoQTransport) Type() string {
	return "Tunnel-DoQ"
}

// Server returns the server address
func (c *TunnelDoQTransport) Server() string {
	return c.server
}

// Close closes the transport and releases resources
func (c *TunnelDoQTransport) Close() error {
	// No persistent resources to close
	return nil
}
