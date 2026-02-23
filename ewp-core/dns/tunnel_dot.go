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

var _ TunnelDNSTransport = (*TunnelDoTTransport)(nil)

// TunnelDoTTransport performs DoT queries through a proxy tunnel
// Implements DNS over TLS (RFC 7858) routed through the proxy
type TunnelDoTTransport struct {
	server    string // e.g., "dns.google:853"
	transport transport.Transport
}

// NewTunnelDoTTransport creates a new DoT transport that uses proxy tunnel
func NewTunnelDoTTransport(server string, trans transport.Transport) *TunnelDoTTransport {
	if server == "" {
		server = "dns.google:853"
	}

	// Parse server address to ensure it has a port
	host, port, err := net.SplitHostPort(server)
	if err != nil {
		// No port specified, add default DoT port 853
		server = net.JoinHostPort(server, "853")
	} else if port == "" {
		server = net.JoinHostPort(host, "853")
	}

	return &TunnelDoTTransport{
		server:    server,
		transport: trans,
	}
}

// QueryRaw performs a raw DNS query through the proxy tunnel using DoT
func (c *TunnelDoTTransport) QueryRaw(ctx context.Context, dnsQuery []byte) ([]byte, error) {
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

	// Connect tunnel to DoT server
	if err := conn.Connect(target, nil); err != nil {
		return nil, fmt.Errorf("tunnel connect failed: %w", err)
	}

	// DoT uses length-prefixed DNS messages (RFC 7858 Section 3.3)
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
		log.V("[TunnelDoT] Partial read: expected %d bytes, got %d", responseLen, totalRead)
	}

	log.V("[TunnelDoT] Query successful: %d bytes", totalRead)
	return response[:totalRead], nil
}

// Type returns the transport type
func (c *TunnelDoTTransport) Type() string {
	return "Tunnel-DoT"
}

// Server returns the server address
func (c *TunnelDoTTransport) Server() string {
	return c.server
}

// Close closes the transport and releases resources
func (c *TunnelDoTTransport) Close() error {
	// No persistent resources to close
	return nil
}
