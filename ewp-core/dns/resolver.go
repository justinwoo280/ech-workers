package dns

import (
	"context"
	"fmt"
	"net"
)

// BootstrapTransport is the interface for DNS transport protocols (DoH, DoT, DoQ)
// These are used for bootstrap resolution (before proxy connection)
type BootstrapTransport interface {
	// Query performs a DNS query for the given domain and record type
	Query(ctx context.Context, domain string, qtype uint16) ([]net.IP, error)

	// Type returns the transport type (e.g., "DoH", "DoT", "DoQ")
	Type() string

	// Server returns the server address
	Server() string

	// Close closes the transport and releases resources
	Close() error
}

// ServerConfig defines a DNS server configuration
type ServerConfig struct {
	Address string // e.g., "dns.alidns.com:853" or "https://dns.alidns.com/dns-query"
	Type    string // "doh", "dot", "doq"
}

// createTransport creates a transport based on server config
func createTransport(config ServerConfig) (BootstrapTransport, error) {
	switch config.Type {
	case "doh":
		return NewDoHTransport(config.Address), nil
	case "dot":
		return NewDoTTransport(config.Address)
	case "doq":
		return NewDoQTransport(config.Address)
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", config.Type)
	}
}
