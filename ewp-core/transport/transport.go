package transport

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// TunnelConn represents a tunnel connection (abstraction interface)
type TunnelConn interface {
	// Connect sends connection request and waits for response
	Connect(target string, initialData []byte) error
	// Read reads data from tunnel to provided buffer (zero-copy optimization)
	Read(buf []byte) (int, error)
	// Write writes data to tunnel
	Write(data []byte) error
	// Close closes the connection
	Close() error
	// StartPing starts heartbeat (returns stop channel)
	StartPing(interval time.Duration) chan struct{}
}

// Transport is the transport layer interface
type Transport interface {
	// Dial establishes a new connection
	Dial() (TunnelConn, error)
	// Name returns the transport layer name
	Name() string
}

// ParsedAddress represents parsed server address
type ParsedAddress struct {
	Scheme  string // ws, wss, grpc, grpcs, http, https
	Host    string
	Port    string
	Path    string // Path for WebSocket/XHTTP, service name for gRPC
	UseTLS  bool
	RawAddr string // Original address
}

// ParseAddress parses server address (Xray format)
// Supported formats:
//   - wss://example.com:443/ws-path
//   - grpcs://example.com:443/ServiceName
//   - https://example.com:443/xhttp
//   - example.com:443/path (defaults to wss)
func ParseAddress(addr string) (*ParsedAddress, error) {
	parsed := &ParsedAddress{
		RawAddr: addr,
		Path:    "/",
	}

	// Remove protocol prefix
	addr = strings.TrimSpace(addr)
	scheme := ""

	if strings.Contains(addr, "://") {
		parts := strings.SplitN(addr, "://", 2)
		scheme = strings.ToLower(parts[0])
		addr = parts[1]
	}

	// Extract path
	slashIdx := strings.Index(addr, "/")
	if slashIdx != -1 {
		parsed.Path = addr[slashIdx:]
		addr = addr[:slashIdx]
	}

	// Parse host:port
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// No port, try to add default port
		host = addr
		switch scheme {
		case "ws", "http":
			port = "80"
		case "wss", "https", "grpc", "grpcs":
			port = "443"
		default:
			port = "443" // Default HTTPS port
		}
	}

	parsed.Host = host
	parsed.Port = port

	// Determine protocol and TLS
	switch scheme {
	case "ws":
		parsed.Scheme = "ws"
		parsed.UseTLS = false
	case "wss":
		parsed.Scheme = "wss"
		parsed.UseTLS = true
	case "grpc":
		parsed.Scheme = "grpc"
		parsed.UseTLS = false
	case "grpcs":
		parsed.Scheme = "grpcs"
		parsed.UseTLS = true
	case "http":
		parsed.Scheme = "http"
		parsed.UseTLS = false
	case "https":
		parsed.Scheme = "https"
		parsed.UseTLS = true
	default:
		// Default to wss
		parsed.Scheme = "wss"
		parsed.UseTLS = true
	}

	return parsed, nil
}

// ParseUUID parses UUID string to [16]byte
func ParseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")

	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(s))
	}

	decoded, err := hex.DecodeString(s)
	if err != nil {
		return uuid, fmt.Errorf("invalid UUID hex: %w", err)
	}

	copy(uuid[:], decoded)
	return uuid, nil
}

// WriteVarint writes a varint-encoded integer
func WriteVarint(buf []byte, value uint64) int {
	i := 0
	for value >= 0x80 {
		buf[i] = byte(value) | 0x80
		value >>= 7
		i++
	}
	buf[i] = byte(value)
	return i + 1
}

// ReadVarint reads a varint-encoded integer
func ReadVarint(buf []byte) (uint64, int) {
	var value uint64
	var shift uint
	i := 0
	for {
		if i >= len(buf) {
			return 0, 0
		}
		b := buf[i]
		value |= uint64(b&0x7f) << shift
		i++
		if b < 0x80 {
			break
		}
		shift += 7
	}
	return value, i
}

// WriteUint16 writes a uint16 in big-endian
func WriteUint16(buf []byte, value uint16) {
	binary.BigEndian.PutUint16(buf, value)
}

// ReadUint16 reads a uint16 in big-endian
func ReadUint16(buf []byte) uint16 {
	return binary.BigEndian.Uint16(buf)
}
