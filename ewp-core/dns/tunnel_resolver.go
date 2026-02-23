package dns

import (
	"context"
	"fmt"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/transport"
)

// TunnelDNSTransport is the interface for DNS protocols through proxy tunnel
// Unlike BootstrapTransport, this routes ALL traffic through the proxy
type TunnelDNSTransport interface {
	// QueryRaw performs a raw DNS query through the tunnel
	QueryRaw(ctx context.Context, dnsQuery []byte) ([]byte, error)

	// Type returns the transport type (e.g., "DoH", "DoT", "DoQ")
	Type() string

	// Server returns the server address
	Server() string

	// Close closes the transport and releases resources
	Close() error
}

// TunnelDNSResolver manages multiple tunnel DNS transports with fallback support
// This is used for TUN mode to route all DNS queries through the proxy
type TunnelDNSResolver struct {
	transports []TunnelDNSTransport
	cache      sync.Map // query hash -> *cachedTunnelResult
	cacheTTL   time.Duration
	timeout    time.Duration
}

type cachedTunnelResult struct {
	response  []byte
	expiresAt time.Time
}

// TunnelDNSConfig configures the tunnel DNS resolver
type TunnelDNSConfig struct {
	Servers  []TunnelServerConfig
	CacheTTL time.Duration
	Timeout  time.Duration
}

// TunnelServerConfig defines a tunnel DNS server configuration
type TunnelServerConfig struct {
	Address string // e.g., "dns.google:853" or "https://dns.google/dns-query"
	Type    string // "doh", "dot", "doq"
}

// NewTunnelDNSResolver creates a new tunnel DNS resolver with multiple transports
func NewTunnelDNSResolver(trans transport.Transport, config TunnelDNSConfig) (*TunnelDNSResolver, error) {
	if len(config.Servers) == 0 {
		// Default configuration: DoQ → DoH → DoT (Google DNS)
		config.Servers = []TunnelServerConfig{
			{Address: "dns.google:853", Type: "doq"},
			{Address: "https://dns.google/dns-query", Type: "doh"},
			{Address: "dns.google:853", Type: "dot"},
		}
	}

	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	resolver := &TunnelDNSResolver{
		transports: make([]TunnelDNSTransport, 0, len(config.Servers)),
		cacheTTL:   config.CacheTTL,
		timeout:    config.Timeout,
	}

	// Create transports from config
	for i, serverCfg := range config.Servers {
		tunnelTransport, err := createTunnelTransport(trans, serverCfg)
		if err != nil {
			log.Printf("[TunnelDNS] Failed to create %s transport (#%d): %v", serverCfg.Type, i+1, err)
			continue
		}
		resolver.transports = append(resolver.transports, tunnelTransport)
		log.Printf("[TunnelDNS] Registered %s: %s (priority #%d)", tunnelTransport.Type(), tunnelTransport.Server(), i+1)
	}

	if len(resolver.transports) == 0 {
		return nil, fmt.Errorf("no valid tunnel transports configured")
	}

	return resolver, nil
}

// createTunnelTransport creates a tunnel transport based on server config
func createTunnelTransport(trans transport.Transport, config TunnelServerConfig) (TunnelDNSTransport, error) {
	switch config.Type {
	case "doh":
		return NewTunnelDoHTransport(config.Address, trans), nil
	case "dot":
		return NewTunnelDoTTransport(config.Address, trans), nil
	case "doq":
		return NewTunnelDoQTransport(config.Address, trans), nil
	default:
		return nil, fmt.Errorf("unsupported tunnel transport type: %s", config.Type)
	}
}

// QueryRaw performs a raw DNS query using fallback strategy
func (r *TunnelDNSResolver) QueryRaw(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	// Generate cache key from query
	cacheKey := fmt.Sprintf("%x", dnsQuery[:min(len(dnsQuery), 32)])

	// Check cache first
	if cached, ok := r.cache.Load(cacheKey); ok {
		result := cached.(*cachedTunnelResult)
		if time.Now().Before(result.expiresAt) {
			log.V("[TunnelDNS] Cache hit")
			return result.response, nil
		}
		r.cache.Delete(cacheKey)
	}

	// Apply timeout to context
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Try each transport in order (fallback strategy)
	var lastErr error
	for i, tunnelTransport := range r.transports {
		log.V("[TunnelDNS] Trying %s (#%d): %s", tunnelTransport.Type(), i+1, tunnelTransport.Server())

		response, err := tunnelTransport.QueryRaw(ctx, dnsQuery)
		if err != nil {
			lastErr = err
			log.V("[TunnelDNS] %s query failed: %v", tunnelTransport.Type(), err)
			log.Printf("[TunnelDNS] ⚠️  %s failed, trying next transport...", tunnelTransport.Type())
			continue
		}

		if len(response) > 0 {
			// Success! Cache and return
			r.cache.Store(cacheKey, &cachedTunnelResult{
				response:  response,
				expiresAt: time.Now().Add(r.cacheTTL),
			})
			log.Printf("[TunnelDNS] ✅ %s query successful: %d bytes", tunnelTransport.Type(), len(response))
			return response, nil
		}
	}

	// All transports failed
	return nil, fmt.Errorf("all tunnel DNS transports failed, last error: %w", lastErr)
}

// ClearCache clears the resolver cache
func (r *TunnelDNSResolver) ClearCache() {
	r.cache = sync.Map{}
	log.Printf("[TunnelDNS] Cache cleared")
}

// Close closes all transports and releases resources
func (r *TunnelDNSResolver) Close() error {
	var lastErr error
	for _, tunnelTransport := range r.transports {
		if err := tunnelTransport.Close(); err != nil {
			lastErr = err
			log.Printf("[TunnelDNS] Error closing %s: %v", tunnelTransport.Type(), err)
		}
	}
	return lastErr
}

// Stats returns resolver statistics
func (r *TunnelDNSResolver) Stats() map[string]interface{} {
	return map[string]interface{}{
		"transports": len(r.transports),
		"cache_ttl":  r.cacheTTL.String(),
		"timeout":    r.timeout.String(),
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
