package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
)

// BootstrapResolver manages multiple DNS transports with fallback support
// This is used to resolve proxy server address without leaking DNS queries
// All transports use direct connection (no proxy)
type BootstrapResolver struct {
	transports []BootstrapTransport
	cache      sync.Map // domain -> *cachedResult
	cacheTTL   time.Duration
	timeout    time.Duration
}

type cachedResult struct {
	ips       []net.IP
	expiresAt time.Time
}

// NewBootstrapResolver creates a new bootstrap resolver with multiple transports
// serversConfig format: "protocol:address, protocol:address, ..."
// Examples:
//   - "doh:https://dns.alidns.com/dns-query, doq:dns.google:853"
//   - "doq:dns.alidns.com:853, doh:https://1.1.1.1/dns-query, dot:1.1.1.1:853"
//
// If empty, defaults to Alibaba Cloud DoH + Cloudflare DoH
func NewBootstrapResolver(serversConfig string) *BootstrapResolver {
	resolver := &BootstrapResolver{
		transports: make([]BootstrapTransport, 0),
		cacheTTL:   5 * time.Minute,
		timeout:    10 * time.Second,
	}

	// Parse servers configuration
	if serversConfig == "" {
		// Default: Use IP addresses to avoid chicken-and-egg problem
		// Alibaba DNS: 223.5.5.5, Cloudflare: 1.1.1.1, Google: 8.8.8.8
		serversConfig = "doh:https://223.5.5.5/dns-query, doh:https://1.1.1.1/dns-query, doh:https://8.8.8.8/dns-query"
	}

	servers := parseBootstrapServers(serversConfig)

	// Create transports
	for i, server := range servers {
		transport, err := createTransport(server)
		if err != nil {
			log.Printf("[Bootstrap] Failed to create %s transport (#%d): %v", server.Type, i+1, err)
			continue
		}
		resolver.transports = append(resolver.transports, transport)
		log.Printf("[Bootstrap] Registered %s: %s (priority #%d)", transport.Type(), transport.Server(), i+1)
	}

	// Fallback to default DoH if no valid transports
	if len(resolver.transports) == 0 {
		log.Printf("[Bootstrap] No valid transports, using default DoH")
		transport := NewDoHTransport("https://1.1.1.1/dns-query")
		resolver.transports = append(resolver.transports, transport)
	}

	return resolver
}

// parseBootstrapServers parses server configuration string
// Format: "protocol:address, protocol:address, ..."
func parseBootstrapServers(config string) []ServerConfig {
	var servers []ServerConfig

	parts := strings.Split(config, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Parse "protocol:address" format
		colonIdx := strings.Index(part, ":")
		if colonIdx == -1 {
			log.Printf("[Bootstrap] Invalid server format (missing protocol): %s", part)
			continue
		}

		protocol := strings.ToLower(strings.TrimSpace(part[:colonIdx]))
		address := strings.TrimSpace(part[colonIdx+1:])

		// Validate protocol
		if protocol != "doh" && protocol != "dot" && protocol != "doq" {
			log.Printf("[Bootstrap] Unsupported protocol: %s", protocol)
			continue
		}

		// Convert domain names to IP addresses for bootstrap DNS servers
		// This avoids chicken-and-egg problem (DNS server needs DNS to resolve)
		address = resolveBootstrapServerAddress(protocol, address)

		servers = append(servers, ServerConfig{
			Type:    protocol,
			Address: address,
		})
	}

	return servers
}

// resolveBootstrapServerAddress converts common DNS server domains to IPs
// This avoids needing DNS to resolve the DNS server itself
func resolveBootstrapServerAddress(protocol, address string) string {
	// Map of well-known DNS servers
	knownServers := map[string]string{
		// Alibaba Cloud DNS
		"dns.alidns.com":                   "223.5.5.5",
		"https://dns.alidns.com/dns-query": "https://223.5.5.5/dns-query",

		// Cloudflare DNS
		"1.1.1.1":                              "1.1.1.1",
		"https://1.1.1.1/dns-query":            "https://1.1.1.1/dns-query",
		"cloudflare-dns.com":                   "1.1.1.1",
		"https://cloudflare-dns.com/dns-query": "https://1.1.1.1/dns-query",

		// Google DNS
		"dns.google":                   "8.8.8.8",
		"https://dns.google/dns-query": "https://8.8.8.8/dns-query",
		"8.8.8.8":                      "8.8.8.8",
		"https://8.8.8.8/dns-query":    "https://8.8.8.8/dns-query",

		// Quad9 DNS
		"dns.quad9.net":                   "9.9.9.9",
		"https://dns.quad9.net/dns-query": "https://9.9.9.9/dns-query",
	}

	if resolved, ok := knownServers[address]; ok {
		log.Printf("[Bootstrap] Resolved %s -> %s", address, resolved)
		return resolved
	}

	// If not in known list, return as-is (assume it's already an IP)
	return address
}

// LookupIP resolves domain to IP addresses with multi-transport fallback
func (r *BootstrapResolver) LookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	// Check cache first
	if cached, ok := r.cache.Load(domain); ok {
		result := cached.(*cachedResult)
		if time.Now().Before(result.expiresAt) {
			log.V("[Bootstrap] Cache hit: %s -> %v", domain, result.ips)
			return result.ips, nil
		}
		r.cache.Delete(domain)
	}

	// Try each transport in order until one succeeds
	var lastErr error
	for i, transport := range r.transports {
		log.V("[Bootstrap] Resolving %s via %s (#%d)...", domain, transport.Type(), i+1)

		ips, err := r.queryWithTransport(ctx, transport, domain)
		if err != nil {
			log.V("[Bootstrap] %s (#%d) failed: %v", transport.Type(), i+1, err)
			lastErr = err
			continue
		}

		if len(ips) > 0 {
			// Cache the result
			r.cache.Store(domain, &cachedResult{
				ips:       ips,
				expiresAt: time.Now().Add(r.cacheTTL),
			})

			log.Printf("[Bootstrap] Resolved %s -> %s", domain, ips[0].String())
			return ips, nil
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all bootstrap DNS transports failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no IP addresses found for %s", domain)
}

// queryWithTransport queries a single transport for both IPv4 and IPv6
func (r *BootstrapResolver) queryWithTransport(ctx context.Context, transport BootstrapTransport, domain string) ([]net.IP, error) {
	// Apply timeout to context
	queryCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var allIPs []net.IP

	// Query A record (IPv4)
	ipv4, err := transport.Query(queryCtx, domain, 1) // Type A
	if err == nil {
		allIPs = append(allIPs, ipv4...)
	} else {
		log.V("[Bootstrap] IPv4 query failed: %v", err)
	}

	// Query AAAA record (IPv6)
	ipv6, err := transport.Query(queryCtx, domain, 28) // Type AAAA
	if err == nil {
		allIPs = append(allIPs, ipv6...)
	} else {
		log.V("[Bootstrap] IPv6 query failed: %v", err)
	}

	if len(allIPs) == 0 {
		return nil, fmt.Errorf("no IP addresses returned")
	}

	return allIPs, nil
}

// ClearCache clears the resolver cache
func (r *BootstrapResolver) ClearCache() {
	r.cache = sync.Map{}
}

// Close closes the resolver and releases all transport resources
func (r *BootstrapResolver) Close() error {
	for _, transport := range r.transports {
		if err := transport.Close(); err != nil {
			log.Printf("[Bootstrap] Failed to close %s transport: %v", transport.Type(), err)
		}
	}
	return nil
}
