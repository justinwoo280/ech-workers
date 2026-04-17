package dns

import (
	"context"
	"net/netip"

	"ewp-core/log"
)

// DNSRouter provides a unified interface for DNS resolution.
// It supports both FakeIP mode (instant fake responses) and real DNS mode
// (forwarding queries through the tunnel with reverse mapping).
type DNSRouter interface {
	// Exchange processes a DNS query and returns the response.
	// In FakeIP mode, returns instant fake responses.
	// In real DNS mode, forwards the query and stores reverse mappings.
	Exchange(ctx context.Context, query []byte) ([]byte, error)

	// LookupReverseMapping returns the domain for a given IP.
	// Checks FakeIP pool first, then reverse mapping cache.
	LookupReverseMapping(ip netip.Addr) (string, bool)

	// IsFakeIP checks if an IP is in the FakeIP range.
	IsFakeIP(ip netip.Addr) bool
}

// DefaultDNSRouter is the default implementation of DNSRouter.
type DefaultDNSRouter struct {
	fakeIPPool     *FakeIPPool
	tunnelResolver *TunnelDNSResolver
	reverseMapping *ReverseMapping
	dnsHandler     DNSHandler // Custom DNS handler
}

// DNSRouterConfig configures the DNS router.
type DNSRouterConfig struct {
	// FakeIPPool enables FakeIP mode when set (TUN mode).
	FakeIPPool *FakeIPPool

	// TunnelResolver enables real DNS mode when set (SOCKS5 mode).
	TunnelResolver *TunnelDNSResolver

	// ReverseMapping stores IP→domain mappings from real DNS responses.
	// Required when TunnelResolver is set.
	ReverseMapping *ReverseMapping
}

// NewDNSRouter creates a new DNS router.
func NewDNSRouter(config DNSRouterConfig) *DefaultDNSRouter {
	router := &DefaultDNSRouter{
		fakeIPPool:     config.FakeIPPool,
		tunnelResolver: config.TunnelResolver,
		reverseMapping: config.ReverseMapping,
	}

	// Inject reverse mapping into tunnel resolver if both are set
	if router.tunnelResolver != nil && router.reverseMapping != nil {
		router.tunnelResolver.SetReverseMapping(router.reverseMapping)
	}

	return router
}

// Exchange processes a DNS query.
// Priority: FakeIP > TunnelResolver > DNSHandler
func (r *DefaultDNSRouter) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	// FakeIP mode: return instant fake response
	if r.fakeIPPool != nil {
		domain := ParseDNSName(query)
		if domain == "" {
			return nil, nil
		}

		// Allocate fake IPs for A and AAAA queries
		fakeIPv4 := r.fakeIPPool.AllocateIPv4(domain)
		fakeIPv6 := r.fakeIPPool.AllocateIPv6(domain)

		response := BuildDNSResponse(query, fakeIPv4, fakeIPv6)
		if response != nil {
			log.V("[DNSRouter] FakeIP response for %s", domain)
			return response, nil
		}
		return nil, nil
	}

	// Real DNS mode: forward through tunnel
	if r.tunnelResolver != nil {
		response, err := r.tunnelResolver.QueryRaw(ctx, query)
		if err != nil {
			return nil, err
		}

		// Store reverse mapping for A/AAAA records
		if r.reverseMapping != nil {
			r.reverseMapping.StoreDNSResponse(response)
		}

		return response, nil
	}

	// Custom DNS handler (e.g., direct DoH)
	if r.dnsHandler != nil {
		response, err := r.dnsHandler(query)
		if err != nil {
			return nil, err
		}

		// Store reverse mapping for A/AAAA records
		if r.reverseMapping != nil {
			r.reverseMapping.StoreDNSResponse(response)
		}

		return response, nil
	}

	return nil, nil
}

// LookupReverseMapping returns the domain for a given IP.
// Checks FakeIP pool first, then reverse mapping cache.
func (r *DefaultDNSRouter) LookupReverseMapping(ip netip.Addr) (string, bool) {
	// Check FakeIP pool first
	if r.fakeIPPool != nil {
		if domain, ok := r.fakeIPPool.LookupByIP(ip); ok {
			return domain, true
		}
	}

	// Check reverse mapping cache
	if r.reverseMapping != nil {
		return r.reverseMapping.Lookup(ip)
	}

	return "", false
}

// IsFakeIP checks if an IP is in the FakeIP range.
func (r *DefaultDNSRouter) IsFakeIP(ip netip.Addr) bool {
	if r.fakeIPPool != nil {
		return r.fakeIPPool.IsFakeIP(ip)
	}
	return false
}

// SetFakeIPPool sets the FakeIP pool (for TUN mode).
func (r *DefaultDNSRouter) SetFakeIPPool(pool *FakeIPPool) {
	r.fakeIPPool = pool
}

// SetTunnelResolver sets the tunnel DNS resolver (for SOCKS5 mode).
func (r *DefaultDNSRouter) SetTunnelResolver(resolver *TunnelDNSResolver) {
	r.tunnelResolver = resolver
}

// SetReverseMapping sets the reverse mapping cache.
func (r *DefaultDNSRouter) SetReverseMapping(rm *ReverseMapping) {
	r.reverseMapping = rm
}

// DNSHandler is a function that handles DNS queries.
type DNSHandler func(query []byte) ([]byte, error)

// SetDNSHandler sets a custom DNS handler for Exchange.
func (r *DefaultDNSRouter) SetDNSHandler(handler DNSHandler) {
	r.dnsHandler = handler
}
