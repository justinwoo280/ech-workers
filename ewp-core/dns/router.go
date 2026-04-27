package dns

import (
	"context"
	"net/netip"

	"ewp-core/log"
)

// DNSRouter provides a unified interface for DNS resolution.
//
// In v2 the only two modes that survive are:
//
//   - FakeIP: instant local fake responses (TUN inbound default)
//   - DNSHandler: a caller-supplied function (e.g. wired to an
//     AsyncResolver / DoH client at server side)
//
// The v1 "TunnelDNSResolver" mode (forward DNS over the EWP tunnel
// from the client) is intentionally gone — application-level DNS
// either lives inside FakeIP, or is whatever the OS does, or is the
// browser's own DoH; we explicitly do NOT try to be sing-box's
// DNS-routing engine.
type DNSRouter interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
	LookupReverseMapping(ip netip.Addr) (string, bool)
	IsFakeIP(ip netip.Addr) bool
}

// DefaultDNSRouter is the default implementation of DNSRouter.
type DefaultDNSRouter struct {
	fakeIPPool     *FakeIPPool
	reverseMapping *ReverseMapping
	dnsHandler     DNSHandler
}

// DNSRouterConfig configures the DNS router.
type DNSRouterConfig struct {
	FakeIPPool     *FakeIPPool
	ReverseMapping *ReverseMapping
}

func NewDNSRouter(config DNSRouterConfig) *DefaultDNSRouter {
	return &DefaultDNSRouter{
		fakeIPPool:     config.FakeIPPool,
		reverseMapping: config.ReverseMapping,
	}
}

// Exchange processes a DNS query.
// Priority: FakeIP > DNSHandler.
func (r *DefaultDNSRouter) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	if r.fakeIPPool != nil {
		domain := ParseDNSName(query)
		if domain == "" {
			return nil, nil
		}
		fakeIPv4 := r.fakeIPPool.AllocateIPv4(domain)
		fakeIPv6 := r.fakeIPPool.AllocateIPv6(domain)
		if response := BuildDNSResponse(query, fakeIPv4, fakeIPv6); response != nil {
			log.V("[DNSRouter] FakeIP response for %s", domain)
			return response, nil
		}
		return nil, nil
	}
	if r.dnsHandler != nil {
		response, err := r.dnsHandler(query)
		if err != nil {
			return nil, err
		}
		if r.reverseMapping != nil {
			r.reverseMapping.StoreDNSResponse(response)
		}
		return response, nil
	}
	return nil, nil
}

func (r *DefaultDNSRouter) LookupReverseMapping(ip netip.Addr) (string, bool) {
	if r.fakeIPPool != nil {
		if domain, ok := r.fakeIPPool.LookupByIP(ip); ok {
			return domain, true
		}
	}
	if r.reverseMapping != nil {
		return r.reverseMapping.Lookup(ip)
	}
	return "", false
}

func (r *DefaultDNSRouter) IsFakeIP(ip netip.Addr) bool {
	if r.fakeIPPool != nil {
		return r.fakeIPPool.IsFakeIP(ip)
	}
	return false
}

func (r *DefaultDNSRouter) SetFakeIPPool(pool *FakeIPPool)       { r.fakeIPPool = pool }
func (r *DefaultDNSRouter) SetReverseMapping(rm *ReverseMapping) { r.reverseMapping = rm }

// DNSHandler is a function that handles DNS queries.
type DNSHandler func(query []byte) ([]byte, error)

func (r *DefaultDNSRouter) SetDNSHandler(handler DNSHandler) { r.dnsHandler = handler }
