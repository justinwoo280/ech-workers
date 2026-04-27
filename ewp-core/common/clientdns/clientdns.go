// Package clientdns is the v2 client-side DNS resolver dedicated to
// translating an EWP server's domain name into IP addresses, used by
// every outer transport (ws / grpc / h3 / xhttp) in its Dial path.
//
// Why a separate package and not the engine-wide AsyncResolver?
//
//   - AsyncResolver lives on the *server* side (or behind any
//     direct outbound) and resolves the DESTINATION names users ask
//     for. Its DoH set is a server operator concern.
//
//   - clientdns lives on the *client* side and resolves the address
//     of the EWP server itself. Its DoH set is a privacy concern of
//     the user — they want to keep their own ISP from learning
//     "this user is talking to my-vps.example.com" before the
//     bootstrap TLS handshake even starts.
//
// They are deliberately independent. Mixing them is wrong: the
// AsyncResolver can be torn down + restarted with the engine, the
// clientdns lives for the entire process lifetime because it's
// queried every time we Dial.
package clientdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"ewp-core/dns"
)

// Resolver is the runtime object every transport gets handed in its
// constructor. nil means "fall back to OS resolver" — that's what
// you get if the user did not configure a client_dns block.
type Resolver struct {
	mc          *dns.MultiClient
	timeout     time.Duration
	cacheTTL    time.Duration
	preferIPv6  bool

	mu    sync.Mutex
	cache map[string]cacheEntry // host (no port) -> entry
}

type cacheEntry struct {
	addrs   []netip.Addr
	expires time.Time
}

// Config is the user-facing configuration shape. It mirrors the
// `client_dns:` YAML block in cmd/ewp/cfg.
type Config struct {
	Servers    []string      // DoH endpoint URLs
	Timeout    time.Duration // per-query budget; 3s if zero
	CacheTTL   time.Duration // positive-cache TTL; 5min if zero
	PreferIPv6 bool          // when both A and AAAA exist, pick AAAA first
}

// New builds a Resolver. Returns nil (and no error) if Servers is
// empty — the resolver is optional, so callers can pass the result
// straight to transports without nil-checking.
func New(cfg Config) (*Resolver, error) {
	if len(cfg.Servers) == 0 {
		return nil, nil
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 3 * time.Second
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 5 * time.Minute
	}

	// Reuse the existing MultiClient — it already does failover,
	// keepalive, and uses the hardened DoH TLS profile (Mozilla CA
	// bundle, TLS 1.3 floor) since the dns/doh.go fix.
	mc := dns.NewMultiClient(cfg.Servers, nil)
	if mc == nil {
		return nil, errors.New("clientdns: MultiClient construction failed")
	}

	return &Resolver{
		mc:         mc,
		timeout:    cfg.Timeout,
		cacheTTL:   cfg.CacheTTL,
		preferIPv6: cfg.PreferIPv6,
		cache:      make(map[string]cacheEntry),
	}, nil
}

// ResolveHostPort parses "host:port", and if host is a domain, asks
// the configured DoH servers for an A/AAAA. Returns the SAME port
// joined with the chosen IP. Honours the cache.
//
// If the resolver is nil, returns the input unchanged — callers can
// pass the result straight to net.Dialer.DialContext("tcp", ...).
func (r *Resolver) ResolveHostPort(ctx context.Context, hostPort string) (string, error) {
	if r == nil {
		return hostPort, nil
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", fmt.Errorf("clientdns: %w", err)
	}
	// Fast path: already an IP literal.
	if ip, err := netip.ParseAddr(host); err == nil {
		_ = ip
		return hostPort, nil
	}
	// Strip any IPv6-zone identifier (e.g. fe80::1%eth0) that
	// SplitHostPort leaves untouched.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}

	addrs, err := r.lookup(ctx, host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("clientdns: no addresses for %q", host)
	}
	chosen := r.choose(addrs)
	if chosen.Is6() && !chosen.Is4In6() {
		return "[" + chosen.String() + "]:" + port, nil
	}
	return chosen.String() + ":" + port, nil
}

// LookupAll returns every cached or freshly-resolved address for
// host. Useful for tests and for happy-eyeballs callers that want to
// race v4 + v6.
func (r *Resolver) LookupAll(ctx context.Context, host string) ([]netip.Addr, error) {
	if r == nil {
		return nil, errors.New("clientdns: nil resolver")
	}
	return r.lookup(ctx, host)
}

func (r *Resolver) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.expires) {
		out := append([]netip.Addr(nil), e.addrs...)
		r.mu.Unlock()
		return out, nil
	}
	r.mu.Unlock()

	queryCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	_ = queryCtx // MultiClient uses its own internal timeout currently;
	// kept here so that when MultiClient grows ctx-aware methods we
	// don't have to plumb it through every transport again.

	// Issue A (1) and AAAA (28) in parallel via QueryRaw — Client.Query
	// is hard-coded to extract the ECH parameter from HTTPS RRs and
	// would return "no ECH parameter found" for plain address records.
	const (
		typeA    uint16 = 1
		typeAAAA uint16 = 28
	)
	var (
		v4Err, v6Err error
		v4, v6       []netip.Addr
		wg           sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		raw, err := r.mc.QueryRaw(dns.BuildQuery(host, typeA))
		if err != nil {
			v4Err = err
			return
		}
		v4 = recordsToAddrs(raw)
	}()
	go func() {
		defer wg.Done()
		raw, err := r.mc.QueryRaw(dns.BuildQuery(host, typeAAAA))
		if err != nil {
			v6Err = err
			return
		}
		v6 = recordsToAddrs(raw)
	}()
	wg.Wait()

	if len(v4) == 0 && len(v6) == 0 {
		// Both legs failed; surface whichever error is more
		// informative.
		if v4Err != nil {
			return nil, fmt.Errorf("clientdns: %s: %w", host, v4Err)
		}
		return nil, fmt.Errorf("clientdns: %s: %w", host, v6Err)
	}

	merged := append(v4, v6...)
	r.mu.Lock()
	r.cache[host] = cacheEntry{
		addrs:   merged,
		expires: time.Now().Add(r.cacheTTL),
	}
	r.mu.Unlock()
	return merged, nil
}

// recordsToAddrs runs the raw DoH response through ParseAddressRecords
// (the existing helper that handles A and AAAA) and turns the printable
// strings into netip.Addrs. Bad entries are silently dropped.
func recordsToAddrs(rawResp []byte) []netip.Addr {
	if len(rawResp) == 0 {
		return nil
	}
	recs, err := dns.ParseAddressRecords(rawResp)
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(recs))
	for _, p := range recs {
		if ip, err := netip.ParseAddr(strings.TrimSpace(p)); err == nil {
			out = append(out, ip)
		}
	}
	return out
}

// choose picks one address from a list according to the configured
// IPv4/IPv6 preference. Round-robin within the chosen family is left
// to the kernel's connect() — the caller usually retries with the
// next entry on failure.
func (r *Resolver) choose(addrs []netip.Addr) netip.Addr {
	if r.preferIPv6 {
		for _, a := range addrs {
			if a.Is6() && !a.Is4In6() {
				return a
			}
		}
	}
	for _, a := range addrs {
		if a.Is4() || a.Is4In6() {
			return a
		}
	}
	return addrs[0] // fall through to whatever is first
}

// Close drops every cache entry. Safe to call multiple times.
func (r *Resolver) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	r.cache = map[string]cacheEntry{}
	r.mu.Unlock()
	return nil
}
