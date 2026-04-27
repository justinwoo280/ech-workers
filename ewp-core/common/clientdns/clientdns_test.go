package clientdns

import (
	"context"
	"net/netip"
	"testing"
)

// TestNilResolver_PassesThrough — the nil resolver is the
// "OS resolver" sentinel; ResolveHostPort must return its input
// unchanged so callers can blindly assign the result.
func TestNilResolver_PassesThrough(t *testing.T) {
	var r *Resolver
	out, err := r.ResolveHostPort(context.Background(), "example.com:443")
	if err != nil {
		t.Fatalf("nil resolver returned error: %v", err)
	}
	if out != "example.com:443" {
		t.Fatalf("nil resolver mutated input: %q", out)
	}
}

// TestNew_EmptyServers_ReturnsNil — an empty config yields a nil
// resolver (not an error). This lets cfg loaders pass the result
// straight to BuildOutbound without nil-checking.
func TestNew_EmptyServers_ReturnsNil(t *testing.T) {
	r, err := New(Config{})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if r != nil {
		t.Fatalf("expected nil resolver for empty config, got %#v", r)
	}
}

// TestResolveHostPort_IPLiteralFastPath — an IP literal must skip the
// DoH lookup entirely (we have no servers wired here, so a real lookup
// would block on TLS). Verifies the fast-path triggers.
func TestResolveHostPort_IPLiteralFastPath(t *testing.T) {
	r, err := New(Config{Servers: []string{"https://1.1.1.1/dns-query"}})
	if err != nil || r == nil {
		t.Fatalf("New: %v / %v", r, err)
	}
	cases := []string{"1.2.3.4:80", "[2001:db8::1]:443"}
	for _, in := range cases {
		out, err := r.ResolveHostPort(context.Background(), in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
		}
		if out != in {
			t.Errorf("%q: mutated to %q", in, out)
		}
	}
}

// TestChoose_PreferIPv6 — when both v4 and v6 are present and
// PreferIPv6 is set, the v6 must win.
func TestChoose_PreferIPv6(t *testing.T) {
	r := &Resolver{preferIPv6: true}
	addrs := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("2001:db8::1"),
	}
	got := r.choose(addrs)
	if got.Is4() {
		t.Fatalf("PreferIPv6 picked v4: %v", got)
	}
}

// TestChoose_PreferIPv4Default — default preference is v4.
func TestChoose_PreferIPv4Default(t *testing.T) {
	r := &Resolver{}
	addrs := []netip.Addr{
		netip.MustParseAddr("2001:db8::1"),
		netip.MustParseAddr("1.2.3.4"),
	}
	got := r.choose(addrs)
	if got.Is6() && !got.Is4In6() {
		t.Fatalf("default picked v6 over v4: %v", got)
	}
}

// TestRecordsToAddrs — directly exercises the helper that parses
// dns.ParseAddressRecords output, since the real DoH path needs a
// network round-trip we can't take in unit tests.
func TestRecordsToAddrs(t *testing.T) {
	// Build a minimal A response by hand — easier than mocking the
	// DoH client. dns.ParseAddressRecords already has its own tests
	// in the dns/ package, so here we just check that empty / nil
	// input behaves.
	if got := recordsToAddrs(nil); got != nil {
		t.Fatalf("nil input: %v", got)
	}
	if got := recordsToAddrs([]byte{}); got != nil {
		t.Fatalf("empty input: %v", got)
	}
	// Garbage input → ParseAddressRecords returns err → recordsToAddrs
	// returns nil rather than panic.
	if got := recordsToAddrs([]byte("not a dns response")); got != nil {
		t.Fatalf("garbage input parsed somehow: %v", got)
	}
}
