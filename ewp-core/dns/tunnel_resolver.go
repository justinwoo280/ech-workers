package dns

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/transport"
)

// TunnelDNSResolver resolves DNS queries through the proxy tunnel using DoH.
// All DNS traffic is encrypted end-to-end: client → tunnel → proxy → DoH server.
//
// Architecture (inspired by sing-box):
//   - Queries are serialized through a semaphore to limit concurrent tunnel connections
//   - Results are cached to avoid redundant tunnel dials
//   - Only DoH is used (DoQ/DoT don't work through TCP CONNECT proxies)
type TunnelDNSResolver struct {
	transport  transport.Transport
	dohServer  string // e.g., "https://dns.google/dns-query"
	cache      sync.Map
	cacheTTL   time.Duration
	timeout    time.Duration
	semaphore  chan struct{} // limits concurrent tunnel connections
}

type cachedDNSResult struct {
	response  []byte
	expiresAt time.Time
}

// TunnelDNSConfig configures the tunnel DNS resolver
type TunnelDNSConfig struct {
	// DoH server URL (default: "https://dns.google/dns-query")
	DoHServer string

	// Maximum concurrent tunnel connections for DNS (default: 4)
	MaxConcurrent int

	// Cache TTL (default: 5 minutes)
	CacheTTL time.Duration

	// Query timeout (default: 10 seconds)
	Timeout time.Duration
}

// NewTunnelDNSResolver creates a new tunnel DNS resolver (DoH only)
func NewTunnelDNSResolver(trans transport.Transport, config TunnelDNSConfig) (*TunnelDNSResolver, error) {
	if trans == nil {
		return nil, fmt.Errorf("transport is required")
	}

	dohServer := config.DoHServer
	if dohServer == "" {
		dohServer = "https://dns.google/dns-query"
	} else if !strings.HasPrefix(dohServer, "https://") && !strings.HasPrefix(dohServer, "http://") {
		dohServer = "https://" + dohServer
	}

	maxConcurrent := config.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 4
	}

	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	resolver := &TunnelDNSResolver{
		transport:  trans,
		dohServer:  dohServer,
		cacheTTL:   cacheTTL,
		timeout:    timeout,
		semaphore:  make(chan struct{}, maxConcurrent),
	}

	log.Printf("[TunnelDNS] Initialized: DoH=%s, maxConcurrent=%d", dohServer, maxConcurrent)
	return resolver, nil
}

// DoHServer returns the configured DoH server URL.
func (r *TunnelDNSResolver) DoHServer() string {
	return r.dohServer
}

// QueryRaw performs a raw DNS query through the proxy tunnel using DoH (RFC 8484).
// Thread-safe: can be called concurrently from multiple goroutines.
func (r *TunnelDNSResolver) QueryRaw(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	if len(dnsQuery) < 12 {
		return nil, fmt.Errorf("DNS query too short: %d bytes", len(dnsQuery))
	}

	// Check cache first (no tunnel connection needed)
	cacheKey := dnsCacheKey(dnsQuery)
	if cached, ok := r.cache.Load(cacheKey); ok {
		result := cached.(*cachedDNSResult)
		if time.Now().Before(result.expiresAt) {
			log.V("[TunnelDNS] Cache hit")
			// Copy the cached response and update the transaction ID
			resp := make([]byte, len(result.response))
			copy(resp, result.response)
			// Set transaction ID from query
			resp[0] = dnsQuery[0]
			resp[1] = dnsQuery[1]
			return resp, nil
		}
		r.cache.Delete(cacheKey)
	}

	// Acquire semaphore (limits concurrent tunnel connections)
	select {
	case r.semaphore <- struct{}{}:
		defer func() { <-r.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Perform DoH query through tunnel
	response, err := r.doHTTPSQuery(ctx, dnsQuery)
	if err != nil {
		return nil, err
	}

	// Cache the response
	r.cache.Store(cacheKey, &cachedDNSResult{
		response:  response,
		expiresAt: time.Now().Add(r.cacheTTL),
	})

	log.V("[TunnelDNS] ✅ DoH query successful: %d bytes", len(response))
	return response, nil
}

// doHTTPSQuery performs a single DoH query through the proxy tunnel.
func (r *TunnelDNSResolver) doHTTPSQuery(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	// Dial tunnel
	tunnelConn, err := r.transport.Dial()
	if err != nil {
		return nil, fmt.Errorf("tunnel dial failed: %w", err)
	}

	// Wait to close the connection only if it's not handed to http.Client
	connClosed := false
	defer func() {
		if !connClosed {
			tunnelConn.Close()
		}
	}()

	// Parse DoH URL
	u, err := url.Parse(r.dohServer)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}

	targetHost := u.Hostname()
	targetPort := u.Port()
	if targetPort == "" {
		if u.Scheme == "https" {
			targetPort = "443"
		} else {
			targetPort = "80"
		}
	}
	target := net.JoinHostPort(targetHost, targetPort)

	// Connect proxy to DoH server
	if err := tunnelConn.Connect(target, nil); err != nil {
		return nil, fmt.Errorf("tunnel connect to %s failed: %w", target, err)
	}

	var netConn net.Conn = &tunnelConnAdapter{TunnelConn: tunnelConn}

	// If HTTPS, wrap with TLS
	if u.Scheme == "https" {
		tlsConfig := &tls.Config{
			ServerName: targetHost,
		}
		tlsConn := tls.Client(&tunnelConnAdapter{TunnelConn: tunnelConn}, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, fmt.Errorf("TLS handshake to DoH server failed: %w", err)
		}
		netConn = tlsConn
	}

	// We pass the ownership of netConn to the http transport
	connClosed = true

	// Custom HTTP Client using the established tunnel (and TLS)
	// When TLS is already handled, we use DialTLSContext so http.Transport
	// does NOT add another TLS layer on top.
	httpTransport := &http.Transport{
		DisableKeepAlives: true,
	}
	if u.Scheme == "https" {
		httpTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netConn, nil
		}
	} else {
		httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return netConn, nil
		}
	}
	client := &http.Client{
		Transport: httpTransport,
		Timeout:   r.timeout,
	}

	// Build DoH POST request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.dohServer, bytes.NewReader(dnsQuery))
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("create HTTP request failed: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// Execute DoH request
	resp, err := client.Do(req)
	if err != nil {
		// client.Do automatically closes the netConn on failure if dial returns it but errors out later
		if !errors.Is(err, net.ErrClosed) {
			netConn.Close()
		}
		return nil, fmt.Errorf("HTTP DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP error: %s", resp.Status)
	}

	// Read response body natively
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body failed: %w", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty response from DoH server")
	}

	return body, nil
}

// dnsCacheKey generates a collision-resistant cache key from a DNS query.
// Uses sha256 of the full query (minus 2-byte transaction ID) truncated to 8 bytes.
// 64-bit key = ~2^-64 collision probability, safe even with EDNS0 extensions.
func dnsCacheKey(query []byte) string {
	if len(query) < 12 {
		return hex.EncodeToString(query)
	}
	h := sha256.Sum256(query[2:])
	return hex.EncodeToString(h[:8])
}

// ClearCache clears the resolver cache.
func (r *TunnelDNSResolver) ClearCache() {
	r.cache = sync.Map{}
	log.Printf("[TunnelDNS] Cache cleared")
}

// Close releases resources.
func (r *TunnelDNSResolver) Close() error {
	return nil
}

// tunnelConnAdapter wraps a transport.TunnelConn to implement net.Conn
// This is required to pass the tunnel connection to tls.Client and http.Transport
type tunnelConnAdapter struct {
	transport.TunnelConn
}

func (a *tunnelConnAdapter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (a *tunnelConnAdapter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (a *tunnelConnAdapter) Write(b []byte) (n int, err error) {
	err = a.TunnelConn.Write(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (a *tunnelConnAdapter) SetDeadline(t time.Time) error {
	return nil
}

func (a *tunnelConnAdapter) SetReadDeadline(t time.Time) error {
	return nil
}

func (a *tunnelConnAdapter) SetWriteDeadline(t time.Time) error {
	return nil
}
