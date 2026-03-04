package dns

import (
	"bytes"
	"context"
	"crypto/tls"
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
// Architecture:
//   - A persistent tunnel+TLS connection is maintained to the DoH server
//   - HTTP/1.1 keep-alive is used for connection reuse (subsequent queries ~50ms)
//   - Auto-reconnect on connection loss
//   - Results are cached to avoid redundant queries
type TunnelDNSResolver struct {
	transport transport.Transport
	dohServer string // e.g., "https://dns.google/dns-query"
	cache     sync.Map
	cacheTTL  time.Duration
	timeout   time.Duration

	// Persistent connection management
	mu         sync.Mutex
	httpClient *http.Client         // reusable HTTP client with keep-alive
	tunnelConn transport.TunnelConn // underlying tunnel connection
	netConn    net.Conn             // TLS-wrapped connection
	connected  bool

	// Pre-parsed URL components (avoid re-parsing on every query)
	targetHost string
	targetPort string
	target     string // host:port for tunnel CONNECT
	useHTTPS   bool
}

type cachedDNSResult struct {
	response  []byte
	expiresAt time.Time
}

// TunnelDNSConfig configures the tunnel DNS resolver
type TunnelDNSConfig struct {
	// DoH server URL (default: "https://dns.google/dns-query")
	DoHServer string

	// Cache TTL (default: 5 minutes)
	CacheTTL time.Duration

	// Query timeout (default: 5 seconds)
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

	cacheTTL := config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Pre-parse DoH URL
	u, err := url.Parse(dohServer)
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

	resolver := &TunnelDNSResolver{
		transport:  trans,
		dohServer:  dohServer,
		cacheTTL:   cacheTTL,
		timeout:    timeout,
		targetHost: targetHost,
		targetPort: targetPort,
		target:     net.JoinHostPort(targetHost, targetPort),
		useHTTPS:   u.Scheme == "https",
	}

	log.Printf("[TunnelDNS] Initialized: DoH=%s, timeout=%s", dohServer, timeout)
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

	// Check cache first (no connection needed)
	cacheKey := dnsCacheKey(dnsQuery)
	if cached, ok := r.cache.Load(cacheKey); ok {
		result := cached.(*cachedDNSResult)
		if time.Now().Before(result.expiresAt) {
			log.V("[TunnelDNS] Cache hit")
			// Copy the cached response and update the transaction ID
			resp := make([]byte, len(result.response))
			copy(resp, result.response)
			resp[0] = dnsQuery[0]
			resp[1] = dnsQuery[1]
			return resp, nil
		}
		r.cache.Delete(cacheKey)
	}

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Perform DoH query through persistent tunnel connection
	response, err := r.doQuery(ctx, dnsQuery)
	if err != nil {
		// On failure, tear down connection so next query will reconnect
		r.closeConn()
		// Retry once with a fresh connection
		response, err = r.doQuery(ctx, dnsQuery)
		if err != nil {
			r.closeConn()
			return nil, err
		}
	}

	// Cache the response
	r.cache.Store(cacheKey, &cachedDNSResult{
		response:  response,
		expiresAt: time.Now().Add(r.cacheTTL),
	})

	log.V("[TunnelDNS] ✅ DoH query successful: %d bytes", len(response))
	return response, nil
}

// doQuery performs a single DoH HTTP POST using the persistent connection.
func (r *TunnelDNSResolver) doQuery(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	client, err := r.ensureConnected(ctx)
	if err != nil {
		return nil, err
	}

	// Build DoH POST request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.dohServer, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request failed: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	// Execute DoH request (reuses persistent connection via keep-alive)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Drain body to allow connection reuse
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("DoH HTTP error: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body failed: %w", err)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("empty response from DoH server")
	}

	return body, nil
}

// ensureConnected returns a reusable HTTP client backed by a persistent tunnel.
// Creates one on first call; subsequent calls return the same client.
func (r *TunnelDNSResolver) ensureConnected(ctx context.Context) (*http.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.connected && r.httpClient != nil {
		return r.httpClient, nil
	}

	// Dial a new tunnel connection
	tunnelConn, err := r.transport.Dial()
	if err != nil {
		return nil, fmt.Errorf("tunnel dial failed: %w", err)
	}

	// CONNECT proxy to DoH server
	if err := tunnelConn.Connect(r.target, nil); err != nil {
		tunnelConn.Close()
		return nil, fmt.Errorf("tunnel connect to %s failed: %w", r.target, err)
	}

	var netConn net.Conn = &tunnelConnAdapter{TunnelConn: tunnelConn}

	// If HTTPS, wrap with TLS
	if r.useHTTPS {
		tlsConfig := &tls.Config{
			ServerName: r.targetHost,
			// Force HTTP/1.1: Go's http.Transport does NOT support HTTP/2 when
			// using custom DialTLSContext. Without this, dns.google negotiates h2
			// via ALPN, then immediately closes the connection because our client
			// sends HTTP/1.1 framing over an h2-negotiated connection → EOF.
			NextProtos: []string{"http/1.1"},
		}
		tlsConn := tls.Client(netConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tunnelConn.Close()
			return nil, fmt.Errorf("TLS handshake to DoH server failed: %w", err)
		}
		netConn = tlsConn
	}

	// Create HTTP client that reuses this single persistent connection.
	// connUsed tracks whether the DialXxxContext callback has been called;
	// the first call returns our pre-established netConn, subsequent calls
	// mean the connection was closed and we need to signal reconnect.
	connUsed := false
	httpTransport := &http.Transport{
		// Keep-alive enabled (default) — connection reuse!
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     90 * time.Second,
	}
	if r.useHTTPS {
		httpTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !connUsed {
				connUsed = true
				return netConn, nil
			}
			// Connection was recycled/closed; signal reconnect needed
			return nil, errors.New("connection lost, reconnect required")
		}
	} else {
		httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !connUsed {
				connUsed = true
				return netConn, nil
			}
			return nil, errors.New("connection lost, reconnect required")
		}
	}

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   r.timeout,
	}

	r.tunnelConn = tunnelConn
	r.netConn = netConn
	r.httpClient = client
	r.connected = true

	log.Printf("[TunnelDNS] Persistent connection established to %s", r.target)
	return client, nil
}

// closeConn tears down the persistent connection (called on error for reconnect).
func (r *TunnelDNSResolver) closeConn() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
		r.httpClient = nil
	}
	if r.netConn != nil {
		r.netConn.Close()
		r.netConn = nil
	}
	if r.tunnelConn != nil {
		r.tunnelConn.Close()
		r.tunnelConn = nil
	}
	r.connected = false
}

// dnsCacheKey generates a fast cache key from a DNS query.
// Extracts QNAME + QTYPE from the wire format (no hashing needed for typical queries).
func dnsCacheKey(query []byte) string {
	if len(query) < 12 {
		return string(query)
	}
	// Use the query body (everything after the 2-byte transaction ID) as key.
	// This avoids SHA-256 overhead while being collision-free for distinct queries.
	return string(query[2:])
}

// ClearCache clears the resolver cache.
func (r *TunnelDNSResolver) ClearCache() {
	r.cache = sync.Map{}
	log.Printf("[TunnelDNS] Cache cleared")
}

// Close releases resources.
func (r *TunnelDNSResolver) Close() error {
	r.closeConn()
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
