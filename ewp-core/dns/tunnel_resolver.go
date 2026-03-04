package dns

import (
	"bytes"
	"context"
	"crypto/tls"
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
//   - Concurrent identical queries are deduplicated (singleflight pattern)
//   - HTTP requests are serialized through a mutex (HTTP/1.1 limitation)
//   - Results are cached with extended TTL (proxy handles real resolution)
//   - Auto-reconnect on connection loss
type TunnelDNSResolver struct {
	transport transport.Transport
	dohServer string // e.g., "https://dns.google/dns-query"
	cache     sync.Map
	cacheTTL  time.Duration
	timeout   time.Duration

	// Persistent connection management
	connMu     sync.Mutex
	httpClient *http.Client         // reusable HTTP client with keep-alive
	tunnelConn transport.TunnelConn // underlying tunnel connection
	netConn    net.Conn             // TLS-wrapped connection
	connected  bool

	// Query serialization (HTTP/1.1 = one request at a time per connection)
	queryMu sync.Mutex

	// Inflight deduplication: identical concurrent queries share one HTTP request
	inflight sync.Map // cacheKey → *inflightQuery

	// Pre-parsed URL components (avoid re-parsing on every query)
	targetHost string
	targetPort string
	target     string // host:port for tunnel CONNECT
	useHTTPS   bool
}

// inflightQuery represents a DNS query currently being resolved.
// Multiple goroutines waiting for the same query share this object.
type inflightQuery struct {
	done     chan struct{} // closed when the query completes
	response []byte
	err      error
}

type cachedDNSResult struct {
	response  []byte
	expiresAt time.Time
}

// TunnelDNSConfig configures the tunnel DNS resolver
type TunnelDNSConfig struct {
	// DoH server URL (default: "https://dns.google/dns-query")
	DoHServer string

	// Cache TTL (default: 30 minutes — long because the proxy resolves on the server side)
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
		cacheTTL = 30 * time.Minute
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

	log.Printf("[TunnelDNS] Initialized: DoH=%s, cacheTTL=%s, timeout=%s", dohServer, cacheTTL, timeout)
	return resolver, nil
}

// DoHServer returns the configured DoH server URL.
func (r *TunnelDNSResolver) DoHServer() string {
	return r.dohServer
}

// QueryRaw performs a raw DNS query through the proxy tunnel using DoH (RFC 8484).
// Thread-safe: can be called concurrently from multiple goroutines.
// Identical concurrent queries are automatically deduplicated.
func (r *TunnelDNSResolver) QueryRaw(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	if len(dnsQuery) < 12 {
		return nil, fmt.Errorf("DNS query too short: %d bytes", len(dnsQuery))
	}

	// 1. Check cache first (instant, no connection needed)
	cacheKey := dnsCacheKey(dnsQuery)
	if cached, ok := r.cache.Load(cacheKey); ok {
		result := cached.(*cachedDNSResult)
		if time.Now().Before(result.expiresAt) {
			log.V("[TunnelDNS] Cache hit")
			resp := make([]byte, len(result.response))
			copy(resp, result.response)
			// Patch transaction ID from querier's original packet
			resp[0] = dnsQuery[0]
			resp[1] = dnsQuery[1]
			return resp, nil
		}
		r.cache.Delete(cacheKey)
	}

	// 2. Inflight deduplication: if same query is already in-flight, wait for it
	if existing, ok := r.inflight.Load(cacheKey); ok {
		q := existing.(*inflightQuery)
		select {
		case <-q.done:
			if q.err != nil {
				return nil, q.err
			}
			resp := make([]byte, len(q.response))
			copy(resp, q.response)
			resp[0] = dnsQuery[0]
			resp[1] = dnsQuery[1]
			return resp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// 3. We are the first goroutine for this query — register inflight entry
	q := &inflightQuery{done: make(chan struct{})}
	if existing, loaded := r.inflight.LoadOrStore(cacheKey, q); loaded {
		// Race: another goroutine registered between our Load and LoadOrStore
		q = existing.(*inflightQuery)
		select {
		case <-q.done:
			if q.err != nil {
				return nil, q.err
			}
			resp := make([]byte, len(q.response))
			copy(resp, q.response)
			resp[0] = dnsQuery[0]
			resp[1] = dnsQuery[1]
			return resp, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// 4. We own this inflight entry — do the actual query
	defer func() {
		close(q.done)
		r.inflight.Delete(cacheKey)
	}()

	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	response, err := r.serialQuery(ctx, dnsQuery)
	if err != nil {
		// Retry once with a fresh connection
		r.closeConn()
		response, err = r.serialQuery(ctx, dnsQuery)
		if err != nil {
			r.closeConn()
			q.err = err
			return nil, err
		}
	}

	// Cache the result
	r.cache.Store(cacheKey, &cachedDNSResult{
		response:  response,
		expiresAt: time.Now().Add(r.cacheTTL),
	})

	q.response = response
	log.V("[TunnelDNS] ✅ Resolved: %d bytes", len(response))

	// Return a copy with the querier's transaction ID
	resp := make([]byte, len(response))
	copy(resp, response)
	resp[0] = dnsQuery[0]
	resp[1] = dnsQuery[1]
	return resp, nil
}

// serialQuery acquires the query mutex and sends a single DoH request.
// HTTP/1.1 on a single connection only supports one request at a time,
// so this mutex prevents concurrent HTTP requests from colliding.
func (r *TunnelDNSResolver) serialQuery(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	r.queryMu.Lock()
	defer r.queryMu.Unlock()

	client, err := r.ensureConnected(ctx)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.dohServer, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request failed: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
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
func (r *TunnelDNSResolver) ensureConnected(ctx context.Context) (*http.Client, error) {
	r.connMu.Lock()
	defer r.connMu.Unlock()

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
			// via ALPN → protocol mismatch → EOF.
			NextProtos: []string{"http/1.1"},
		}
		tlsConn := tls.Client(netConn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			tunnelConn.Close()
			return nil, fmt.Errorf("TLS handshake to DoH server failed: %w", err)
		}
		netConn = tlsConn
	}

	// Build HTTP client that reuses this single persistent connection.
	connReady := true
	httpTransport := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1,
		IdleConnTimeout:     90 * time.Second,
	}
	if r.useHTTPS {
		httpTransport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if connReady {
				connReady = false
				return netConn, nil
			}
			return nil, fmt.Errorf("connection lost")
		}
	} else {
		httpTransport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			if connReady {
				connReady = false
				return netConn, nil
			}
			return nil, fmt.Errorf("connection lost")
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

// closeConn tears down the persistent connection.
func (r *TunnelDNSResolver) closeConn() {
	r.connMu.Lock()
	defer r.connMu.Unlock()

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

// dnsCacheKey returns the query body (minus 2-byte transaction ID) as the cache key.
// Collision-free for distinct queries without any hashing overhead.
func dnsCacheKey(query []byte) string {
	if len(query) < 12 {
		return string(query)
	}
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
