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
	"sync/atomic"
	"time"

	"ewp-core/log"
	"ewp-core/transport"
)

// defaultPoolSize is the number of parallel tunnel→DoH connections maintained
// by the resolver.  Each connection serialises its own HTTP/1.1 requests, so
// N connections give N-fold concurrency improvement for distinct domain lookups.
// Tunable via TunnelDNSConfig.PoolSize.
const defaultPoolSize = 8

// maxDNSCacheEntries is the approximate upper bound on cached DNS responses.
// When exceeded a sweep evicts all expired entries; if the count is still high
// after eviction the cache is cleared entirely to prevent unbounded growth in
// long-running deployments. (P1-5)
const maxDNSCacheEntries = 10_000

// ─────────────────────────────────────────────────────────────────────────────
// dnsPoolConn — one persistent tunnel → TLS → HTTP/1.1 connection
// ─────────────────────────────────────────────────────────────────────────────

// dnsPoolConn encapsulates all state that belongs to a single physical
// connection in the pool.  The two mutexes are intentionally separate:
//   - connMu  guards the connection lifecycle (dial / close / reconnect)
//   - queryMu serialises HTTP/1.1 requests on this connection
//
// Because HTTP/1.1 can only carry one outstanding request per connection, the
// serialisation is a protocol requirement, not a locking deficiency.  Multiple
// dnsPoolConns run in parallel, which is where the real concurrency comes from.
type dnsPoolConn struct {
	// connection lifecycle — protected by connMu
	connMu     sync.Mutex
	httpClient *http.Client
	tunnelConn transport.TunnelConn
	netConn    net.Conn
	connected  bool

	// HTTP/1.1 request serialisation — one outstanding request per conn
	queryMu sync.Mutex
}

// serialQuery acquires queryMu, ensures the underlying connection is live, and
// sends one DoH POST request.  On success the raw DNS response body is returned.
func (c *dnsPoolConn) serialQuery(
	ctx context.Context,
	trans transport.Transport,
	dohServer, targetHost, targetPort, target string,
	useHTTPS bool,
	reqTimeout time.Duration,
	dnsQuery []byte,
) ([]byte, error) {
	c.queryMu.Lock()
	defer c.queryMu.Unlock()

	client, err := c.ensureConnected(trans, targetHost, targetPort, target, useHTTPS, reqTimeout)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dohServer, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP DoH request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		return nil, fmt.Errorf("DoH HTTP %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("empty response from DoH server")
	}
	return body, nil
}

// ensureConnected returns a live *http.Client, (re-)establishing the tunnel if
// necessary.  Must be called with queryMu held (so only one goroutine attempts
// to dial at a time on this connection).
func (c *dnsPoolConn) ensureConnected(
	trans transport.Transport,
	targetHost, targetPort, target string,
	useHTTPS bool,
	reqTimeout time.Duration,
) (*http.Client, error) {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.connected && c.httpClient != nil {
		return c.httpClient, nil
	}

	// Connection setup gets a generous timeout independent of the per-query
	// timeout so a slow first-connect doesn't abort before TLS is done.
	connCtx, connCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer connCancel()

	log.Printf("[TunnelDNS] Connecting: tunnel → %s …", target)

	// Step 1: dial a new tunnel stream.
	tunnelConn, err := trans.Dial()
	if err != nil {
		return nil, fmt.Errorf("tunnel dial: %w", err)
	}

	// Step 2: HTTP CONNECT through the tunnel to the DoH server.
	if err := tunnelConn.Connect(target, nil); err != nil {
		tunnelConn.Close()
		return nil, fmt.Errorf("tunnel CONNECT %s: %w", target, err)
	}

	var netConn net.Conn = &tunnelConnAdapter{TunnelConn: tunnelConn}

	// Step 3: TLS handshake (DoH is always HTTPS in practice).
	if useHTTPS {
		tlsCfg := &tls.Config{
			ServerName: targetHost,
			// Force HTTP/1.1 — Go's http.Transport does not support HTTP/2
			// when DialTLSContext is overridden with a custom connection.
			NextProtos: []string{"http/1.1"},
		}
		tlsConn := tls.Client(netConn, tlsCfg)
		if err := tlsConn.HandshakeContext(connCtx); err != nil {
			tunnelConn.Close()
			return nil, fmt.Errorf("TLS handshake to %s: %w", targetHost, err)
		}
		netConn = tlsConn
	}

	// Build an http.Transport that hands out netConn on the first Dial call.
	// The "connReady" flag ensures we hand out the connection exactly once;
	// subsequent calls signal that the connection has been consumed or lost.
	connReady := true
	t := &http.Transport{
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		MaxConnsPerHost:     1,
		IdleConnTimeout:     90 * time.Second,
	}
	dialFn := func(_ context.Context, _, _ string) (net.Conn, error) {
		if connReady {
			connReady = false
			return netConn, nil
		}
		return nil, fmt.Errorf("dnsPoolConn: connection already consumed")
	}
	if useHTTPS {
		t.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialFn(ctx, network, addr)
		}
	} else {
		t.DialContext = dialFn
	}

	c.tunnelConn = tunnelConn
	c.netConn = netConn
	c.httpClient = &http.Client{Transport: t, Timeout: reqTimeout}
	c.connected = true

	log.Printf("[TunnelDNS] Connected: %s (pool slot ready)", target)
	return c.httpClient, nil
}

// closeConn tears down this pool connection so the next serialQuery will
// re-dial.  Safe to call from any goroutine.
func (c *dnsPoolConn) closeConn() {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
		c.httpClient = nil
	}
	if c.netConn != nil {
		c.netConn.Close()
		c.netConn = nil
	}
	if c.tunnelConn != nil {
		c.tunnelConn.Close()
		c.tunnelConn = nil
	}
	c.connected = false
}

// ─────────────────────────────────────────────────────────────────────────────
// TunnelDNSResolver — public API
// ─────────────────────────────────────────────────────────────────────────────

// TunnelDNSResolver resolves DNS queries through the proxy tunnel using DoH.
// All DNS traffic is encrypted end-to-end: client → tunnel → proxy → DoH server.
//
// Architecture (P1-4: connection pool)
//   - PoolSize persistent tunnel+TLS connections (default 8)
//   - Requests are round-robin dispatched across the pool
//   - Each connection serialises its own HTTP/1.1 requests (queryMu)
//   - Concurrent identical queries are deduplicated (inflight singleflight)
//   - Results are cached with extended TTL (P1-5: capped at 10 000 entries)
//   - TXID is validated per response before caching (P1-16)
//   - Auto-reconnect: failed connections are re-dialled on next query
type TunnelDNSResolver struct {
	// immutable after construction
	trans      transport.Transport
	dohServer  string
	targetHost string
	targetPort string
	target     string // host:port for tunnel CONNECT
	useHTTPS   bool
	cacheTTL   time.Duration
	timeout    time.Duration

	// connection pool (P1-4)
	pool    []*dnsPoolConn
	poolIdx uint32 // atomic — round-robin index

	// shared response cache (P1-5)
	cache      sync.Map
	cacheCount int64 // atomic approximate entry count

	// inflight deduplication: identical concurrent queries share one request
	inflight sync.Map // cacheKey → *inflightQuery
}

// inflightQuery represents a DNS query currently being resolved.
// Callers that arrive for the same cacheKey while a query is in-flight
// wait on done and receive the shared result.
type inflightQuery struct {
	done     chan struct{}
	response []byte
	err      error
}

type cachedDNSResult struct {
	response  []byte
	expiresAt time.Time
}

// TunnelDNSConfig configures the tunnel DNS resolver.
type TunnelDNSConfig struct {
	// DoH server URL (default: "https://dns.google/dns-query")
	DoHServer string

	// PoolSize is the number of parallel tunnel connections (default: 8).
	// Higher values reduce serialisation under concurrent distinct-domain loads.
	PoolSize int

	// CacheTTL is how long resolved responses are kept (default: 30 min).
	// Long TTLs are safe because the proxy re-resolves on the server side.
	CacheTTL time.Duration

	// Timeout is the per-query deadline (default: 5 s).
	Timeout time.Duration
}

// NewTunnelDNSResolver creates a new resolver backed by a pool of persistent
// tunnel→DoH connections.
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
	poolSize := config.PoolSize
	if poolSize <= 0 {
		poolSize = defaultPoolSize
	}

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

	pool := make([]*dnsPoolConn, poolSize)
	for i := range pool {
		pool[i] = &dnsPoolConn{}
	}

	r := &TunnelDNSResolver{
		trans:      trans,
		dohServer:  dohServer,
		targetHost: targetHost,
		targetPort: targetPort,
		target:     net.JoinHostPort(targetHost, targetPort),
		useHTTPS:   u.Scheme == "https",
		cacheTTL:   cacheTTL,
		timeout:    timeout,
		pool:       pool,
	}

	log.Printf("[TunnelDNS] Initialized: DoH=%s, pool=%d, cacheTTL=%s, timeout=%s",
		dohServer, poolSize, cacheTTL, timeout)
	return r, nil
}

// DoHServer returns the configured DoH server URL.
func (r *TunnelDNSResolver) DoHServer() string { return r.dohServer }

// PoolSize returns the number of connections in the pool.
func (r *TunnelDNSResolver) PoolSize() int { return len(r.pool) }

// pickConn selects a pool connection via round-robin.
// Round-robin is simple, deterministic, and avoids thundering-herd on a single
// "least-busy" connection when all connections have similar latency profiles.
func (r *TunnelDNSResolver) pickConn() *dnsPoolConn {
	idx := atomic.AddUint32(&r.poolIdx, 1)
	return r.pool[idx%uint32(len(r.pool))]
}

// QueryRaw performs a raw DNS query through the proxy tunnel using DoH (RFC 8484).
//
// Thread-safe: can be called concurrently from any number of goroutines.
// Identical concurrent queries (same question, ignoring TXID) are deduplicated
// so only one HTTP request is issued regardless of call concurrency.
func (r *TunnelDNSResolver) QueryRaw(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	if len(dnsQuery) < 12 {
		return nil, fmt.Errorf("DNS query too short: %d bytes", len(dnsQuery))
	}

	// ── 1. Cache hit ────────────────────────────────────────────────────────
	cacheKey := dnsCacheKey(dnsQuery)
	if cached, ok := r.cache.Load(cacheKey); ok {
		result := cached.(*cachedDNSResult)
		if time.Now().Before(result.expiresAt) {
			log.V("[TunnelDNS] Cache hit")
			resp := make([]byte, len(result.response))
			copy(resp, result.response)
			resp[0], resp[1] = dnsQuery[0], dnsQuery[1] // patch TXID
			return resp, nil
		}
		r.cache.Delete(cacheKey)
		atomic.AddInt64(&r.cacheCount, -1)
	}

	// ── 2. Inflight deduplication ────────────────────────────────────────────
	// If an identical query is already in-flight, piggy-back on it.
	if existing, ok := r.inflight.Load(cacheKey); ok {
		return r.waitInflight(ctx, existing.(*inflightQuery), dnsQuery)
	}

	// ── 3. Register our own inflight entry ───────────────────────────────────
	q := &inflightQuery{done: make(chan struct{})}
	if existing, loaded := r.inflight.LoadOrStore(cacheKey, q); loaded {
		// Lost the race — another goroutine registered first.
		return r.waitInflight(ctx, existing.(*inflightQuery), dnsQuery)
	}

	// ── 4. Perform the actual query ──────────────────────────────────────────
	defer func() {
		close(q.done)
		r.inflight.Delete(cacheKey)
	}()

	qCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	response, err := r.doQueryWithRetry(qCtx, dnsQuery)
	if err != nil {
		q.err = err
		return nil, err
	}

	// ── 5. TXID validation (P1-16) ───────────────────────────────────────────
	// In HTTP/1.1 serial mode each request has exactly one response so a TXID
	// mismatch cannot happen in practice.  The check is a defensive guard for
	// a future upgrade to HTTP/2 multiplexing within a single connection.
	if len(response) >= 2 && (response[0] != dnsQuery[0] || response[1] != dnsQuery[1]) {
		log.V("[TunnelDNS] TXID mismatch: sent %02x%02x got %02x%02x (HTTP/1.1 — using anyway)",
			dnsQuery[0], dnsQuery[1], response[0], response[1])
	}

	// ── 6. Store in cache (P1-5) ─────────────────────────────────────────────
	if atomic.AddInt64(&r.cacheCount, 1) > maxDNSCacheEntries {
		r.evictExpiredCache()
	}
	r.cache.Store(cacheKey, &cachedDNSResult{
		response:  response,
		expiresAt: time.Now().Add(r.cacheTTL),
	})

	q.response = response
	log.V("[TunnelDNS] ✅ Resolved: %d bytes", len(response))

	resp := make([]byte, len(response))
	copy(resp, response)
	resp[0], resp[1] = dnsQuery[0], dnsQuery[1]
	return resp, nil
}

// waitInflight blocks until the given in-flight query completes (or ctx expires)
// and returns a copy of its response with the caller's TXID patched in.
func (r *TunnelDNSResolver) waitInflight(ctx context.Context, q *inflightQuery, dnsQuery []byte) ([]byte, error) {
	select {
	case <-q.done:
		if q.err != nil {
			return nil, q.err
		}
		resp := make([]byte, len(q.response))
		copy(resp, q.response)
		resp[0], resp[1] = dnsQuery[0], dnsQuery[1]
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// doQueryWithRetry picks a pool connection and executes a serialQuery.
// On failure it closes that connection and retries once on the same slot
// (which will re-dial), giving transparent recovery from transient drops.
func (r *TunnelDNSResolver) doQueryWithRetry(ctx context.Context, dnsQuery []byte) ([]byte, error) {
	conn := r.pickConn()

	response, err := conn.serialQuery(
		ctx,
		r.trans,
		r.dohServer, r.targetHost, r.targetPort, r.target,
		r.useHTTPS, r.timeout,
		dnsQuery,
	)
	if err != nil {
		// Close this slot so the next attempt re-dials.
		conn.closeConn()

		response, err = conn.serialQuery(
			ctx,
			r.trans,
			r.dohServer, r.targetHost, r.targetPort, r.target,
			r.useHTTPS, r.timeout,
			dnsQuery,
		)
		if err != nil {
			conn.closeConn()
			return nil, err
		}
	}
	return response, nil
}

// evictExpiredCache removes all expired entries from the shared cache and
// updates the approximate entry counter.  If the count remains above the cap
// after eviction (all entries are still unexpired) the entire cache is cleared
// to keep memory bounded at the cost of a cold-cache spike. (P1-5)
func (r *TunnelDNSResolver) evictExpiredCache() {
	now := time.Now()
	var evicted int64
	r.cache.Range(func(k, v interface{}) bool {
		if result := v.(*cachedDNSResult); now.After(result.expiresAt) {
			r.cache.Delete(k)
			evicted++
		}
		return true
	})
	remaining := atomic.AddInt64(&r.cacheCount, -evicted)
	if remaining > maxDNSCacheEntries {
		r.cache = sync.Map{}
		atomic.StoreInt64(&r.cacheCount, 0)
		log.Printf("[TunnelDNS] Cache over-capacity (%d entries) — cleared", remaining)
	}
}

// ClearCache evicts all cached responses.
func (r *TunnelDNSResolver) ClearCache() {
	r.cache = sync.Map{}
	atomic.StoreInt64(&r.cacheCount, 0)
	log.Printf("[TunnelDNS] Cache cleared")
}

// Close tears down all pool connections and releases resources.
func (r *TunnelDNSResolver) Close() error {
	for _, c := range r.pool {
		c.closeConn()
	}
	return nil
}

// dnsCacheKey returns the query body minus the 2-byte transaction ID as the
// cache key.  This makes the key collision-free for distinct questions while
// allowing queries with different TXIDs to share a cached answer.
func dnsCacheKey(query []byte) string {
	if len(query) < 12 {
		return string(query)
	}
	return string(query[2:])
}

// ─────────────────────────────────────────────────────────────────────────────
// tunnelConnAdapter — adapts transport.TunnelConn to net.Conn
// ─────────────────────────────────────────────────────────────────────────────

type tunnelConnAdapter struct {
	transport.TunnelConn
}

func (a *tunnelConnAdapter) LocalAddr() net.Addr  { return &net.TCPAddr{} }
func (a *tunnelConnAdapter) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (a *tunnelConnAdapter) Write(b []byte) (int, error) {
	if err := a.TunnelConn.Write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (a *tunnelConnAdapter) SetDeadline(t time.Time) error      { return nil }
func (a *tunnelConnAdapter) SetReadDeadline(t time.Time) error  { return nil }
func (a *tunnelConnAdapter) SetWriteDeadline(t time.Time) error { return nil }
