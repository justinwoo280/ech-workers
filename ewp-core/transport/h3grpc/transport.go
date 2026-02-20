package h3grpc

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Transport implements HTTP/3 transport for gRPC-Web
type Transport struct {
	serverAddr     string
	serverIP       string
	uuidStr        string
	password       string
	uuid           [16]byte
	useECH         bool
	enableFlow     bool
	enablePQC      bool
	useTrojan      bool
	serviceName    string
	authority      string
	idleTimeout    time.Duration
	concurrency    int
	echManager     *commontls.ECHManager

	// Anti-DPI settings
	userAgent      string
	contentType    string

	// HTTP/3 specific — protected by mu
	mu             sync.RWMutex
	client         *http.Client
	http3Transport *http3.Transport
	quicConfig     *quic.Config
	tlsConfig      *tls.Config
}

// New creates a new HTTP/3 transport
func New(serverAddr, serverIP, uuidStr string, useECH, enableFlow bool, serviceName string, echManager *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocol(serverAddr, serverIP, uuidStr, "", useECH, enableFlow, false, false, serviceName, echManager)
}

// NewWithProtocol creates a new HTTP/3 transport with full options
func NewWithProtocol(serverAddr, serverIP, uuidStr, password string, useECH, enableFlow, enablePQC, useTrojan bool, serviceName string, echManager *commontls.ECHManager) (*Transport, error) {
	var uuid [16]byte
	if !useTrojan {
		var err error
		uuid, err = transport.ParseUUID(uuidStr)
		if err != nil {
			return nil, fmt.Errorf("invalid UUID: %w", err)
		}
	}

	if serviceName == "" {
		serviceName = "ProxyService"
	}
	serviceName = strings.TrimPrefix(serviceName, "/")

	t := &Transport{
		serverAddr:  serverAddr,
		serverIP:    serverIP,
		uuidStr:     uuidStr,
		password:    password,
		uuid:        uuid,
		useECH:      useECH,
		enableFlow:  enableFlow,
		enablePQC:   enablePQC,
		useTrojan:   useTrojan,
		serviceName: serviceName,
		authority:   "",
		idleTimeout: 30 * time.Second,
		concurrency: 4,
		echManager:  echManager,

		userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		contentType: "application/octet-stream",
	}

	if err := t.initClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP/3 client: %w", err)
	}

	return t, nil
}

// initClient builds the TLS/QUIC/HTTP stack.
// Must be called under t.mu write lock (or during construction before the Transport escapes).
func (t *Transport) initClient() error {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return fmt.Errorf("invalid server address: %w", err)
	}

	tlsCfg, err := commontls.NewClient(commontls.ClientOptions{
		ServerName: parsed.Host,
		EnableECH:  t.useECH,
		EnablePQC:  t.enablePQC,
		ECHManager: t.echManager,
	})
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}

	stdTLSConfig, err := tlsCfg.TLSConfig()
	if err != nil {
		return fmt.Errorf("failed to get TLS config: %w", err)
	}

	// Force HTTP/3 ALPN
	stdTLSConfig.NextProtos = []string{"h3"}

	// Enable session resumption for 0-RTT
	stdTLSConfig.ClientSessionCache = tls.NewLRUClientSessionCache(100)

	t.tlsConfig = stdTLSConfig

	t.quicConfig = &quic.Config{
		InitialStreamReceiveWindow:     6 * 1024 * 1024,
		MaxStreamReceiveWindow:         16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 15 * 1024 * 1024,
		MaxConnectionReceiveWindow:     25 * 1024 * 1024,
		MaxIdleTimeout:                 t.idleTimeout,
		KeepAlivePeriod:                10 * time.Second,
		DisablePathMTUDiscovery:        false,
		EnableDatagrams:                false,
		Allow0RTT:                      true,
	}

	t.http3Transport = &http3.Transport{
		TLSClientConfig:    t.tlsConfig,
		QUICConfig:         t.quicConfig,
		DisableCompression: true,
	}

	t.client = &http.Client{
		Transport: t.http3Transport,
		Timeout:   0,
	}

	return nil
}

// getClient returns the current HTTP client under a read lock.
func (t *Transport) getClient() *http.Client {
	t.mu.RLock()
	c := t.client
	t.mu.RUnlock()
	return c
}

// reinitClient closes the old HTTP/3 transport and builds a fresh one.
// Called after updating the ECH config so all future dials use the new key.
func (t *Transport) reinitClient() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.http3Transport != nil {
		t.http3Transport.Close()
		t.http3Transport = nil
	}

	return t.initClient()
}

// SetAuthority sets the :authority pseudo-header
func (t *Transport) SetAuthority(authority string) *Transport {
	t.authority = authority
	return t
}

// SetConcurrency sets the number of concurrent streams
func (t *Transport) SetConcurrency(n int) *Transport {
	if n > 0 {
		t.concurrency = n
	}
	return t
}

// SetIdleTimeout sets the QUIC connection idle timeout
func (t *Transport) SetIdleTimeout(d time.Duration) *Transport {
	t.idleTimeout = d
	if t.quicConfig != nil {
		t.quicConfig.MaxIdleTimeout = d
	}
	return t
}

// SetUserAgent sets custom User-Agent header
func (t *Transport) SetUserAgent(ua string) *Transport {
	if ua != "" {
		t.userAgent = ua
	}
	return t
}

// SetContentType sets custom Content-Type header
func (t *Transport) SetContentType(ct string) *Transport {
	if ct != "" {
		t.contentType = ct
	}
	return t
}

// Name returns the transport name
func (t *Transport) Name() string {
	var name string
	if t.useTrojan {
		name = "H3+Trojan"
	} else if t.enableFlow {
		name = "H3+Flow"
	} else {
		name = "H3+EWP"
	}
	if t.useECH {
		name += "+ECH(QUIC)"
	} else {
		name += "+TLS"
	}
	return name
}

// Dial creates a new connection
func (t *Transport) Dial() (transport.TunnelConn, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	host := parsed.Host
	port := parsed.Port
	addr := net.JoinHostPort(host, port)
	resolvedIP := t.serverIP

	// Resolve serverIP if it's a domain name
	if resolvedIP != "" && !isIPAddress(resolvedIP) {
		ips, err := net.LookupIP(resolvedIP)
		if err != nil {
			log.Printf("[H3] System DNS resolution failed for serverIP %s: %v", resolvedIP, err)
			return nil, fmt.Errorf("DNS resolution failed for serverIP: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
			log.V("[H3] Resolved serverIP %s -> %s", t.serverIP, resolvedIP)
		} else {
			return nil, fmt.Errorf("no IPs returned for serverIP %s", t.serverIP)
		}
	}

	// If no serverIP specified, resolve using system DNS
	if resolvedIP == "" && !isIPAddress(host) {
		ips, err := net.LookupIP(host)
		if err != nil {
			log.Printf("[H3] System DNS resolution failed for %s: %v", host, err)
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
		}
	}

	if resolvedIP != "" {
		addr = net.JoinHostPort(resolvedIP, port)
		log.Printf("[H3] Connecting to: %s (SNI: %s)", addr, host)
	} else {
		log.Printf("[H3] Connecting to: %s", addr)
	}

	scheme := "https"
	path := "/" + t.serviceName + "/Tunnel"

	var url string
	if t.authority != "" {
		url = fmt.Sprintf("%s://%s%s", scheme, t.authority, path)
	} else {
		url = fmt.Sprintf("%s://%s%s", scheme, addr, path)
	}

	log.V("[H3] Connecting to %s (resolved: %s)", url, addr)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", t.contentType)
	req.Header.Set("User-Agent", t.userAgent)

	// Ensure SNI matches the domain (not the raw IP) for Host header and ECH routing
	if t.serverIP != "" && t.authority == "" {
		req.Host = host
	} else if t.authority != "" {
		req.Host = t.authority
	}

	conn := &Conn{
		transport:  t,
		request:    req,
		uuid:       t.uuid,
		password:   t.password,
		enableFlow: t.enableFlow,
		useTrojan:  t.useTrojan,
		recvChan:   make(chan []byte, 32),
		sendChan:   make(chan []byte, 32),
		closeChan:  make(chan struct{}),
		connReady:  make(chan struct{}),
	}

	return conn, nil
}

// Close closes the transport and cleans up resources
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.http3Transport != nil {
		t.http3Transport.Close()
	}
	return nil
}

// Stats returns transport statistics
func (t *Transport) Stats() map[string]interface{} {
	return map[string]interface{}{
		"transport":    "h3grpc",
		"server":       t.serverAddr,
		"ech_enabled":  t.useECH,
		"flow_enabled": t.enableFlow,
		"pqc_enabled":  t.enablePQC,
		"concurrency":  t.concurrency,
	}
}

// isIPAddress checks if a string is a valid IP address
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// handleECHRejection extracts the server's ECH retry config from a rejection error,
// updates the ECH manager, and reinitialises the HTTP/3 client with the new config.
// Returns nil when the config was successfully updated (caller should retry the dial).
func (t *Transport) handleECHRejection(err error) error {
	if !t.useECH || t.echManager == nil {
		return errors.New("ECH not enabled or no manager")
	}

	var echRejErr *tls.ECHRejectionError
	if !errors.As(err, &echRejErr) {
		return errors.New("not an ECH rejection error")
	}

	retryList := echRejErr.RetryConfigList
	if len(retryList) == 0 {
		log.Printf("[H3] Server rejected ECH without retry config (misconfigured server or wrong domain)")
		return errors.New("empty retry config")
	}

	log.Printf("[H3] ECH rejected by server; updating config from retry list (%d bytes)", len(retryList))

	if err := t.echManager.UpdateFromRetry(retryList); err != nil {
		return fmt.Errorf("update ECH config: %w", err)
	}

	if err := t.reinitClient(); err != nil {
		return fmt.Errorf("reinit client after ECH update: %w", err)
	}

	log.Printf("[H3] ECH config updated; new client ready for retry")
	return nil
}
