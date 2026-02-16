package h3grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	commontls "ewp-core/common/tls"
	"ewp-core/dns"
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
	
	// Bootstrap resolver
	bootstrapResolver *dns.BootstrapResolver

	// HTTP/3 specific
	client         *http.Client
	http3Transport *http3.Transport
	quicConfig     *quic.Config
	tlsConfig      *tls.Config
	
	// Connection pool
	connPool       sync.Pool
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
		serverAddr:        serverAddr,
		serverIP:          serverIP,
		uuidStr:           uuidStr,
		password:          password,
		uuid:              uuid,
		useECH:            useECH,
		enableFlow:        enableFlow,
		enablePQC:         enablePQC,
		useTrojan:         useTrojan,
		serviceName:       serviceName,
		authority:         "",
		idleTimeout:       30 * time.Second,
		concurrency:       4,
		echManager:        echManager,
		
		// Default anti-DPI settings (browser-like)
		userAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		contentType: "application/octet-stream",
	}

	// Initialize bootstrap resolver (DoH over H2)
	bootstrapResolver := dns.NewBootstrapResolver("")
	t.bootstrapResolver = bootstrapResolver

	// Initialize HTTP/3 client
	if err := t.initClient(); err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP/3 client: %w", err)
	}

	return t, nil
}

// initClient initializes the HTTP/3 client with QUIC config
func (t *Transport) initClient() error {
	// Parse server address
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return fmt.Errorf("invalid server address: %w", err)
	}

	// Create TLS config
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

	// Create QUIC config with optimized parameters
	t.quicConfig = &quic.Config{
		// Stream flow control windows
		InitialStreamReceiveWindow:     6 * 1024 * 1024,  // 6MB
		MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16MB
		
		// Connection flow control windows
		InitialConnectionReceiveWindow: 15 * 1024 * 1024, // 15MB
		MaxConnectionReceiveWindow:     25 * 1024 * 1024, // 25MB
		
		// Timeouts
		MaxIdleTimeout:                 t.idleTimeout,
		KeepAlivePeriod:                10 * time.Second,
		
		// Performance optimizations
		DisablePathMTUDiscovery:        false, // Enable MTU discovery
		EnableDatagrams:                false, // Don't need datagram support
		
		// 0-RTT support
		Allow0RTT:                      true,
	}

	// Create HTTP/3 Transport
	t.http3Transport = &http3.Transport{
		TLSClientConfig:    t.tlsConfig,
		QUICConfig:         t.quicConfig,
		DisableCompression: true, // gRPC handles its own compression
	}

	// Create HTTP client
	t.client = &http.Client{
		Transport: t.http3Transport,
		Timeout:   0, // No timeout for long-lived connections
	}

	return nil
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
		name += "+ECH"
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

	// Determine target host and port
	host := parsed.Host
	port := parsed.Port
	addr := net.JoinHostPort(host, port)
	resolvedIP := t.serverIP
	
	// Resolve serverIP if it's a domain name
	if resolvedIP != "" && !isIPAddress(resolvedIP) {
		log.Printf("[H3] Configured serverIP is a domain (%s), resolving...", resolvedIP)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		ips, err := t.bootstrapResolver.LookupIP(ctx, resolvedIP)
		if err != nil {
			log.Printf("[H3] Bootstrap DNS resolution failed for serverIP %s: %v", resolvedIP, err)
			return nil, fmt.Errorf("bootstrap DNS resolution failed for serverIP: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
			log.Printf("[H3] Bootstrap resolved serverIP %s -> %s", t.serverIP, resolvedIP)
		} else {
			log.Printf("[H3] No IPs returned for serverIP %s", t.serverIP)
			return nil, fmt.Errorf("no IPs returned for serverIP %s", t.serverIP)
		}
	}
	
	// If no serverIP specified, resolve using bootstrap resolver (DoH over H2)
	if resolvedIP == "" && !isIPAddress(host) {
		log.Printf("[H3] Resolving server address: %s", host)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		ips, err := t.bootstrapResolver.LookupIP(ctx, host)
		if err != nil {
			log.Printf("[H3] Bootstrap DNS resolution failed for %s: %v", host, err)
			return nil, fmt.Errorf("bootstrap DNS resolution failed: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
			log.Printf("[H3] Bootstrap resolved %s -> %s", host, resolvedIP)
		} else {
			log.Printf("[H3] No IPs returned for %s", host)
		}
	} else if isIPAddress(host) {
		log.Printf("[H3] Server address is already an IP: %s", host)
	} else if resolvedIP != "" {
		log.Printf("[H3] Using resolved server IP: %s", resolvedIP)
	}
	
	// Use resolved IP if available
	if resolvedIP != "" {
		addr = net.JoinHostPort(resolvedIP, port)
		log.Printf("[H3] Connecting to: %s (SNI: %s)", addr, host)
	} else {
		log.Printf("[H3] Connecting to: %s", addr)
	}

	// Build request URL
	scheme := "https"
	path := "/" + t.serviceName + "/Tunnel"
	
	var url string
	if t.authority != "" {
		url = fmt.Sprintf("%s://%s%s", scheme, t.authority, path)
	} else {
		url = fmt.Sprintf("%s://%s%s", scheme, addr, path)
	}

	log.V("[H3] Connecting to %s (resolved: %s)", url, addr)

	// Create request
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers (use custom values for anti-DPI)
	req.Header.Set("Content-Type", t.contentType)
	req.Header.Set("User-Agent", t.userAgent)
	
	// Override Host header if using custom IP
	if t.serverIP != "" && t.authority == "" {
		req.Host = host
	} else if t.authority != "" {
		req.Host = t.authority
	}

	// Create connection
	conn := &Conn{
		transport:   t,
		request:     req,
		client:      t.client,
		uuid:        t.uuid,
		password:    t.password,
		enableFlow:  t.enableFlow,
		useTrojan:   t.useTrojan,
		encoder:     nil, // Will be set after response
		decoder:     nil, // Will be set after response
		recvChan:    make(chan []byte, 16),
		sendChan:    make(chan []byte, 16),
		closeChan:   make(chan struct{}),
	}

	return conn, nil
}

// Close closes the transport and cleans up resources
func (t *Transport) Close() error {
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

// handleECHRejection checks if error is ECH rejection and updates config
func (t *Transport) handleECHRejection(err error) error {
	if err == nil {
		return errors.New("nil error")
	}

	// Try to extract ECH rejection error
	// Go's tls.ECHRejectionError is returned wrapped in connection errors
	var echRejErr interface{ RetryConfigList() []byte }
	
	// Check if error message contains ECH rejection
	errMsg := err.Error()
	if !strings.Contains(errMsg, "server rejected ECH") && 
	   !strings.Contains(errMsg, "ECH") {
		return errors.New("not ECH rejection")
	}

	// Try to unwrap and find ECHRejectionError
	cause := err
	for cause != nil {
		// Check if this error has RetryConfigList method
		if rejErr, ok := cause.(interface{ RetryConfigList() []byte }); ok {
			echRejErr = rejErr
			break
		}
		
		// Try to unwrap
		unwrapped := errors.Unwrap(cause)
		if unwrapped == nil {
			break
		}
		cause = unwrapped
	}

	if echRejErr == nil {
		log.Printf("[H3] ECH rejection detected but no retry config available")
		return errors.New("no retry config")
	}

	retryList := echRejErr.RetryConfigList()
	if len(retryList) == 0 {
		log.Printf("[H3] Server rejected ECH without retry config (secure signal)")
		return errors.New("empty retry config")
	}

	log.Printf("[H3] Updating ECH config from server retry (%d bytes)", len(retryList))
	return t.echManager.UpdateFromRetry(retryList)
}
