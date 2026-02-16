package grpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	commonnet "ewp-core/common/net"
	commontls "ewp-core/common/tls"
	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/transport"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

type grpcConnKey struct {
	addr      string
	authority string
	useTLS    bool
	useECH    bool
}

var (
	grpcConnPool      = make(map[grpcConnKey]*grpc.ClientConn)
	grpcConnPoolMutex sync.Mutex
)

type Transport struct {
	serverAddr          string
	serverIP            string
	uuidStr             string
	password            string  // Trojan password
	uuid                [16]byte
	useECH              bool
	enableFlow          bool
	enablePQC           bool
	useTrojan           bool    // Use Trojan protocol
	serviceName         string
	authority           string
	idleTimeout         time.Duration
	healthCheckTimeout  time.Duration
	permitWithoutStream bool
	initialWindowSize   int32
	userAgent           string
	contentType         string
	echManager          *commontls.ECHManager
	bootstrapResolver   *dns.BootstrapResolver
}

func New(serverAddr, serverIP, uuidStr string, useECH, enableFlow bool, serviceName string, echManager *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocol(serverAddr, serverIP, uuidStr, "", useECH, enableFlow, false, false, serviceName, echManager)
}

func NewWithProtocol(serverAddr, serverIP, uuidStr, password string, useECH, enableFlow, enablePQC, useTrojan bool, serviceName string, echManager *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocolAndBootstrap(serverAddr, serverIP, uuidStr, password, useECH, enableFlow, enablePQC, useTrojan, serviceName, echManager, "")
}

func NewWithProtocolAndBootstrap(serverAddr, serverIP, uuidStr, password string, useECH, enableFlow, enablePQC, useTrojan bool, serviceName string, echManager *commontls.ECHManager, bootstrapDNS string) (*Transport, error) {
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

	// Initialize bootstrap resolver (DoH over H2)
	bootstrapResolver := dns.NewBootstrapResolver(bootstrapDNS)

	return &Transport{
		serverAddr:          serverAddr,
		serverIP:            serverIP,
		uuidStr:             uuidStr,
		password:            password,
		uuid:                uuid,
		useECH:              useECH,
		enableFlow:          enableFlow,
		enablePQC:           enablePQC,
		useTrojan:           useTrojan,
		serviceName:         serviceName,
		authority:           "",
		idleTimeout:         0,
		healthCheckTimeout:  0,
		permitWithoutStream: false,
		initialWindowSize:   0,
		userAgent:           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
		contentType:         "application/octet-stream",
		echManager:          echManager,
		bootstrapResolver:   bootstrapResolver,
	}, nil
}

func (t *Transport) SetAuthority(authority string) *Transport {
	t.authority = authority
	return t
}

func (t *Transport) SetKeepalive(idleTimeout, healthCheckTimeout time.Duration, permitWithoutStream bool) *Transport {
	t.idleTimeout = idleTimeout
	t.healthCheckTimeout = healthCheckTimeout
	t.permitWithoutStream = permitWithoutStream
	return t
}

func (t *Transport) SetInitialWindowSize(size int32) *Transport {
	t.initialWindowSize = size
	return t
}

func (t *Transport) SetUserAgent(userAgent string) *Transport {
	t.userAgent = userAgent
	return t
}

func (t *Transport) SetContentType(contentType string) *Transport {
	if contentType != "" {
		t.contentType = contentType
	}
	return t
}

func (t *Transport) Name() string {
	var name string
	if t.useTrojan {
		name = "gRPC+Trojan"
	} else if t.enableFlow {
		name = "gRPC+Flow"
	} else {
		name = "gRPC+EWP"
	}
	if t.useECH {
		name += "+ECH"
	} else {
		name += "+TLS"
	}
	return name
}

func (t *Transport) Dial() (transport.TunnelConn, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	addr := net.JoinHostPort(parsed.Host, parsed.Port)
	resolvedIP := t.serverIP
	
	// Resolve serverIP if it's a domain name
	if resolvedIP != "" && !isIPAddress(resolvedIP) {
		log.Printf("[gRPC] Configured serverIP is a domain (%s), resolving...", resolvedIP)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		ips, err := t.bootstrapResolver.LookupIP(ctx, resolvedIP)
		if err != nil {
			log.Printf("[gRPC] Bootstrap DNS resolution failed for serverIP %s: %v", resolvedIP, err)
			return nil, fmt.Errorf("bootstrap DNS resolution failed for serverIP: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
			log.Printf("[gRPC] Bootstrap resolved serverIP %s -> %s", t.serverIP, resolvedIP)
		} else {
			log.Printf("[gRPC] No IPs returned for serverIP %s", t.serverIP)
			return nil, fmt.Errorf("no IPs returned for serverIP %s", t.serverIP)
		}
	}
	
	// If no serverIP specified, resolve using bootstrap resolver (DoH over H2)
	if resolvedIP == "" && !isIPAddress(parsed.Host) {
		log.Printf("[gRPC] Resolving server address: %s", parsed.Host)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		ips, err := t.bootstrapResolver.LookupIP(ctx, parsed.Host)
		if err != nil {
			log.Printf("[gRPC] Bootstrap DNS resolution failed for %s: %v", parsed.Host, err)
			return nil, fmt.Errorf("bootstrap DNS resolution failed: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
			log.Printf("[gRPC] Bootstrap resolved %s -> %s", parsed.Host, resolvedIP)
		} else {
			log.Printf("[gRPC] No IPs returned for %s", parsed.Host)
		}
	} else if isIPAddress(parsed.Host) {
		log.Printf("[gRPC] Server address is already an IP: %s", parsed.Host)
	} else if resolvedIP != "" {
		log.Printf("[gRPC] Using resolved server IP: %s", resolvedIP)
	}
	
	if resolvedIP != "" {
		addr = net.JoinHostPort(resolvedIP, parsed.Port)
		log.Printf("[gRPC] Connecting to: %s (SNI: %s)", addr, parsed.Host)
	} else {
		log.Printf("[gRPC] Connecting to: %s", addr)
	}

	conn, err := t.getOrCreateConn(parsed.Host, addr)
	if err != nil {
		// Check for ECH rejection and retry with updated config
		if t.useECH && t.echManager != nil {
			if echErr := t.handleECHRejection(err); echErr == nil {
				log.Printf("[gRPC] ECH rejected, retrying with updated config...")
				// Retry connection with updated ECH config
				conn, err = t.getOrCreateConn(parsed.Host, addr)
				if err != nil {
					return nil, fmt.Errorf("retry after ECH update failed: %w", err)
				}
			}
		}
		if err != nil {
			return nil, err
		}
	}

	streamPath := "/" + t.serviceName + "/Tunnel"
	streamDesc := &grpc.StreamDesc{
		StreamName:    "Tunnel",
		ServerStreams: true,
		ClientStreams: true,
	}

	stream, err := conn.NewStream(context.Background(), streamDesc, streamPath)
	if err != nil {
		return nil, fmt.Errorf("gRPC stream failed: %w", err)
	}

	return NewConn(conn, stream, t.uuid, t.password, t.enableFlow, t.useTrojan), nil
}

func (t *Transport) getOrCreateConn(host, addr string) (*grpc.ClientConn, error) {
	key := grpcConnKey{
		addr:      addr,
		authority: t.authority,
		useTLS:    true,
		useECH:    t.useECH,
	}

	grpcConnPoolMutex.Lock()
	defer grpcConnPoolMutex.Unlock()

	if conn, found := grpcConnPool[key]; found {
		state := conn.GetState()
		if state != connectivity.Shutdown && state != connectivity.TransientFailure {
			return conn, nil
		}
		conn.Close()
		delete(grpcConnPool, key)
	}

	var opts []grpc.DialOption

	// Use TCP Fast Open for reduced latency
	opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
		return commonnet.DialTFOContext(ctx, "tcp", address, 10*time.Second)
	}))

	opts = append(opts, grpc.WithConnectParams(grpc.ConnectParams{
		Backoff: backoff.Config{
			BaseDelay:  500 * time.Millisecond,
			Multiplier: 1.5,
			Jitter:     0.2,
			MaxDelay:   19 * time.Second,
		},
		MinConnectTimeout: 5 * time.Second,
	}))

	tlsConfig, err := commontls.NewClient(commontls.ClientOptions{
		ServerName: host,
		EnableECH:  t.useECH,
		EnablePQC:  t.enablePQC,
		ECHManager: t.echManager,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	stdConfig, err := tlsConfig.TLSConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get TLS config: %w", err)
	}

	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(stdConfig)))

	if t.authority != "" {
		opts = append(opts, grpc.WithAuthority(t.authority))
	}

	idleTimeout := t.idleTimeout
	if idleTimeout == 0 {
		idleTimeout = 60 * time.Second
	}
	healthCheckTimeout := t.healthCheckTimeout
	if healthCheckTimeout == 0 {
		healthCheckTimeout = 10 * time.Second
	}
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                idleTimeout,
		Timeout:             healthCheckTimeout,
		PermitWithoutStream: true,
	}))

	if t.initialWindowSize > 0 {
		opts = append(opts, grpc.WithInitialWindowSize(t.initialWindowSize))
	} else {
		opts = append(opts, grpc.WithInitialWindowSize(4*1024*1024))
		opts = append(opts, grpc.WithInitialConnWindowSize(4*1024*1024))
	}

	if t.userAgent != "" {
		opts = append(opts, grpc.WithUserAgent(t.userAgent))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("gRPC dial failed: %w", err)
	}

	grpcConnPool[key] = conn
	log.V("[gRPC] New connection: %s", addr)

	return conn, nil
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
		log.Printf("[gRPC] ECH rejection detected but no retry config available")
		return errors.New("no retry config")
	}

	retryList := echRejErr.RetryConfigList()
	if len(retryList) == 0 {
		log.Printf("[gRPC] Server rejected ECH without retry config (secure signal)")
		return errors.New("empty retry config")
	}

	log.Printf("[gRPC] Updating ECH config from server retry (%d bytes)", len(retryList))
	return t.echManager.UpdateFromRetry(retryList)
}
