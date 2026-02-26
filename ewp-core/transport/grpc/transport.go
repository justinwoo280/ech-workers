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
	bypass    bool
}

var (
	grpcConnPool      = make(map[grpcConnKey]*grpc.ClientConn)
	grpcConnPoolMutex sync.Mutex
)

type Transport struct {
	serverAddr          string
	uuidStr             string
	password            string // Trojan password
	uuid                [16]byte
	useECH              bool
	enableFlow          bool
	enablePQC           bool
	useTrojan           bool // Use Trojan protocol
	serviceName         string
	authority           string
	sni                 string
	idleTimeout         time.Duration
	healthCheckTimeout  time.Duration
	permitWithoutStream bool
	initialWindowSize   int32
	userAgent           string
	echManager          *commontls.ECHManager
	bypassCfg           *transport.BypassConfig
}

func New(serverAddr, uuidStr string, useECH, enableFlow bool, serviceName string, echManager *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocol(serverAddr, uuidStr, "", useECH, enableFlow, false, false, serviceName, echManager)
}

func NewWithProtocol(serverAddr, uuidStr, password string, useECH, enableFlow, enablePQC, useTrojan bool, serviceName string, echManager *commontls.ECHManager) (*Transport, error) {
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

	return &Transport{
		serverAddr:          serverAddr,
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
		echManager:          echManager,
	}, nil
}

func (t *Transport) SetAuthority(authority string) *Transport {
	t.authority = authority
	return t
}

func (t *Transport) SetSNI(sni string) *Transport {
	t.sni = sni
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

func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) {
	t.bypassCfg = cfg
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

	// Resolve serverAddr host to IP
	var resolvedIP string
	if !isIPAddress(parsed.Host) {
		ip, err := transport.ResolveIP(t.bypassCfg, parsed.Host, parsed.Port)
		if err != nil {
			log.Printf("[gRPC] DNS resolution failed for %s: %v", parsed.Host, err)
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		resolvedIP = ip
	}

	if resolvedIP != "" {
		addr = net.JoinHostPort(resolvedIP, parsed.Port)
		effectiveSNI := parsed.Host
		if t.sni != "" {
			effectiveSNI = t.sni
		}
		log.Printf("[gRPC] Connecting to: %s (SNI: %s)", addr, effectiveSNI)
	} else {
		log.Printf("[gRPC] Connecting to: %s", addr)
	}

	conn, err := t.getOrCreateConn(parsed.Host, t.sni, addr)
	if err != nil {
		// Check for ECH rejection and retry with updated config
		if t.useECH && t.echManager != nil {
			if echErr := t.handleECHRejection(err); echErr == nil {
				log.Printf("[gRPC] ECH rejected, retrying with updated config...")
				// Retry connection with updated ECH config
				conn, err = t.getOrCreateConn(parsed.Host, t.sni, addr)
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

func (t *Transport) getOrCreateConn(host, sniOverride, addr string) (*grpc.ClientConn, error) {
	if sniOverride != "" {
		host = sniOverride
	}
	key := grpcConnKey{
		addr:      addr,
		authority: t.authority,
		useTLS:    true,
		useECH:    t.useECH,
		bypass:    t.bypassCfg != nil,
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

	// Use bypass dialer in TUN mode to avoid routing loops; else TFO
	opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, address string) (net.Conn, error) {
		if t.bypassCfg != nil && t.bypassCfg.TCPDialer != nil {
			return t.bypassCfg.TCPDialer.DialContext(ctx, "tcp", address)
		}
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

	conn, err := grpc.NewClient(addr, opts...)
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
