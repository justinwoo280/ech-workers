package grpc

import (
	"context"
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
	echManager          *commontls.ECHManager
}

func New(serverAddr, serverIP, uuidStr string, useECH, enableFlow bool, serviceName string, echManager *commontls.ECHManager) *Transport {
	return NewWithProtocol(serverAddr, serverIP, uuidStr, "", useECH, enableFlow, false, false, serviceName, echManager)
}

func NewWithProtocol(serverAddr, serverIP, uuidStr, password string, useECH, enableFlow, enablePQC, useTrojan bool, serviceName string, echManager *commontls.ECHManager) *Transport {
	var uuid [16]byte
	if !useTrojan {
		var err error
		uuid, err = transport.ParseUUID(uuidStr)
		if err != nil {
			log.Printf("[gRPC] Unable to parse UUID: %v", err)
		}
	}

	if serviceName == "" {
		serviceName = "ProxyService"
	}
	serviceName = strings.TrimPrefix(serviceName, "/")

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
		userAgent:           "",
		echManager:          echManager,
	}
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
	if t.serverIP != "" {
		addr = net.JoinHostPort(t.serverIP, parsed.Port)
	}

	conn, err := t.getOrCreateConn(parsed.Host, addr)
	if err != nil {
		return nil, err
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
