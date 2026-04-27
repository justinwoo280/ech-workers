// Package grpc is the gRPC-over-TLS outer transport for EWP v2.
// One SocketData proto on the wire = one v2 outer message.
package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"ewp-core/common/clientdns"
	commontls "ewp-core/common/tls"
	pb "ewp-core/proto"
	"ewp-core/transport"
)

type connPoolKey struct {
	host string
	sni  string
	ech  bool
}

// Transport implements transport.Transport for gRPC-over-TLS.
type Transport struct {
	serverAddr  string
	serviceName string

	useECH       bool
	useMozillaCA bool
	enablePQC    bool
	echManager   *commontls.ECHManager

	sni  string
	host string

	mu        sync.Mutex
	pool      map[connPoolKey]*grpc.ClientConn
	bypassCfg *transport.BypassConfig
	resolver  *clientdns.Resolver
}

// SetClientResolver wires the privacy-preserving DoH resolver used to
// translate the EWP server's domain name to an IP at Dial time.
func (t *Transport) SetClientResolver(r *clientdns.Resolver) {
	t.mu.Lock()
	t.resolver = r
	// Drop pooled conns — they were dialed with possibly a different
	// resolver (or none); a fresh one might pick a different IP.
	for k, c := range t.pool {
		_ = c.Close()
		delete(t.pool, k)
	}
	t.mu.Unlock()
}

// New constructs a v2 gRPC transport. serviceName is the service name
// of the proxy gRPC service (kept for protocol/path stability).
func New(serverAddr, serviceName string, useECH, useMozillaCA, enablePQC bool, echManager *commontls.ECHManager) *Transport {
	if serviceName == "" {
		serviceName = "ProxyService"
	}
	return &Transport{
		serverAddr:   serverAddr,
		serviceName:  serviceName,
		useECH:       useECH,
		useMozillaCA: useMozillaCA,
		enablePQC:    enablePQC,
		echManager:   echManager,
		pool:         make(map[connPoolKey]*grpc.ClientConn),
	}
}

func (t *Transport) Name() string { return "grpc" }

func (t *Transport) SetSNI(sni string)   { t.sni = sni }
func (t *Transport) SetHost(host string) { t.host = host }

func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) {
	t.mu.Lock()
	t.bypassCfg = cfg
	t.mu.Unlock()
}

func (t *Transport) bypass() *transport.BypassConfig {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bypassCfg
}

// Dial opens a new gRPC streaming RPC and returns a v2 TunnelConn.
func (t *Transport) Dial() (transport.TunnelConn, error) {
	host, port, err := net.SplitHostPort(t.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("grpc: bad serverAddr %q: %w", t.serverAddr, err)
	}
	sni := t.sni
	if sni == "" {
		sni = host
	}

	clientConn, err := t.getOrDialPool(host, port, sni)
	if err != nil {
		// One ECH retry: evict and re-dial.
		if t.useECH {
			t.evictPool(host, sni)
			clientConn, err = t.getOrDialPool(host, port, sni)
		}
		if err != nil {
			return nil, fmt.Errorf("grpc: dial: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	streamDesc := &grpc.StreamDesc{
		StreamName:    "Tunnel",
		ServerStreams: true,
		ClientStreams: true,
	}
	method := fmt.Sprintf("/%s/Tunnel", t.serviceName)
	stream, err := clientConn.NewStream(ctx, streamDesc, method)
	if err != nil {
		cancel()
		t.evictPool(host, sni)
		return nil, fmt.Errorf("grpc: new stream: %w", err)
	}
	_ = pb.SocketData{} // ensure proto import is used
	return newConn(stream, cancel), nil
}

func (t *Transport) getOrDialPool(host, port, sni string) (*grpc.ClientConn, error) {
	key := connPoolKey{host: host, sni: sni, ech: t.useECH}
	t.mu.Lock()
	if c, ok := t.pool[key]; ok {
		t.mu.Unlock()
		return c, nil
	}
	t.mu.Unlock()

	cfg, err := commontls.NewSTDConfig(sni, t.useMozillaCA, t.enablePQC)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}
	tlsCfg.NextProtos = []string{"h2"}
	if t.useECH && t.echManager != nil {
		echList, err := t.echManager.Get()
		if err != nil {
			return nil, err
		}
		tlsCfg.EncryptedClientHelloConfigList = echList
		tlsCfg.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
			return errors.New("server rejected ECH")
		}
	}
	creds := credentials.NewTLS(tlsCfg)

	dialer := func(ctx context.Context, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
		if bp := t.bypass(); bp != nil && bp.TCPDialer != nil {
			d = bp.TCPDialer
		}
		t.mu.Lock()
		resolver := t.resolver
		t.mu.Unlock()
		if resolver != nil {
			resolved, rerr := resolver.ResolveHostPort(ctx, addr)
			if rerr != nil {
				return nil, fmt.Errorf("grpc: client dns: %w", rerr)
			}
			addr = resolved
		}
		return d.DialContext(ctx, "tcp", addr)
	}

	conn, err := grpc.NewClient(
		net.JoinHostPort(host, port),
		grpc.WithTransportCredentials(creds),
		grpc.WithContextDialer(dialer),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   5 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
	)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.pool[key] = conn
	t.mu.Unlock()
	return conn, nil
}

func (t *Transport) evictPool(host, sni string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, c := range t.pool {
		if k.host == host && k.sni == sni {
			_ = c.Close()
			delete(t.pool, k)
		}
	}
}

var _ transport.Transport = (*Transport)(nil)
