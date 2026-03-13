package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sync/singleflight"
)

const (
	defaultInitialPacketSize = 1350

	backoffInitial = 500 * time.Millisecond
	backoffMax     = 30 * time.Second
	backoffMult    = 2
)

// Transport implements transport.Transport over a single QUIC connection.
//
// TCP tunnels use HTTP/3 CONNECT (RFC 9110 §9.3.6).
// UDP tunnels use HTTP/3 Extended CONNECT with :protocol=connect-udp (RFC 9298 / MASQUE).
//
// Both share one QUIC connection; QUIC multiplexes streams and datagrams natively
// so there is no head-of-line blocking between independent flows.
type Transport struct {
	serverAddr   string
	uuid         [16]byte
	sni          string
	useECH       bool
	enablePQC    bool
	useMozillaCA bool
	echManager   *commontls.ECHManager
	udpTemplate  *uritemplate.Template
	bypassCfg    *transport.BypassConfig

	mu          sync.Mutex
	tlsConfig   *tls.Config
	quicConfig  *quic.Config
	quicConn    *quic.Conn
	clientConn  *http3.ClientConn
	h3Transport *http3.Transport // held so it can be closed on reconnect (M-1)

	sfGroup      singleflight.Group
	backoffMu    sync.Mutex
	backoffUntil time.Time
	backoffDelay time.Duration

	// stopCh is closed by Close() to unblock waitBackoff and stop reconnect loops (M-2).
	stopOnce sync.Once
	stopCh   chan struct{}
}

// New creates a MASQUE client transport.
// udpTemplateStr is the RFC 6570 URI template for the UDP proxy endpoint,
// e.g. "https://proxy.example.com/masque/{target_host}/{target_port}".
func New(serverAddr, uuidStr, udpTemplateStr string, useECH, useMozillaCA, enablePQC bool, echManager *commontls.ECHManager) (*Transport, error) {
	uuid, err := transport.ParseUUID(uuidStr)
	if err != nil {
		return nil, fmt.Errorf("masque: invalid UUID: %w", err)
	}

	tmpl, err := uritemplate.New(udpTemplateStr)
	if err != nil {
		return nil, fmt.Errorf("masque: invalid UDP template: %w", err)
	}

	parsed, err := transport.ParseAddress(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("masque: invalid server address: %w", err)
	}

	t := &Transport{
		serverAddr:   net.JoinHostPort(parsed.Host, parsed.Port),
		uuid:         uuid,
		useECH:       useECH,
		useMozillaCA: useMozillaCA,
		enablePQC:    enablePQC,
		echManager:   echManager,
		udpTemplate:  tmpl,
		stopCh:       make(chan struct{}),
	}

	if err := t.initConfigs(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Transport) initConfigs() error {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return fmt.Errorf("masque: parse address: %w", err)
	}

	serverName := t.sni
	if serverName == "" {
		serverName = parsed.Host
	}

	tlsCfg, err := commontls.NewClient(commontls.ClientOptions{
		ServerName:   serverName,
		UseMozillaCA: t.useMozillaCA,
		EnableECH:    t.useECH,
		EnablePQC:    t.enablePQC,
		ECHManager:   t.echManager,
	})
	if err != nil {
		return fmt.Errorf("masque: TLS config: %w", err)
	}

	stdTLS, err := tlsCfg.TLSConfig()
	if err != nil {
		return fmt.Errorf("masque: get TLS config: %w", err)
	}
	stdTLS.NextProtos = []string{http3.NextProtoH3}
	stdTLS.ClientSessionCache = tls.NewLRUClientSessionCache(64)
	t.tlsConfig = stdTLS

	t.quicConfig = &quic.Config{
		MaxIncomingStreams:              1024,
		MaxIncomingUniStreams:           32,
		InitialStreamReceiveWindow:     16 * 1024 * 1024,
		MaxStreamReceiveWindow:         64 * 1024 * 1024,
		InitialConnectionReceiveWindow: 64 * 1024 * 1024,
		MaxConnectionReceiveWindow:     512 * 1024 * 1024,
		MaxIdleTimeout:                 90 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		EnableDatagrams:                true,
		Allow0RTT:                      true,
		InitialPacketSize:              defaultInitialPacketSize,
	}
	return nil
}

// Name returns a human-readable transport name.
func (t *Transport) Name() string {
	name := "MASQUE"
	if t.useECH {
		name += "+ECH"
	}
	if t.enablePQC {
		name += "+PQC"
	}
	return name
}

// SetSNI overrides the TLS SNI.
// If the new TLS config cannot be built, the SNI is reverted and the existing
// connection is kept alive (H-1: prevents silently entering a broken state).
func (t *Transport) SetSNI(sni string) *Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	prev := t.sni
	t.sni = sni
	if err := t.initConfigs(); err != nil {
		log.V("[MASQUE] SetSNI: initConfigs failed (%v), reverting to %q", err, prev)
		t.sni = prev
		_ = t.initConfigs()
		return t
	}
	t.dropConn()
	return t
}

// SetAuthority is an alias for SetSNI (kept for interface parity with other transports).
func (t *Transport) SetAuthority(authority string) *Transport {
	return t.SetSNI(authority)
}

// SetBypassConfig injects a bypass dialer for TUN mode.
func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bypassCfg = cfg
	t.dropConn()
}

// dropConn invalidates the current connection so the next Dial() reconnects.
// Must be called with mu held.
func (t *Transport) dropConn() {
	if t.h3Transport != nil {
		t.h3Transport.Close()
		t.h3Transport = nil
	}
	t.quicConn = nil
	t.clientConn = nil
}

// Close shuts down the transport, unblocking any pending backoff and closing
// the underlying QUIC connection (M-2, M-4).
func (t *Transport) Close() error {
	t.stopOnce.Do(func() { close(t.stopCh) })
	t.mu.Lock()
	defer t.mu.Unlock()
	t.dropConn()
	return nil
}

// Dial returns a TunnelConn backed by an HTTP/3 stream on the shared QUIC connection.
func (t *Transport) Dial() (transport.TunnelConn, error) {
	cc, err := t.getClientConn()
	if err != nil {
		return nil, err
	}
	return newConn(cc, t.uuid, t.udpTemplate), nil
}

// getClientConn returns the live http3.ClientConn, reconnecting if needed.
func (t *Transport) getClientConn() (*http3.ClientConn, error) {
	t.mu.Lock()
	cc := t.clientConn
	t.mu.Unlock()

	if cc != nil {
		select {
		case <-cc.Context().Done():
		default:
			return cc, nil
		}
		log.V("[MASQUE] ClientConn dead, reconnecting")
		t.mu.Lock()
		if t.clientConn == cc {
			t.dropConn()
		}
		t.mu.Unlock()
	}

	if err := t.waitBackoff(); err != nil {
		return nil, err
	}

	v, err, _ := t.sfGroup.Do("connect", func() (interface{}, error) {
		cc, err := t.connect()
		if err != nil {
			t.recordBackoffFailure()
			return nil, err
		}
		t.resetBackoff()
		return cc, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*http3.ClientConn), nil
}

func (t *Transport) connect() (*http3.ClientConn, error) {
	t.mu.Lock()
	tlsConfig := t.tlsConfig
	quicConfig := t.quicConfig
	bypassCfg := t.bypassCfg
	t.mu.Unlock()

	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	host := parsed.Host
	port := parsed.Port

	if !isIPAddress(host) {
		resolved, err := transport.ResolveIP(bypassCfg, host, port)
		if err != nil {
			return nil, fmt.Errorf("masque: DNS resolve %s: %w", host, err)
		}
		log.V("[MASQUE] Resolved %s -> %s", host, resolved)
		host = resolved
	}

	addr := net.JoinHostPort(host, port)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var qconn *quic.Conn
	if bypassCfg != nil && bypassCfg.UDPListenConfig != nil {
		qconn, err = t.bypassDial(ctx, addr, tlsConfig, quicConfig, bypassCfg)
	} else {
		qconn, err = quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	}
	if err != nil {
		return nil, fmt.Errorf("masque: QUIC dial %s: %w", addr, err)
	}

	h3tr := &http3.Transport{EnableDatagrams: true}
	cc := h3tr.NewClientConn(qconn)

	select {
	case <-cc.ReceivedSettings():
	case <-cc.Context().Done():
		h3tr.Close()
		return nil, errors.New("masque: connection closed before settings received")
	case <-ctx.Done():
		h3tr.Close()
		return nil, context.Cause(ctx)
	}

	settings := cc.Settings()
	if !settings.EnableDatagrams {
		h3tr.Close()
		qconn.CloseWithError(0, "")
		return nil, errors.New("masque: server did not enable QUIC datagrams")
	}
	if !settings.EnableExtendedConnect {
		h3tr.Close()
		qconn.CloseWithError(0, "")
		return nil, errors.New("masque: server did not enable Extended CONNECT")
	}

	t.mu.Lock()
	if old := t.h3Transport; old != nil {
		old.Close()
	}
	t.h3Transport = h3tr
	t.quicConn = qconn
	t.clientConn = cc
	t.mu.Unlock()

	log.V("[MASQUE] Connected to %s", t.serverAddr)
	return cc, nil
}

func (t *Transport) bypassDial(ctx context.Context, addr string, tlsCfg *tls.Config, qCfg *quic.Config, cfg *transport.BypassConfig) (*quic.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", addr, err)
	}
	bindAddr := ":0"
	if cfg.LocalIP != nil && udpAddr.IP.To4() != nil {
		bindAddr = net.JoinHostPort(cfg.LocalIP.String(), "0")
	}
	pconn, err := cfg.UDPListenConfig.ListenPacket(ctx, "udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("bind UDP: %w", err)
	}
	qt := &quic.Transport{Conn: pconn}
	conn, err := qt.DialEarly(ctx, udpAddr, tlsCfg, qCfg)
	if err != nil {
		qt.Close()
		return nil, err
	}
	return conn, nil
}

func (t *Transport) waitBackoff() error {
	t.backoffMu.Lock()
	until := t.backoffUntil
	t.backoffMu.Unlock()
	if d := time.Until(until); d > 0 {
		log.V("[MASQUE] Backoff: waiting %v", d.Round(time.Millisecond))
		select {
		case <-time.After(d):
		case <-t.stopCh:
			return errors.New("masque: transport closed")
		}
	}
	return nil
}

func (t *Transport) recordBackoffFailure() {
	t.backoffMu.Lock()
	defer t.backoffMu.Unlock()
	if t.backoffDelay == 0 {
		t.backoffDelay = backoffInitial
	} else {
		t.backoffDelay *= backoffMult
		if t.backoffDelay > backoffMax {
			t.backoffDelay = backoffMax
		}
	}
	t.backoffUntil = time.Now().Add(t.backoffDelay)
}

func (t *Transport) resetBackoff() {
	t.backoffMu.Lock()
	t.backoffDelay = 0
	t.backoffUntil = time.Time{}
	t.backoffMu.Unlock()
}

func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}
