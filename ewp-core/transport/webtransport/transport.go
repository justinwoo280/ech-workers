package webtransport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/quic-go/quic-go"
	wtransport "github.com/quic-go/webtransport-go"
	"golang.org/x/sync/singleflight"
)

// Transport implements transport.Transport over WebTransport (QUIC + HTTP/3 + EWP).
//
// A single QUIC connection (webtransport.Session) is shared across all Dial()
// calls: each Dial() opens a new bidi stream on the existing session.
// When the session breaks it is transparently replaced on the next Dial().
//
// Reconnect storms are prevented via singleflight: only one goroutine performs
// the QUIC handshake at a time; all others wait for the shared result.
// Exponential backoff prevents tight retry loops in TUN mode.
type Transport struct {
	serverAddr   string // "host:port"
	path         string // HTTP path, e.g. "/wt"
	uuid         [16]byte
	password     string
	enableFlow   bool
	useTrojan    bool
	sni          string
	useECH       bool
	enablePQC    bool
	useMozillaCA bool
	echManager   *commontls.ECHManager
	idleTimeout  time.Duration
	bypassCfg    *transport.BypassConfig

	mu         sync.Mutex
	tlsConfig  *tls.Config
	quicConfig *quic.Config
	dialer     *wtransport.Dialer
	sess       *wtransport.Session

	// reconnect serialisation & backoff
	sfGroup       singleflight.Group
	backoffMu     sync.Mutex
	backoffUntil  time.Time
	backoffDelay  time.Duration
}

// New creates a WebTransport client transport.
func New(serverAddr, uuidStr string, useECH, useMozillaCA, enablePQC bool, path string, echManager *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocol(serverAddr, uuidStr, "", useECH, useMozillaCA, false, enablePQC, false, path, echManager)
}

// NewWithProtocol creates a WebTransport client transport with full protocol support.
func NewWithProtocol(serverAddr, uuidStr, password string, useECH, useMozillaCA, enableFlow, enablePQC, useTrojan bool, path string, echManager *commontls.ECHManager) (*Transport, error) {
	var uuid [16]byte
	if !useTrojan {
		var err error
		uuid, err = transport.ParseUUID(uuidStr)
		if err != nil {
			return nil, fmt.Errorf("invalid UUID: %w", err)
		}
	}

	parsed, err := transport.ParseAddress(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	if path == "" {
		if parsed.Path != "" && parsed.Path != "/" {
			path = parsed.Path
		} else {
			path = "/wt"
		}
	}

	addr := net.JoinHostPort(parsed.Host, parsed.Port)

	t := &Transport{
		serverAddr:   addr,
		path:         path,
		uuid:         uuid,
		password:     password,
		enableFlow:   enableFlow,
		useTrojan:    useTrojan,
		useECH:       useECH,
		useMozillaCA: useMozillaCA,
		enablePQC:    enablePQC,
		echManager:   echManager,
		idleTimeout:  30 * time.Second,
	}

	if err := t.initDialer(); err != nil {
		return nil, err
	}
	return t, nil
}

// initDialer builds TLS + QUIC config and creates the webtransport.Dialer.
// Must be called with mu held (or during construction before the Transport escapes).
func (t *Transport) initDialer() error {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return fmt.Errorf("parse server address: %w", err)
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
		return fmt.Errorf("create TLS config: %w", err)
	}

	stdTLS, err := tlsCfg.TLSConfig()
	if err != nil {
		return fmt.Errorf("get TLS config: %w", err)
	}

	stdTLS.NextProtos = []string{"h3"}
	stdTLS.ClientSessionCache = tls.NewLRUClientSessionCache(64)

	t.tlsConfig = stdTLS

	t.quicConfig = &quic.Config{
		InitialStreamReceiveWindow:        6 * 1024 * 1024,
		MaxStreamReceiveWindow:            16 * 1024 * 1024,
		InitialConnectionReceiveWindow:    15 * 1024 * 1024,
		MaxConnectionReceiveWindow:        25 * 1024 * 1024,
		MaxIdleTimeout:                    t.idleTimeout,
		KeepAlivePeriod:                   10 * time.Second,
		EnableDatagrams:                   true, // required by WebTransport spec
		Allow0RTT:                         true,
		EnableStreamResetPartialDelivery:  true,
	}

	d := &wtransport.Dialer{
		TLSClientConfig: t.tlsConfig,
		QUICConfig:      t.quicConfig,
	}

	if t.bypassCfg != nil && t.bypassCfg.UDPListenConfig != nil {
		d.DialAddr = t.makeBypassDial(t.bypassCfg.UDPListenConfig, t.bypassCfg.LocalIP)
	}

	t.dialer = d
	return nil
}

// makeBypassDial returns a DialAddr function that binds the QUIC UDP socket
// to the physical network interface, bypassing the TUN routing table.
//
// On Windows, IP_UNICAST_IF alone is unreliable for unicast when the TUN
// default route has a lower metric. Binding to the physical interface's
// local IP (e.g. 192.168.0.100:0) guarantees the kernel routes the packet
// through the NIC that owns that address, not through the TUN device.
func (t *Transport) makeBypassDial(lc *net.ListenConfig, localIP net.IP) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return nil, fmt.Errorf("bypass dial: resolve %s: %w", addr, err)
		}
		bindAddr := ":0"
		if localIP != nil && udpAddr.IP.To4() != nil {
			bindAddr = net.JoinHostPort(localIP.String(), "0")
		}
		pconn, err := lc.ListenPacket(ctx, "udp", bindAddr)
		if err != nil {
			return nil, fmt.Errorf("bypass dial: bind UDP: %w", err)
		}
		qt := &quic.Transport{Conn: pconn}
		conn, err := qt.DialEarly(ctx, udpAddr, tlsCfg, cfg)
		if err != nil {
			qt.Close()
			return nil, fmt.Errorf("bypass dial: QUIC: %w", err)
		}
		return conn, nil
	}
}

// Name returns a descriptive transport name.
func (t *Transport) Name() string {
	name := "WebTransport"
	if t.useTrojan {
		name += "+Trojan"
	} else if t.enableFlow {
		name += "+Flow"
	} else {
		name += "+EWP"
	}
	if t.useECH {
		name += "+ECH"
	}
	if t.enablePQC {
		name += "+PQC"
	}
	return name
}

// SetAuthority sets the :authority pseudo-header and HTTP Host header override
func (t *Transport) SetAuthority(authority string) *Transport {
	t.mu.Lock()
	t.sni = authority // In WebTransport, we use SNI to influence Host override as well.
	t.reinitDialer()
	t.mu.Unlock()
	return t
}

// SetSNI overrides the TLS SNI (useful when connecting via IP with CDN domain).
func (t *Transport) SetSNI(sni string) *Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sni = sni
	t.reinitDialer()
	return t
}

// SetIdleTimeout sets the QUIC connection idle timeout.
func (t *Transport) SetIdleTimeout(d time.Duration) *Transport {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.idleTimeout = d
	if t.quicConfig != nil {
		t.quicConfig.MaxIdleTimeout = d
	}
	return t
}

// SetBypassConfig injects a bypass dialer for TUN mode.
func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.bypassCfg = cfg
	t.reinitDialer()
}

// reinitDialer must be called with mu held.
func (t *Transport) reinitDialer() {
	// Invalidate current session so next Dial() reconnects with new settings.
	t.sess = nil
	if err := t.initDialer(); err != nil {
		log.Printf("[WebTransport] Failed to reinit dialer: %v", err)
	}
}

// Dial opens a new bidi stream on the shared WebTransport session,
// reconnecting transparently if the session has died.
func (t *Transport) Dial() (transport.TunnelConn, error) {
	stream, err := t.openStream()
	if err != nil {
		return nil, err
	}
	return newConn(stream, t.uuid, t.password, t.enableFlow, t.useTrojan), nil
}

func (t *Transport) openStream() (*wtransport.Stream, error) {
	// Fast path: use the existing live session.
	t.mu.Lock()
	sess := t.sess
	t.mu.Unlock()

	if sess != nil {
		stream, err := sess.OpenStreamSync(context.Background())
		if err == nil {
			return stream, nil
		}
		log.V("[WebTransport] Session broken (%v), reconnecting", err)
		// Only nil out sess if it's still the one we observed (avoid clobbering
		// a session that another goroutine already replaced).
		t.mu.Lock()
		if t.sess == sess {
			t.sess = nil
		}
		t.mu.Unlock()
	}

	// Check backoff before attempting to reconnect.
	if err := t.waitBackoff(); err != nil {
		return nil, err
	}

	// Singleflight: only one goroutine initiates the QUIC handshake at a time.
	// All concurrent callers share the single result (success or error).
	v, err, _ := t.sfGroup.Do("connect", func() (interface{}, error) {
		s, err := t.connect()
		if err != nil {
			t.recordBackoffFailure()
			return nil, err
		}
		t.resetBackoff()
		return s, nil
	})
	if err != nil {
		return nil, err
	}

	sess = v.(*wtransport.Session)
	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		return nil, fmt.Errorf("open stream after reconnect: %w", err)
	}
	return stream, nil
}

const (
	backoffInitial = 500 * time.Millisecond
	backoffMax     = 30 * time.Second
	backoffMult    = 2
)

// waitBackoff blocks until the current backoff window expires.
// Returns an error only if the context is cancelled (future: ctx propagation).
func (t *Transport) waitBackoff() error {
	t.backoffMu.Lock()
	until := t.backoffUntil
	t.backoffMu.Unlock()

	if d := time.Until(until); d > 0 {
		log.V("[WebTransport] Backoff: waiting %v before reconnect", d.Round(time.Millisecond))
		time.Sleep(d)
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
	log.V("[WebTransport] Backoff: next retry in %v", t.backoffDelay)
}

func (t *Transport) resetBackoff() {
	t.backoffMu.Lock()
	t.backoffDelay = 0
	t.backoffUntil = time.Time{}
	t.backoffMu.Unlock()
}

func (t *Transport) connect() (*wtransport.Session, error) {
	t.mu.Lock()
	dialer := t.dialer
	t.mu.Unlock()

	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	// Resolve hostname to IP (avoids TUN routing loops and picks best edge node).
	host := parsed.Host
	port := parsed.Port
	if !isIPAddress(host) {
		resolved, err := transport.ResolveIP(t.bypassCfg, host, port)
		if err != nil {
			log.Printf("[WebTransport] DNS resolve failed for %s: %v", host, err)
			return nil, fmt.Errorf("DNS resolve: %w", err)
		}
		log.V("[WebTransport] Resolved %s -> %s", host, resolved)
		host = resolved
	}

	// Build the WebTransport URL. Use the original hostname as authority so
	// TLS SNI and virtual hosting work correctly even when connecting via IP.
	authority := net.JoinHostPort(parsed.Host, port)
	connectAddr := fmt.Sprintf("https://%s%s", authority, t.path)
	if host != parsed.Host {
		// Override Host header with the authority (original domain) while
		// connecting to the resolved IP.
		connectAddr = fmt.Sprintf("https://%s%s", net.JoinHostPort(host, port), t.path)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	hdr := http.Header{}
	if host != parsed.Host {
		hdr.Set("Host", authority)
	}

	log.V("[WebTransport] Connecting to %s (path: %s)", connectAddr, t.path)
	_, sess, err := dialer.Dial(ctx, connectAddr, hdr)
	if err != nil {
		// Handle ECH rejection: update key and retry once.
		if retryErr := t.handleECHRejection(err); retryErr == nil {
			t.mu.Lock()
			dialer = t.dialer
			t.mu.Unlock()
			ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel2()
			_, sess, err = dialer.Dial(ctx2, connectAddr, hdr)
		}
		if err != nil {
			return nil, fmt.Errorf("webtransport dial: %w", err)
		}
	}

	t.mu.Lock()
	t.sess = sess
	t.mu.Unlock()

	log.V("[WebTransport] Session established to %s", t.serverAddr)
	return sess, nil
}

// handleECHRejection extracts the server's ECH retry config, updates the
// ECH manager, and rebuilds the dialer.  Returns nil on success (caller retries).
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
		log.Printf("[WebTransport] ECH rejected with empty retry list")
		return errors.New("empty retry config")
	}

	log.Printf("[WebTransport] ECH rejected; updating config (%d bytes)", len(retryList))

	if err := t.echManager.UpdateFromRetry(retryList); err != nil {
		return fmt.Errorf("update ECH config: %w", err)
	}

	t.mu.Lock()
	t.reinitDialer()
	t.mu.Unlock()

	log.Printf("[WebTransport] ECH config updated; retrying")
	return nil
}

// isIPAddress reports whether s is a valid IP address (not a hostname).
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}
