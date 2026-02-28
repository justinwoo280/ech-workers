package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	commonnet "ewp-core/common/net"
	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/gorilla/websocket"
)

// Transport implements WebSocket transport
type Transport struct {
	serverAddr string
	token      string
	password   string // Trojan password
	uuid       [16]byte
	useECH     bool
	enableFlow bool
	enablePQC  bool
	useTrojan  bool // Use Trojan protocol instead of EWP
	path       string
	host       string
	sni        string
	headers    map[string]string
	echManager *commontls.ECHManager
	bypassCfg  *transport.BypassConfig
}

// New creates a new WebSocket transport
func New(serverAddr, token string, useECH, enableFlow bool, path string, echMgr *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocol(serverAddr, token, "", useECH, enableFlow, false, false, path, echMgr)
}

// NewWithProtocol creates a new WebSocket transport with protocol selection
func NewWithProtocol(serverAddr, token, password string, useECH, enableFlow, enablePQC, useTrojan bool, path string, echMgr *commontls.ECHManager) (*Transport, error) {
	var uuid [16]byte
	if !useTrojan {
		var err error
		uuid, err = transport.ParseUUID(token)
		if err != nil {
			return nil, fmt.Errorf("invalid UUID: %w", err)
		}
	}

	if path == "" {
		path = "/"
	}

	return &Transport{
		serverAddr: serverAddr,
		token:      token,
		password:   password,
		uuid:       uuid,
		useECH:     useECH,
		enableFlow: enableFlow,
		enablePQC:  enablePQC,
		useTrojan:  useTrojan,
		path:       path,
		headers:    make(map[string]string),
		echManager: echMgr,
	}, nil
}

// Name returns transport name
func (t *Transport) Name() string {
	name := "WebSocket"
	if t.useTrojan {
		name += "+Trojan"
	} else if t.enableFlow {
		name += "+Vision"
	} else {
		name += "+EWP"
	}
	if t.useECH {
		name += "+ECH"
	} else {
		name += "+TLS"
	}
	return name
}

// Dial establishes a WebSocket connection
func (t *Transport) Dial() (transport.TunnelConn, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	wsURL := fmt.Sprintf("wss://%s:%s%s", parsed.Host, parsed.Port, t.path)

	// SNI: explicit override → server host fallback
	serverName := t.sni
	if serverName == "" {
		serverName = parsed.Host
	}

	// Build TLS config using interface abstraction
	tlsConfig, err := commontls.NewClient(commontls.ClientOptions{
		ServerName: serverName,
		EnableECH:  t.useECH,
		EnablePQC:  t.enablePQC,
		ECHManager: t.echManager,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}

	stdConfig, err := tlsConfig.TLSConfig()
	if err != nil {
		return nil, err
	}

	// Resolve serverAddr host to IP
	var resolvedIP string
	if !isIPAddress(parsed.Host) {
		ip, err := transport.ResolveIP(t.bypassCfg, parsed.Host, parsed.Port)
		if err != nil {
			log.Printf("[WebSocket] DNS resolution failed for %s: %v", parsed.Host, err)
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		resolvedIP = ip
	}

	// Configure dialer — use NetDialTLSContext for explicit TLS control.
	// gorilla/websocket's HandshakeTimeout does NOT properly enforce deadlines
	// when using custom NetDial, causing TLS handshake to hang indefinitely
	// in TUN mode. By using NetDialTLSContext we manually control both TCP
	// dial and TLS handshake with proper context-based timeouts.
	dialer := websocket.Dialer{
		// Do NOT set TLSClientConfig — we handle TLS manually in NetDialTLSContext.
		// Do NOT set HandshakeTimeout — we use context timeout instead.
		NetDialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if resolvedIP != "" {
				_, p, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				address = net.JoinHostPort(resolvedIP, p)
			}
			log.Printf("[WebSocket] Connecting to: %s (SNI: %s)", address, serverName)

			// Phase 1: TCP connect (bypass dialer with timeout)
			var rawConn net.Conn
			var dialErr error
			if t.bypassCfg != nil && t.bypassCfg.TCPDialer != nil {
				t.bypassCfg.TCPDialer.Timeout = 10 * time.Second
				rawConn, dialErr = t.bypassCfg.TCPDialer.DialContext(ctx, network, address)
			} else {
				rawConn, dialErr = commonnet.DialTFO(network, address, 10*time.Second)
			}
			if dialErr != nil {
				log.Printf("[WebSocket] TCP dial failed: %s -> %v", address, dialErr)
				return nil, dialErr
			}
			log.Printf("[WebSocket] TCP connected: %s -> %s", rawConn.LocalAddr(), rawConn.RemoteAddr())

			// Phase 2: TLS handshake (with context deadline enforcement)
			tlsConn := tls.Client(rawConn, stdConfig)
			if deadline, ok := ctx.Deadline(); ok {
				tlsConn.SetDeadline(deadline)
			}
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				rawConn.Close()
				log.Printf("[WebSocket] TLS handshake failed: %s -> %v", address, err)
				return nil, err
			}
			// Clear deadline so it doesn't affect subsequent reads/writes
			tlsConn.SetDeadline(time.Time{})
			log.Printf("[WebSocket] TLS connected: %s (proto: %s)", address, tlsConn.ConnectionState().NegotiatedProtocol)
			return tlsConn, nil
		},
	}

	// Set headers
	headers := http.Header{}
	if t.host != "" {
		headers.Set("Host", t.host)
	}
	for k, v := range t.headers {
		headers.Set(k, v)
	}

	// Sec-WebSocket-Protocol: server uses this for authentication.
	// EWP mode: UUID string; Trojan mode: password string.
	if t.useTrojan {
		dialer.Subprotocols = []string{t.password}
	} else {
		dialer.Subprotocols = []string{t.token}
	}

	// Connect with hard context timeout (TCP + TLS + HTTP upgrade must all complete)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	wsConn, resp, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		if resp != nil {
			log.Printf("[WebSocket] Upgrade failed: %v (HTTP %d)", err, resp.StatusCode)
		} else {
			log.Printf("[WebSocket] Dial failed: %v", err)
		}
		// Check for ECH rejection and retry with updated config
		if t.useECH && t.echManager != nil {
			if echErr := t.handleECHRejection(err); echErr == nil {
				log.Printf("[WebSocket] ECH rejected, retrying with updated config...")
				ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel2()
				wsConn, _, err = dialer.DialContext(ctx2, wsURL, headers)
				if err != nil {
					return nil, fmt.Errorf("retry after ECH update failed: %w", err)
				}
			}
		}
		if err != nil {
			return nil, err
		}
	}

	log.Printf("[WebSocket] Connected to %s", wsURL)

	// Return connection based on protocol configuration
	if t.useTrojan {
		return NewTrojanConn(wsConn, t.password), nil
	}
	if t.enableFlow {
		return NewFlowConn(wsConn, t.uuid), nil
	}
	return NewSimpleConnWithUUID(wsConn, t.uuid), nil
}

func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) {
	t.bypassCfg = cfg
}

func (t *Transport) SetHost(host string) *Transport {
	t.host = host
	return t
}

func (t *Transport) SetSNI(sni string) *Transport {
	t.sni = sni
	return t
}

func (t *Transport) SetHeaders(headers map[string]string) *Transport {
	t.headers = headers
	return t
}

// isIPAddress checks if a string is an IP address
func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// handleECHRejection checks if error is ECH rejection and updates config
func (t *Transport) handleECHRejection(err error) error {
	if err == nil {
		return errors.New("nil error")
	}

	var echRejErr interface{ RetryConfigList() []byte }
	errMsg := err.Error()
	if !strings.Contains(errMsg, "server rejected ECH") && !strings.Contains(errMsg, "ECH") {
		return errors.New("not ECH rejection")
	}

	cause := err
	for cause != nil {
		if rejErr, ok := cause.(interface{ RetryConfigList() []byte }); ok {
			echRejErr = rejErr
			break
		}
		unwrapped := errors.Unwrap(cause)
		if unwrapped == nil {
			break
		}
		cause = unwrapped
	}

	if echRejErr == nil {
		log.Printf("[WebSocket] ECH rejection detected but no retry config available")
		return errors.New("no retry config")
	}

	retryList := echRejErr.RetryConfigList()
	if len(retryList) == 0 {
		log.Printf("[WebSocket] Server rejected ECH without retry config (secure signal)")
		return errors.New("empty retry config")
	}

	log.Printf("[WebSocket] Updating ECH config from server retry (%d bytes)", len(retryList))
	return t.echManager.UpdateFromRetry(retryList)
}
