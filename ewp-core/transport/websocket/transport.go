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

	"github.com/lxzan/gws"
)

type Transport struct {
	serverAddr string
	token      string
	password   string
	uuid       [16]byte
	useECH     bool
	enableFlow bool
	enablePQC  bool
	useTrojan  bool
	path       string
	host       string
	sni        string
	headers    map[string]string
	echManager *commontls.ECHManager
	bypassCfg  *transport.BypassConfig
}

func New(serverAddr, token string, useECH, enableFlow bool, path string, echMgr *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocol(serverAddr, token, "", useECH, enableFlow, false, false, path, echMgr)
}

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

func (t *Transport) Dial() (transport.TunnelConn, error) {
	conn, err := t.dial()
	if err != nil {
		if t.useECH && t.echManager != nil {
			if echErr := t.handleECHRejection(err); echErr == nil {
				log.Printf("[WebSocket] ECH rejected, retrying with updated config...")
				conn, err = t.dial()
				if err != nil {
					return nil, fmt.Errorf("retry after ECH update failed: %w", err)
				}
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return conn, nil
}

func (t *Transport) dial() (transport.TunnelConn, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	serverName := t.sni
	if serverName == "" {
		serverName = parsed.Host
	}

	httpHost := parsed.Host
	if t.host != "" {
		httpHost = t.host
	}

	var resolvedIP string
	if !isIPAddress(parsed.Host) {
		ip, err := transport.ResolveIP(t.bypassCfg, parsed.Host, parsed.Port)
		if err != nil {
			log.Printf("[WebSocket] DNS resolution failed for %s: %v", parsed.Host, err)
			return nil, fmt.Errorf("DNS resolution failed: %w", err)
		}
		resolvedIP = ip
	}

	connectAddr := net.JoinHostPort(parsed.Host, parsed.Port)
	if resolvedIP != "" {
		connectAddr = net.JoinHostPort(resolvedIP, parsed.Port)
	}
	log.V("[WebSocket] Connecting to: %s (SNI: %s)", connectAddr, serverName)

	tlsConfig, err := commontls.NewClient(commontls.ClientOptions{
		ServerName: serverName,
		EnableECH:  t.useECH,
		EnablePQC:  t.enablePQC,
		ECHManager: t.echManager,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS config: %w", err)
	}
	stdConfig, err := tlsConfig.TLSConfig()
	if err != nil {
		return nil, err
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dialCancel()

	var rawConn net.Conn
	if t.bypassCfg != nil && t.bypassCfg.TCPDialer != nil {
		t.bypassCfg.TCPDialer.Timeout = 10 * time.Second
		rawConn, err = t.bypassCfg.TCPDialer.DialContext(dialCtx, "tcp", connectAddr)
	} else {
		rawConn, err = commonnet.DialTFO("tcp", connectAddr, 10*time.Second)
	}
	if err != nil {
		return nil, fmt.Errorf("TCP dial: %w", err)
	}
	log.V("[WebSocket] TCP connected: %s -> %s", rawConn.LocalAddr(), rawConn.RemoteAddr())

	tlsConn := tls.Client(rawConn, stdConfig)
	if deadline, ok := dialCtx.Deadline(); ok {
		tlsConn.SetDeadline(deadline)
	}
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	tlsConn.SetDeadline(time.Time{})
	log.V("[WebSocket] TLS connected: %s (proto: %s)", connectAddr, tlsConn.ConnectionState().NegotiatedProtocol)

	wsURL := fmt.Sprintf("wss://%s:%s%s", httpHost, parsed.Port, t.path)

	reqHeader := http.Header{}
	for k, v := range t.headers {
		reqHeader.Set(k, v)
	}
	if t.useTrojan {
		reqHeader.Set("Sec-WebSocket-Protocol", t.password)
	} else {
		reqHeader.Set("Sec-WebSocket-Protocol", t.token)
	}

	c := newConn(t.uuid, t.password, t.enableFlow, t.useTrojan)

	socket, _, err := gws.NewClientFromConn(c, &gws.ClientOption{
		Addr:           wsURL,
		RequestHeader:  reqHeader,
		ReadBufferSize: 65536,
	}, tlsConn)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("WS upgrade: %w", err)
	}
	c.socket = socket
	go socket.ReadLoop()

	log.V("[WebSocket] Connected to %s", wsURL)
	return c, nil
}

func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) { t.bypassCfg = cfg }

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

func isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

func (t *Transport) handleECHRejection(err error) error {
	if err == nil {
		return errors.New("nil error")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "server rejected ECH") && !strings.Contains(errMsg, "ECH") {
		return errors.New("not ECH rejection")
	}
	var echRejErr interface{ RetryConfigList() []byte }
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
