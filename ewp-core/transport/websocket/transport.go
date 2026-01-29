package websocket

import (
	"fmt"
	"net"
	"net/http"
	"time"

	commonnet "ewp-core/common/net"
	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/gorilla/websocket"
)

// Transport implements WebSocket transport
type Transport struct {
	serverAddr  string
	serverIP    string
	token       string
	password    string  // Trojan password
	uuid        [16]byte
	useECH      bool
	enableFlow  bool
	enablePQC   bool
	useTrojan   bool    // Use Trojan protocol instead of EWP
	path        string
	host        string
	headers     map[string]string
	echManager  *commontls.ECHManager
}

// New creates a new WebSocket transport
func New(serverAddr, serverIP, token string, useECH, enableFlow bool, path string, echMgr *commontls.ECHManager) *Transport {
	return NewWithProtocol(serverAddr, serverIP, token, "", useECH, enableFlow, false, false, path, echMgr)
}

// NewWithProtocol creates a new WebSocket transport with protocol selection
func NewWithProtocol(serverAddr, serverIP, token, password string, useECH, enableFlow, enablePQC, useTrojan bool, path string, echMgr *commontls.ECHManager) *Transport {
	var uuid [16]byte
	if !useTrojan {
		var err error
		uuid, err = transport.ParseUUID(token)
		if err != nil {
			log.Warn("Failed to parse UUID, using token as-is: %v", err)
		}
	}

	if path == "" {
		path = "/"
	}

	return &Transport{
		serverAddr: serverAddr,
		serverIP:   serverIP,
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
	}
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

	// Build TLS config using interface abstraction
	tlsConfig, err := commontls.NewClient(commontls.ClientOptions{
		ServerName: parsed.Host,
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

	// Configure dialer with TCP Fast Open support
	dialer := websocket.Dialer{
		TLSClientConfig:  stdConfig,
		HandshakeTimeout: 10 * time.Second,
		NetDial: func(network, address string) (net.Conn, error) {
			// Use custom server IP if provided
			if t.serverIP != "" {
				_, p, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				address = net.JoinHostPort(t.serverIP, p)
			}
			// Use TCP Fast Open for reduced latency
			return commonnet.DialTFO(network, address, 10*time.Second)
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

	// Connect
	wsConn, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		return nil, err
	}

	log.V("[WebSocket] Connected to %s", wsURL)

	// Return connection based on protocol configuration
	if t.useTrojan {
		return NewTrojanConn(wsConn, t.password), nil
	}
	if t.enableFlow {
		return NewFlowConn(wsConn, t.uuid), nil
	}
	return NewSimpleConn(wsConn, t.token), nil
}
