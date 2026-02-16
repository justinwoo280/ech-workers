package websocket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	commonnet "ewp-core/common/net"
	commontls "ewp-core/common/tls"
	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/gorilla/websocket"
)

// Transport implements WebSocket transport
type Transport struct {
	serverAddr        string
	serverIP          string
	token             string
	password          string  // Trojan password
	uuid              [16]byte
	useECH            bool
	enableFlow        bool
	enablePQC         bool
	useTrojan         bool    // Use Trojan protocol instead of EWP
	path              string
	host              string
	headers           map[string]string
	echManager        *commontls.ECHManager
	bootstrapResolver *dns.BootstrapResolver
}

// New creates a new WebSocket transport
func New(serverAddr, serverIP, token string, useECH, enableFlow bool, path string, echMgr *commontls.ECHManager) (*Transport, error) {
	return NewWithProtocol(serverAddr, serverIP, token, "", useECH, enableFlow, false, false, path, echMgr)
}

// NewWithProtocol creates a new WebSocket transport with protocol selection
func NewWithProtocol(serverAddr, serverIP, token, password string, useECH, enableFlow, enablePQC, useTrojan bool, path string, echMgr *commontls.ECHManager) (*Transport, error) {
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

	// Initialize bootstrap resolver (DoH over H2)
	bootstrapResolver := dns.NewBootstrapResolver("")

	return &Transport{
		serverAddr:        serverAddr,
		serverIP:          serverIP,
		token:             token,
		password:          password,
		uuid:              uuid,
		useECH:            useECH,
		enableFlow:        enableFlow,
		enablePQC:         enablePQC,
		useTrojan:         useTrojan,
		path:              path,
		headers:           make(map[string]string),
		echManager:        echMgr,
		bootstrapResolver: bootstrapResolver,
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

	// Resolve serverIP if it's a domain name
	resolvedIP := t.serverIP
	if resolvedIP != "" && !isIPAddress(resolvedIP) {
		log.Printf("[WebSocket] Configured serverIP is a domain (%s), resolving...", resolvedIP)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		ips, err := t.bootstrapResolver.LookupIP(ctx, resolvedIP)
		if err != nil {
			log.Printf("[WebSocket] Bootstrap DNS resolution failed for serverIP %s: %v", resolvedIP, err)
			return nil, fmt.Errorf("bootstrap DNS resolution failed for serverIP: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
			log.Printf("[WebSocket] Bootstrap resolved serverIP %s -> %s", t.serverIP, resolvedIP)
		} else {
			log.Printf("[WebSocket] No IPs returned for serverIP %s", t.serverIP)
			return nil, fmt.Errorf("no IPs returned for serverIP %s", t.serverIP)
		}
	}

	// If no serverIP, resolve serverAddr
	if resolvedIP == "" && !isIPAddress(parsed.Host) {
		log.Printf("[WebSocket] Resolving server address: %s", parsed.Host)
		
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		
		ips, err := t.bootstrapResolver.LookupIP(ctx, parsed.Host)
		if err != nil {
			log.Printf("[WebSocket] Bootstrap DNS resolution failed for %s: %v", parsed.Host, err)
			return nil, fmt.Errorf("bootstrap DNS resolution failed: %w", err)
		}
		if len(ips) > 0 {
			resolvedIP = ips[0].String()
			log.Printf("[WebSocket] Bootstrap resolved %s -> %s", parsed.Host, resolvedIP)
		}
	}

	// Configure dialer with TCP Fast Open support
	dialer := websocket.Dialer{
		TLSClientConfig:  stdConfig,
		HandshakeTimeout: 10 * time.Second,
		NetDial: func(network, address string) (net.Conn, error) {
			// Use resolved IP if available
			if resolvedIP != "" {
				_, p, err := net.SplitHostPort(address)
				if err != nil {
					return nil, err
				}
				address = net.JoinHostPort(resolvedIP, p)
				log.Printf("[WebSocket] Connecting to: %s (SNI: %s)", address, parsed.Host)
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
		// Check for ECH rejection and retry with updated config
		if t.useECH && t.echManager != nil {
			if echErr := t.handleECHRejection(err); echErr == nil {
				log.Printf("[WebSocket] ECH rejected, retrying with updated config...")
				// Retry connection with updated ECH config
				wsConn, _, err = dialer.Dial(wsURL, headers)
				if err != nil {
					return nil, fmt.Errorf("retry after ECH update failed: %w", err)
				}
			}
		}
		if err != nil {
			return nil, err
		}
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

func (t *Transport) SetHost(host string) *Transport {
	t.host = host
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
