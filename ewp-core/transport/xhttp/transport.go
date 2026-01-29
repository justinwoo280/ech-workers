package xhttp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	commonnet "ewp-core/common/net"
	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"

	"golang.org/x/net/http2"
	"net/http"
)

type Transport struct {
	serverAddr string
	serverIP   string
	token      string
	password   string  // Trojan password
	uuid       [16]byte
	uuidStr    string
	useECH     bool
	enableFlow bool
	enablePQC  bool
	useTrojan  bool    // Use Trojan protocol
	path       string
	paddingMin int
	paddingMax int
	mode       string
	echManager *commontls.ECHManager
}

func New(serverAddr, serverIP, token string, useECH, enableFlow bool, path string, echManager *commontls.ECHManager) *Transport {
	return NewWithProtocol(serverAddr, serverIP, token, "", useECH, enableFlow, false, false, path, echManager)
}

func NewWithProtocol(serverAddr, serverIP, token, password string, useECH, enableFlow, enablePQC, useTrojan bool, path string, echManager *commontls.ECHManager) *Transport {
	var uuid [16]byte
	if !useTrojan {
		var err error
		uuid, err = transport.ParseUUID(token)
		if err != nil {
			log.Printf("[XHTTP] Unable to parse UUID: %v", err)
		}
	}

	if path == "" {
		path = "/xhttp"
	}

	return &Transport{
		serverAddr: serverAddr,
		serverIP:   serverIP,
		token:      token,
		password:   password,
		uuid:       uuid,
		uuidStr:    token,
		useECH:     useECH,
		enableFlow: enableFlow,
		enablePQC:  enablePQC,
		useTrojan:  useTrojan,
		path:       path,
		paddingMin: 100,
		paddingMax: 1000,
		mode:       "stream-one",
		echManager: echManager,
	}
}

func (t *Transport) SetMode(mode string) *Transport {
	t.mode = mode
	return t
}

func (t *Transport) SetPaddingRange(min, max int) *Transport {
	t.paddingMin = min
	t.paddingMax = max
	return t
}

func (t *Transport) Name() string {
	name := "XHTTP"
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
	if t.mode == "stream-down" {
		return t.dialStreamDown()
	}
	return t.dialStreamOne()
}

func (t *Transport) createHTTPClient(host, port string) (*http.Client, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

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
		return nil, fmt.Errorf("failed to get TLS config: %w", err)
	}

	stdConfig.NextProtos = []string{"h2"}

	target := net.JoinHostPort(host, port)
	if t.serverIP != "" {
		target = net.JoinHostPort(t.serverIP, port)
	}

	h2Transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			// Use TCP Fast Open for reduced latency
			rawConn, err := commonnet.DialTFOContext(ctx, "tcp", target, 10*time.Second)
			if err != nil {
				return nil, err
			}
			return tls.Client(rawConn, stdConfig), nil
		},
		IdleConnTimeout:            90 * time.Second,
		ReadIdleTimeout:            30 * time.Second,
		StrictMaxConcurrentStreams: true,
	}

	return &http.Client{
		Transport: h2Transport,
		Timeout:   0,
	}, nil
}

func (t *Transport) dialStreamOne() (transport.TunnelConn, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	httpClient, err := t.createHTTPClient(parsed.Host, parsed.Port)
	if err != nil {
		return nil, err
	}

	log.V("[XHTTP] HTTP/2 transport ready for %s", parsed.Host)

	return NewStreamOneConn(
		httpClient,
		parsed.Host,
		parsed.Port,
		t.path,
		t.uuid,
		t.uuidStr,
		t.password,
		t.enableFlow,
		t.useTrojan,
		t.paddingMin,
		t.paddingMax,
	), nil
}

func (t *Transport) dialStreamDown() (transport.TunnelConn, error) {
	parsed, err := transport.ParseAddress(t.serverAddr)
	if err != nil {
		return nil, err
	}

	httpClient, err := t.createHTTPClient(parsed.Host, parsed.Port)
	if err != nil {
		return nil, err
	}

	return NewStreamDownConn(
		httpClient,
		parsed.Host,
		parsed.Port,
		t.path,
		t.uuid,
		t.uuidStr,
		t.password,
		t.enableFlow,
		t.useTrojan,
		t.paddingMin,
		t.paddingMax,
	), nil
}
