// Package xhttp carries v2 outer messages over HTTP/1.1 stream-one
// (one long POST per Dial: req body = uplink, resp body = downlink).
// Each leg is framed with a 4-byte big-endian length prefix.
package xhttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"ewp-core/common/clientdns"
	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"
)

type Transport struct {
	serverAddr string
	path       string

	useECH       bool
	useMozillaCA bool
	enablePQC    bool
	echManager   *commontls.ECHManager

	sni  string
	host string

	mu        sync.Mutex
	bypassCfg *transport.BypassConfig
	resolver  *clientdns.Resolver
}

// SetClientResolver wires the privacy-preserving DoH resolver.
func (t *Transport) SetClientResolver(r *clientdns.Resolver) {
	t.mu.Lock()
	t.resolver = r
	t.mu.Unlock()
}

func New(serverAddr, path string, useECH, useMozillaCA, enablePQC bool, echManager *commontls.ECHManager) *Transport {
	if path == "" {
		path = "/"
	}
	return &Transport{
		serverAddr:   serverAddr,
		path:         path,
		useECH:       useECH,
		useMozillaCA: useMozillaCA,
		enablePQC:    enablePQC,
		echManager:   echManager,
	}
}

func (t *Transport) Name() string { return "xhttp" }

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

func (t *Transport) Dial() (transport.TunnelConn, error) {
	host, port, err := net.SplitHostPort(t.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("xhttp: bad serverAddr %q: %w", t.serverAddr, err)
	}
	sni := t.sni
	if sni == "" {
		sni = host
	}

	cfg, err := commontls.NewSTDConfig(sni, t.useMozillaCA, t.enablePQC)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := cfg.TLSConfig()
	if err != nil {
		return nil, err
	}
	tlsCfg.NextProtos = []string{"http/1.1"}
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

	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	if bp := t.bypass(); bp != nil && bp.TCPDialer != nil {
		dialer = bp.TCPDialer
	}

	httpTransport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		ForceAttemptHTTP2:     false, // stay HTTP/1.1 for true streaming
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			t.mu.Lock()
			resolver := t.resolver
			t.mu.Unlock()
			if resolver != nil {
				resolved, rerr := resolver.ResolveHostPort(ctx, addr)
				if rerr != nil {
					return nil, fmt.Errorf("xhttp: client dns: %w", rerr)
				}
				addr = resolved
			}
			rawConn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			tlsConn := tls.Client(rawConn, tlsCfg)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			return tlsConn, nil
		},
	}

	httpHost := t.host
	if httpHost == "" {
		httpHost = host
	}
	target := url.URL{Scheme: "https", Host: net.JoinHostPort(httpHost, port), Path: t.path}

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, target.String(), pr)
	if err != nil {
		return nil, err
	}
	req.Host = httpHost
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := httpTransport.RoundTrip(req)
	if err != nil {
		_ = pw.CloseWithError(err)
		return nil, fmt.Errorf("xhttp: roundtrip: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.CloseWithError(errors.New("non-200"))
		return nil, fmt.Errorf("xhttp: status %s", resp.Status)
	}
	log.V("[xhttp] tunnel established (%s)", t.serverAddr)

	return newStreamOneConn(resp.Body, pw, &transportCloser{tr: httpTransport}), nil
}

type transportCloser struct{ tr *http.Transport }

func (c *transportCloser) Close() error {
	c.tr.CloseIdleConnections()
	return nil
}

var _ transport.Transport = (*Transport)(nil)
