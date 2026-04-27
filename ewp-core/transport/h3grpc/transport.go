// Package h3grpc carries v2 outer messages over HTTP/3 + gRPC-Web
// framing. Streaming uses one POST per Dial: the request body is the
// uplink, the response body is the downlink. Each gRPC-Web frame =
// one v2 outer message.
package h3grpc

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

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	commontls "ewp-core/common/tls"
	"ewp-core/log"
	"ewp-core/transport"
)

// Transport implements transport.Transport for HTTP/3 + gRPC-Web.
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
	rt        *http3.Transport
	bypassCfg *transport.BypassConfig
}

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
	}
}

func (t *Transport) Name() string { return "h3grpc" }

func (t *Transport) SetSNI(sni string)   { t.sni = sni }
func (t *Transport) SetHost(host string) { t.host = host }

func (t *Transport) SetBypassConfig(cfg *transport.BypassConfig) {
	t.mu.Lock()
	t.bypassCfg = cfg
	t.rt = nil // force rebuild next Dial
	t.mu.Unlock()
}

func (t *Transport) bypass() *transport.BypassConfig {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bypassCfg
}

func (t *Transport) initRoundTripper(host, sni string) (*http3.Transport, error) {
	t.mu.Lock()
	if t.rt != nil {
		rt := t.rt
		t.mu.Unlock()
		return rt, nil
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
	tlsCfg.NextProtos = []string{"h3"}
	if t.useECH && t.echManager != nil {
		echList, err := t.echManager.Get()
		if err != nil {
			return nil, err
		}
		tlsCfg.EncryptedClientHelloConfigList = echList
		tlsCfg.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
			return errors.New("server rejected ECH")
		}
		// ECH + 0-RTT + session-cache do not mix; turn the latter two off.
		tlsCfg.SessionTicketsDisabled = true
		tlsCfg.ClientSessionCache = nil
	}

	dial := makeBypassQUICDial(t.bypass())

	rt := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:        45 * time.Second,
			KeepAlivePeriod:       15 * time.Second,
			MaxIncomingStreams:    256,
			MaxIncomingUniStreams: 256,
			Allow0RTT:             !t.useECH, // never with ECH
		},
		Dial: dial,
	}
	t.mu.Lock()
	t.rt = rt
	t.mu.Unlock()
	return rt, nil
}

// Dial opens a long-lived bidi POST: req.Body is the uplink, resp.Body
// is the downlink, both framed as gRPC-Web.
func (t *Transport) Dial() (transport.TunnelConn, error) {
	host, port, err := net.SplitHostPort(t.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("h3grpc: bad serverAddr %q: %w", t.serverAddr, err)
	}
	sni := t.sni
	if sni == "" {
		sni = host
	}

	rt, err := t.initRoundTripper(host, sni)
	if err != nil {
		return nil, err
	}

	httpHost := t.host
	if httpHost == "" {
		httpHost = host
	}
	target := url.URL{Scheme: "https", Host: net.JoinHostPort(httpHost, port), Path: "/" + t.serviceName + "/Tunnel"}

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, target.String(), pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc-web+proto")
	req.Header.Set("X-Grpc-Web", "1")
	req.Host = httpHost

	resp, err := rt.RoundTrip(req)
	if err != nil {
		_ = pw.CloseWithError(err)
		return nil, fmt.Errorf("h3grpc: roundtrip: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = pw.CloseWithError(errors.New("non-200"))
		return nil, fmt.Errorf("h3grpc: status %s", resp.Status)
	}
	log.V("[h3grpc] tunnel established (%s)", t.serverAddr)

	enc := NewGRPCWebEncoder(pw, false)
	dec := NewGRPCWebDecoder(resp.Body)
	closer := &dualCloser{a: pw, b: resp.Body}
	return newConn(dec, enc, closer), nil
}

type dualCloser struct{ a, b io.Closer }

func (d *dualCloser) Close() error {
	_ = d.a.Close()
	return d.b.Close()
}

// makeBypassQUICDial builds a quic-go dial function bound to the
// bypass UDP listen config when we are in TUN mode.
func makeBypassQUICDial(bp *transport.BypassConfig) func(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (*quic.Conn, error) {
		var lc *net.ListenConfig
		if bp != nil && bp.UDPListenConfig != nil {
			lc = bp.UDPListenConfig
		} else {
			lc = &net.ListenConfig{}
		}
		pc, err := lc.ListenPacket(ctx, "udp", "")
		if err != nil {
			return nil, err
		}
		raddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			_ = pc.Close()
			return nil, err
		}
		tr := &quic.Transport{Conn: pc.(*net.UDPConn)}
		return tr.Dial(ctx, raddr, tlsCfg, qcfg)
	}
}

var _ transport.Transport = (*Transport)(nil)
