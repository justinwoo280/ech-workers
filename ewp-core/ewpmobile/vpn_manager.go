//go:build android

package ewpmobile

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"ewp-core/common/clientdns"
	commontls "ewp-core/common/tls"
	"ewp-core/dns"
	"ewp-core/engine"
	"ewp-core/log"
	"ewp-core/outbound/direct"
	"ewp-core/outbound/ewpclient"
	v2 "ewp-core/protocol/ewp/v2"
	"ewp-core/transport"
	"ewp-core/transport/grpc"
	"ewp-core/transport/h3grpc"
	"ewp-core/transport/websocket"
	"ewp-core/transport/xhttp"
	"ewp-core/tun"
)

// VPNConfig is the v2 mobile config consumed by export_vpn.go and the
// Kotlin layer. v1 fields (EnableFlow, AppProtocol, XhttpMode, ECHDomain,
// TunMask, ContentType, EnableTLS, MinTLSVersion, ...) are intentionally
// gone — see export_vpn.go.
type VPNConfig struct {
	ServerAddr string // host:port of the upstream EWP server
	Token      string // hex-encoded 16-byte UUID

	Protocol string // "ws" | "grpc" | "xhttp" | "h3grpc"
	Path     string // listener path (e.g. "/ewp" or gRPC service name)

	SNI  string
	Host string

	EnableECH bool
	// ECHDomain holds the host whose HTTPS RR carries the ECH key set.
	// Empty = use SNI / ServerAddr; set to "cloudflare-ech.com" for
	// Cloudflare-fronted deployments (the most common reason this
	// field is non-empty).
	ECHDomain string

	DoHServers []string

	TUNMTU  int
	TUNIPv4 string
	TUNIPv6 string
	DNSv4   string
	DNSv6   string
}

type vpnManager struct {
	mu      sync.RWMutex
	running bool

	ctx    context.Context
	cancel context.CancelFunc

	config *VPNConfig

	echMgr   *commontls.ECHManager
	resolver *dns.AsyncResolver

	tr      transport.Transport
	out     *ewpclient.Outbound
	tunInst *tun.TUN
	eng     *engine.Engine

	startTime time.Time
}

func newVPNManager() *vpnManager { return &vpnManager{} }

func (vm *vpnManager) Start(tunFD int, cfg *VPNConfig) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if vm.running {
		return fmt.Errorf("vpn already running")
	}
	if cfg == nil || cfg.ServerAddr == "" || cfg.Token == "" {
		return fmt.Errorf("ServerAddr and Token are required")
	}

	uuid, err := decodeUUIDHex(cfg.Token)
	if err != nil {
		return fmt.Errorf("token: %w", err)
	}

	vm.ctx, vm.cancel = context.WithCancel(context.Background())
	vm.config = cfg

	// 1. DoH AsyncResolver — DoH-only, never OS resolver.
	dohServers := cfg.DoHServers
	if len(dohServers) == 0 {
		dohServers = []string{"https://1.1.1.1/dns-query", "https://dns.google/dns-query"}
	}
	vm.resolver = dns.NewAsyncResolver(dns.AsyncResolverConfig{DoHServers: dohServers})

	// 2. ECH manager (optional).
	if cfg.EnableECH {
		// ECH lookup-domain priority chain. The ONLY reason we don't
		// always use SNI is centralised ECH services like Cloudflare's,
		// where the ECH HTTPS RR lives on cloudflare-ech.com and has
		// nothing to do with the user's actual backend hostname.
		domain := cfg.ECHDomain
		if domain == "" {
			domain = cfg.SNI
		}
		if domain == "" {
			domain = hostOnly(cfg.ServerAddr)
		}
		vm.echMgr = commontls.NewECHManager(domain, dohServers...)
	}

	// 3. Build outer transport.
	tr, err := vm.buildTransport()
	if err != nil {
		vm.cleanupOnFail()
		return err
	}
	vm.tr = tr

	// 3a. Build the privacy-preserving server-name resolver and inject
	// it into the transport. We reuse the same DoH list as
	// AsyncResolver — on mobile the threat model is unitary (the user
	// trusts these DoH servers for everything, otherwise they wouldn't
	// have configured them), so a single setting is friendlier than
	// the desktop's split server_name_dns / dns / ech.bootstrap_doh
	// triplet.
	if snResolver, snErr := clientdns.New(clientdns.Config{Servers: dohServers}); snErr == nil && snResolver != nil {
		if r, ok := tr.(interface {
			SetClientResolver(*clientdns.Resolver)
		}); ok {
			r.SetClientResolver(snResolver)
		}
	}

	// 4. EWP client outbound + a direct outbound for completeness.
	out := ewpclient.New("ewp", tr, uuid)
	vm.out = out

	// 5. Engine with static "ewp" route.
	eng := engine.New(&engine.StaticRouter{Tag: "ewp"})
	if err := eng.AddOutbound(out); err != nil {
		vm.cleanupOnFail()
		return fmt.Errorf("engine.AddOutbound: %w", err)
	}
	if err := eng.AddOutbound(direct.New("direct", 30*time.Second)); err != nil {
		vm.cleanupOnFail()
		return fmt.Errorf("engine.AddOutbound direct: %w", err)
	}
	vm.eng = eng

	// 6. TUN inbound bound to the Android-provided fd.
	tunCfg := &tun.Config{
		IP:               firstNonEmpty(cfg.TUNIPv4, "10.233.0.2"),
		DNS:              firstNonEmpty(cfg.DNSv4, "10.233.0.1"),
		IPv6:             cfg.TUNIPv6,
		IPv6DNS:          cfg.DNSv6,
		MTU:              firstPositive(cfg.TUNMTU, 1420),
		Stack:            "gvisor",
		ServerAddr:       cfg.ServerAddr,
		BypassDoHServers: dohServers,
		OnBypass: func(b *transport.BypassConfig) {
			// On Android we wrap the bypass dialer's syscall.Control
			// hook so each TCP connect / UDP listen we make goes
			// through VpnService.protect(fd). Without this the
			// outbound's own packets get re-captured by the TUN
			// device and we hit infinite recursion + battery drain.
			//
			// The hook is best-effort: if no SocketProtector has
			// been registered (Kotlin side hasn't called
			// SetSocketProtector yet), we keep the unprotected
			// dialer rather than fail closed — letting the user at
			// least see the routing-loop log line.
			if IsSocketProtectorSet() {
				b = wrapBypassWithProtector(b)
			}
			tr.SetBypassConfig(b)
		},
	}
	t, err := tun.NewWithFD(tunCfg, tunFD)
	if err != nil {
		vm.cleanupOnFail()
		return fmt.Errorf("tun.NewWithFD: %w", err)
	}
	vm.tunInst = t
	if err := eng.AddInbound(t.AsInbound("tun")); err != nil {
		vm.cleanupOnFail()
		return fmt.Errorf("engine.AddInbound tun: %w", err)
	}

	if err := eng.Start(vm.ctx); err != nil {
		vm.cleanupOnFail()
		return fmt.Errorf("engine.Start: %w", err)
	}

	vm.running = true
	vm.startTime = time.Now()
	log.Printf("[ewpmobile] VPN up: server=%s proto=%s ech=%v", cfg.ServerAddr, cfg.Protocol, cfg.EnableECH)
	return nil
}

func (vm *vpnManager) Stop() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if !vm.running {
		return nil
	}

	if vm.cancel != nil {
		vm.cancel()
	}
	if vm.eng != nil {
		_ = vm.eng.Close()
	}
	if vm.tunInst != nil {
		_ = vm.tunInst.Close()
	}
	if vm.echMgr != nil {
		vm.echMgr.Stop()
	}
	if vm.resolver != nil {
		_ = vm.resolver.Close()
	}

	vm.running = false
	vm.eng = nil
	vm.tunInst = nil
	vm.out = nil
	vm.tr = nil
	vm.echMgr = nil
	vm.resolver = nil

	log.Printf("[ewpmobile] VPN down")
	return nil
}

func (vm *vpnManager) IsRunning() bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.running
}

func (vm *vpnManager) GetStats() string {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	if !vm.running {
		return `{"running":false}`
	}
	out := map[string]interface{}{
		"running":    true,
		"uptime":     time.Since(vm.startTime).Seconds(),
		"serverAddr": vm.config.ServerAddr,
		"protocol":   vm.config.Protocol,
		"ech":        vm.config.EnableECH,
		"tunMTU":     vm.config.TUNMTU,
	}
	b, _ := json.Marshal(out)
	return string(b)
}

func (vm *vpnManager) cleanupOnFail() {
	if vm.cancel != nil {
		vm.cancel()
	}
	if vm.echMgr != nil {
		vm.echMgr.Stop()
		vm.echMgr = nil
	}
	if vm.resolver != nil {
		_ = vm.resolver.Close()
		vm.resolver = nil
	}
}

func (vm *vpnManager) buildTransport() (transport.Transport, error) {
	c := vm.config
	const useMozillaCA, enablePQC = true, true

	switch c.Protocol {
	case "", "ws", "websocket":
		t := websocket.New(c.ServerAddr, firstNonEmpty(c.Path, "/ewp"), c.EnableECH, useMozillaCA, enablePQC, vm.echMgr)
		applySNIHost(t, c.SNI, c.Host)
		return t, nil
	case "grpc":
		t := grpc.New(c.ServerAddr, firstNonEmpty(c.Path, "ProxyService"), c.EnableECH, useMozillaCA, enablePQC, vm.echMgr)
		applySNIHost(t, c.SNI, c.Host)
		return t, nil
	case "xhttp":
		t := xhttp.New(c.ServerAddr, firstNonEmpty(c.Path, "/ewp"), c.EnableECH, useMozillaCA, enablePQC, vm.echMgr)
		applySNIHost(t, c.SNI, c.Host)
		return t, nil
	case "h3grpc", "h3":
		t := h3grpc.New(c.ServerAddr, firstNonEmpty(c.Path, "ProxyService"), c.EnableECH, useMozillaCA, enablePQC, vm.echMgr)
		applySNIHost(t, c.SNI, c.Host)
		return t, nil
	default:
		return nil, fmt.Errorf("unknown protocol %q", c.Protocol)
	}
}

type sniHostSetter interface {
	SetSNI(string)
	SetHost(string)
}

func applySNIHost(t any, sni, host string) {
	if s, ok := t.(sniHostSetter); ok {
		if sni != "" {
			s.SetSNI(sni)
		}
		if host != "" {
			s.SetHost(host)
		}
	}
}

func decodeUUIDHex(s string) ([v2.UUIDLen]byte, error) {
	var u [v2.UUIDLen]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return u, err
	}
	if len(b) != v2.UUIDLen {
		return u, fmt.Errorf("uuid: want %d bytes, got %d", v2.UUIDLen, len(b))
	}
	copy(u[:], b)
	return u, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstPositive(a, b int) int {
	if a > 0 {
		return a
	}
	return b
}

func hostOnly(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}

var vmInst = newVPNManager()
