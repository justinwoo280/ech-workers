//go:build !android

package tun

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/transport"
	ewpbypass "ewp-core/tun/bypass"
	ewpgvisor "ewp-core/tun/gvisor"
	tunsetup "ewp-core/tun/setup"

	tun "golang.zx2c4.com/wireguard/tun"
)

type gvisorUDPWriter struct {
	stack *ewpgvisor.Stack
}

func (w *gvisorUDPWriter) WriteTo(p []byte, src netip.AddrPort, dst netip.AddrPort) error {
	if w.stack == nil {
		return fmt.Errorf("stack is nil")
	}
	return w.stack.WriteUDP(p, src, dst)
}

func (w *gvisorUDPWriter) ReleaseConn(src netip.AddrPort, dst netip.AddrPort) {
	if w.stack != nil {
		w.stack.ReleaseWriteConn(src, dst)
	}
}

type Config struct {
	IP              string
	DNS             string
	IPv6            string
	IPv6DNS         string
	MTU             int
	Stack           string
	Transport       transport.Transport
	ServerAddr      string // proxy server address; used to detect the physical outbound interface for bypass dialing
	TunnelDoHServer string // DoH server URL for tunnel DNS resolver (default: https://dns.google/dns-query)
}

type TUN struct {
	device    tun.Device
	stack     *ewpgvisor.Stack
	handler   *Handler
	config    *Config
	ctx       context.Context
	cancel    context.CancelFunc
	ifName    string    // actual OS interface name returned by tun.Device.Name()
	closeOnce sync.Once // ensures Close() is idempotent
}

func New(cfg *Config) (*TUN, error) {
	ctx, cancel := context.WithCancel(context.Background())

	udpWriter := &gvisorUDPWriter{stack: nil}
	handler := NewHandler(ctx, cfg.Transport, udpWriter)

	dnsResolver, dnsErr := dns.NewTunnelDNSResolver(cfg.Transport, dns.TunnelDNSConfig{
		DoHServer: cfg.TunnelDoHServer,
	})
	if dnsErr != nil {
		log.Printf("[TUN] Warning: tunnel DNS resolver init failed: %v (DNS will use generic UDP proxy)", dnsErr)
	} else {
		handler.SetDNSResolver(dnsResolver)
		log.Printf("[TUN] Tunnel DNS resolver initialized (DoH server: %s)", dnsResolver.DoHServer())
	}

	mtu := uint32(cfg.MTU)
	if mtu == 0 {
		mtu = 1500
	}

	ipStr := cfg.IP
	if !strings.Contains(ipStr, "/") {
		ipStr += "/24"
	}
	_, err := netip.ParsePrefix(ipStr)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("parse IPv4 address failed: %w", err)
	}

	tunDevice, err := tun.CreateTUN("ewp-tun", int(mtu))
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create TUN device failed: %w", err)
	}

	stackConfig := &ewpgvisor.StackConfig{
		MTU:        int(mtu),
		TCPHandler: handler.HandleTCP,
		UDPHandler: handler.HandleUDP,
	}

	stack, err := ewpgvisor.NewStack(tunDevice, stackConfig)
	if err != nil {
		tunDevice.Close()
		cancel()
		return nil, fmt.Errorf("create gvisor stack failed: %w", err)
	}

	udpWriter.stack = stack

	return &TUN{
		device:  tunDevice,
		stack:   stack,
		handler: handler,
		config:  cfg,
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// Setup configures the OS network interface and routing table, then injects
// a bypass dialer into the transport so proxy connections don't loop through
// the TUN device.
//
// MUST be called after New() and BEFORE Start(). The bypass dialer is created
// first (while the physical default route is still in place), then the TUN
// routes are added — this ordering is critical to correctly identify the
// physical outbound interface.
func (t *TUN) Setup() error {
	ifName, err := t.device.Name()
	if err != nil {
		return fmt.Errorf("get TUN interface name: %w", err)
	}
	t.ifName = ifName
	log.Printf("[TUN] Interface name: %s", ifName)

	// Step 1 — bypass dialer BEFORE route changes.
	// NewBypassDialer probes the current routing table (UDP connect to server IP)
	// to detect the physical outbound interface. This must happen before we add
	// the TUN default route, otherwise the probe would pick the TUN itself.
	if t.config.ServerAddr != "" {
		bd, err := ewpbypass.NewBypassDialer(t.config.ServerAddr)
		if err != nil {
			log.Printf("[TUN] Warning: bypass dialer init failed: %v (routing loop risk)", err)
		} else {
			t.config.Transport.SetBypassConfig(bd.ToBypassConfig())
			log.Printf("[TUN] Bypass dialer active on interface %s", ifName)
		}
	} else {
		log.Printf("[TUN] Warning: ServerAddr not set — bypass dialer disabled, routing loop possible")
	}

	// Step 2 — assign IP address and add default routes through the TUN.
	mtu := t.config.MTU
	if mtu <= 0 {
		mtu = 1500
	}
	if err := tunsetup.SetupTUN(ifName, t.config.IP, t.config.IPv6, t.config.DNS, t.config.IPv6DNS, mtu); err != nil {
		return fmt.Errorf("configure TUN network: %w", err)
	}

	log.Printf("[TUN] Network configured: interface=%s IPv4=%s IPv6=%s MTU=%d",
		ifName, t.config.IP, t.config.IPv6, mtu)
	return nil
}

func (t *TUN) Start() error {
	log.Printf("[TUN] TUN mode started (stack=%s)", t.config.Stack)
	log.Printf("[TUN] IPv4: %s", t.config.IP)
	if t.config.IPv6 != "" {
		log.Printf("[TUN] IPv6: %s", t.config.IPv6)
	}
	log.Printf("[TUN] DNS: IPv4=%s, IPv6=%s", t.config.DNS, t.config.IPv6DNS)

	<-t.ctx.Done()
	return nil
}

func (t *TUN) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		log.Printf("[TUN] Stopping TUN mode...")

		if t.cancel != nil {
			t.cancel()
		}

		if t.stack != nil {
			t.stack.Close()
		}

		// Close the underlying TUN device (releases Wintun handle on Windows,
		// fd on Linux/macOS). Must come after stack.Close() so gVisor stops
		// reading from the device before we destroy it.
		if t.device != nil {
			t.device.Close()
		}

		if t.ifName != "" {
			if err := tunsetup.TeardownTUN(t.ifName); err != nil {
				log.Printf("[TUN] Teardown warning: %v", err)
			}
		}

		log.Printf("[TUN] TUN mode stopped")
	})
	return closeErr
}
