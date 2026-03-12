package bypass

import (
	"context"
	"fmt"
	"net"

	"ewp-core/log"
	"ewp-core/transport"
)

// BypassDialer creates TCP and UDP dialers that bypass the TUN routing table
// by binding sockets directly to the physical network interface.
//
// MUST be created BEFORE the TUN device is started so that the outbound
// interface can be detected via the kernel's pre-TUN routing table.
type BypassDialer struct {
	iface   *net.Interface
	localIP net.IP

	// Dialer is a net.Dialer whose Control function binds every TCP socket
	// to the physical interface, bypassing TUN routing.
	Dialer *net.Dialer

	// ListenConfig is a net.ListenConfig whose Control function binds every
	// UDP socket to the physical interface, bypassing TUN routing.
	ListenConfig *net.ListenConfig
}

// NewBypassDialer detects the physical outbound interface and returns a
// BypassDialer that routes around the TUN device.
//
// On Linux, policy routing is configured via netlink so that all sockets
// marked with bypassFWMark (SO_MARK) bypass the TUN default route.
// Call Close() when the TUN device is torn down to remove the routing rules.
func NewBypassDialer(serverAddr string) (*BypassDialer, error) {
	probeIP := "8.8.8.8"
	if serverAddr != "" {
		if ip := net.ParseIP(serverAddr); ip != nil {
			if ip.To4() == nil {
				probeIP = serverAddr // IPv6
			} else {
				probeIP = serverAddr
			}
		}
	}

	// Use a UDP probe-connect to let the kernel choose the best outbound
	// interface.  No packet is actually sent; this is address-selection only.
	conn, err := net.Dial("udp", net.JoinHostPort(probeIP, "80"))
	if err != nil {
		// Fallback to default if probe fails
		conn, err = net.Dial("udp", "8.8.8.8:80")
		if err != nil {
			return nil, fmt.Errorf("bypass dialer: detect outbound interface: %w", err)
		}
	}
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	conn.Close()

	iface, err := findInterfaceByIP(localAddr.IP)
	if err != nil {
		return nil, fmt.Errorf("bypass dialer: identify physical interface for %s: %w", localAddr.IP, err)
	}

	log.Info("[TUN] Bypass dialer: interface=%s ip=%s", iface.Name, localAddr.IP)

	controlFn := makeBypassControl(iface)
	bd := &BypassDialer{
		iface:        iface,
		localIP:      localAddr.IP,
		Dialer:       &net.Dialer{Control: controlFn},
		ListenConfig: &net.ListenConfig{Control: controlFn},
	}

	if err := bd.platformSetup(); err != nil {
		log.Printf("[TUN] Bypass route setup: %v (non-fatal, bypass may not work correctly)", err)
	}
	return bd, nil
}

// Close removes any kernel routing rules and routes installed by NewBypassDialer.
// Must be called when the TUN interface is torn down (e.g. on program exit).
func (b *BypassDialer) Close() {
	b.platformCleanup()
}

// ToBypassConfig converts to the transport.BypassConfig used by all transports.
// A BypassResolver is automatically created so that DNS queries also bypass the TUN
// and all resolved IPs are probed to select the optimal CDN edge node.
func (b *BypassDialer) ToBypassConfig() *transport.BypassConfig {
	cfg := &transport.BypassConfig{
		TCPDialer:       b.Dialer,
		UDPListenConfig: b.ListenConfig,
		LocalIP:         b.localIP,
	}
	cfg.Resolver = transport.NewBypassResolver(cfg, "")
	return cfg
}

// ListenUDP creates a UDP PacketConn bound to the physical interface (for QUIC).
func (b *BypassDialer) ListenUDP(ctx context.Context) (net.PacketConn, error) {
	return b.ListenConfig.ListenPacket(ctx, "udp", net.JoinHostPort(b.localIP.String(), "0"))
}

// findInterfaceByIP finds the network interface that owns the given IP address.
func findInterfaceByIP(ip net.IP) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ifIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ifIP = v.IP
			case *net.IPAddr:
				ifIP = v.IP
			}
			if ifIP != nil && ifIP.Equal(ip) {
				return &iface, nil
			}
		}
	}
	return nil, fmt.Errorf("no interface found for IP %s", ip)
}
