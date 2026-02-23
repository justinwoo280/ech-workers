package tun

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
func NewBypassDialer(serverIP string) (*BypassDialer, error) {
	probeIP := "8.8.8.8"
	if serverIP != "" {
		if ip := net.ParseIP(serverIP); ip != nil {
			if ip.To4() == nil {
				probeIP = "[2001:4860:4860::8888]" // Default IPv6 probe if server is IPv6
				// Optionally, just use the server IP itself: probeIP = net.JoinHostPort(serverIP, "80")
				probeIP = serverIP
			} else {
				probeIP = serverIP
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
	return &BypassDialer{
		iface:        iface,
		localIP:      localAddr.IP,
		Dialer:       &net.Dialer{Control: controlFn},
		ListenConfig: &net.ListenConfig{Control: controlFn},
	}, nil
}

// ToBypassConfig converts to the transport.BypassConfig used by all transports.
func (b *BypassDialer) ToBypassConfig() *transport.BypassConfig {
	return &transport.BypassConfig{
		TCPDialer:       b.Dialer,
		UDPListenConfig: b.ListenConfig,
	}
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
