//go:build windows

package setup

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
)

func SetupTUN(ifName, ipCIDR, ipv6CIDR, dns, ipv6DNS string, mtu int) error {
	if ipCIDR != "" {
		if !strings.Contains(ipCIDR, "/") {
			ipCIDR += "/24"
		}
		prefix, err := netip.ParsePrefix(ipCIDR)
		if err != nil {
			return fmt.Errorf("parse IPv4 CIDR: %w", err)
		}
		ip := prefix.Addr().Unmap().String()
		mask := prefixToMask(prefix)
		gw := deriveGatewayV4(prefix)

		if err := run("netsh", "interface", "ip", "set", "address",
			"name="+ifName, "static", ip, mask); err != nil {
			return fmt.Errorf("netsh set IPv4 address: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "set", "subinterface",
			ifName, fmt.Sprintf("mtu=%d", mtu), "store=active"); err != nil {
			return fmt.Errorf("netsh set MTU: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "add", "route",
			"0.0.0.0/0", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("netsh add IPv4 default route: %w", err)
		}
	}

	if dns != "" {
		if err := run("netsh", "interface", "ip", "set", "dns",
			"name="+ifName, "static", dns, "primary"); err != nil {
			return fmt.Errorf("netsh set IPv4 DNS: %w", err)
		}
	}

	if ipv6CIDR != "" {
		if !strings.Contains(ipv6CIDR, "/") {
			ipv6CIDR += "/64"
		}
		prefix, err := netip.ParsePrefix(ipv6CIDR)
		if err != nil {
			return fmt.Errorf("parse IPv6 CIDR: %w", err)
		}
		gw6 := deriveGatewayV6(prefix)

		if err := run("netsh", "interface", "ipv6", "set", "address",
			ifName, prefix.Addr().String()); err != nil {
			return fmt.Errorf("netsh set IPv6 address: %w", err)
		}
		if err := run("netsh", "interface", "ipv6", "add", "route",
			"::/0", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("netsh add IPv6 default route: %w", err)
		}
	}

	if ipv6DNS != "" {
		if err := run("netsh", "interface", "ipv6", "add", "dnsserver",
			ifName, ipv6DNS, "index=1"); err != nil {
			return fmt.Errorf("netsh set IPv6 DNS: %w", err)
		}
	}

	return nil
}

func TeardownTUN(ifName string) error {
	_ = run("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/0", ifName)
	_ = run("netsh", "interface", "ipv6", "delete", "route", "::/0", ifName)
	return nil
}

// deriveGatewayV4 returns the first usable host IP in the subnet as the virtual gateway.
// If that address equals the TUN client IP, it advances by one more.
func deriveGatewayV4(prefix netip.Prefix) string {
	gw := prefix.Masked().Addr().Next()
	if gw == prefix.Addr().Unmap() {
		gw = gw.Next()
	}
	return gw.String()
}

// deriveGatewayV6 returns the first usable host IP in the IPv6 prefix as the virtual gateway.
func deriveGatewayV6(prefix netip.Prefix) string {
	gw := prefix.Masked().Addr().Next()
	if gw == prefix.Addr() {
		gw = gw.Next()
	}
	return gw.String()
}

func prefixToMask(prefix netip.Prefix) string {
	mask := net.CIDRMask(prefix.Bits(), 32)
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
