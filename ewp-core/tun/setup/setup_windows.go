//go:build windows

package setup

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"

	ewplog "ewp-core/log"
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
		// Set interface metric to 1 (lowest) so Windows DNS Client
		// prefers this interface's DNS server over physical NIC DNS.
		if err := run("netsh", "interface", "ipv4", "set", "interface",
			ifName, "metric=1"); err != nil {
			return fmt.Errorf("netsh set IPv4 interface metric: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "add", "route",
			"0.0.0.0/1", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("netsh add IPv4 route 0.0.0.0/1: %w", err)
		}
		if err := run("netsh", "interface", "ipv4", "add", "route",
			"128.0.0.0/1", ifName, "nexthop="+gw, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("netsh add IPv4 route 128.0.0.0/1: %w", err)
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
		// Set IPv6 interface metric to 1 as well
		if err := run("netsh", "interface", "ipv6", "set", "interface",
			ifName, "metric=1"); err != nil {
			return fmt.Errorf("netsh set IPv6 interface metric: %w", err)
		}
		if err := run("netsh", "interface", "ipv6", "add", "route",
			"::/1", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("netsh add IPv6 route ::/1: %w", err)
		}
		if err := run("netsh", "interface", "ipv6", "add", "route",
			"8000::/1", ifName, "nexthop="+gw6, "metric=1", "store=active"); err != nil {
			return fmt.Errorf("netsh add IPv6 route 8000::/1: %w", err)
		}
	}

	if ipv6DNS != "" {
		if err := run("netsh", "interface", "ipv6", "add", "dnsserver",
			ifName, ipv6DNS, "index=1"); err != nil {
			return fmt.Errorf("netsh set IPv6 DNS: %w", err)
		}
	}

	// Suppress DNS on all other interfaces to prevent Windows SMHNR
	// (Smart Multi-Homed Name Resolution) from querying physical NIC DNS.
	suppressOtherDNS(ifName)

	// Flush DNS cache so stale entries from the physical NIC are discarded.
	_ = run("ipconfig", "/flushdns")

	return nil
}

func TeardownTUN(ifName string) error {
	_ = run("netsh", "interface", "ipv4", "delete", "route", "0.0.0.0/1", ifName)
	_ = run("netsh", "interface", "ipv4", "delete", "route", "128.0.0.0/1", ifName)
	_ = run("netsh", "interface", "ipv6", "delete", "route", "::/1", ifName)
	_ = run("netsh", "interface", "ipv6", "delete", "route", "8000::/1", ifName)

	// Restore DNS on other interfaces (set back to automatic metric)
	restoreOtherDNS(ifName)
	_ = run("ipconfig", "/flushdns")

	return nil
}

// suppressOtherDNS raises the interface metric on all other connected adapters
// to 9999 so Windows DNS Client will not use their DNS servers.
// Uses PowerShell Get-NetAdapter (locale-independent) instead of netsh text parsing.
func suppressOtherDNS(tunIfName string) {
	// PowerShell one-liner: get all connected adapters except our TUN,
	// then set their IPv4 and IPv6 interface metrics to 9999.
	psCmd := fmt.Sprintf(
		`Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne '%s' } | ForEach-Object { `+
			`Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -InterfaceMetric 9999 -ErrorAction SilentlyContinue; `+
			`Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -InterfaceMetric 9999 -ErrorAction SilentlyContinue; `+
			`Write-Host "Suppressed: $($_.Name)" `+
			`}`,
		tunIfName,
	)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).CombinedOutput()
	if err != nil {
		ewplog.Printf("[TUN] Warning: DNS suppression failed: %v (output: %s)", err, strings.TrimSpace(string(out)))
	} else {
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				ewplog.Printf("[TUN] %s", line)
			}
		}
	}
}

// restoreOtherDNS sets all non-TUN interfaces back to automatic metric (0).
func restoreOtherDNS(tunIfName string) {
	psCmd := fmt.Sprintf(
		`Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -ne '%s' } | ForEach-Object { `+
			`Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -AutomaticMetric Enabled -ErrorAction SilentlyContinue; `+
			`Set-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv6 -AutomaticMetric Enabled -ErrorAction SilentlyContinue `+
			`}`,
		tunIfName,
	)
	_ = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd).Run()
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
