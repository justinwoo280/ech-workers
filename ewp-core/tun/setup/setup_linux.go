//go:build linux && !android

// On linux desktop we drive iproute2 / sysctl directly. On Android
// the VpnService API in Java has already configured the TUN device
// before our binary even sees the fd; the corresponding stubs live
// in setup_other.go.

package setup

import (
	"fmt"
	"os/exec"
	"strings"
)

func SetupTUN(ifName, ipCIDR, ipv6CIDR, dns, ipv6DNS string, mtu int) error {
	if err := run("ip", "link", "set", ifName, "mtu", fmt.Sprint(mtu), "up"); err != nil {
		return fmt.Errorf("bring up interface: %w", err)
	}

	if ipCIDR != "" {
		if !strings.Contains(ipCIDR, "/") {
			ipCIDR += "/24"
		}
		if err := run("ip", "addr", "add", ipCIDR, "dev", ifName); err != nil {
			return fmt.Errorf("assign IPv4: %w", err)
		}
		if err := run("ip", "route", "add", "0.0.0.0/0", "dev", ifName, "metric", "1"); err != nil {
			return fmt.Errorf("add IPv4 default route: %w", err)
		}
	}

	if ipv6CIDR != "" {
		if !strings.Contains(ipv6CIDR, "/") {
			ipv6CIDR += "/64"
		}
		if err := run("ip", "-6", "addr", "add", ipv6CIDR, "dev", ifName); err != nil {
			return fmt.Errorf("assign IPv6: %w", err)
		}
		if err := run("ip", "-6", "route", "add", "::/0", "dev", ifName, "metric", "1"); err != nil {
			return fmt.Errorf("add IPv6 default route: %w", err)
		}
	}

	// Configure DNS via systemd-resolved (resolvectl).
	// "~." makes this interface the default resolver for all domains.
	// Failures are non-fatal: DNS traffic still routes through TUN via 0.0.0.0/0,
	// as long as the pre-existing system DNS is a public (non-LAN) address.
	if dns != "" || ipv6DNS != "" {
		args := []string{"dns", ifName}
		if dns != "" {
			args = append(args, dns)
		}
		if ipv6DNS != "" {
			args = append(args, ipv6DNS)
		}
		if err := run("resolvectl", args...); err == nil {
			_ = run("resolvectl", "domain", ifName, "~.")
		}
	}

	return nil
}

func TeardownTUN(ifName string) error {
	_ = run("ip", "link", "set", ifName, "down")
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
