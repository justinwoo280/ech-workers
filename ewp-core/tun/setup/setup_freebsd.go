//go:build freebsd

package setup

import (
	"fmt"
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
		local := prefix.Addr().Unmap()
		peer := peerAddr(local)

		// FreeBSD tun is a point-to-point interface: ifconfig <iface> <local> <peer>
		if err := run("ifconfig", ifName, local.String(), peer.String(), "mtu", fmt.Sprint(mtu), "up"); err != nil {
			return fmt.Errorf("ifconfig IPv4: %w", err)
		}
		if err := run("route", "add", "-net", "0.0.0.0/0", peer.String()); err != nil {
			return fmt.Errorf("add IPv4 default route: %w", err)
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
		local := prefix.Addr()
		if err := run("ifconfig", ifName, "inet6", local.String(),
			"prefixlen", fmt.Sprint(prefix.Bits()), "up"); err != nil {
			return fmt.Errorf("ifconfig IPv6: %w", err)
		}
		if err := run("route", "add", "-inet6", "default", "-interface", ifName); err != nil {
			return fmt.Errorf("add IPv6 default route: %w", err)
		}
	}

	// Configure DNS via resolvconf if available (non-fatal).
	if dns != "" || ipv6DNS != "" {
		_ = configureFreeBSDDNS(ifName, dns, ipv6DNS)
	}

	return nil
}

func TeardownTUN(ifName string) error {
	_ = run("route", "delete", "-net", "default", "-interface", ifName)
	_ = run("route", "delete", "-inet6", "default", "-interface", ifName)
	_ = run("ifconfig", ifName, "down")
	_ = run("resolvconf", "-d", ifName)
	return nil
}

func configureFreeBSDDNS(ifName, dns, ipv6DNS string) error {
	var lines []string
	if dns != "" {
		lines = append(lines, "nameserver "+dns)
	}
	if ipv6DNS != "" {
		lines = append(lines, "nameserver "+ipv6DNS)
	}
	content := strings.Join(lines, "\n") + "\n"
	cmd := exec.Command("resolvconf", "-a", ifName, "-m", "0", "-x")
	cmd.Stdin = strings.NewReader(content)
	_, err := cmd.CombinedOutput()
	return err
}

// peerAddr returns the remote end of the point-to-point link: local ± 1 on the last byte.
func peerAddr(local netip.Addr) netip.Addr {
	if local.Is4() {
		a := local.As4()
		if a[3] < 255 {
			a[3]++
		} else {
			a[3]--
		}
		return netip.AddrFrom4(a)
	}
	a := local.As16()
	if a[15] < 255 {
		a[15]++
	} else {
		a[15]--
	}
	return netip.AddrFrom16(a)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}
