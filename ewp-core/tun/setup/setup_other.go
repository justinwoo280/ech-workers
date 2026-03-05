//go:build !linux && !darwin && !windows && !freebsd

package setup

import "fmt"

func SetupTUN(ifName, ipCIDR, ipv6CIDR, dns, ipv6DNS string, mtu int) error {
	return fmt.Errorf("TUN network setup not supported on this platform")
}

func TeardownTUN(ifName string) error {
	return nil
}
