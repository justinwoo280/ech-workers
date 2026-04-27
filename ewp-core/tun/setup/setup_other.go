//go:build android || (!linux && !darwin && !windows && !freebsd)

package setup

// SetupTUN is a no-op on Android (the VpnService Java layer already
// brings the interface up and installs routes before we receive the
// fd) and on any platform we don't have a netlink/route helper for.
func SetupTUN(ifName, ipCIDR, ipv6CIDR, dns, ipv6DNS string, mtu int) error {
	return nil
}

// TeardownTUN is a no-op on the same platforms.
func TeardownTUN(ifName string) error { return nil }
