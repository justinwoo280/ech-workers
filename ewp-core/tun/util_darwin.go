//go:build darwin

package tun

import (
	"net"
	"os"
)

func IsAdmin() bool {
	return os.Geteuid() == 0
}

func parseIPv4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv4(0, 0, 0, 0)
	}
	return ip.To4()
}
