//go:build linux || android

package tun

import (
	"net"
)

func parseIPv4(s string) net.IP {
	ip := net.ParseIP(s)
	if ip == nil {
		return net.IPv4(0, 0, 0, 0)
	}
	return ip.To4()
}
