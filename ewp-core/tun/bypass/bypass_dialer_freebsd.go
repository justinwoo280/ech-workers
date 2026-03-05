//go:build freebsd

package bypass

import (
	"net"
	"syscall"
)

// makeBypassControl returns a socket Control function that binds each socket
// to the physical network interface by binding to the interface's source IP.
// FreeBSD does not support SO_BINDTODEVICE or IP_BOUND_IF; source-IP binding
// is the portable BSD alternative.
func makeBypassControl(iface *net.Interface) func(network, address string, c syscall.RawConn) error {
	addrs, _ := iface.Addrs()

	var ip4 [4]byte
	var ip6 [16]byte
	var hasIP4, hasIP6 bool

	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip == nil {
			continue
		}
		if v4 := ip.To4(); v4 != nil && !hasIP4 {
			copy(ip4[:], v4)
			hasIP4 = true
		} else if ip.To16() != nil && !hasIP6 {
			copy(ip6[:], ip.To16())
			hasIP6 = true
		}
	}

	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			isIPv6 := len(network) > 0 && network[len(network)-1] == '6'
			if isIPv6 && hasIP6 {
				bindErr = syscall.Bind(int(fd), &syscall.SockaddrInet6{Addr: ip6})
			} else if !isIPv6 && hasIP4 {
				bindErr = syscall.Bind(int(fd), &syscall.SockaddrInet4{Addr: ip4})
			}
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
