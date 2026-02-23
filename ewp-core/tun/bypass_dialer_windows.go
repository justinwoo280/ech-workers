//go:build windows

package tun

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ipProtoIP     = 0  // IPPROTO_IP
	ipProtoIPv6   = 41 // IPPROTO_IPV6
	ipUnicastIF   = 31 // IP_UNICAST_IF
	ipv6UnicastIF = 31 // IPV6_UNICAST_IF
)

// makeBypassControl returns a socket Control function that binds each socket
// to the physical network interface using IP_UNICAST_IF / IPV6_UNICAST_IF.
func makeBypassControl(iface *net.Interface) func(network, address string, c syscall.RawConn) error {
	ifIndex := uint32(iface.Index)
	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			handle := windows.Handle(fd)
			isIPv6 := len(network) > 0 && network[len(network)-1] == '6'
			if isIPv6 {
				bindErr = windows.Setsockopt(
					handle,
					ipProtoIPv6,
					ipv6UnicastIF,
					(*byte)(unsafe.Pointer(&ifIndex)),
					int32(unsafe.Sizeof(ifIndex)),
				)
			} else {
				bindErr = windows.Setsockopt(
					handle,
					ipProtoIP,
					ipUnicastIF,
					(*byte)(unsafe.Pointer(&ifIndex)),
					int32(unsafe.Sizeof(ifIndex)),
				)
			}
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
