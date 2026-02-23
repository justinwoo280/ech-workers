//go:build linux || android

package tun

import (
	"net"
	"syscall"
)

// makeBypassControl returns a socket Control function that binds each socket
// to the physical network interface using SO_BINDTODEVICE.
func makeBypassControl(iface *net.Interface) func(network, address string, c syscall.RawConn) error {
	name := iface.Name
	return func(network, address string, c syscall.RawConn) error {
		var bindErr error
		err := c.Control(func(fd uintptr) {
			bindErr = syscall.SetsockoptString(
				int(fd),
				syscall.SOL_SOCKET,
				syscall.SO_BINDTODEVICE,
				name,
			)
		})
		if err != nil {
			return err
		}
		return bindErr
	}
}
