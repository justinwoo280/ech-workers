//go:build linux || android

package bypass

import (
	"net"
	"syscall"
)

const bypassFWMark = 0xEC011

// makeBypassControl returns a socket Control function that sets SO_MARK on each
// socket so that policy routing (configured by setupBypassRoutes) sends the
// packet through the physical NIC rather than the TUN default route.
//
// This mirrors Android's VpnService.protect() mechanism:
//   - SO_MARK labels the socket
//   - A routing rule (ip rule add fwmark <mark> lookup <table>) handles bypass
func makeBypassControl(_ *net.Interface) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var setErr error
		err := c.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, bypassFWMark)
		})
		if err != nil {
			return err
		}
		return setErr
	}
}
