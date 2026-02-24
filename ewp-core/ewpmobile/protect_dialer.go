package ewpmobile

import (
	"net"
	"syscall"

	"ewp-core/transport"
)

func makeProtectedBypassConfig() *transport.BypassConfig {
	control := func(network, address string, c syscall.RawConn) error {
		c.Control(func(fd uintptr) {
			ProtectSocket(int(fd))
		})
		return nil
	}
	return &transport.BypassConfig{
		TCPDialer:       &net.Dialer{Control: control},
		UDPListenConfig: &net.ListenConfig{Control: control},
	}
}
