package net

import (
	"context"
	"net"
	"syscall"
	"time"

	"ewp-core/log"
)

// DialTFO establishes a TCP connection with TCP Fast Open enabled
func DialTFO(network, address string, timeout time.Duration) (net.Conn, error) {
	return DialTFOContext(context.Background(), network, address, timeout)
}

// DialTFOContext establishes a TCP connection with TCP Fast Open enabled and context support
func DialTFOContext(ctx context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
	// Parse address
	tcpAddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// Create socket with TFO support
	conn, err := dialTCPWithTFO(ctx, tcpAddr, timeout)
	if err != nil {
		// Fallback to standard dial if TFO fails
		log.V("[TFO] Failed to enable TCP Fast Open, falling back to standard dial: %v", err)
		
		if timeout > 0 {
			return net.DialTimeout(network, address, timeout)
		}
		
		d := &net.Dialer{}
		return d.DialContext(ctx, network, address)
	}

	return conn, nil
}

// dialTCPWithTFO creates a TCP connection with Fast Open enabled
func dialTCPWithTFO(ctx context.Context, addr *net.TCPAddr, timeout time.Duration) (net.Conn, error) {
	// Create dialer with TFO-specific configuration
	d := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var syscallErr error
			err := c.Control(func(fd uintptr) {
				// Enable TCP Fast Open on the socket
				syscallErr = enableTFO(int(fd))
			})
			if err != nil {
				return err
			}
			return syscallErr
		},
	}

	return d.DialContext(ctx, "tcp", addr.String())
}

// ListenTFO creates a TCP listener with TCP Fast Open enabled
func ListenTFO(network, address string) (net.Listener, error) {
	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var syscallErr error
			err := c.Control(func(fd uintptr) {
				// Enable TCP Fast Open on the listener socket
				syscallErr = enableTFOListener(int(fd))
			})
			if err != nil {
				return err
			}
			return syscallErr
		},
	}

	lis, err := lc.Listen(context.Background(), network, address)
	if err != nil {
		// Fallback to standard listen if TFO fails
		log.V("[TFO] Failed to enable TCP Fast Open on listener, falling back to standard listen: %v", err)
		return net.Listen(network, address)
	}

	return lis, nil
}
