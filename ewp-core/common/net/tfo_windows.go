// +build windows

package net

import (
	"syscall"

	"ewp-core/log"
)

const (
	TCP_FASTOPEN = 15 // TCP_FASTOPEN socket option for Windows
)

// enableTFO enables TCP Fast Open on a socket (Windows implementation)
func enableTFO(fd int) error {
	// Windows 10 (version 1607+) supports TCP Fast Open
	// Set TCP_FASTOPEN socket option
	err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
	if err != nil {
		log.V("[TFO] Failed to enable TCP Fast Open on Windows: %v", err)
		return err
	}
	
	log.V("[TFO] TCP Fast Open enabled on socket %d", fd)
	return nil
}

// enableTFOListener enables TCP Fast Open on a listener socket (Windows implementation)
func enableTFOListener(fd int) error {
	// Windows 10 (version 1607+) supports TCP Fast Open for server sockets
	// Set TCP_FASTOPEN socket option
	err := syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
	if err != nil {
		log.V("[TFO] Failed to enable TCP Fast Open on listener (Windows): %v", err)
		return err
	}
	
	log.V("[TFO] TCP Fast Open enabled on listener socket %d", fd)
	return nil
}
