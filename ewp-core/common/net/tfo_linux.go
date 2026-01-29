// +build linux

package net

import (
	"syscall"

	"ewp-core/log"
)

const (
	TCP_FASTOPEN = 23 // TCP_FASTOPEN socket option for Linux
)

// enableTFO enables TCP Fast Open on a socket (Linux implementation)
func enableTFO(fd int) error {
	// Linux kernel 3.7+ supports TCP Fast Open
	// Set TCP_FASTOPEN socket option with queue length
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 5)
	if err != nil {
		log.V("[TFO] Failed to enable TCP Fast Open on Linux: %v", err)
		return err
	}
	
	log.V("[TFO] TCP Fast Open enabled on socket %d", fd)
	return nil
}

// enableTFOListener enables TCP Fast Open on a listener socket (Linux implementation)
func enableTFOListener(fd int) error {
	// Linux kernel 3.7+ supports TCP Fast Open for server sockets
	// The value is the max queue length for pending TFO connections
	// Typical values: 5-128
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 128)
	if err != nil {
		log.V("[TFO] Failed to enable TCP Fast Open on listener (Linux): %v", err)
		return err
	}
	
	log.V("[TFO] TCP Fast Open enabled on listener socket %d (queue=128)", fd)
	return nil
}
