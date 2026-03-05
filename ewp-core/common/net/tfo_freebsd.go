//go:build freebsd

package net

import (
	"syscall"

	"ewp-core/log"
)

const (
	TCP_FASTOPEN = 0x401 // FreeBSD 12+ (sys/netinet/tcp.h)
)

func enableTFO(fd int) error {
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
	if err != nil {
		log.V("[TFO] Failed to enable TCP Fast Open on FreeBSD: %v", err)
		return err
	}
	log.V("[TFO] TCP Fast Open enabled on socket %d", fd)
	return nil
}

func enableTFOListener(fd int) error {
	err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 128)
	if err != nil {
		log.V("[TFO] Failed to enable TCP Fast Open on listener (FreeBSD): %v", err)
		return err
	}
	log.V("[TFO] TCP Fast Open enabled on listener socket %d (queue=128)", fd)
	return nil
}
