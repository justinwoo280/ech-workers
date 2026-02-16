//go:build darwin

package net

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	TCP_FASTOPEN = 0x105
)

func enableTFO(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_FASTOPEN, 1)
}

func enableTFOListener(fd int) error {
	return unix.SetsockoptInt(fd, unix.IPPROTO_TCP, TCP_FASTOPEN, 1)
}
