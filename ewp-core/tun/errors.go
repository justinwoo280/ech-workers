package tun

import "errors"

// Common errors for TUN packet handling
var (
	ErrClosed             = errors.New("connection closed")
	ErrUnauthorizedSource = errors.New("unauthorized source address")
	ErrInvalidSOCKS5Header = errors.New("invalid SOCKS5 UDP header")
)
