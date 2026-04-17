package network

import (
	"io"

	"ewp-core/transport"
)

// PacketReader is the interface for reading UDP packets.
// Each call to ReadPacket returns a single UDP datagram.
type PacketReader interface {
	// ReadPacket reads a UDP packet into buf and returns the number of bytes read
	// and the source/destination address. buf is provided by the caller.
	ReadPacket(buf []byte) (n int, addr transport.Endpoint, err error)
}

// PacketWriter is the interface for writing UDP packets.
// Each call to WritePacket sends a single UDP datagram.
type PacketWriter interface {
	// WritePacket writes a UDP packet to the specified destination address.
	WritePacket(payload []byte, addr transport.Endpoint) error
}

// PacketConn is the interface for a bidirectional UDP packet connection.
// It combines PacketReader, PacketWriter, and io.Closer.
type PacketConn interface {
	PacketReader
	PacketWriter
	io.Closer
}
