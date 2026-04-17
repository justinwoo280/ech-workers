package network

import (
	"ewp-core/common/bufferpool"
)

// CopyPacket copies UDP packets from src to dst until an error occurs.
// It uses the buffer pool for zero-allocation packet copying.
// Returns the error that caused the copy to stop (typically io.EOF or connection closed).
func CopyPacket(dst PacketWriter, src PacketReader) error {
	buf := bufferpool.GetUDP()
	defer bufferpool.PutUDP(buf)

	for {
		n, addr, err := src.ReadPacket(buf)
		if err != nil {
			return err
		}

		if err := dst.WritePacket(buf[:n], addr); err != nil {
			return err
		}
	}
}
