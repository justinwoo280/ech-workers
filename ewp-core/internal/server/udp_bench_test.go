package server

import (
	"net"
	"net/netip"
	"testing"

	"ewp-core/protocol/ewp"
)

// BenchmarkUDPEncodeOld 模拟旧的分配方式
func BenchmarkUDPEncodeOld(b *testing.B) {
	globalID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 12345,
	}
	payload := make([]byte, 1400) // 典型 UDP 包大小

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := &ewp.UDPPacket{
			GlobalID: globalID,
			Status:   ewp.UDPStatusKeep,
			Target:   remoteAddr,
			Payload:  payload,
		}
		data, err := ewp.EncodeUDPPacket(pkt)
		if err != nil {
			b.Fatal(err)
		}
		_ = data
	}
}

// BenchmarkUDPEncodeNew 使用新的零分配方式
func BenchmarkUDPEncodeNew(b *testing.B) {
	globalID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	remoteAddr := &net.UDPAddr{
		IP:   net.ParseIP("192.168.1.1"),
		Port: 12345,
	}
	payload := make([]byte, 1400)

	// 模拟池化缓冲区
	writeBuf := make([]byte, 0, 2048)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		writeBuf = writeBuf[:0]
		addr, _ := netip.AddrFromSlice(remoteAddr.IP)
		addrPort := netip.AddrPortFrom(addr, uint16(remoteAddr.Port))
		writeBuf = ewp.AppendUDPAddrFrame(
			writeBuf,
			globalID,
			ewp.UDPStatusKeep,
			addrPort,
			payload,
		)
		_ = writeBuf
	}
}
