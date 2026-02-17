package tun

import (
	"context"
	"net"
	"time"

	commpool "ewp-core/common/bufferpool"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Handler struct {
	transport transport.Transport
	ctx       context.Context
}

func NewHandler(ctx context.Context, trans transport.Transport) *Handler {
	return &Handler{
		transport: trans,
		ctx:       ctx,
	}
}

func (h *Handler) PrepareConnection(network string, source M.Socksaddr, destination M.Socksaddr) error {
	log.V("[TUN] Preparing connection: %s %s -> %s", network, source, destination)
	return nil
}

func (h *Handler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() {
		if onClose != nil {
			onClose(nil)
		}
	}()

	target := destination.String()
	log.Printf("[TUN TCP] New connection: %s -> %s", source, target)

	tunnelConn, err := h.transport.Dial()
	if err != nil {
		log.Printf("[TUN TCP] Tunnel dial failed: %v", err)
		conn.Close()
		return
	}
	defer tunnelConn.Close()

	stopPing := tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	if err := tunnelConn.Connect(target, nil); err != nil {
		log.Printf("[TUN TCP] CONNECT failed: %v", err)
		conn.Close()
		return
	}

	log.Printf("[TUN TCP] Connected: %s", target)

	done := make(chan bool, 2)

	go func() {
		buf := commpool.GetLarge()
		defer commpool.PutLarge(buf)

		for {
			n, err := conn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if err := tunnelConn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := tunnelConn.Read(buf)
			if err != nil {
				done <- true
				return
			}

			if _, err := conn.Write(buf[:n]); err != nil {
				done <- true
				return
			}
		}
	}()

	<-done
	log.Printf("[TUN TCP] Disconnected: %s", target)
}

func (h *Handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() {
		if onClose != nil {
			onClose(nil)
		}
	}()

	target := destination.String()
	
	// Detect WebRTC STUN/TURN requests
	if destination.Port == 3478 || destination.Port == 19302 {
		log.Printf("[TUN WebRTC] STUN request intercepted: %s -> %s (tunneled)", source, target)
	} else {
		log.V("[TUN UDP] New packet connection: %s -> %s", source, target)
	}

	tunnelConn, err := h.transport.Dial()
	if err != nil {
		log.Printf("[TUN UDP] Tunnel dial failed: %v", err)
		conn.Close()
		return
	}
	defer tunnelConn.Close()

	stopPing := tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	if err := tunnelConn.ConnectUDP(target, nil); err != nil {
		log.Printf("[TUN UDP] ConnectUDP failed: %v", err)
		conn.Close()
		return
	}

	log.V("[TUN UDP] Connected: %s", target)

	done := make(chan bool, 2)

	go func() {
		buffer := buf.New()
		defer buffer.Release()
		
		for {
			buffer.Reset()
			addr, err := conn.ReadPacket(buffer)
			if err != nil {
				done <- true
				return
			}

			packet := buffer.Bytes()
			udpTarget := addr.String()
			
			if err := tunnelConn.ConnectUDP(udpTarget, packet); err != nil {
				log.V("[TUN UDP] Packet send failed: %v", err)
				continue
			}
		}
	}()

	go func() {
		readBuf := make([]byte, 32*1024)
		for {
			n, err := tunnelConn.Read(readBuf)
			if err != nil {
				done <- true
				return
			}

			buffer := buf.NewSize(n)
			buffer.Write(readBuf[:n])
			
			if err := conn.WritePacket(buffer, destination); err != nil {
				buffer.Release()
				log.V("[TUN UDP] Response write failed: %v", err)
				continue
			}
			buffer.Release()
		}
	}()

	<-done
	log.V("[TUN UDP] Disconnected: %s", target)
}
