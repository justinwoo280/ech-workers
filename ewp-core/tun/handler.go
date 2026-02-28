package tun

import (
	"context"
	"net"
	"sync"
	"time"

	commpool "ewp-core/common/bufferpool"
	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/transport"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type Handler struct {
	transport   transport.Transport
	ctx         context.Context
	dnsResolver *dns.TunnelDNSResolver
}

func NewHandler(ctx context.Context, trans transport.Transport) *Handler {
	return &Handler{
		transport: trans,
		ctx:       ctx,
	}
}

// SetDNSResolver sets the tunnel DNS resolver for handling DNS queries (port 53).
// When set, DNS queries intercepted by sing-tun are resolved through the proxy tunnel
// using DoH/DoT/DoQ, preventing DNS leaks and ensuring encrypted resolution.
func (h *Handler) SetDNSResolver(resolver *dns.TunnelDNSResolver) {
	h.dnsResolver = resolver
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
	defer conn.Close()

	stopPing := tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	if err := tunnelConn.Connect(target, nil); err != nil {
		log.Printf("[TUN TCP] CONNECT failed: %v", err)
		return
	}

	log.Printf("[TUN TCP] Connected: %s", target)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		b := commpool.GetLarge()
		defer commpool.PutLarge(b)
		for {
			n, err := conn.Read(b)
			if err != nil {
				tunnelConn.Close()
				return
			}
			if err := tunnelConn.Write(b[:n]); err != nil {
				conn.Close()
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		b := commpool.GetLarge()
		defer commpool.PutLarge(b)
		for {
			n, err := tunnelConn.Read(b)
			if err != nil {
				conn.Close()
				return
			}
			if _, err := conn.Write(b[:n]); err != nil {
				tunnelConn.Close()
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("[TUN TCP] Disconnected: %s", target)
}

func (h *Handler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() {
		if onClose != nil {
			onClose(nil)
		}
	}()

	target := destination.String()

	// DNS interception: resolve port 53 queries locally through the tunnel DNS resolver
	// (DoH/DoT/DoQ), then write the response back to the TUN device directly.
	if destination.Port == 53 && h.dnsResolver != nil {
		log.V("[TUN DNS] Intercepted DNS query: %s -> %s", source, target)
		h.handleDNS(ctx, conn, source, destination)
		return
	}

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
	defer conn.Close()

	stopPing := tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	if err := tunnelConn.ConnectUDP(target, nil); err != nil {
		log.Printf("[TUN UDP] ConnectUDP failed: %v", err)
		return
	}

	log.V("[TUN UDP] Connected: %s", target)

	// wg ensures both goroutines finish before defers run (conn/tunnelConn.Close).
	// Previously a bare channel <-done exited after the first goroutine signalled,
	// leaving the second goroutine writing to already-closed connections.
	var wg sync.WaitGroup
	wg.Add(2)

	// TUN → tunnel
	go func() {
		defer wg.Done()
		readBuf := buf.New()
		defer readBuf.Release()
		for {
			readBuf.Reset()
			addr, err := conn.ReadPacket(readBuf)
			if err != nil {
				tunnelConn.Close()
				return
			}
			if err := tunnelConn.WriteUDP(addr.String(), readBuf.Bytes()); err != nil {
				log.V("[TUN UDP] Packet send failed: %v", err)
				conn.Close()
				return
			}
		}
	}()

	// tunnel → TUN
	// ReadUDPTo reads payload directly into the provided buffer; we wrap it in a pooled sing
	// buffer (buf.New, not buf.NewSize) so WritePacket can return it to the pool.
	go func() {
		defer wg.Done()
		for {
			// Allocate from sing's fixed-size pool (better pool hit rate than NewSize).
			writeBuf := buf.New()
			n, err := tunnelConn.ReadUDPTo(writeBuf.FreeBytes())
			if err != nil {
				writeBuf.Release()
				conn.Close()
				return
			}
			writeBuf.Resize(0, n)
			if err := conn.WritePacket(writeBuf, destination); err != nil {
				writeBuf.Release()
				log.V("[TUN UDP] Response write failed: %v", err)
				tunnelConn.Close()
				return
			}
			// On success WritePacket takes ownership; no Release needed here.
		}
	}()

	wg.Wait()
	log.V("[TUN UDP] Disconnected: %s", target)
}

// handleDNS reads DNS query packets from the TUN PacketConn in a loop,
// resolves each through the TunnelDNSResolver (DoH via proxy tunnel), and writes
// responses back. Each query is processed in a separate goroutine to allow
// concurrent resolution. Pattern inspired by sing-box's NewDNSPacketConnection.
func (h *Handler) handleDNS(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr) {
	defer conn.Close()

	// Read DNS packets in a loop (a single PacketConn may carry multiple queries)
	for {
		queryBuf := buf.New()
		dest, err := conn.ReadPacket(queryBuf)
		if err != nil {
			queryBuf.Release()
			return // connection closed or error
		}

		dnsQuery := make([]byte, queryBuf.Len())
		copy(dnsQuery, queryBuf.Bytes())
		queryBuf.Release()

		if len(dnsQuery) < 12 {
			log.V("[TUN DNS] Query too short (%d bytes), ignoring", len(dnsQuery))
			continue
		}

		// Resolve each query concurrently (like sing-box's go func() pattern)
		go func(query []byte, replyDest M.Socksaddr) {
			response, err := h.dnsResolver.QueryRaw(ctx, query)
			if err != nil {
				log.Printf("[TUN DNS] Resolution failed: %v", err)
				return
			}

			if len(response) == 0 {
				log.Printf("[TUN DNS] Empty response")
				return
			}

			// Write DNS response back to TUN
			respBuf := buf.New()
			_, _ = respBuf.Write(response)
			if err := conn.WritePacket(respBuf, replyDest); err != nil {
				respBuf.Release()
				log.V("[TUN DNS] Failed to write response: %v", err)
				return
			}

			log.V("[TUN DNS] Resolved: %d bytes", len(response))
		}(dnsQuery, dest)
	}
}
