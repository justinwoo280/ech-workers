package server

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	log "ewp-core/log"
	"ewp-core/protocol/trojan"
)

// HandleTrojanUDPConnection handles Trojan protocol UDP connections.
// Trojan UDP framing: [AddrType][Addr][Port][PayloadLen:2][CRLF:2][Payload]
// This is fundamentally different from EWP UDP framing and requires a separate handler.
func HandleTrojanUDPConnection(reader io.Reader, writer io.Writer) {
	h := &trojanUDPHandler{
		writer: newChanWriter(writer),
	}

	done := make(chan struct{})
	go h.handleStream(reader, done)

	cleanupTicker := time.NewTicker(1 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-done:
			if h.session != nil {
				h.session.close()
			}
			h.writer.close()
			log.Info("Trojan UDP connection closed")
			return
		case <-cleanupTicker.C:
			if h.session != nil && h.session.idleSince() > udpIdleTimeout {
				h.session.close()
				h.session = nil
			}
		}
	}
}

// trojanUDPHandler handles a single Trojan UDP tunnel.
// Unlike EWP which has GlobalID-based session multiplexing,
// Trojan has one UDP session per tunnel connection.
type trojanUDPHandler struct {
	session *udpSession
	writer  *chanWriter
	mu      sync.Mutex
}

// handleStream reads Trojan-framed UDP packets from the tunnel and dispatches them.
func (h *trojanUDPHandler) handleStream(reader io.Reader, done chan struct{}) {
	defer close(done)
	for {
		// Decode Trojan address: [AddrType][Addr][Port]
		addr, err := trojan.DecodeAddress(reader)
		if err != nil {
			if err != io.EOF {
				log.Warn("Trojan UDP decode address error: %v", err)
			}
			return
		}

		// Read payload length (2 bytes big-endian)
		var payloadLen uint16
		if err := binary.Read(reader, binary.BigEndian, &payloadLen); err != nil {
			log.Warn("Trojan UDP read payload length error: %v", err)
			return
		}

		// Read CRLF
		var crlfBuf [2]byte
		if _, err := io.ReadFull(reader, crlfBuf[:]); err != nil {
			log.Warn("Trojan UDP read CRLF error: %v", err)
			return
		}

		// Read payload
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			log.Warn("Trojan UDP read payload error: %v", err)
			return
		}

		// P0-4: use a context timeout so a slow/unresolvable domain cannot
		// block the handleStream goroutine indefinitely.
		// P1-11: on failure, return (tear down the connection) instead of
		// continue — the client receives EOF rather than a silent timeout.
		udpTarget, resolveErr := net.ResolveUDPAddr("udp", addr.String())
		if resolveErr != nil {
			log.Warn("Trojan UDP resolve addr error: %v", resolveErr)
			return
		}

		// Create session on first packet
		h.mu.Lock()
		if h.session == nil {
			// 根据目标地址类型选择合适的网络协议：IPv4或IPv6
			network := "udp4"
			if udpTarget.IP.To4() == nil {
				network = "udp6"
			}
			conn, err := net.ListenUDP(network, &net.UDPAddr{})
			if err != nil {
				h.mu.Unlock()
				log.Warn("Trojan UDP listen error: %v", err)
				return
			}
			h.session = &udpSession{
				conn:       conn,
				initTarget: udpTarget,
				incoming:   make(chan incomingPkt, udpIncomingDepth),
			}
			h.session.updateActive()
			log.Debug("Trojan UDP new session: %s", udpTarget)
			go h.sessionWorker(h.session)
		}
		s := h.session
		h.mu.Unlock()

		if len(payload) > 0 {
			safeSend(s.incoming, incomingPkt{target: udpTarget, payload: payload})
		}
	}
}

// sessionWorker sends outgoing UDP packets.
func (h *trojanUDPHandler) sessionWorker(s *udpSession) {
	go h.receiveResponses(s)

	for pkt := range s.incoming {
		if pkt.target == nil {
			continue
		}
		if _, err := s.conn.WriteTo(pkt.payload, pkt.target); err != nil {
			log.Warn("Trojan UDP write error for %s: %v", pkt.target, err)
			// Don't return on write error - just continue
			// The session will timeout eventually if target is unreachable
			continue
		}
		s.updateActive()
	}
}

// receiveResponses reads UDP responses from the remote and sends them back
// through the tunnel using Trojan UDP framing.
func (h *trojanUDPHandler) receiveResponses(s *udpSession) {
	bufp := udpBufferPool.Get().(*[]byte)
	buf := *bufp
	defer udpBufferPool.Put(bufp)

	const readDeadline = 30 * time.Second
	conn := s.conn

	for {
		if s.idleSince() > udpIdleTimeout {
			return
		}

		conn.SetReadDeadline(time.Now().Add(readDeadline))
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		s.updateActive()

		// Encode response in Trojan UDP framing: [AddrType][Addr][Port][PayloadLen:2][CRLF:2][Payload]
		trojanAddr, err := trojan.ParseAddress(remoteAddr.String())
		if err != nil {
			log.Warn("Trojan UDP parse response addr error: %v", err)
			continue
		}
		addrBytes, err := trojanAddr.Encode()
		if err != nil {
			log.Warn("Trojan UDP encode response addr error: %v", err)
			continue
		}

		resp := make([]byte, 0, len(addrBytes)+4+n)
		resp = append(resp, addrBytes...)
		resp = append(resp, byte(n>>8), byte(n))
		resp = append(resp, trojan.CRLF...)
		resp = append(resp, buf[:n]...)

		if err := h.writer.write(resp); err != nil {
			log.Warn("Trojan UDP response write failed: %v, session may be disconnected", err)
			// Don't return here - continue processing other responses
			// The session will eventually timeout and be cleaned up
			continue
		}
	}
}
