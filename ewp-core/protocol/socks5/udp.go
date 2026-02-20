package socks5

import (
	"fmt"
	"net"
	"sync"
	"time"

	commpool "ewp-core/common/bufferpool"
	"ewp-core/log"
	"ewp-core/transport"
)

const udpSessionIdleTimeout = 5 * time.Minute

// udpSession holds a persistent tunnel connection for one UDP destination.
type udpSession struct {
	tunnelConn transport.TunnelConn
	stopPing   chan struct{}
	lastActive time.Time
	mu         sync.Mutex
}

func (s *udpSession) touch() {
	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()
}

func (s *udpSession) close() {
	select {
	case <-s.stopPing:
	default:
		close(s.stopPing)
	}
	s.tunnelConn.Close()
}

// sessionMap manages per-destination UDP sessions.
type sessionMap struct {
	mu       sync.Mutex
	sessions map[string]*udpSession
}

func newSessionMap() *sessionMap {
	return &sessionMap{sessions: make(map[string]*udpSession)}
}

func (m *sessionMap) getOrCreate(target string, dialFn func() (transport.TunnelConn, error)) (*udpSession, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, ok := m.sessions[target]; ok {
		return s, false, nil
	}

	conn, err := dialFn()
	if err != nil {
		return nil, true, fmt.Errorf("dial tunnel: %w", err)
	}

	stopPing := conn.StartPing(30 * time.Second)
	s := &udpSession{
		tunnelConn: conn,
		stopPing:   stopPing,
		lastActive: time.Now(),
	}
	m.sessions[target] = s
	return s, true, nil
}

func (m *sessionMap) closeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.sessions {
		s.close()
	}
	m.sessions = make(map[string]*udpSession)
}

func (m *sessionMap) closeIdle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for target, s := range m.sessions {
		s.mu.Lock()
		idle := now.Sub(s.lastActive) > udpSessionIdleTimeout
		s.mu.Unlock()
		if idle {
			s.close()
			delete(m.sessions, target)
			log.V("[UDP] Session idle-expired: %s", target)
		}
	}
}

// HandleUDPAssociate handles a SOCKS5 UDP ASSOCIATE command.
// dnsHandler handles DNS-over-HTTPS (port 53 traffic).
// dialFn creates new tunnel connections for non-DNS UDP targets.
func HandleUDPAssociate(
	tcpConn net.Conn,
	clientAddr string,
	dnsHandler func([]byte) ([]byte, error),
	dialFn func() (transport.TunnelConn, error),
) error {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		log.Printf("[UDP] %s resolve address failed: %v", clientAddr, err)
		SendErrorReply(tcpConn)
		return err
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("[UDP] %s listen failed: %v", clientAddr, err)
		SendErrorReply(tcpConn)
		return err
	}

	localPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	log.Printf("[UDP] %s UDP ASSOCIATE on port %d", clientAddr, localPort)

	response := []byte{Version5, ReplySuccess, 0x00, AddressTypeIPv4}
	response = append(response, 127, 0, 0, 1)
	response = append(response, byte(localPort>>8), byte(localPort&0xff))
	if _, err := tcpConn.Write(response); err != nil {
		udpConn.Close()
		return err
	}

	// Parse the client's TCP source IP for source validation.
	clientIP := parseClientIP(clientAddr)

	sessions := newSessionMap()
	stopChan := make(chan struct{})

	go relayUDPLoop(udpConn, clientAddr, clientIP, stopChan, dnsHandler, dialFn, sessions)

	// Block until the control TCP connection is closed (any read/error).
	tcpConn.SetReadDeadline(time.Time{})
	buf := make([]byte, 1)
	tcpConn.Read(buf)

	close(stopChan)
	udpConn.Close()
	sessions.closeAll()

	log.Printf("[UDP] %s UDP ASSOCIATE closed", clientAddr)
	return nil
}

func parseClientIP(clientAddr string) net.IP {
	host, _, err := net.SplitHostPort(clientAddr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

func relayUDPLoop(
	udpConn *net.UDPConn,
	clientAddr string,
	clientIP net.IP,
	stopChan chan struct{},
	dnsHandler func([]byte) ([]byte, error),
	dialFn func() (transport.TunnelConn, error),
	sessions *sessionMap,
) {
	idleTicker := time.NewTicker(1 * time.Minute)
	defer idleTicker.Stop()

	buf := commpool.GetUDP()
	defer commpool.PutUDP(buf)

	var lastSenderAddr *net.UDPAddr

	for {
		select {
		case <-stopChan:
			return
		case <-idleTicker.C:
			sessions.closeIdle()
			continue
		default:
		}

		udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, senderAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		// Source validation: only accept packets from the client that initiated ASSOCIATE.
		if clientIP != nil && !senderAddr.IP.Equal(clientIP) {
			log.V("[UDP] %s rejected packet from unexpected source %s", clientAddr, senderAddr)
			continue
		}

		if n < 10 {
			continue
		}

		// RSV(2) + FRAG(1) check.
		if buf[0] != 0x00 || buf[1] != 0x00 {
			continue
		}
		if buf[2] != 0x00 {
			log.V("[UDP] %s fragmented UDP not supported (frag=%d)", clientAddr, buf[2])
			continue
		}

		atyp := buf[3]
		var headerLen int
		var dstHost string
		var dstPort int

		switch atyp {
		case AddressTypeIPv4:
			if n < 10 {
				continue
			}
			dstHost = net.IP(buf[4:8]).String()
			dstPort = int(buf[8])<<8 | int(buf[9])
			headerLen = 10

		case AddressTypeDomain:
			if n < 5 {
				continue
			}
			domainLen := int(buf[4])
			if n < 7+domainLen {
				continue
			}
			dstHost = string(buf[5 : 5+domainLen])
			dstPort = int(buf[5+domainLen])<<8 | int(buf[6+domainLen])
			headerLen = 7 + domainLen

		case AddressTypeIPv6:
			if n < 22 {
				continue
			}
			dstHost = net.IP(buf[4:20]).String()
			dstPort = int(buf[20])<<8 | int(buf[21])
			headerLen = 22

		default:
			continue
		}

		target := fmt.Sprintf("%s:%d", dstHost, dstPort)

		headerCopy := make([]byte, headerLen)
		copy(headerCopy, buf[:headerLen])
		payloadCopy := make([]byte, n-headerLen)
		copy(payloadCopy, buf[headerLen:n])

		lastSenderAddr = senderAddr

		if dstPort == 53 && dnsHandler != nil {
			log.V("[UDP-DNS] %s -> %s", clientAddr, target)
			go handleDNSRelay(udpConn, senderAddr, payloadCopy, headerCopy, dnsHandler)
		} else {
			if dstPort == 3478 || dstPort == 19302 {
				log.Printf("[UDP-STUN] %s -> %s (WebRTC STUN tunneled)", clientAddr, target)
			} else {
				log.V("[UDP] %s -> %s", clientAddr, target)
			}
			go handleTunnelUDP(udpConn, senderAddr, payloadCopy, headerCopy, target, sessions, dialFn, &lastSenderAddr)
		}
	}
}

func handleDNSRelay(
	udpConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	dnsQuery []byte,
	socks5Header []byte,
	dnsHandler func([]byte) ([]byte, error),
) {
	resp, err := dnsHandler(dnsQuery)
	if err != nil {
		log.Printf("[UDP-DNS] DoH query failed: %v", err)
		return
	}
	response := make([]byte, 0, len(socks5Header)+len(resp))
	response = append(response, socks5Header...)
	response = append(response, resp...)
	if _, err := udpConn.WriteToUDP(response, clientAddr); err != nil {
		log.V("[UDP-DNS] write response failed: %v", err)
	}
}

func handleTunnelUDP(
	udpConn *net.UDPConn,
	clientAddr *net.UDPAddr,
	payload []byte,
	socks5Header []byte,
	target string,
	sessions *sessionMap,
	dialFn func() (transport.TunnelConn, error),
	lastSender **net.UDPAddr,
) {
	session, isNew, err := sessions.getOrCreate(target, dialFn)
	if err != nil {
		log.Printf("[UDP] %s tunnel dial failed for %s: %v", clientAddr, target, err)
		return
	}

	if isNew {
		if err := session.tunnelConn.ConnectUDP(target, payload); err != nil {
			log.Printf("[UDP] %s ConnectUDP failed for %s: %v", clientAddr, target, err)
			sessions.mu.Lock()
			delete(sessions.sessions, target)
			sessions.mu.Unlock()
			session.close()
			return
		}
		// Start response reader goroutine for this session.
		go readTunnelResponses(udpConn, session, socks5Header, target, lastSender)
	} else {
		if err := session.tunnelConn.WriteUDP(target, payload); err != nil {
			log.V("[UDP] %s WriteUDP failed for %s: %v", clientAddr, target, err)
		}
	}
	session.touch()
}

func readTunnelResponses(
	udpConn *net.UDPConn,
	session *udpSession,
	socks5Header []byte,
	target string,
	lastSender **net.UDPAddr,
) {
	for {
		payload, err := session.tunnelConn.ReadUDP()
		if err != nil {
			log.V("[UDP] Tunnel response read ended for %s: %v", target, err)
			return
		}
		if len(payload) == 0 {
			continue
		}

		session.touch()

		sender := *lastSender
		if sender == nil {
			continue
		}

		response := make([]byte, 0, len(socks5Header)+len(payload))
		response = append(response, socks5Header...)
		response = append(response, payload...)

		if _, err := udpConn.WriteToUDP(response, sender); err != nil {
			log.V("[UDP] write response to client failed for %s: %v", target, err)
		}
	}
}
