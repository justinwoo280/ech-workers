package protocol

import (
	"bufio"
	"net"
	"time"

	commonnet "ewp-core/common/net"
	"ewp-core/dns"
	"ewp-core/log"
	httpproxy "ewp-core/protocol/http"
	"ewp-core/protocol/socks5"
	"ewp-core/transport"
)

const defaultMaxConnections = 4096

type Server struct {
	listenAddr    string
	tunnelHandler *TunnelHandler
	dnsClient     *dns.Client
	users         socks5.Users
	semaphore     chan struct{} // nil = unlimited
}

func NewServer(listenAddr string, trans transport.Transport, dnsServer string, users socks5.Users, maxConns int) *Server {
	s := &Server{
		listenAddr:    listenAddr,
		tunnelHandler: NewTunnelHandler(trans),
		dnsClient:     dns.NewClient(dnsServer),
		users:         users,
	}
	if maxConns <= 0 {
		maxConns = defaultMaxConnections
	}
	s.semaphore = make(chan struct{}, maxConns)
	return s
}

func (s *Server) Run() error {
	listener, err := commonnet.ListenTFO("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("[Proxy] Server started: %s (SOCKS5 + HTTP) with TCP Fast Open", s.listenAddr)
	log.Printf("[Proxy] ✅ SOCKS5: Full UDP support (WebRTC STUN/TURN tunneled)")
	log.Printf("[Proxy] ⚠️  HTTP: TCP only (WebRTC may leak, use SOCKS5 or TUN mode)")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[Proxy] Accept connection failed: %v", err)
			continue
		}

		select {
		case s.semaphore <- struct{}{}:
			go func() {
				defer func() { <-s.semaphore }()
				s.handleConnection(conn)
			}()
		default:
			log.Printf("[Proxy] Max connections reached, dropping connection from %s", conn.RemoteAddr())
			conn.Close()
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	reader := bufio.NewReader(conn)
	headerBytes, err := reader.Peek(1)
	if err != nil {
		log.V("[Proxy] %s peek first byte failed: %v", clientAddr, err)
		return
	}

	firstByte := headerBytes[0]

	switch firstByte {
	case 0x04, 0x05:
		s.handleSOCKS(conn, reader, clientAddr)
	default:
		s.handleHTTP(conn, reader, clientAddr)
	}
}

func (s *Server) handleSOCKS(conn net.Conn, reader *bufio.Reader, clientAddr string) {
	onConnect := func(conn net.Conn, req *socks5.Request, initialData []byte) error {
		return s.tunnelHandler.HandleTunnel(conn, req.Target, clientAddr, initialData, func() error {
			return socks5.SendSuccessReply(conn)
		})
	}

	onUDPAssociate := func(conn net.Conn, clientAddr string) error {
		dnsHandler := func(dnsQuery []byte) ([]byte, error) {
			return s.dnsClient.QueryRaw(dnsQuery)
		}
		return socks5.HandleUDPAssociate(conn, clientAddr, dnsHandler, s.tunnelHandler.Dial)
	}

	if err := socks5.HandleConnection(conn, reader, s.users, onConnect, onUDPAssociate); err != nil {
		if !IsNormalCloseError(err) {
			log.Printf("[SOCKS] %s proxy failed: %v", clientAddr, err)
		}
	}
}

func (s *Server) handleHTTP(conn net.Conn, reader *bufio.Reader, clientAddr string) {
	onConnect := func(conn net.Conn, target string) error {
		return s.tunnelHandler.HandleTunnel(conn, target, clientAddr, nil, func() error {
			return httpproxy.SendConnectSuccess(conn)
		})
	}

	onProxy := func(conn net.Conn, target string, firstFrame string) error {
		return s.tunnelHandler.HandleTunnel(conn, target, clientAddr, []byte(firstFrame), func() error {
			return nil
		})
	}

	if err := httpproxy.HandleConnection(conn, reader, onConnect, onProxy); err != nil {
		if !IsNormalCloseError(err) {
			log.Printf("[HTTP] %s proxy failed: %v", clientAddr, err)
		}
	}
}
