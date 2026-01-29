package protocol

import (
	"bufio"
	"net"
	"time"

	commonnet "ewp-core/common/net"
	"ewp-core/dns"
	httpproxy "ewp-core/protocol/http"
	"ewp-core/protocol/socks5"
	"ewp-core/log"
	"ewp-core/transport"
)

type Server struct {
	listenAddr  string
	tunnelHandler *TunnelHandler
	dnsClient   *dns.Client
}

func NewServer(listenAddr string, trans transport.Transport, dnsServer string) *Server {
	return &Server{
		listenAddr:  listenAddr,
		tunnelHandler: NewTunnelHandler(trans),
		dnsClient:   dns.NewClient(dnsServer),
	}
}

func (s *Server) Run() error {
	listener, err := commonnet.ListenTFO("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer listener.Close()

	log.Printf("[Proxy] Server started: %s (SOCKS5 + HTTP) with TCP Fast Open", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("[Proxy] Accept connection failed: %v", err)
			continue
		}

		go s.handleConnection(conn)
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
		return socks5.HandleUDPAssociate(conn, clientAddr, dnsHandler)
	}

	if err := socks5.HandleConnection(conn, reader, onConnect, onUDPAssociate); err != nil {
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
