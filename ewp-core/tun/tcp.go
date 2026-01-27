package tun

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	commpool "ewp-core/common/bufferpool"
	"ewp-core/log"
	"ewp-core/transport"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type TCPHandler struct {
	stack     *stack.Stack
	transport transport.Transport
	connCount int64
}

func NewTCPHandler(st *stack.Stack, trans transport.Transport) *TCPHandler {
	return &TCPHandler{
		stack:     st,
		transport: trans,
	}
}

func (h *TCPHandler) Start() error {
	var wq waiter.Queue
	ep, err := h.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return fmt.Errorf("create endpoint failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{
		Port: 0,
	}); err != nil {
		return fmt.Errorf("bind failed: %v", err)
	}

	if err := ep.Listen(128); err != nil {
		return fmt.Errorf("listen failed: %v", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	for {
		n, wq, err := ep.Accept(nil)
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}
			log.Printf("[TCP] Accept connection failed: %v", err)
			continue
		}

		go h.handleConnection(n, wq)
	}
}

func (h *TCPHandler) handleConnection(ep tcpip.Endpoint, wq *waiter.Queue) {
	defer ep.Close()

	atomic.AddInt64(&h.connCount, 1)
	connID := atomic.LoadInt64(&h.connCount)

	remoteAddr, _ := ep.GetRemoteAddress()
	localAddr, _ := ep.GetLocalAddress()

	target := fmt.Sprintf("%s:%d", net.IP(remoteAddr.Addr.AsSlice()).String(), remoteAddr.Port)
	log.Printf("[TCP:%d] New connection: %s:%d -> %s", connID,
		net.IP(localAddr.Addr.AsSlice()).String(), localAddr.Port, target)

	conn := gonet.NewTCPConn(wq, ep)
	defer conn.Close()

	tunnelConn, err := h.transport.Dial()
	if err != nil {
		log.Printf("[TCP:%d] Tunnel connection failed: %v", connID, err)
		return
	}
	defer tunnelConn.Close()

	stopPing := tunnelConn.StartPing(10 * time.Second)
	defer close(stopPing)

	if err := tunnelConn.Connect(target, nil); err != nil {
		log.Printf("[TCP:%d] CONNECT failed: %v", connID, err)
		return
	}

	log.Printf("[TCP:%d] Connected: %s", connID, target)

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
	log.Printf("[TCP:%d] Disconnected: %s", connID, target)
}
