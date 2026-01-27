package tun

import (
	"bytes"
	"fmt"
	"net"

	"ewp-core/dns"
	"ewp-core/log"
	"ewp-core/transport"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type UDPHandler struct {
	stack      *stack.Stack
	transport  transport.Transport
	dnsClient  *dns.Client
	handler    *UDPConnectionHandler
	writeUDPFn func(src, dst *net.UDPAddr, payload []byte)
}

func NewUDPHandler(st *stack.Stack, trans transport.Transport, dnsServer string) *UDPHandler {
	h := &UDPHandler{
		stack:     st,
		transport: trans,
		dnsClient: dns.NewClient(dnsServer),
	}

	h.writeUDPFn = h.writeUDPResponse
	h.handler = NewUDPConnectionHandler(trans, h.writeUDPFn)

	log.Printf("[UDP] Full-Cone NAT handler started (IPv4/IPv6)")

	return h
}

func (h *UDPHandler) Start() {
	go h.handleIPv4()
	go h.handleIPv6()
}

func (h *UDPHandler) handleIPv4() {
	var wq waiter.Queue
	ep, err := h.stack.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		log.Fatalf("[UDP4] Create endpoint failed: %v", err)
	}

	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		log.Fatalf("[UDP4] Bind failed: %v", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	h.handleLoop(ep, notifyCh, false)
}

func (h *UDPHandler) handleIPv6() {
	var wq waiter.Queue
	ep, err := h.stack.NewEndpoint(udp.ProtocolNumber, ipv6.ProtocolNumber, &wq)
	if err != nil {
		log.Printf("[UDP6] Create endpoint failed: %v (IPv6 may not be enabled)", err)
		return
	}

	if err := ep.Bind(tcpip.FullAddress{}); err != nil {
		log.Printf("[UDP6] Bind failed: %v", err)
		return
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventIn)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	h.handleLoop(ep, notifyCh, true)
}

func (h *UDPHandler) handleLoop(ep tcpip.Endpoint, notifyCh chan struct{}, isIPv6 bool) {
	protoName := "UDP4"
	if isIPv6 {
		protoName = "UDP6"
	}

	for {
		var buf bytes.Buffer
		res, err := ep.Read(&buf, tcpip.ReadOptions{
			NeedRemoteAddr: true,
		})
		if err != nil {
			if _, ok := err.(*tcpip.ErrWouldBlock); ok {
				<-notifyCh
				continue
			}
			continue
		}
		addr := res.RemoteAddr

		data := buf.Bytes()
		if len(data) > 0 {
			if addr.Port == 53 {
				go h.handleDNSQuery(ep, &addr, data)
				continue
			}

			if h.handler != nil {
				var srcIP net.IP
				if isIPv6 {
					srcIP = net.ParseIP("fd00::1")
				} else {
					srcIP = net.ParseIP("10.0.0.1")
				}
				srcAddr := &net.UDPAddr{
					IP:   srcIP,
					Port: 12345,
				}
				dstAddr := &net.UDPAddr{
					IP:   net.IP(addr.Addr.AsSlice()),
					Port: int(addr.Port),
				}

				if err := h.handler.HandlePacket(srcAddr, dstAddr, data); err != nil {
					log.V("[%s] Handle failed: %v", protoName, err)
				}
			} else {
				target := fmt.Sprintf("%s:%d", net.IP(addr.Addr.AsSlice()).String(), addr.Port)
				log.V("[%s] Received packet -> %s (UDP handler not initialized)", protoName, target)
			}
		}
	}
}

func (h *UDPHandler) handleDNSQuery(ep tcpip.Endpoint, clientAddr *tcpip.FullAddress, query []byte) {
	dnsResponse, err := h.dnsClient.QueryRaw(query)
	if err != nil {
		log.Printf("[DNS] DoH query failed: %v", err)
		return
	}

	var buf bytes.Buffer
	buf.Write(dnsResponse)
	_, tcpipErr := ep.Write(&buf, tcpip.WriteOptions{
		To: clientAddr,
	})
	if tcpipErr != nil {
		log.Printf("[DNS] Send response failed: %v", tcpipErr)
		return
	}

	log.Printf("[DNS] Query successful: %d bytes", len(dnsResponse))
}

func (h *UDPHandler) writeUDPResponse(src, dst *net.UDPAddr, payload []byte) {
	isIPv6 := src.IP.To4() == nil

	var srcIP, dstIP []byte
	var networkProto tcpip.NetworkProtocolNumber

	if isIPv6 {
		srcIP = src.IP.To16()
		dstIP = dst.IP.To16()
		networkProto = ipv6.ProtocolNumber
	} else {
		srcIP = src.IP.To4()
		dstIP = dst.IP.To4()
		networkProto = ipv4.ProtocolNumber
	}

	srcAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(srcIP),
		Port: uint16(src.Port),
	}
	dstAddr := tcpip.FullAddress{
		Addr: tcpip.AddrFromSlice(dstIP),
		Port: uint16(dst.Port),
	}

	var respWq waiter.Queue
	respEp, err := h.stack.NewEndpoint(udp.ProtocolNumber, networkProto, &respWq)
	if err != nil {
		log.V("[UDP] Create response endpoint failed: %v", err)
		return
	}
	defer respEp.Close()

	if err := respEp.Bind(srcAddr); err != nil {
		log.V("[UDP] Bind source address failed: %v", err)
		return
	}

	var buf bytes.Buffer
	buf.Write(payload)
	_, tcpipErr := respEp.Write(&buf, tcpip.WriteOptions{
		To: &dstAddr,
	})
	if tcpipErr != nil {
		log.V("[UDP] Send response failed: %v", tcpipErr)
	}
}

func (h *UDPHandler) Close() {
	if h.handler != nil {
		h.handler.Close()
	}
}
