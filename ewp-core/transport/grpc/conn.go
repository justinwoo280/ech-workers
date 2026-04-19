package grpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
	pb "ewp-core/proto"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
	"ewp-core/transport"

	"google.golang.org/grpc"
)

type Conn struct {
	conn              *grpc.ClientConn
	stream            grpc.ClientStream
	uuid              [16]byte
	password          string
	key               [trojan.KeyLength]byte
	mu                sync.Mutex
	enableFlow        bool
	useTrojan         bool
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
	udpGlobalID       [8]byte
	leftover          []byte
	ctx               context.Context    // P2-13: Context for stream cancellation
	cancel            context.CancelFunc // P2-13: Cancel func to unblock RecvMsg

	// P1-UDP-OPT: 可重用缓冲区用于 WriteUDP（零分配热路径）
	udpWriteBuf []byte
	udpWriteMu  sync.Mutex
}

func NewConn(conn *grpc.ClientConn, stream grpc.ClientStream, uuid [16]byte, password string, enableFlow, useTrojan bool, ctx context.Context, cancel context.CancelFunc) *Conn {
	c := &Conn{
		conn:       conn,
		stream:     stream,
		uuid:       uuid,
		password:   password,
		enableFlow: enableFlow,
		useTrojan:  useTrojan,
		ctx:        ctx,    // P2-13: Store context for cancellation
		cancel:     cancel, // P2-13: Store cancel func
	}
	if useTrojan {
		c.key = trojan.GenerateKey(password)
	}
	return c
}

func (c *Conn) Connect(target string, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojan(target, initialData)
	}
	return c.connectEWP(target, initialData)
}

func (c *Conn) connectTrojan(target string, initialData []byte) error {
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	var handshakeData []byte
	handshakeData = append(handshakeData, c.key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandTCP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	// Append initial data
	if len(initialData) > 0 {
		handshakeData = append(handshakeData, initialData...)
	}

	c.mu.Lock()
	err = c.stream.SendMsg(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send trojan handshake: %w", err)
	}

	log.V("[Trojan] gRPC handshake sent, target: %s", target)
	return nil
}

func (c *Conn) ConnectUDP(target transport.Endpoint, initialData []byte) error {
	if c.useTrojan {
		return c.connectTrojanUDP(target, initialData)
	}
	return c.connectEWPUDP(target, initialData)
}

func (c *Conn) connectTrojanUDP(target transport.Endpoint, initialData []byte) error {

	var handshakeData []byte
	handshakeData = append(handshakeData, c.key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandUDP)

	if target.Domain != "" {
		handshakeData = append(handshakeData, trojan.AddressTypeDomain, byte(len(target.Domain)))
		handshakeData = append(handshakeData, []byte(target.Domain)...)
		handshakeData = append(handshakeData, byte(target.Port>>8), byte(target.Port))
	} else {
		handshakeData = trojan.AppendAddrPort(handshakeData, target.Addr)
	}
	handshakeData = append(handshakeData, trojan.CRLF...)

	c.mu.Lock()
	err := c.stream.SendMsg(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send trojan UDP handshake: %w", err)
	}

	// For Trojan UDP, no additional EWP UDPStatusNew packet is needed.
	// The UDP handshake and target are already sent.

	log.V("[Trojan] gRPC UDP handshake sent, target: %s", target)
	return nil
}

func (c *Conn) connectEWP(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	c.mu.Lock()
	err = c.stream.SendMsg(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	respMsg := &pb.SocketData{}
	err = c.stream.RecvMsg(respMsg)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respMsg.Content, req.Version, req.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	if len(initialData) > 0 {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	log.V("[EWP] gRPC handshake success, target: %s", target)
	return nil
}

func (c *Conn) connectEWPUDP(target transport.Endpoint, initialData []byte) error {
	var addr ewp.Address
	if target.Domain != "" {
		addr = ewp.Address{Type: ewp.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = ewp.AddressFromAddrPort(target.Addr)
	}

	ewpReq := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)
	handshakeData, err := ewpReq.Encode()
	if err != nil {
		return fmt.Errorf("encode EWP UDP handshake: %w", err)
	}

	c.mu.Lock()
	err = c.stream.SendMsg(&pb.SocketData{Content: handshakeData})
	c.mu.Unlock()
	if err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	respMsg := &pb.SocketData{}
	err = c.stream.RecvMsg(respMsg)
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respMsg.Content, ewpReq.Version, ewpReq.Nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
		c.writeOnceUserUUID = make([]byte, 16)
		copy(c.writeOnceUserUUID, c.uuid[:])
	}

	// Always send UDPStatusNew to establish session on server (with target address)
	c.udpGlobalID = ewp.NewGlobalID()

	var encoded []byte
	if target.Domain != "" {
		// Send domain directly to server; local DNS resolution would return a FakeIP in TUN mode.
		pkt := &ewp.UDPPacketDomain{
			GlobalID: c.udpGlobalID,
			Status:   ewp.UDPStatusNew,
			Domain:   target.Domain,
			Port:     target.Port,
			Payload:  initialData,
		}
		var encErr error
		encoded, encErr = ewp.EncodeUDPDomainPacket(pkt)
		if encErr != nil {
			return fmt.Errorf("encode UDP domain packet: %w", encErr)
		}
	} else {
		pkt := &ewp.UDPPacketAddr{
			GlobalID: c.udpGlobalID,
			Status:   ewp.UDPStatusNew,
			Target:   target.Addr,
			Payload:  initialData,
		}
		var encErr error
		encoded, encErr = ewp.EncodeUDPAddrPacket(pkt)
		if encErr != nil {
			return fmt.Errorf("encode UDP packet: %w", encErr)
		}
	}

	if err := c.Write(encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}

	log.V("[EWP] gRPC UDP handshake success, target: %s", target)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel (StatusKeep)
func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
	c.udpWriteMu.Lock()
	defer c.udpWriteMu.Unlock()

	if c.useTrojan {
		return c.writeTrojanUDPPooled(target, data)
	}

	// P1-UDP-OPT: EWP 路径使用可重用缓冲区
	requiredCap := 2 + 8 + 1 + 1 + 19 + 2 + len(data) // 最大尺寸（IPv6）
	if target.Domain != "" {
		requiredCap = 2 + 8 + 1 + 1 + (1 + 1 + len(target.Domain) + 2) + 2 + len(data)
	}

	if cap(c.udpWriteBuf) < requiredCap {
		c.udpWriteBuf = make([]byte, 0, requiredCap)
	}

	c.udpWriteBuf = c.udpWriteBuf[:0]

	if target.Domain != "" {
		c.udpWriteBuf = ewp.AppendUDPDomainFrame(
			c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep,
			target.Domain, target.Port, data,
		)
	} else {
		c.udpWriteBuf = ewp.AppendUDPAddrFrame(
			c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep,
			target.Addr, data,
		)
	}

	return c.Write(c.udpWriteBuf)
}

func (c *Conn) writeTrojanUDPPooled(target transport.Endpoint, data []byte) error {
	// P1-UDP-OPT: Trojan 路径使用可重用缓冲区
	length := uint16(len(data))
	addrLen := 7
	if target.Domain != "" {
		addrLen = 1 + 1 + len(target.Domain) + 2
	} else if target.Addr.Addr().Is6() {
		addrLen = 19
	}

	requiredCap := addrLen + 4 + len(data)
	if cap(c.udpWriteBuf) < requiredCap {
		c.udpWriteBuf = make([]byte, 0, requiredCap)
	}

	c.udpWriteBuf = c.udpWriteBuf[:0]

	if target.Domain != "" {
		c.udpWriteBuf = append(c.udpWriteBuf, trojan.AddressTypeDomain, byte(len(target.Domain)))
		c.udpWriteBuf = append(c.udpWriteBuf, []byte(target.Domain)...)
		c.udpWriteBuf = append(c.udpWriteBuf, byte(target.Port>>8), byte(target.Port))
	} else {
		c.udpWriteBuf = trojan.AppendAddrPort(c.udpWriteBuf, target.Addr)
	}
	c.udpWriteBuf = append(c.udpWriteBuf, byte(length>>8), byte(length))
	c.udpWriteBuf = append(c.udpWriteBuf, trojan.CRLF...)
	c.udpWriteBuf = append(c.udpWriteBuf, data...)

	c.mu.Lock()
	err := c.stream.SendMsg(&pb.SocketData{Content: c.udpWriteBuf})
	c.mu.Unlock()
	return err
}

// ReadUDP reads and decodes an EWP-framed or Trojan-framed UDP response packet
func (c *Conn) ReadUDP() ([]byte, error) {
	resp := &pb.SocketData{}
	if err := c.stream.RecvMsg(resp); err != nil {
		return nil, err
	}
	data := resp.Content
	
	if c.useTrojan {
		// Trojan UDP decode: [Address][Length(16)][CRLF][Payload]
		// In gRPC stream, each RecvMsg usually contains exactly one frame
		// but we still need to strip the header
		// Fake an io.Reader to use DecodeAddress, though we have all data in memory
		// Actually, since this is a datagram, we can just slice it manually
		if len(data) < 4 { // Minimal size
			return nil, fmt.Errorf("trojan udp frame too small")
		}
		// Skip Type(1)+Length(...) 
		// Easy way: find CRLF since address can't contain CRLF
		// It's safer to just decode address.
		// For simplicity, we can use bytes.Index(data, trojan.CRLF) if we assume host doesn't have CRLF
		// But port is 2 bytes which might be \r\n. So we must parse.
		// Wait, we can just use io.ReadFull from bytes.Reader 
		// Actually we just return the payload, let me implement a quick slicer
		return decodeTrojanUDP(data)
	}

	if c.enableFlow && c.flowState != nil {
		data = c.flowState.ProcessDownlink(data)
	}
	return ewp.DecodeUDPPayload(data)
}

// ReadUDPTo reads and decodes an EWP-framed UDP response packet directly into the provided buffer
func (c *Conn) ReadUDPTo(buf []byte) (int, error) {
	resp := &pb.SocketData{}
	if err := c.stream.RecvMsg(resp); err != nil {
		return 0, err
	}
	data := resp.Content

	if c.useTrojan {
		payload, err := decodeTrojanUDP(data)
		if err != nil {
			return 0, err
		}
		n := copy(buf, payload)
		return n, nil
	}

	if c.enableFlow && c.flowState != nil {
		data = c.flowState.ProcessDownlink(data)
	}
	return ewp.DecodeUDPPayloadTo(data, buf)
}

// ReadUDPFrom reads a UDP response and returns the real remote address.
func (c *Conn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	resp := &pb.SocketData{}
	if err := c.stream.RecvMsg(resp); err != nil {
		return 0, netip.AddrPort{}, err
	}
	data := resp.Content

	if c.useTrojan {
		payload, addr, err := decodeTrojanUDPWithAddr(data)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		n := copy(buf, payload)
		return n, addr, nil
	}

	if c.enableFlow && c.flowState != nil {
		data = c.flowState.ProcessDownlink(data)
	}
	return ewp.DecodeUDPAddrPayloadTo(data, buf)
}

func decodeTrojanUDP(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty trojan udp payload")
	}
	offset := 1
	var addrLen int
	switch data[0] {
	case trojan.AddressTypeIPv4:
		addrLen = 4
	case trojan.AddressTypeIPv6:
		addrLen = 16
	case trojan.AddressTypeDomain:
		if len(data) < 2 {
			return nil, fmt.Errorf("truncated trojan domain")
		}
		addrLen = int(data[1])
		offset++
	default:
		return nil, fmt.Errorf("unknown trojan address type: %d", data[0])
	}
	
	headerLen := offset + addrLen + 2 // Type + Addr + Port
	if len(data) < headerLen+4 { // + Length(2) + CRLF(2)
		return nil, fmt.Errorf("truncated trojan udp header")
	}
	
	payloadLen := int(data[headerLen])<<8 | int(data[headerLen+1])
	payloadStart := headerLen + 4
	
	if len(data) < payloadStart+payloadLen {
		return nil, fmt.Errorf("truncated trojan udp payload")
	}
	return data[payloadStart : payloadStart+payloadLen], nil
}

func decodeTrojanUDPWithAddr(data []byte) ([]byte, netip.AddrPort, error) {
	if len(data) < 1 {
		return nil, netip.AddrPort{}, fmt.Errorf("empty trojan udp payload")
	}
	offset := 1
	var addrLen int
	var remoteAddr netip.AddrPort

	switch data[0] {
	case trojan.AddressTypeIPv4:
		addrLen = 4
		if len(data) >= offset+addrLen+2 {
			ip := netip.AddrFrom4(*(*[4]byte)(data[offset : offset+addrLen]))
			port := binary.BigEndian.Uint16(data[offset+addrLen : offset+addrLen+2])
			remoteAddr = netip.AddrPortFrom(ip, port)
		}
	case trojan.AddressTypeIPv6:
		addrLen = 16
		if len(data) >= offset+addrLen+2 {
			ip := netip.AddrFrom16(*(*[16]byte)(data[offset : offset+addrLen]))
			port := binary.BigEndian.Uint16(data[offset+addrLen : offset+addrLen+2])
			remoteAddr = netip.AddrPortFrom(ip, port)
		}
	case trojan.AddressTypeDomain:
		if len(data) < 2 {
			return nil, netip.AddrPort{}, fmt.Errorf("truncated trojan domain")
		}
		addrLen = int(data[1])
		offset++
	default:
		return nil, netip.AddrPort{}, fmt.Errorf("unknown trojan address type: %d", data[0])
	}
	
	headerLen := offset + addrLen + 2
	if len(data) < headerLen+4 {
		return nil, netip.AddrPort{}, fmt.Errorf("truncated trojan udp header")
	}
	
	payloadLen := int(data[headerLen])<<8 | int(data[headerLen+1])
	payloadStart := headerLen + 4
	
	if len(data) < payloadStart+payloadLen {
		return nil, netip.AddrPort{}, fmt.Errorf("truncated trojan udp payload")
	}
	return data[payloadStart : payloadStart+payloadLen], remoteAddr, nil
}

func (c *Conn) Read(buf []byte) (int, error) {
	var data []byte
	if len(c.leftover) > 0 {
		data = c.leftover
		c.leftover = nil
	} else {
		resp := &pb.SocketData{}
		if err := c.stream.RecvMsg(resp); err != nil {
			return 0, err
		}
		data = resp.Content
		if !c.useTrojan && c.enableFlow && c.flowState != nil {
			data = c.flowState.ProcessDownlink(data)
		}
	}

	n := copy(buf, data)
	if n < len(data) {
		c.leftover = append([]byte(nil), data[n:]...)
	}
	return n, nil
}

func (c *Conn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stream == nil {
		return io.EOF
	}

	var writeData []byte
	// Only apply flow processing for EWP mode
	if !c.useTrojan && c.enableFlow && c.flowState != nil {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	err := c.stream.SendMsg(&pb.SocketData{Content: writeData})
	if err != nil {
		if strings.Contains(err.Error(), "transport is closing") ||
			strings.Contains(err.Error(), "connection reset") ||
			strings.Contains(err.Error(), "broken pipe") {
			return io.EOF
		}
	}
	return err
}

// Close closes the connection and cancels the stream context
// P2-13: Cancel context to ensure RecvMsg goroutine exits
func (c *Conn) Close() error {
	// P2-13: Cancel context first to unblock RecvMsg
	if c.cancel != nil {
		c.cancel()
	}
	if c.stream != nil {
		c.stream.CloseSend()
	}
	return nil
}

// StartPing implements the TunnelConn interface but is a no-op for gRPC.
// P2-12: gRPC connections rely on HTTP/2 PING frames and keepalive settings
// configured via SetKeepalive() rather than application-level pings.
// The returned channel is never closed and serves only to satisfy the interface.
func (c *Conn) StartPing(interval time.Duration) chan struct{} {
	stopChan := make(chan struct{})
	return stopChan
}
