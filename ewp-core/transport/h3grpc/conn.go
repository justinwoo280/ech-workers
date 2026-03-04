package h3grpc

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"ewp-core/log"
	pb "ewp-core/proto"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"
	"ewp-core/transport"

	"google.golang.org/protobuf/proto"
)

// Conn implements transport.TunnelConn for HTTP/3
type Conn struct {
	transport  *Transport
	request    *http.Request
	response   *http.Response

	uuid       [16]byte
	password   string
	key        [trojan.KeyLength]byte
	enableFlow bool
	useTrojan  bool

	encoder *GRPCWebEncoder
	decoder *GRPCWebDecoder

	// Flow control (EWP Vision)
	flowState *ewp.FlowState

	// Trojan (simplified, without mux for now)
	trojanConnected bool

	// Channels for async I/O
	recvChan  chan []byte
	sendChan  chan []byte
	closeChan chan struct{}
	connReady chan struct{} // closed when H3 connection is established

	// State
	connected      bool
	closed         bool
	mu             sync.Mutex
	closeOnce      sync.Once
	cancelFn       context.CancelFunc
	activePipeRead *io.PipeReader // active request body; closed on Close()
	udpGlobalID    [8]byte
	readLeftover   []byte // unread bytes from the previous recvChan pop

	// Goroutine management
	wg sync.WaitGroup
}

// signalClose closes closeChan exactly once, safely from any goroutine.
func (c *Conn) signalClose() {
	c.closeOnce.Do(func() { close(c.closeChan) })
}

// establishH3 starts the HTTP/3 request and initialises encoder/decoder.
// It is safe to call only once. Returns immediately; callers must call
// waitConnected to know when the connection is ready.
// When ECH is enabled and the server rejects the key, the connection is
// retried once with the updated config supplied by the server.
func (c *Conn) establishH3() error {
	c.mu.Lock()
	if c.connected {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	go func() {
		var (
			resp       *http.Response
			pipeWriter *io.PipeWriter
		)

		const maxAttempts = 2
		for attempt := 0; attempt < maxAttempts; attempt++ {
			pr, pw := io.Pipe()

			ctx, cancel := context.WithCancel(context.Background())
			req := c.request.Clone(ctx)
			req.Body = pr

			c.mu.Lock()
			c.cancelFn = cancel
			c.activePipeRead = pr
			c.mu.Unlock()

			var err error
			resp, err = c.transport.getClient().Do(req)
			if err != nil {
				pw.CloseWithError(err)
				cancel()

				// On first attempt only: try ECH retry
				if attempt == 0 && c.transport.useECH {
					if retryErr := c.transport.handleECHRejection(err); retryErr == nil {
						log.Printf("[H3] ECH rejected by server, retrying with updated config")
						continue
					}
				}

				log.Printf("[H3] Request failed: %v", err)
				c.signalClose()
				return
			}

			pipeWriter = pw
			break
		}

		if resp == nil {
			c.signalClose()
			return
		}

		c.mu.Lock()
		c.response = resp
		c.encoder = NewGRPCWebEncoder(pipeWriter, false)
		c.decoder = NewGRPCWebDecoder(resp.Body)
		if c.enableFlow {
			c.flowState = ewp.NewFlowState(c.uuid[:])
		}
		c.connected = true
		c.mu.Unlock()

		log.V("[H3] HTTP/3 connection established")
		close(c.connReady)

		c.wg.Add(1)
		go c.receiveLoop()
	}()

	return nil
}

// waitConnected blocks until the H3 connection is ready or fails.
func (c *Conn) waitConnected() error {
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	select {
	case <-c.connReady:
		return nil
	case <-timer.C:
		return fmt.Errorf("connection timeout")
	case <-c.closeChan:
		return fmt.Errorf("connection closed")
	}
}

// Connect sends initial TCP connection request.
func (c *Conn) Connect(target string, initialData []byte) error {
	log.V("[H3] Connecting to target: %s", target)

	if err := c.establishH3(); err != nil {
		return err
	}
	if err := c.waitConnected(); err != nil {
		return err
	}

	if c.useTrojan {
		return c.trojanConnect(target, initialData)
	}
	return c.ewpConnect(target, initialData)
}

// ewpConnect sends EWP protocol connect request
func (c *Conn) ewpConnect(target string, initialData []byte) error {
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	socketData := &pb.SocketData{Content: handshakeData}
	data, err := proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("marshal handshake: %w", err)
	}
	if err := c.encoder.Encode(data); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	select {
	case respData := <-c.recvChan:
		resp, err := ewp.DecodeHandshakeResponse(respData, req.Version, req.Nonce, c.uuid)
		if err != nil {
			return fmt.Errorf("decode handshake response: %w", err)
		}
		if resp.Status != ewp.StatusOK {
			return fmt.Errorf("handshake failed: status=%d", resp.Status)
		}
	case <-c.closeChan:
		return fmt.Errorf("connection closed during handshake")
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
	}

	if len(initialData) > 0 {
		if err := c.Write(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	log.V("[H3] EWP TCP connect ok: %s", target)
	return nil
}

// trojanConnect sends Trojan protocol connect request
func (c *Conn) trojanConnect(target string, initialData []byte) error {
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

	// Send handshake
	socketData := &pb.SocketData{Content: handshakeData}
	data, err := proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("failed to marshal handshake: %w", err)
	}

	if err := c.encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	c.trojanConnected = true
	log.V("[H3] Trojan connect sent for %s", target)
	return nil
}

// ConnectUDP sends initial UDP connection request.
func (c *Conn) ConnectUDP(target transport.Endpoint, initialData []byte) error {
	if err := c.establishH3(); err != nil {
		return err
	}
	if err := c.waitConnected(); err != nil {
		return err
	}

	if c.useTrojan {
		return c.trojanConnectUDP(target, initialData)
	}
	return c.ewpConnectUDP(target, initialData)
}

// trojanConnectUDP sends Trojan protocol UDP connect request
func (c *Conn) trojanConnectUDP(target transport.Endpoint, initialData []byte) error {
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

	// Send Trojan handshake
	socketData := &pb.SocketData{Content: handshakeData}
	marshaledData, err := proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("failed to marshal UDP handshake: %w", err)
	}

	if err := c.encoder.Encode(marshaledData); err != nil {
		return fmt.Errorf("failed to send UDP handshake: %w", err)
	}

	// For Trojan UDP, no additional EWP UDPStatusNew packet is needed.
	// The UDP handshake and target are already sent.

	c.trojanConnected = true
	log.V("[H3] Trojan UDP connect sent for %v", target)
	return nil
}

// ewpConnectUDP sends EWP protocol UDP connect request
func (c *Conn) ewpConnectUDP(target transport.Endpoint, initialData []byte) error {
	// Parse target address
	var addr ewp.Address
	if target.Domain != "" {
		addr = ewp.Address{Type: ewp.AddressTypeDomain, Host: target.Domain, Port: target.Port}
	} else {
		addr = ewp.AddressFromAddrPort(target.Addr)
	}

	// Create UDP handshake request with CommandUDP
	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	// Send handshake request
	socketData := &pb.SocketData{Content: handshakeData}
	data, err := proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("failed to marshal handshake: %w", err)
	}

	if err := c.encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to send handshake: %w", err)
	}

	select {
	case respData := <-c.recvChan:
		resp, err := ewp.DecodeHandshakeResponse(respData, req.Version, req.Nonce, c.uuid)
		if err != nil {
			return fmt.Errorf("decode UDP handshake response: %w", err)
		}
		if resp.Status != ewp.StatusOK {
			return fmt.Errorf("UDP handshake failed: status=%d", resp.Status)
		}
	case <-c.closeChan:
		return fmt.Errorf("connection closed during UDP handshake")
	}

	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
	}

	// Always send UDPStatusNew to establish session on server (with target address)
	c.udpGlobalID = ewp.NewGlobalID()

	targetAddr := target.Addr
	if target.Domain != "" && !targetAddr.IsValid() {
		if ips, err := net.LookupIP(target.Domain); err == nil && len(ips) > 0 {
			if ip4 := ips[0].To4(); ip4 != nil {
				ip, _ := netip.AddrFromSlice(ip4)
				targetAddr = netip.AddrPortFrom(ip, target.Port)
			} else {
				ip, _ := netip.AddrFromSlice(ips[0].To16())
				targetAddr = netip.AddrPortFrom(ip, target.Port)
			}
		}
	}

	pkt := &ewp.UDPPacketAddr{
		GlobalID: c.udpGlobalID,
		Status:   ewp.UDPStatusNew,
		Target:   targetAddr,
		Payload:  initialData,
	}

	encoded, err := ewp.EncodeUDPAddrPacket(pkt)
	if err != nil {
		return fmt.Errorf("encode UDP packet: %w", err)
	}

	// Apply flow padding if enabled
	var writeData []byte
	if c.flowState != nil {
		userUUID := c.uuid[:]
		writeData = c.flowState.PadUplink(encoded, &userUUID)
	} else {
		writeData = encoded
	}

	socketData = &pb.SocketData{Content: writeData}
	data, err = proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("failed to marshal UDP packet: %w", err)
	}

	if err := c.encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to send UDP new packet: %w", err)
	}

	log.V("[H3] EWP UDP connect sent for %v", target)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel
func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
	if c.useTrojan {
		length := uint16(len(data))
		addrLen := 7
		if target.Domain != "" {
			addrLen = 1 + 1 + len(target.Domain) + 2
		} else if target.Addr.Addr().Is6() {
			addrLen = 19
		}
		buf := make([]byte, 0, addrLen+4+len(data))
		if target.Domain != "" {
			buf = append(buf, trojan.AddressTypeDomain, byte(len(target.Domain)))
			buf = append(buf, []byte(target.Domain)...)
			buf = append(buf, byte(target.Port>>8), byte(target.Port))
		} else {
			buf = trojan.AppendAddrPort(buf, target.Addr)
		}
		buf = append(buf, byte(length>>8), byte(length))
		buf = append(buf, trojan.CRLF...)
		buf = append(buf, data...)
		return c.Write(buf)
	}

	targetAddr := target.Addr
	if target.Domain != "" && !targetAddr.IsValid() {
		if ips, err := net.LookupIP(target.Domain); err == nil && len(ips) > 0 {
			if ip4 := ips[0].To4(); ip4 != nil {
				ip, _ := netip.AddrFromSlice(ip4)
				targetAddr = netip.AddrPortFrom(ip, target.Port)
			} else {
				ip, _ := netip.AddrFromSlice(ips[0].To16())
				targetAddr = netip.AddrPortFrom(ip, target.Port)
			}
		}
	}

	addrLen := 7
	if targetAddr.IsValid() && targetAddr.Addr().Is6() {
		addrLen = 19
	}
	totalCap := 2 + 8 + 1 + 1 + addrLen + 2 + len(data)
	buf := make([]byte, 0, totalCap)
	buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, targetAddr, data)
	return c.Write(buf)
}

// ReadUDP reads and decodes a UDP response packet
func (c *Conn) ReadUDP() ([]byte, error) {
	if c.closed {
		return nil, io.EOF
	}
	select {
	case data := <-c.recvChan:
		if c.useTrojan {
			return decodeTrojanUDP(data)
		}
		return ewp.DecodeUDPPayload(data)
	case <-c.closeChan:
		return nil, io.EOF
	}
}

// ReadUDPTo reads and decodes a UDP response packet directly into the provided buffer
func (c *Conn) ReadUDPTo(buf []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}
	select {
	case data := <-c.recvChan:
		if c.useTrojan {
			payload, err := decodeTrojanUDP(data)
			if err != nil {
				return 0, err
			}
			n := copy(buf, payload)
			return n, nil
		}
		return ewp.DecodeUDPPayloadTo(data, buf)
	case <-c.closeChan:
		return 0, io.EOF
	}
}

// ReadUDPFrom reads a UDP response and returns the real remote address.
func (c *Conn) ReadUDPFrom(buf []byte) (int, netip.AddrPort, error) {
	if c.closed {
		return 0, netip.AddrPort{}, io.EOF
	}
	select {
	case data := <-c.recvChan:
		if c.useTrojan {
			payload, addr, err := decodeTrojanUDPWithAddr(data)
			if err != nil {
				return 0, netip.AddrPort{}, err
			}
			n := copy(buf, payload)
			return n, addr, nil
		}
		return ewp.DecodeUDPAddrPayloadTo(data, buf)
	case <-c.closeChan:
		return 0, netip.AddrPort{}, io.EOF
	}
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

// Read reads data from the connection.
// Leftover bytes from a previous oversized chunk are returned first.
func (c *Conn) Read(buf []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}

	var data []byte
	if len(c.readLeftover) > 0 {
		data = c.readLeftover
	} else {
		select {
		case d, ok := <-c.recvChan:
			if !ok {
				return 0, io.EOF
			}
			data = d
		case <-c.closeChan:
			return 0, io.EOF
		}
	}

	n := copy(buf, data)
	if n < len(data) {
		c.readLeftover = data[n:]
	} else {
		c.readLeftover = nil
	}
	return n, nil
}

// Write writes data to the connection
func (c *Conn) Write(data []byte) error {
	if c.closed {
		return io.ErrClosedPipe
	}

	// Build socket data
	socketData := &pb.SocketData{
		Content: data,
	}

	// Apply flow padding if enabled
	if c.enableFlow && c.flowState != nil {
		userUUID := c.uuid[:]
		socketData.Content = c.flowState.PadUplink(socketData.Content, &userUUID)
	}

	// Marshal protobuf
	encoded, err := proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	// Encode and send via gRPC-Web
	c.mu.Lock()
	encoder := c.encoder
	c.mu.Unlock()

	if encoder == nil {
		return fmt.Errorf("encoder not initialized")
	}

	if err := encoder.Encode(encoded); err != nil {
		return fmt.Errorf("failed to send data: %w", err)
	}

	return nil
}

// Close closes the connection
func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	log.V("[H3] Closing connection")

	c.signalClose()

	// Cancel the HTTP/3 request context.
	c.mu.Lock()
	cancel := c.cancelFn
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	// Close the active request body pipe to unblock the encoder
	c.mu.Lock()
	pr := c.activePipeRead
	c.mu.Unlock()
	if pr != nil {
		pr.CloseWithError(io.ErrClosedPipe)
	}

	// Close response body
	if c.response != nil && c.response.Body != nil {
		c.response.Body.Close()
	}

	// Wait for goroutines to finish
	c.wg.Wait()

	return nil
}

// StartPing starts periodic ping (not needed for HTTP/3 - has built-in keepalive)
func (c *Conn) StartPing(interval time.Duration) chan struct{} {
	// QUIC has built-in keepalive, no application-level ping goroutine needed.
	// Return an open channel so the caller's defer close() does not panic.
	return make(chan struct{})
}

// receiveLoop receives and processes incoming messages
func (c *Conn) receiveLoop() {
	defer c.wg.Done()
	defer c.signalClose()

	for {
		// Decode gRPC-Web frame
		data, err := c.decoder.Decode()
		if err != nil {
			if err != io.EOF {
				log.V("[H3] Receive error: %v", err)
			}
			return
		}

		// Unmarshal protobuf
		var socketData pb.SocketData
		if err := proto.Unmarshal(data, &socketData); err != nil {
			log.Printf("[H3] Failed to unmarshal data: %v", err)
			continue
		}

		// Get content (flow padding is removed on server side)
		content := socketData.Content

		if len(content) == 0 {
			continue
		}

		// Send to receive channel
		select {
		case c.recvChan <- content:
		case <-c.closeChan:
			return
		}
	}
}

// LocalAddr returns the local address (not applicable for HTTP/3)
func (c *Conn) LocalAddr() string {
	return "http3-client"
}

// RemoteAddr returns the remote address
func (c *Conn) RemoteAddr() string {
	if c.request != nil {
		return c.request.URL.Host
	}
	return c.transport.serverAddr
}
