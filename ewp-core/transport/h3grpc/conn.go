package h3grpc

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"ewp-core/log"
	pb "ewp-core/proto"
	"ewp-core/protocol/ewp"
	"ewp-core/protocol/trojan"

	"google.golang.org/protobuf/proto"
)

// Conn implements transport.TunnelConn for HTTP/3
type Conn struct {
	transport  *Transport
	request    *http.Request
	response   *http.Response
	client     *http.Client
	
	uuid       [16]byte
	password   string
	enableFlow bool
	useTrojan  bool

	encoder    *GRPCWebEncoder
	decoder    *GRPCWebDecoder
	
	// Flow control (EWP Vision)
	flowState  *ewp.FlowState
	
	// Trojan (simplified, without mux for now)
	trojanConnected bool
	
	// Channels for async I/O
	recvChan   chan []byte
	sendChan   chan []byte
	closeChan  chan struct{}
	
	// State
	connected  bool
	closed     bool
	mu         sync.Mutex
	
	// Goroutine management
	wg         sync.WaitGroup
}

// Connect sends initial connection request
func (c *Conn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return fmt.Errorf("already connected")
	}

	log.V("[H3] Connecting to target: %s", target)

	// Create request body pipe
	pipeReader, pipeWriter := io.Pipe()
	c.request.Body = pipeReader

	// Start request in background
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if !c.connected {
			cancel()
		}
	}()

	c.request = c.request.WithContext(ctx)

	// Send HTTP/3 request
	go func() {
		resp, err := c.client.Do(c.request)
		if err != nil {
			log.Printf("[H3] Request failed: %v", err)
			pipeWriter.CloseWithError(err)
			close(c.closeChan)
			return
		}

		c.mu.Lock()
		c.response = resp
		
		// Initialize encoder/decoder
		c.encoder = NewGRPCWebEncoder(pipeWriter, false)
		c.decoder = NewGRPCWebDecoder(resp.Body)
		
		// Initialize flow state if enabled
		if c.enableFlow {
			c.flowState = ewp.NewFlowState(c.uuid[:])
		}
		
		c.connected = true
		c.mu.Unlock()

		log.V("[H3] HTTP/3 connection established")

		// Start receiver goroutine
		c.wg.Add(1)
		go c.receiveLoop()
	}()

	// Wait for connection to establish (with timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(10 * time.Second)

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			connected := c.connected
			c.mu.Unlock()
			if connected {
				goto Connected
			}
		case <-timeout:
			return fmt.Errorf("connection timeout")
		case <-c.closeChan:
			return fmt.Errorf("connection closed")
		}
	}

Connected:
	// Send connect request
	if c.useTrojan {
		return c.trojanConnect(target, initialData)
	}
	return c.ewpConnect(target, initialData)
}

// ewpConnect sends EWP protocol connect request
func (c *Conn) ewpConnect(target string, initialData []byte) error {
	// Parse target address
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
	}

	// Encode address to bytes
	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode address: %w", err)
	}

	// Build connect request
	connectReq := &pb.SocketData{
		Content: make([]byte, 16+len(addrBytes)+len(initialData)),
	}

	// Copy UUID
	copy(connectReq.Content[0:16], c.uuid[:])

	// Copy address
	copy(connectReq.Content[16:], addrBytes)

	// Copy initial data if present
	if len(initialData) > 0 {
		copy(connectReq.Content[16+len(addrBytes):], initialData)
	}

	// Apply flow padding if enabled
	if c.enableFlow && c.flowState != nil {
		userUUID := c.uuid[:]
		connectReq.Content = c.flowState.PadUplink(connectReq.Content, &userUUID)
	}

	// Marshal protobuf
	data, err := proto.Marshal(connectReq)
	if err != nil {
		return fmt.Errorf("failed to marshal connect request: %w", err)
	}

	// Encode and send
	if err := c.encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to send connect request: %w", err)
	}

	log.V("[H3] Connect request sent for %s", target)
	return nil
}

// trojanConnect sends Trojan protocol connect request
func (c *Conn) trojanConnect(target string, initialData []byte) error {
	// Parse target address
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	// Generate key
	key := trojan.GenerateKey(c.password)

	// Build Trojan handshake
	var handshakeData []byte
	handshakeData = append(handshakeData, key[:]...)
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

func (c *Conn) ConnectUDP(target string, initialData []byte) error {
	if c.useTrojan {
		return c.trojanConnectUDP(target, initialData)
	}
	
	// Wait for connection to establish (similar to Connect)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.After(10 * time.Second)

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			connected := c.connected
			c.mu.Unlock()
			if connected {
				goto Connected
			}
		case <-timeout:
			return fmt.Errorf("connection timeout")
		case <-c.closeChan:
			return fmt.Errorf("connection closed")
		}
	}

Connected:
	return c.ewpConnectUDP(target, initialData)
}

// trojanConnectUDP sends Trojan protocol UDP connect request
func (c *Conn) trojanConnectUDP(target string, initialData []byte) error {
	// Parse target address
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	// Generate key
	key := trojan.GenerateKey(c.password)

	// Build Trojan UDP handshake
	var handshakeData []byte
	handshakeData = append(handshakeData, key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandUDP)  // ← UDP command

	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	// Append initial data (UDP packet)
	if len(initialData) > 0 {
		handshakeData = append(handshakeData, initialData...)
	}

	// Send handshake
	socketData := &pb.SocketData{Content: handshakeData}
	data, err := proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("failed to marshal UDP handshake: %w", err)
	}

	if err := c.encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to send UDP handshake: %w", err)
	}

	c.trojanConnected = true
	log.V("[H3] Trojan UDP connect sent for %s", target)
	return nil
}

// ewpConnectUDP sends EWP protocol UDP connect request
func (c *Conn) ewpConnectUDP(target string, initialData []byte) error {
	// Parse target address
	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("invalid target address: %w", err)
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

	// Initialize flow state if enabled
	if c.enableFlow {
		c.flowState = ewp.NewFlowState(c.uuid[:])
	}

	// Send initial UDP packet if provided (with UDP framing)
	if len(initialData) > 0 {
		udpAddr, err := net.ResolveUDPAddr("udp", target)
		if err != nil {
			return fmt.Errorf("resolve UDP address: %w", err)
		}

		// Generate GlobalID for this session
		pseudoLocalAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
		globalID := ewp.GenerateGlobalID(pseudoLocalAddr)

		pkt := &ewp.UDPPacket{
			GlobalID: globalID,
			Status:   ewp.UDPStatusNew,
			Target:   udpAddr,
			Payload:  initialData,
		}

		encoded, err := ewp.EncodeUDPPacket(pkt)
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

		socketData := &pb.SocketData{Content: writeData}
		data, err := proto.Marshal(socketData)
		if err != nil {
			return fmt.Errorf("failed to marshal UDP packet: %w", err)
		}

		if err := c.encoder.Encode(data); err != nil {
			return fmt.Errorf("failed to send UDP packet: %w", err)
		}
	}

	log.V("[H3] EWP UDP connect sent for %s", target)
	return nil
}

// Read reads data from the connection
func (c *Conn) Read(buf []byte) (int, error) {
	if c.closed {
		return 0, io.EOF
	}

	select {
	case data := <-c.recvChan:
		n := copy(buf, data)
		return n, nil
	case <-c.closeChan:
		return 0, io.EOF
	}
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

	// Close channels
	close(c.closeChan)

	// Close request body
	if c.request != nil && c.request.Body != nil {
		c.request.Body.Close()
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
	// QUIC has built-in keepalive, no need for application-level ping
	done := make(chan struct{})
	close(done)
	return done
}

// receiveLoop receives and processes incoming messages
func (c *Conn) receiveLoop() {
	defer c.wg.Done()
	defer close(c.recvChan)

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
