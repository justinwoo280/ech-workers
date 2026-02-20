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

	uuid       [16]byte
	password   string
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

// ConnectUDP sends initial UDP connection request.
func (c *Conn) ConnectUDP(target string, initialData []byte) error {
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
func (c *Conn) trojanConnectUDP(target string, initialData []byte) error {
	// Parse target address
	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	// Generate key
	key := trojan.GenerateKey(c.password)

	// Build Trojan UDP handshake (without raw initial data)
	var handshakeData []byte
	handshakeData = append(handshakeData, key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandUDP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return fmt.Errorf("encode address: %w", err)
	}
	handshakeData = append(handshakeData, addrBytes...)
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

	// Send EWP UDPStatusNew as separate message to establish session on server
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	c.udpGlobalID = ewp.NewGlobalID()

	pkt := &ewp.UDPPacket{
		GlobalID: c.udpGlobalID,
		Status:   ewp.UDPStatusNew,
		Target:   udpAddr,
		Payload:  initialData,
	}

	encoded, err := ewp.EncodeUDPPacket(pkt)
	if err != nil {
		return fmt.Errorf("encode UDP new packet: %w", err)
	}

	if err := c.Write(encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
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

	// Always send UDPStatusNew to establish session on server (with target address)
	udpAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	c.udpGlobalID = ewp.NewGlobalID()

	pkt := &ewp.UDPPacket{
		GlobalID: c.udpGlobalID,
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

	socketData = &pb.SocketData{Content: writeData}
	data, err = proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("failed to marshal UDP packet: %w", err)
	}

	if err := c.encoder.Encode(data); err != nil {
		return fmt.Errorf("failed to send UDP new packet: %w", err)
	}

	log.V("[H3] EWP UDP connect sent for %s", target)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel (StatusKeep)
func (c *Conn) WriteUDP(target string, data []byte) error {
	encoded, err := ewp.EncodeUDPKeepPacket(c.udpGlobalID, data)
	if err != nil {
		return fmt.Errorf("encode UDP keep packet: %w", err)
	}
	return c.Write(encoded)
}

// ReadUDP reads and decodes an EWP-framed UDP response packet
func (c *Conn) ReadUDP() ([]byte, error) {
	if c.closed {
		return nil, io.EOF
	}
	select {
	case data := <-c.recvChan:
		return ewp.DecodeUDPPayload(data)
	case <-c.closeChan:
		return nil, io.EOF
	}
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
	// QUIC has built-in keepalive, no need for application-level ping
	done := make(chan struct{})
	close(done)
	return done
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
