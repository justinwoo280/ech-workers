package websocket

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
	"ewp-core/protocol/ewp"

	"github.com/gorilla/websocket"
)

// SimpleConn implements simple WebSocket connection (Cloudflare Workers compatible)
type SimpleConn struct {
	conn            *websocket.Conn
	uuid            [16]byte
	connected       bool
	mu              sync.Mutex
	version         byte
	nonce           [12]byte
	heartbeatPeriod time.Duration
	earlyDataLength int
	earlyDataSent   bool
	udpGlobalID     [8]byte
}

// NewSimpleConn creates a new simple WebSocket connection
func NewSimpleConn(conn *websocket.Conn, token string) *SimpleConn {
	return &SimpleConn{
		conn: conn,
	}
}

// NewSimpleConnWithUUID creates a simple connection with UUID
func NewSimpleConnWithUUID(conn *websocket.Conn, uuid [16]byte) *SimpleConn {
	return &SimpleConn{
		conn: conn,
		uuid: uuid,
	}
}

// Connect sends connection request using EWP protocol
func (c *SimpleConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandTCP, addr)
	c.version = req.Version
	c.nonce = req.Nonce

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	// Send handshake with optional early data
	if c.earlyDataLength > 0 && len(initialData) > 0 && len(initialData) <= c.earlyDataLength && !c.earlyDataSent {
		combinedData := append(handshakeData, initialData...)
		if err := c.conn.WriteMessage(websocket.BinaryMessage, combinedData); err != nil {
			return fmt.Errorf("send handshake with early data: %w", err)
		}
		c.earlyDataSent = true
	} else {
		if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
			return fmt.Errorf("send handshake: %w", err)
		}
	}

	// Read handshake response
	_, respData, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respData, c.version, c.nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
	}

	// Send initial data if not sent with early data
	if len(initialData) > 0 && !c.earlyDataSent {
		if err := c.conn.WriteMessage(websocket.BinaryMessage, initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	c.connected = true
	log.V("[EWP] Handshake successful, target: %s", target)
	return nil
}

// ConnectUDP sends UDP connection request using EWP native UDP protocol
func (c *SimpleConn) ConnectUDP(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := ewp.ParseAddress(target)
	if err != nil {
		return fmt.Errorf("parse address: %w", err)
	}

	// Use CommandUDP for UDP connections
	req := ewp.NewHandshakeRequest(c.uuid, ewp.CommandUDP, addr)
	c.version = req.Version
	c.nonce = req.Nonce

	handshakeData, err := req.Encode()
	if err != nil {
		return fmt.Errorf("encode handshake: %w", err)
	}

	// Send handshake
	if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

	// Read handshake response
	_, respData, err := c.conn.ReadMessage()
	if err != nil {
		return fmt.Errorf("read handshake response: %w", err)
	}

	resp, err := ewp.DecodeHandshakeResponse(respData, c.version, c.nonce, c.uuid)
	if err != nil {
		return fmt.Errorf("decode handshake response: %w", err)
	}

	if resp.Status != ewp.StatusOK {
		return fmt.Errorf("handshake failed with status: %d", resp.Status)
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

	if err := c.conn.WriteMessage(websocket.BinaryMessage, encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}

	c.connected = true
	log.V("[EWP] UDP handshake successful, target: %s", target)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel (StatusKeep)
func (c *SimpleConn) WriteUDP(target string, data []byte) error {
	encoded, err := ewp.EncodeUDPKeepPacket(c.udpGlobalID, data)
	if err != nil {
		return fmt.Errorf("encode UDP keep packet: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.BinaryMessage, encoded)
}

// ReadUDP reads and decodes an EWP-framed UDP response packet
func (c *SimpleConn) ReadUDP() ([]byte, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	return ewp.DecodeUDPPayload(msg)
}

// Read reads data from WebSocket
func (c *SimpleConn) Read(buf []byte) (int, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// Check for control messages
	if len(msg) > 0 {
		str := string(msg)
		if str == "CLOSE" {
			return 0, io.EOF
		}
		if strings.HasPrefix(str, "ERROR:") {
			return 0, errors.New(str)
		}
	}

	n := copy(buf, msg)
	return n, nil
}

// Write writes data to WebSocket
func (c *SimpleConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

// Close closes the connection
func (c *SimpleConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Send CLOSE message
	_ = c.conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
	return c.conn.Close()
}

// StartPing starts heartbeat
func (c *SimpleConn) StartPing(interval time.Duration) chan struct{} {
	if c.heartbeatPeriod > 0 {
		interval = c.heartbeatPeriod
	}
	if interval == 0 {
		return make(chan struct{})
	}

	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				err := c.conn.WriteMessage(websocket.PingMessage, nil)
				c.mu.Unlock()
				if err != nil {
					return
				}
			case <-stop:
				return
			}
		}
	}()
	return stop
}

// SetEarlyData configures early data length
func (c *SimpleConn) SetEarlyData(length int) {
	c.earlyDataLength = length
}

// SetHeartbeat configures heartbeat period
func (c *SimpleConn) SetHeartbeat(period time.Duration) {
	c.heartbeatPeriod = period
}
