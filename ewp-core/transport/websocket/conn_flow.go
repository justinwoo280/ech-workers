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

// FlowConn implements EWP Flow protocol connection (Vision-style flow control)
type FlowConn struct {
	conn              *websocket.Conn
	uuid              [16]byte
	streamID          uint16
	connected         bool
	mu                sync.Mutex
	version           byte
	nonce             [12]byte
	flowState         *ewp.FlowState
	writeOnceUserUUID []byte
	heartbeatPeriod   time.Duration
	earlyDataLength   int
	earlyDataSent     bool
	udpGlobalID       [8]byte
}

// NewFlowConn creates a new Flow WebSocket connection
func NewFlowConn(conn *websocket.Conn, uuid [16]byte) *FlowConn {
	return &FlowConn{
		conn:     conn,
		uuid:     uuid,
		streamID: 1,
	}
}

// writeMsg writes data applying flow state padding, without acquiring c.mu.
// Caller must hold c.mu or ensure exclusive access.
func (c *FlowConn) writeMsg(data []byte) error {
	var writeData []byte
	if c.flowState != nil {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}
	return c.conn.WriteMessage(websocket.BinaryMessage, writeData)
}

// Connect sends connection request using EWP Flow protocol
func (c *FlowConn) Connect(target string, initialData []byte) error {
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

	if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

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

	// Initialize Flow State
	c.flowState = ewp.NewFlowState(c.uuid[:])
	c.writeOnceUserUUID = make([]byte, 16)
	copy(c.writeOnceUserUUID, c.uuid[:])

	if len(initialData) > 0 && !c.earlyDataSent {
		if err := c.writeMsg(initialData); err != nil {
			return fmt.Errorf("send initial data: %w", err)
		}
	}

	c.connected = true
	log.V("[Flow] Handshake successful, target: %s, StreamID: %d", target, c.streamID)
	return nil
}

// ConnectUDP sends UDP connection request using EWP native UDP protocol
func (c *FlowConn) ConnectUDP(target string, initialData []byte) error {
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

	if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
		return fmt.Errorf("send handshake: %w", err)
	}

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

	// Initialize Flow State for UDP session
	c.flowState = ewp.NewFlowState(c.uuid[:])
	c.writeOnceUserUUID = make([]byte, 16)
	copy(c.writeOnceUserUUID, c.uuid[:])

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

	if err := c.writeMsg(encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}

	c.connected = true
	log.V("[Flow] UDP handshake successful, target: %s, StreamID: %d", target, c.streamID)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel (StatusKeep)
func (c *FlowConn) WriteUDP(target string, data []byte) error {
	encoded, err := ewp.EncodeUDPKeepPacket(c.udpGlobalID, data)
	if err != nil {
		return fmt.Errorf("encode UDP keep packet: %w", err)
	}
	return c.Write(encoded)
}

// ReadUDP reads and decodes an EWP-framed UDP response packet
func (c *FlowConn) ReadUDP() ([]byte, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	if c.flowState != nil {
		msg = c.flowState.ProcessDownlink(msg)
	}
	return ewp.DecodeUDPPayload(msg)
}

// Read reads data from WebSocket with Flow protocol unpacking
func (c *FlowConn) Read(buf []byte) (int, error) {
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

	// Process Flow protocol unpacking (remove padding)
	if c.flowState != nil {
		msg = c.flowState.ProcessDownlink(msg)
	}

	n := copy(buf, msg)
	return n, nil
}

// Write writes data to WebSocket with Flow protocol padding
func (c *FlowConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Apply Flow protocol padding
	var writeData []byte
	if c.flowState != nil {
		writeData = c.flowState.PadUplink(data, &c.writeOnceUserUUID)
	} else {
		writeData = data
	}

	return c.conn.WriteMessage(websocket.BinaryMessage, writeData)
}

// Close closes the connection
func (c *FlowConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
	return c.conn.Close()
}

// StartPing starts heartbeat
func (c *FlowConn) StartPing(interval time.Duration) chan struct{} {
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
func (c *FlowConn) SetEarlyData(length int) {
	c.earlyDataLength = length
}

// SetHeartbeat configures heartbeat period
func (c *FlowConn) SetHeartbeat(period time.Duration) {
	c.heartbeatPeriod = period
}
