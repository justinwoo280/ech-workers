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
	"ewp-core/protocol/trojan"

	"github.com/gorilla/websocket"
)

// TrojanConn implements Trojan protocol over WebSocket
type TrojanConn struct {
	conn            *websocket.Conn
	password        string
	key             [trojan.KeyLength]byte
	connected       bool
	mu              sync.Mutex
	heartbeatPeriod time.Duration
	udpGlobalID     [8]byte
}

// NewTrojanConn creates a new Trojan WebSocket connection
func NewTrojanConn(conn *websocket.Conn, password string) *TrojanConn {
	return &TrojanConn{
		conn:     conn,
		password: password,
		key:      trojan.GenerateKey(password),
	}
}

// Connect sends Trojan handshake
func (c *TrojanConn) Connect(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return err
	}

	// Build handshake data
	var handshakeData []byte
	handshakeData = append(handshakeData, c.key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandTCP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	// Append initial data if any
	if len(initialData) > 0 {
		handshakeData = append(handshakeData, initialData...)
	}

	// Send handshake (Trojan has no response)
	if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
		return err
	}

	c.connected = true
	log.V("[Trojan] Handshake sent, target: %s", target)
	return nil
}

func (c *TrojanConn) ConnectUDP(target string, initialData []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	addr, err := trojan.ParseAddress(target)
	if err != nil {
		return err
	}

	// Build Trojan UDP handshake (without raw initial data)
	var handshakeData []byte
	handshakeData = append(handshakeData, c.key[:]...)
	handshakeData = append(handshakeData, trojan.CRLF...)
	handshakeData = append(handshakeData, trojan.CommandUDP)

	addrBytes, err := addr.Encode()
	if err != nil {
		return err
	}
	handshakeData = append(handshakeData, addrBytes...)
	handshakeData = append(handshakeData, trojan.CRLF...)

	// Send Trojan handshake as first WebSocket message
	if err := c.conn.WriteMessage(websocket.BinaryMessage, handshakeData); err != nil {
		return err
	}

	// Send EWP UDPStatusNew as second message to establish session on server
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

	if err := c.conn.WriteMessage(websocket.BinaryMessage, encoded); err != nil {
		return fmt.Errorf("send UDP new packet: %w", err)
	}

	c.connected = true
	log.V("[Trojan] UDP handshake sent, target: %s", target)
	return nil
}

// WriteUDP sends a subsequent UDP packet over the established UDP tunnel (StatusKeep, EWP framing)
func (c *TrojanConn) WriteUDP(target string, data []byte) error {
	encoded, err := ewp.EncodeUDPKeepPacket(c.udpGlobalID, data)
	if err != nil {
		return fmt.Errorf("encode UDP keep packet: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.BinaryMessage, encoded)
}

// ReadUDP reads and decodes an EWP-framed UDP response packet
func (c *TrojanConn) ReadUDP() ([]byte, error) {
	_, msg, err := c.conn.ReadMessage()
	if err != nil {
		return nil, err
	}
	return ewp.DecodeUDPPayload(msg)
}

// Read reads data from WebSocket
func (c *TrojanConn) Read(buf []byte) (int, error) {
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
func (c *TrojanConn) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

// Close closes the connection
func (c *TrojanConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
	return c.conn.Close()
}

// StartPing starts heartbeat
func (c *TrojanConn) StartPing(interval time.Duration) chan struct{} {
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
