package websocket

import (
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"ewp-core/log"
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
