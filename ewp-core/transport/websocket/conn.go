package websocket

import (
	"errors"
	"sync"
	"time"

	"github.com/lxzan/gws"

	"ewp-core/transport"
)

// Conn is a v2 message-bounded TunnelConn over a single WebSocket
// connection. Each WS binary frame carries exactly one v2 message.
//
// Concurrency: gws.Conn.WriteMessage is goroutine-safe; gws delivers
// inbound frames via the OnMessage event handler so we buffer them
// in inbox for ReadMessage to drain.
type Conn struct {
	socket *gws.Conn
	inbox  chan []byte

	closeOnce sync.Once
	closeCh   chan struct{}
}

func newConn() *Conn {
	return &Conn{
		inbox:   make(chan []byte, 64),
		closeCh: make(chan struct{}),
	}
}

func (c *Conn) attach(socket *gws.Conn) { c.socket = socket }

// SendMessage writes one v2 message as a single WebSocket binary
// frame. Safe to call concurrently with ReadMessage.
func (c *Conn) SendMessage(b []byte) error {
	if c.socket == nil {
		return errors.New("ws: not connected")
	}
	return c.socket.WriteMessage(gws.OpcodeBinary, b)
}

// ReadMessage returns the next message delivered by the WS event
// handler. Blocks until one arrives or the connection closes.
func (c *Conn) ReadMessage() ([]byte, error) {
	select {
	case b, ok := <-c.inbox:
		if !ok {
			return nil, errors.New("ws: closed")
		}
		return b, nil
	case <-c.closeCh:
		return nil, errors.New("ws: closed")
	}
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
		if c.socket != nil {
			_ = c.socket.WriteClose(1000, nil) // RFC 6455 Normal Closure
		}
	})
	return nil
}

// ----------------------------------------------------------------------
// gws event handler: each Conn IS its own event handler.
// gws calls OnOpen / OnClose / OnPing / OnPong / OnMessage on us.
// ----------------------------------------------------------------------

func (c *Conn) OnOpen(socket *gws.Conn)               {}
func (c *Conn) OnClose(socket *gws.Conn, err error)   { c.Close() }
func (c *Conn) OnPing(socket *gws.Conn, payload []byte) { _ = socket.WritePong(nil) }
func (c *Conn) OnPong(socket *gws.Conn, payload []byte) {}

func (c *Conn) OnMessage(socket *gws.Conn, msg *gws.Message) {
	defer msg.Close()
	if msg.Opcode != gws.OpcodeBinary {
		return
	}
	// Copy because gws reuses msg.Data buffer after OnMessage returns.
	cp := make([]byte, msg.Data.Len())
	copy(cp, msg.Data.Bytes())
	select {
	case c.inbox <- cp:
	case <-c.closeCh:
	}
}

// Compile-time check.
var _ transport.TunnelConn = (*Conn)(nil)

// silence unused import if heartbeat helpers move out later
var _ = time.Now
