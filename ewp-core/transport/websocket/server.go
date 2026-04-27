package websocket

import (
	"io"
	"sync"

	"github.com/lxzan/gws"
)

// ServerAdapter wraps a server-side gws connection and bridges the event-driven
// OnMessage API to the blocking Read()/Write() interface expected by the tunnel handler.
// It also implements gws.Event so it can be passed directly as the per-connection handler.
type ServerAdapter struct {
	gws.BuiltinEventHandler

	socket    *gws.Conn
	msgCh     chan *gws.Message
	closeCh   chan struct{}
	closeOnce sync.Once
	leftover  []byte
}

func NewServerAdapter() *ServerAdapter {
	return &ServerAdapter{
		msgCh:   make(chan *gws.Message, 16),
		closeCh: make(chan struct{}),
	}
}

// SetSocket must be called immediately after the gws Upgrade succeeds.
func (a *ServerAdapter) SetSocket(socket *gws.Conn) {
	a.socket = socket
}

// --- gws.Event callbacks ---

func (a *ServerAdapter) OnClose(socket *gws.Conn, err error) {
	a.closeOnce.Do(func() { close(a.closeCh) })
}

func (a *ServerAdapter) OnPing(socket *gws.Conn, payload []byte) {
	_ = socket.WritePong(payload)
}

func (a *ServerAdapter) OnMessage(socket *gws.Conn, message *gws.Message) {
	select {
	case a.msgCh <- message:
	case <-a.closeCh:
		message.Close()
	}
}

// ReadFirst blocks until the first message arrives (used to sniff the protocol header).
func (a *ServerAdapter) ReadFirst() ([]byte, error) {
	select {
	case msg, ok := <-a.msgCh:
		if !ok {
			return nil, io.EOF
		}
		data := make([]byte, len(msg.Bytes()))
		copy(data, msg.Bytes())
		msg.Close()
		return data, nil
	case <-a.closeCh:
		return nil, io.EOF
	}
}

// Read implements the server transport.Transport interface (blocking, leftover-safe).
func (a *ServerAdapter) Read() ([]byte, error) {
	if len(a.leftover) > 0 {
		data := a.leftover
		a.leftover = nil
		return data, nil
	}
	select {
	case msg, ok := <-a.msgCh:
		if !ok {
			return nil, io.EOF
		}
		data := make([]byte, len(msg.Bytes()))
		copy(data, msg.Bytes())
		msg.Close()
		return data, nil
	case <-a.closeCh:
		return nil, io.EOF
	}
}

func (a *ServerAdapter) Write(data []byte) error {
	return a.socket.WriteMessage(gws.OpcodeBinary, data)
}

func (a *ServerAdapter) Close() error {
	a.closeOnce.Do(func() {
		close(a.closeCh)
		_ = a.socket.WriteClose(1000, nil)
	})
	return nil
}

// --- v2 transport.TunnelConn surface ---

// SendMessage is the v2 alias for Write — one WS binary frame per call.
func (a *ServerAdapter) SendMessage(b []byte) error { return a.Write(b) }

// ReadMessage is the v2 alias for Read — one WS binary frame per call.
func (a *ServerAdapter) ReadMessage() ([]byte, error) { return a.Read() }
