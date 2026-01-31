package websocket

import (
	"io"

	"github.com/gorilla/websocket"
)

type ServerAdapter struct {
	conn   *websocket.Conn
	closed bool
}

func NewServerAdapter(conn *websocket.Conn) *ServerAdapter {
	return &ServerAdapter{
		conn:   conn,
		closed: false,
	}
}

func (a *ServerAdapter) Read() ([]byte, error) {
	_, msg, err := a.conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if string(msg) == "CLOSE" {
		return nil, io.EOF
	}

	return msg, nil
}

func (a *ServerAdapter) Write(data []byte) error {
	return a.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (a *ServerAdapter) Close() error {
	if !a.closed {
		a.closed = true
		a.conn.WriteMessage(websocket.TextMessage, []byte("CLOSE"))
		return a.conn.Close()
	}
	return nil
}
