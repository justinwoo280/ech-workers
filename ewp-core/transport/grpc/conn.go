package grpc

import (
	"errors"
	"sync"

	"google.golang.org/grpc"

	pb "ewp-core/proto"
	"ewp-core/transport"
)

// Conn is a v2 message-bounded TunnelConn over a gRPC bidi stream.
// One SendMessage = one SocketData proto on the wire.
type Conn struct {
	stream  grpc.ClientStream
	cancel  func()
	rdMu    sync.Mutex
	wrMu    sync.Mutex
	closeMu sync.Mutex
	closed  bool
}

func newConn(stream grpc.ClientStream, cancel func()) *Conn {
	return &Conn{stream: stream, cancel: cancel}
}

func (c *Conn) SendMessage(b []byte) error {
	c.wrMu.Lock()
	defer c.wrMu.Unlock()
	if c.closed {
		return errors.New("grpc: closed")
	}
	return c.stream.SendMsg(&pb.SocketData{Content: b})
}

func (c *Conn) ReadMessage() ([]byte, error) {
	c.rdMu.Lock()
	defer c.rdMu.Unlock()
	var msg pb.SocketData
	if err := c.stream.RecvMsg(&msg); err != nil {
		return nil, err
	}
	return msg.Content, nil
}

func (c *Conn) Close() error {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

var _ transport.TunnelConn = (*Conn)(nil)
