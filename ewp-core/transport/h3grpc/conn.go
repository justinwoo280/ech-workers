package h3grpc

import (
	"errors"
	"io"
	"sync"

	"ewp-core/transport"
)

// Conn is a v2 message-bounded TunnelConn over an HTTP/3 streaming
// request/response pair using gRPC-Web framing. Each gRPC-Web frame
// (5-byte header + payload) carries exactly one v2 outer message.
type Conn struct {
	dec    *GRPCWebDecoder
	enc    *GRPCWebEncoder
	closer io.Closer

	rdMu, wrMu sync.Mutex

	closeOnce sync.Once
	closed    bool
}

func newConn(dec *GRPCWebDecoder, enc *GRPCWebEncoder, closer io.Closer) *Conn {
	return &Conn{dec: dec, enc: enc, closer: closer}
}

func (c *Conn) SendMessage(b []byte) error {
	c.wrMu.Lock()
	defer c.wrMu.Unlock()
	if c.closed {
		return errors.New("h3grpc: closed")
	}
	return c.enc.Encode(b)
}

func (c *Conn) ReadMessage() ([]byte, error) {
	c.rdMu.Lock()
	defer c.rdMu.Unlock()
	return c.dec.Decode()
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed = true
		if c.closer != nil {
			_ = c.closer.Close()
		}
	})
	return nil
}

var _ transport.TunnelConn = (*Conn)(nil)
