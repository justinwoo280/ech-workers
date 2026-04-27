package xhttp

import (
	"encoding/binary"
	"errors"
	"io"
	"sync"

	"ewp-core/transport"
)

// Conn is a v2 message-bounded TunnelConn over a single HTTP/1.1
// long-lived POST. Framing on both legs is a 4-byte big-endian length
// prefix followed by the payload — one frame per v2 outer message.
type Conn struct {
	body   io.ReadCloser // server response body (downlink)
	pw     io.WriteCloser // pipe writer fed into request body (uplink)
	closer io.Closer      // closes underlying http transport state

	rdMu, wrMu sync.Mutex
	closeOnce  sync.Once
	closed     bool
}

func newStreamOneConn(body io.ReadCloser, pw io.WriteCloser, closer io.Closer) *Conn {
	return &Conn{body: body, pw: pw, closer: closer}
}

func (c *Conn) SendMessage(b []byte) error {
	c.wrMu.Lock()
	defer c.wrMu.Unlock()
	if c.closed {
		return errors.New("xhttp: closed")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := c.pw.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.pw.Write(b)
	return err
}

func (c *Conn) ReadMessage() ([]byte, error) {
	c.rdMu.Lock()
	defer c.rdMu.Unlock()
	var hdr [4]byte
	if _, err := io.ReadFull(c.body, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 {
		return nil, nil
	}
	if n > 4*1024*1024 { // sane cap
		return nil, errors.New("xhttp: frame too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.body, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed = true
		_ = c.pw.Close()
		_ = c.body.Close()
		if c.closer != nil {
			_ = c.closer.Close()
		}
	})
	return nil
}

var _ transport.TunnelConn = (*Conn)(nil)
