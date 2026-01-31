package browser_dialer

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/gorilla/websocket"
)

type BrowserClient struct {
	headers http.Header
}

func NewBrowserClient(headers http.Header) *BrowserClient {
	return &BrowserClient{
		headers: headers,
	}
}

func (c *BrowserClient) IsClosed() bool {
	return false
}

func (c *BrowserClient) OpenStream(ctx context.Context, url string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	if body != nil {
		return nil, nil, nil, &BrowserDialerError{Message: "bidirectional streaming for browser dialer not implemented yet"}
	}

	conn, err := DialGet(url, c.headers)
	dummyAddr := &net.TCPAddr{IP: net.IPv4zero, Port: 0}
	if err != nil {
		return nil, dummyAddr, dummyAddr, err
	}

	return NewWebSocketReadCloser(conn), conn.RemoteAddr(), conn.LocalAddr(), nil
}

func (c *BrowserClient) PostPacket(ctx context.Context, url string, body io.Reader, contentLength int64) error {
	bytes, err := io.ReadAll(body)
	if err != nil {
		return err
	}

	err = DialPost(url, c.headers, bytes)
	if err != nil {
		return err
	}

	return nil
}

type WebSocketReadCloser struct {
	conn   *websocket.Conn
	reader io.Reader
}

func NewWebSocketReadCloser(conn *websocket.Conn) *WebSocketReadCloser {
	return &WebSocketReadCloser{
		conn:   conn,
		reader: nil,
	}
}

func (w *WebSocketReadCloser) Read(p []byte) (n int, err error) {
	for {
		if w.reader != nil {
			n, err = w.reader.Read(p)
			if err != io.EOF {
				return n, err
			}
			w.reader = nil
		}

		msgType, msg, err := w.conn.ReadMessage()
		if err != nil {
			return 0, err
		}

		if msgType != websocket.BinaryMessage {
			continue
		}
		
		if len(msg) > len(p) {
			copy(p, msg[:len(p)])
			w.reader = io.NopCloser(io.MultiReader(io.NopCloser(&byteReader{data: msg[len(p):]})))
			return len(p), nil
		}
		
		copy(p, msg)
		return len(msg), nil
	}
}

type byteReader struct {
	data []byte
	pos  int
}

func (br *byteReader) Read(p []byte) (n int, err error) {
	if br.pos >= len(br.data) {
		return 0, io.EOF
	}
	n = copy(p, br.data[br.pos:])
	br.pos += n
	return n, nil
}

func (w *WebSocketReadCloser) Close() error {
	return w.conn.Close()
}
