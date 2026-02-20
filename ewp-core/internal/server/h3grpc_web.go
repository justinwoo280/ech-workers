package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"time"

	"ewp-core/log"
	pb "ewp-core/proto"

	"google.golang.org/protobuf/proto"
)

// GRPCWebH3Transport implements TransportAdapter over a raw HTTP/3 request/response
// pair using gRPC-Web framing. It bypasses grpc.Server entirely, which requires
// r.ProtoMajor == 2 and therefore cannot be used with HTTP/3 (ProtoMajor == 3).
type GRPCWebH3Transport struct {
	reader io.Reader
	writer io.Writer
	flush  func()
	closed bool
}

// NewGRPCWebH3Transport creates a GRPCWebH3Transport from an HTTP/3 request body
// (reader) and response writer (writer). flush is called after every Write so that
// data is not buffered inside the HTTP/3 layer; it may be nil.
func NewGRPCWebH3Transport(reader io.Reader, writer io.Writer, flush func()) *GRPCWebH3Transport {
	return &GRPCWebH3Transport{
		reader: reader,
		writer: writer,
		flush:  flush,
	}
}

// Read reads one gRPC-Web frame from the request body and returns its payload
// after decoding the protobuf SocketData wrapper.
func (t *GRPCWebH3Transport) Read() ([]byte, error) {
	if t.closed {
		return nil, io.EOF
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(t.reader, header); err != nil {
		return nil, err
	}

	msgLen := binary.BigEndian.Uint32(header[1:5])
	if msgLen == 0 {
		return nil, fmt.Errorf("empty gRPC-Web frame")
	}
	if msgLen > 64*1024*1024 {
		return nil, fmt.Errorf("gRPC-Web frame too large: %d bytes", msgLen)
	}

	msg := make([]byte, msgLen)
	if _, err := io.ReadFull(t.reader, msg); err != nil {
		return nil, err
	}

	var socketData pb.SocketData
	if err := proto.Unmarshal(msg, &socketData); err != nil {
		return nil, fmt.Errorf("unmarshal SocketData: %w", err)
	}

	return socketData.Content, nil
}

// Write encodes data as a protobuf SocketData and sends it as a gRPC-Web frame.
func (t *GRPCWebH3Transport) Write(data []byte) error {
	if t.closed {
		return io.ErrClosedPipe
	}

	socketData := &pb.SocketData{Content: data}
	msg, err := proto.Marshal(socketData)
	if err != nil {
		return fmt.Errorf("marshal SocketData: %w", err)
	}

	header := make([]byte, 5)
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], uint32(len(msg)))

	if _, err := t.writer.Write(header); err != nil {
		return err
	}
	if _, err := t.writer.Write(msg); err != nil {
		return err
	}
	if t.flush != nil {
		t.flush()
	}
	return nil
}

// Close marks the transport as closed.
func (t *GRPCWebH3Transport) Close() error {
	t.closed = true
	return nil
}

// NewH3GRPCWebHandler returns an http.Handler that handles gRPC-Web framed tunnel
// connections over HTTP/3 without involving grpc.Server (which requires HTTP/2).
// protocolFactory is called once per request to create the protocol handler.
func NewH3GRPCWebHandler(protocolFactory func() ProtocolHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(http.StatusOK)

		var flush func()
		if f, ok := w.(http.Flusher); ok {
			flush = f.Flush
		}

		clientIP := r.RemoteAddr

		transport := NewGRPCWebH3Transport(r.Body, w, flush)

		handshakeData, err := transport.Read()
		if err != nil {
			log.Warn("[H3] Failed to read handshake from %s: %v", clientIP, err)
			return
		}

		opts := TunnelOptions{
			Protocol: protocolFactory(),
			Transport: transport,
			ClientIP:  clientIP,
			Timeout:   10 * time.Second,
		}

		if err := EstablishTunnel(context.Background(), handshakeData, opts); err != nil {
			log.Debug("[H3] Tunnel closed for %s: %v", clientIP, err)
		}
	})
}
