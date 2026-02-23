package h3grpc

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// gRPC-Web frame flags
	grpcWebFlagUncompressed = 0x00
	grpcWebFlagCompressed   = 0x01

	// gRPC-Web Content-Type
	ContentTypeGRPCWeb     = "application/grpc-web+proto"
	ContentTypeGRPCWebText = "application/grpc-web-text+proto"

	// Standard gRPC Content-Type (for comparison)
	ContentTypeGRPC = "application/grpc+proto"
)

// GRPCWebEncoder encodes messages in gRPC-Web binary format
// Format: [Compressed-Flag: 1 byte][Message-Length: 4 bytes][Protobuf Message]
type GRPCWebEncoder struct {
	writer     io.Writer
	compressed bool
}

// NewGRPCWebEncoder creates a new gRPC-Web encoder
func NewGRPCWebEncoder(w io.Writer, compressed bool) *GRPCWebEncoder {
	return &GRPCWebEncoder{
		writer:     w,
		compressed: compressed,
	}
}

// Encode encodes a message into gRPC-Web format and writes to the underlying writer.
// Zero-length data is allowed and produces a heartbeat frame (5-byte header, no body).
func (e *GRPCWebEncoder) Encode(data []byte) error {
	// Prepare header: [Compressed-Flag: 1 byte][Length: 4 bytes]
	header := make([]byte, 5)

	// Set compression flag
	if e.compressed {
		header[0] = grpcWebFlagCompressed
	} else {
		header[0] = grpcWebFlagUncompressed
	}

	// Set message length (big-endian uint32)
	binary.BigEndian.PutUint32(header[1:5], uint32(len(data)))

	// Write header
	if _, err := e.writer.Write(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write message body (skipped for heartbeat frames where len == 0)
	if len(data) > 0 {
		if _, err := e.writer.Write(data); err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}
	}

	return nil
}

// GRPCWebDecoder decodes messages from gRPC-Web binary format
type GRPCWebDecoder struct {
	reader io.Reader
}

// NewGRPCWebDecoder creates a new gRPC-Web decoder
func NewGRPCWebDecoder(r io.Reader) *GRPCWebDecoder {
	return &GRPCWebDecoder{
		reader: r,
	}
}

// Decode reads and decodes a single gRPC-Web message
// Returns the decompressed message data, or io.EOF if stream ended
func (d *GRPCWebDecoder) Decode() ([]byte, error) {
	// Read 5-byte header: [Compressed-Flag: 1 byte][Length: 4 bytes]
	header := make([]byte, 5)
	if _, err := io.ReadFull(d.reader, header); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	// Parse compression flag
	compressed := header[0] == grpcWebFlagCompressed

	// Parse message length
	messageLen := binary.BigEndian.Uint32(header[1:5])

	if messageLen == 0 {
		// Heartbeat frame: zero-length body, silently acknowledged.
		return []byte{}, nil
	}

	// Sanity check: prevent excessive memory allocation
	if messageLen > 64*1024*1024 { // 64MB max
		return nil, fmt.Errorf("message too large: %d bytes", messageLen)
	}

	// Read message body
	message := make([]byte, messageLen)
	if _, err := io.ReadFull(d.reader, message); err != nil {
		return nil, fmt.Errorf("failed to read message body: %w", err)
	}

	// Handle decompression if needed
	if compressed {
		// Note: We don't support compression in this simple implementation
		// Cloudflare CDN typically doesn't compress gRPC-Web frames
		return nil, fmt.Errorf("compressed messages not supported yet")
	}

	return message, nil
}

// GRPCWebFrameReader provides a Reader interface for gRPC-Web frames
// Useful for streaming scenarios
type GRPCWebFrameReader struct {
	decoder       *GRPCWebDecoder
	currentFrame  []byte
	currentOffset int
}

// NewGRPCWebFrameReader creates a frame reader
func NewGRPCWebFrameReader(r io.Reader) *GRPCWebFrameReader {
	return &GRPCWebFrameReader{
		decoder: NewGRPCWebDecoder(r),
	}
}

// Read implements io.Reader by decoding gRPC-Web frames
func (r *GRPCWebFrameReader) Read(p []byte) (int, error) {
	// If we have data in current frame, return it
	if r.currentFrame != nil && r.currentOffset < len(r.currentFrame) {
		n := copy(p, r.currentFrame[r.currentOffset:])
		r.currentOffset += n

		// If frame is fully consumed, clear it
		if r.currentOffset >= len(r.currentFrame) {
			r.currentFrame = nil
			r.currentOffset = 0
		}

		return n, nil
	}

	// Decode next frame
	frame, err := r.decoder.Decode()
	if err != nil {
		return 0, err
	}

	// Copy to output buffer
	n := copy(p, frame)

	// If buffer is too small, save remaining data
	if n < len(frame) {
		r.currentFrame = frame
		r.currentOffset = n
	}

	return n, nil
}

// GRPCWebFrameWriter provides a Writer interface for gRPC-Web frames
type GRPCWebFrameWriter struct {
	encoder *GRPCWebEncoder
}

// NewGRPCWebFrameWriter creates a frame writer
func NewGRPCWebFrameWriter(w io.Writer, compressed bool) *GRPCWebFrameWriter {
	return &GRPCWebFrameWriter{
		encoder: NewGRPCWebEncoder(w, compressed),
	}
}

// Write implements io.Writer by encoding data as gRPC-Web frames
func (w *GRPCWebFrameWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if err := w.encoder.Encode(p); err != nil {
		return 0, err
	}

	return len(p), nil
}

// WriteFrame writes a complete gRPC-Web frame
func (w *GRPCWebFrameWriter) WriteFrame(data []byte) error {
	return w.encoder.Encode(data)
}
