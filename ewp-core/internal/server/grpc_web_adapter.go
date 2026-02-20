package server

import (
	"io"
	"net/http"
	"strings"

	"google.golang.org/grpc"
)

// GRPCWebAdapter wraps a standard gRPC server to support gRPC-Web requests
// It detects Content-Type and adapts gRPC-Web format to standard gRPC format
type GRPCWebAdapter struct {
	grpcServer *grpc.Server
}

// NewGRPCWebAdapter creates a new gRPC-Web adapter
func NewGRPCWebAdapter(grpcServer *grpc.Server) *GRPCWebAdapter {
	return &GRPCWebAdapter{
		grpcServer: grpcServer,
	}
}

// ServeHTTP implements http.Handler
func (a *GRPCWebAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	contentType := r.Header.Get("Content-Type")

	// Check if this is a gRPC-Web request.
	// Accept both the standard gRPC-Web content types and application/octet-stream,
	// since the h3grpc client uses gRPC-Web framing with octet-stream for CDN obfuscation.
	if strings.HasPrefix(contentType, "application/grpc-web") || contentType == "application/octet-stream" {
		a.handleGRPCWeb(w, r)
		return
	}

	// Standard gRPC request - pass through directly
	a.grpcServer.ServeHTTP(w, r)
}

// handleGRPCWeb handles gRPC-Web requests by converting them to standard gRPC
func (a *GRPCWebAdapter) handleGRPCWeb(w http.ResponseWriter, r *http.Request) {
	// gRPC-Web uses the same frame format as gRPC ([compressed:1][length:4][data])
	// So we just need to:
	// 1. Change Content-Type header to standard gRPC
	// 2. Pass through the body (frame format is identical)
	// 3. Change response Content-Type back to gRPC-Web

	// Wrap the request to change Content-Type
	r.Header.Set("Content-Type", "application/grpc+proto")

	// Wrap ResponseWriter to modify response headers
	wrappedWriter := &grpcWebResponseWriter{
		ResponseWriter: w,
		headerWritten:  false,
	}

	// Delegate to standard gRPC server
	a.grpcServer.ServeHTTP(wrappedWriter, r)
}

// grpcWebResponseWriter wraps http.ResponseWriter to modify gRPC response headers for gRPC-Web
type grpcWebResponseWriter struct {
	http.ResponseWriter
	headerWritten bool
}

func (w *grpcWebResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		// Modify Content-Type for gRPC-Web clients
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.headerWritten = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *grpcWebResponseWriter) WriteHeader(statusCode int) {
	if !w.headerWritten {
		w.Header().Set("Content-Type", "application/grpc-web+proto")
		w.headerWritten = true
	}
	w.ResponseWriter.WriteHeader(statusCode)
}

// Flush implements http.Flusher
func (w *grpcWebResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// grpcWebUnwrapReader is a pass-through reader since gRPC-Web and gRPC use the same frame format
// This is kept for clarity and potential future enhancements (e.g., decompression)
type grpcWebUnwrapReader struct {
	reader io.Reader
}

func (r *grpcWebUnwrapReader) Read(p []byte) (int, error) {
	// gRPC-Web frame format: [compressed:1][length:4][data]
	// Standard gRPC format: [compressed:1][length:4][data]
	// They're identical, so just pass through
	return r.reader.Read(p)
}
