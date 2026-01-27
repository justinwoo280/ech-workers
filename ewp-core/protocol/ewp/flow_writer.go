package ewp

import (
	"io"
)

// FlowWriter wraps a writer and applies Vision-style padding
type FlowWriter struct {
	writer           io.Writer
	state            *FlowState
	isUplink         bool
	writeOnceUserUUID []byte
}

// NewFlowWriter creates a new flow writer
func NewFlowWriter(writer io.Writer, state *FlowState, isUplink bool) *FlowWriter {
	// Copy UserUUID for one-time write
	uuidCopy := make([]byte, len(state.UserUUID))
	copy(uuidCopy, state.UserUUID)

	return &FlowWriter{
		writer:            writer,
		state:             state,
		isUplink:          isUplink,
		writeOnceUserUUID: uuidCopy,
	}
}

// Write writes padded data
func (w *FlowWriter) Write(p []byte) (n int, err error) {
	if w.state == nil {
		return w.writer.Write(p)
	}

	// Check if should switch to direct copy
	if w.state.ShouldDirectCopy(w.isUplink) {
		return w.writer.Write(p)
	}

	// Apply padding
	var padded []byte
	if w.isUplink {
		padded = w.state.PadUplink(p, &w.writeOnceUserUUID)
	} else {
		padded = w.state.PadDownlink(p, &w.writeOnceUserUUID)
	}

	_, err = w.writer.Write(padded)
	if err != nil {
		return 0, err
	}

	return len(p), nil // Return original length
}

// Close closes the underlying writer if it implements io.Closer
func (w *FlowWriter) Close() error {
	if closer, ok := w.writer.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// FlowReader wraps a reader and removes Vision-style padding
type FlowReader struct {
	reader   io.Reader
	state    *FlowState
	isUplink bool
}

// NewFlowReader creates a new flow reader
func NewFlowReader(reader io.Reader, state *FlowState, isUplink bool) *FlowReader {
	return &FlowReader{
		reader:   reader,
		state:    state,
		isUplink: isUplink,
	}
}

// Read reads and unpads data
func (r *FlowReader) Read(p []byte) (n int, err error) {
	if r.state == nil {
		return r.reader.Read(p)
	}

	// Check if should switch to direct copy
	if r.state.ShouldDirectCopy(!r.isUplink) {
		return r.reader.Read(p)
	}

	// Read raw data
	buf := make([]byte, len(p)*2) // Allocate extra space for padding
	n, err = r.reader.Read(buf)
	if err != nil {
		return 0, err
	}

	// Remove padding
	var unpadded []byte
	if r.isUplink {
		unpadded = r.state.ProcessUplink(buf[:n])
	} else {
		unpadded = r.state.ProcessDownlink(buf[:n])
	}

	// Copy to output buffer
	copied := copy(p, unpadded)
	return copied, nil
}

// Close closes the underlying reader if it implements io.Closer
func (r *FlowReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
