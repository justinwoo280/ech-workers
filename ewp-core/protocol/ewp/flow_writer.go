package ewp

import (
	"io"
	"sync"
)

const readBufPoolSize = 32 * 1024

var readBufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, readBufPoolSize)
		return &buf
	},
}

// leftoverPool 复用 leftover 切片，减少 GC 压力
var leftoverPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 0, readBufPoolSize)
		return &buf
	},
}

// FlowWriter wraps a writer and applies Vision-style padding
type FlowWriter struct {
	writer            io.Writer
	state             *FlowState
	isUplink          bool
	writeOnceUserUUID []byte
}

// NewFlowWriter creates a new flow writer
func NewFlowWriter(writer io.Writer, state *FlowState, isUplink bool) *FlowWriter {
	var uuidCopy []byte
	if state != nil {
		uuidCopy = make([]byte, len(state.UserUUID))
		copy(uuidCopy, state.UserUUID)
	}

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
	leftover []byte // 上次 Read 未消费完的数据
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
	// 优先消费上次剩余数据，避免丢弃
	if len(r.leftover) > 0 {
		copied := copy(p, r.leftover)
		r.leftover = r.leftover[copied:]
		if len(r.leftover) == 0 {
			r.leftover = nil
		}
		return copied, nil
	}

	if r.state == nil {
		return r.reader.Read(p)
	}

	// 已进入直传模式，跳过 unpadding
	// P0-3: use ShouldDirectCopyRead which reads the Reader-side flags
	// (UplinkReaderDirectCopy / DownlinkReaderDirectCopy), not the Writer-side
	// flags that ShouldDirectCopy returns.
	if r.state.ShouldDirectCopyRead(r.isUplink) {
		return r.reader.Read(p)
	}

	// 从池中取读缓冲，大小为 p 的 2 倍以容纳 padding
	needed := len(p) * 2
	var buf []byte
	var pooledPtr *[]byte
	if needed <= readBufPoolSize {
		pooledPtr = readBufPool.Get().(*[]byte)
		buf = (*pooledPtr)[:needed]
	} else {
		buf = make([]byte, needed)
	}

	n, err = r.reader.Read(buf)
	if err != nil {
		if pooledPtr != nil {
			readBufPool.Put(pooledPtr)
		}
		return 0, err
	}

	// Unpadding：ProcessUplink/Downlink 在直传路径下会直接返回 buf 的子切片，
	// 因此必须在归还 buf 之前完成所有数据拷贝。
	var unpadded []byte
	if r.isUplink {
		unpadded = r.state.ProcessUplink(buf[:n])
	} else {
		unpadded = r.state.ProcessDownlink(buf[:n])
	}

	// ✅ 先完成拷贝，再归还池——防止 use-after-free
	copied := copy(p, unpadded)

	// 若 unpadded 超出 p，将剩余数据独立保存（不依赖池内存）
	if copied < len(unpadded) {
		rest := unpadded[copied:]
		r.leftover = make([]byte, len(rest))
		copy(r.leftover, rest)
	}

	// 归还池缓冲（此时 unpadded 的内容已全部拷走，安全归还）
	if pooledPtr != nil {
		readBufPool.Put(pooledPtr)
	}

	return copied, nil
}

// Close closes the underlying reader if it implements io.Closer
func (r *FlowReader) Close() error {
	if closer, ok := r.reader.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
