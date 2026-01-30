package xhttp

import (
	"io"
	"sync"
)

// WaitReadCloser - 基于 Xray-core 设计的异步响应处理
// 支持延迟设置响应体，提前返回连接
type WaitReadCloser struct {
	Wait     chan struct{}
	ReadCloser io.ReadCloser
	mu       sync.Mutex
}

// NewWaitReadCloser 创建新的 WaitReadCloser
func NewWaitReadCloser() *WaitReadCloser {
	return &WaitReadCloser{
		Wait: make(chan struct{}),
	}
}

// SetReadCloser 设置实际的 ReadCloser
func (w *WaitReadCloser) SetReadCloser(rc io.ReadCloser) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ReadCloser = rc
	close(w.Wait)
}

// Close 关闭 WaitReadCloser
func (w *WaitReadCloser) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	if w.ReadCloser != nil {
		return w.ReadCloser.Close()
	}
	return nil
}

// Read 读取数据，支持延迟等待
func (w *WaitReadCloser) Read(b []byte) (int, error) {
	if w.ReadCloser == nil {
		// 等待 ReadCloser 被设置
		if <-w.Wait; w.ReadCloser == nil {
			return 0, io.ErrClosedPipe
		}
	}
	return w.ReadCloser.Read(b)
}

// Fail 设置失败状态
func (w *WaitReadCloser) Fail(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	
	if w.ReadCloser == nil {
		w.ReadCloser = &errorReader{err: err}
		close(w.Wait)
	}
}

// errorReader 返回错误的 Reader
type errorReader struct {
	err error
}

func (r *errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func (r *errorReader) Close() error {
	return nil
}
