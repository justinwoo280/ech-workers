package xhttp

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// XmuxHTTPClient 包装 HTTP 客户端实现 XmuxConn 接口
type XmuxHTTPClient struct {
	client      *http.Client
	closed      int32  // 使用 atomic 操作
	lastActive  int64  // UnixNano 时间戳
	requestCount int64 // 请求计数
	mu          sync.RWMutex
}

// NewXmuxHTTPClient 创建新的 Xmux HTTP 客户端
func NewXmuxHTTPClient(client *http.Client) *XmuxHTTPClient {
	return &XmuxHTTPClient{
		client:     client,
		lastActive: time.Now().UnixNano(),
	}
}

// IsClosed 检查连接是否已关闭
func (x *XmuxHTTPClient) IsClosed() bool {
	return atomic.LoadInt32(&x.closed) == 1
}

// Close 关闭连接
func (x *XmuxHTTPClient) Close() error {
	if !atomic.CompareAndSwapInt32(&x.closed, 0, 1) {
		return nil // 已经关闭
	}
	
	// 关闭 HTTP 客户端的空闲连接
	if transport, ok := x.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	
	return nil
}

// GetLastActiveTime 获取最后活跃时间
func (x *XmuxHTTPClient) GetLastActiveTime() time.Time {
	nano := atomic.LoadInt64(&x.lastActive)
	return time.Unix(0, nano)
}

// GetRequestCount 获取请求计数
func (x *XmuxHTTPClient) GetRequestCount() int64 {
	return atomic.LoadInt64(&x.requestCount)
}

// IncrementRequestCount 增加请求计数
func (x *XmuxHTTPClient) IncrementRequestCount() {
	atomic.AddInt64(&x.requestCount, 1)
	atomic.StoreInt64(&x.lastActive, time.Now().UnixNano())
}

// GetClient 获取原始 HTTP 客户端
func (x *XmuxHTTPClient) GetClient() *http.Client {
	return x.client
}

// XmuxStreamOneConn 包装 StreamOneConn 实现 XmuxConn 接口
type XmuxStreamOneConn struct {
	conn        *StreamOneConn
	closed      int32
	lastActive  int64
	requestCount int64
	mu          sync.RWMutex
}

// NewXmuxStreamOneConn 创建新的 Xmux StreamOne 连接
func NewXmuxStreamOneConn(conn *StreamOneConn) *XmuxStreamOneConn {
	return &XmuxStreamOneConn{
		conn:       conn,
		lastActive: time.Now().UnixNano(),
	}
}

// IsClosed 检查连接是否已关闭
func (x *XmuxStreamOneConn) IsClosed() bool {
	return atomic.LoadInt32(&x.closed) == 1
}

// Close 关闭连接
func (x *XmuxStreamOneConn) Close() error {
	if !atomic.CompareAndSwapInt32(&x.closed, 0, 1) {
		return nil // 已经关闭
	}
	
	return x.conn.Close()
}

// GetLastActiveTime 获取最后活跃时间
func (x *XmuxStreamOneConn) GetLastActiveTime() time.Time {
	nano := atomic.LoadInt64(&x.lastActive)
	return time.Unix(0, nano)
}

// GetRequestCount 获取请求计数
func (x *XmuxStreamOneConn) GetRequestCount() int64 {
	return atomic.LoadInt64(&x.requestCount)
}

// IncrementRequestCount 增加请求计数
func (x *XmuxStreamOneConn) IncrementRequestCount() {
	atomic.AddInt64(&x.requestCount, 1)
	atomic.StoreInt64(&x.lastActive, time.Now().UnixNano())
}

// GetConn 获取原始连接
func (x *XmuxStreamOneConn) GetConn() *StreamOneConn {
	return x.conn
}

// XmuxStreamDownConn 包装 StreamDownConn 实现 XmuxConn 接口
type XmuxStreamDownConn struct {
	conn        *StreamDownConn
	closed      int32
	lastActive  int64
	requestCount int64
	mu          sync.RWMutex
}

// NewXmuxStreamDownConn 创建新的 Xmux StreamDown 连接
func NewXmuxStreamDownConn(conn *StreamDownConn) *XmuxStreamDownConn {
	return &XmuxStreamDownConn{
		conn:       conn,
		lastActive: time.Now().UnixNano(),
	}
}

// IsClosed 检查连接是否已关闭
func (x *XmuxStreamDownConn) IsClosed() bool {
	return atomic.LoadInt32(&x.closed) == 1
}

// Close 关闭连接
func (x *XmuxStreamDownConn) Close() error {
	if !atomic.CompareAndSwapInt32(&x.closed, 0, 1) {
		return nil // 已经关闭
	}
	
	return x.conn.Close()
}

// GetLastActiveTime 获取最后活跃时间
func (x *XmuxStreamDownConn) GetLastActiveTime() time.Time {
	nano := atomic.LoadInt64(&x.lastActive)
	return time.Unix(0, nano)
}

// GetRequestCount 获取请求计数
func (x *XmuxStreamDownConn) GetRequestCount() int64 {
	return atomic.LoadInt64(&x.requestCount)
}

// IncrementRequestCount 增加请求计数
func (x *XmuxStreamDownConn) IncrementRequestCount() {
	atomic.AddInt64(&x.requestCount, 1)
	atomic.StoreInt64(&x.lastActive, time.Now().UnixNano())
}

// GetConn 获取原始连接
func (x *XmuxStreamDownConn) GetConn() *StreamDownConn {
	return x.conn
}
