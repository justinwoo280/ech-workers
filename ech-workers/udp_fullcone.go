package main

import (
	"io"
	"log"
	"net"
	"sync"
	"time"

	"ech-client/ewp"
)

// UDP Full-Cone NAT 实现 (基于 Xray-core proxy/tun/udp_fullcone.go)
// 按源地址映射连接，实现 Full-Cone NAT，支持 P2P/游戏/语音

// UDPResponseCallback 用于将 UDP 响应发送回客户端
type UDPResponseCallback func(src, dst *net.UDPAddr, payload []byte)

// UDPConnectionHandler 处理 TUN 模式下的 UDP 连接
type UDPConnectionHandler struct {
	sync.Mutex
	conns           map[string]*UDPProxyConn // key: 源地址 (src:port)
	transport       Transport                // 代理传输层
	sessionManager  *ewp.UDPSessionManager
	cleanupInterval time.Duration
	connTimeout     time.Duration
	responseCallback UDPResponseCallback     // 响应回调
}

// UDPProxyConn 代表一个 UDP 代理连接
type UDPProxyConn struct {
	handler    *UDPConnectionHandler
	srcAddr    *net.UDPAddr          // 客户端源地址
	globalID   [8]byte               // 会话标识
	tunnel     TunnelConn            // 到代理服务器的连接
	egress     chan *ewp.UDPPacket   // 发送队列
	lastActive time.Time
	closed     bool
	mu         sync.Mutex
}

// NewUDPConnectionHandler 创建 UDP 连接处理器
func NewUDPConnectionHandler(transport Transport, callback UDPResponseCallback) *UDPConnectionHandler {
	h := &UDPConnectionHandler{
		conns:            make(map[string]*UDPProxyConn),
		transport:        transport,
		sessionManager:   ewp.NewUDPSessionManager(),
		cleanupInterval:  30 * time.Second,
		connTimeout:      2 * time.Minute,
		responseCallback: callback,
	}
	go h.cleanupLoop()
	return h
}

// HandlePacket 处理来自 TUN 的 UDP 包
// 实现 Full-Cone NAT：按源地址映射，不按目标地址
func (h *UDPConnectionHandler) HandlePacket(src *net.UDPAddr, dst *net.UDPAddr, data []byte) error {
	srcKey := src.String()

	h.Lock()
	conn, exists := h.conns[srcKey]
	if !exists {
		// 创建新连接
		conn = &UDPProxyConn{
			handler:    h,
			srcAddr:    src,
			globalID:   ewp.GenerateGlobalID(src),
			egress:     make(chan *ewp.UDPPacket, 64),
			lastActive: time.Now(),
		}
		h.conns[srcKey] = conn
		h.Unlock()

		// 启动连接处理
		go conn.run()
	} else {
		h.Unlock()
	}

	// 更新活动时间
	conn.mu.Lock()
	conn.lastActive = time.Now()
	conn.mu.Unlock()

	// 构建 UDP 包
	pkt := &ewp.UDPPacket{
		GlobalID: conn.globalID,
		Status:   ewp.UDPStatusKeep,
		Target:   dst,
		Payload:  data,
	}

	// 第一个包需要带完整地址
	if !exists {
		pkt.Status = ewp.UDPStatusNew
	}

	// 发送到队列
	select {
	case conn.egress <- pkt:
	default:
		// 队列满，丢弃
		logV("[UDP-FC] 队列满，丢弃包: %s -> %s", src, dst)
	}

	return nil
}

// run 运行 UDP 代理连接
func (c *UDPProxyConn) run() {
	defer c.close()

	// 建立到代理服务器的连接
	tunnel, err := c.handler.transport.Dial()
	if err != nil {
		log.Printf("[UDP-FC] 建立隧道失败: %v", err)
		return
	}
	c.tunnel = tunnel

	// 发送 UDP 连接请求 (特殊目标地址表示 UDP 模式)
	udpTarget := "udp://0.0.0.0:0"
	if err := tunnel.Connect(udpTarget, nil); err != nil {
		log.Printf("[UDP-FC] 连接失败: %v", err)
		return
	}

	logV("[UDP-FC] 连接建立: %s (GlobalID: %x)", c.srcAddr, c.globalID[:4])

	// 启动读取协程
	go c.readLoop()

	// 写入循环
	c.writeLoop()
}

// writeLoop 发送数据到代理服务器
func (c *UDPProxyConn) writeLoop() {
	for pkt := range c.egress {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		// 编码 UDP 包
		data, err := ewp.EncodeUDPPacket(pkt)
		if err != nil {
			log.Printf("[UDP-FC] 编码失败: %v", err)
			continue
		}

		// 发送到隧道
		if err := c.tunnel.Write(data); err != nil {
			log.Printf("[UDP-FC] 发送失败: %v", err)
			return
		}
	}
}

// readLoop 从代理服务器接收数据
func (c *UDPProxyConn) readLoop() {
	buf := make([]byte, 65536)
	reader := &tunnelReader{tunnel: c.tunnel, buf: buf}

	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()

		// 解码 UDP 包
		pkt, err := ewp.DecodeUDPPacket(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("[UDP-FC] 解码失败: %v", err)
			}
			return
		}

		// 发送回客户端
		c.sendToClient(pkt)
	}
}

// sendToClient 发送数据回客户端 (通过回调)
func (c *UDPProxyConn) sendToClient(pkt *ewp.UDPPacket) {
	if pkt.Target == nil || len(pkt.Payload) == 0 {
		return
	}

	// 通过回调发送回客户端
	if c.handler.responseCallback != nil {
		c.handler.responseCallback(pkt.Target, c.srcAddr, pkt.Payload)
	}

	logV("[UDP-FC] 收到响应: %s -> %s (%d bytes)", pkt.Target, c.srcAddr, len(pkt.Payload))
}

// close 关闭连接
func (c *UDPProxyConn) close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.mu.Unlock()

	close(c.egress)
	if c.tunnel != nil {
		c.tunnel.Close()
	}

	// 从管理器中删除
	c.handler.Lock()
	delete(c.handler.conns, c.srcAddr.String())
	c.handler.Unlock()

	logV("[UDP-FC] 连接关闭: %s", c.srcAddr)
}

// cleanupLoop 定期清理过期连接
func (h *UDPConnectionHandler) cleanupLoop() {
	ticker := time.NewTicker(h.cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		h.Lock()
		now := time.Now()
		var toDelete []string
		for key, conn := range h.conns {
			conn.mu.Lock()
			if now.Sub(conn.lastActive) > h.connTimeout {
				toDelete = append(toDelete, key)
			}
			conn.mu.Unlock()
		}
		h.Unlock()

		for _, key := range toDelete {
			h.Lock()
			if conn, exists := h.conns[key]; exists {
				go conn.close()
			}
			h.Unlock()
		}
	}
}

// Close 关闭所有连接
func (h *UDPConnectionHandler) Close() {
	h.Lock()
	defer h.Unlock()

	for _, conn := range h.conns {
		go conn.close()
	}
	h.conns = make(map[string]*UDPProxyConn)
}

// tunnelReader 适配器，让 TunnelConn 实现 io.Reader
type tunnelReader struct {
	tunnel TunnelConn
	buf    []byte
	data   []byte
	pos    int
}

func (r *tunnelReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		// 需要读取更多数据
		n, err := r.tunnel.Read(r.buf)
		if err != nil {
			return 0, err
		}
		r.data = r.buf[:n]
		r.pos = 0
	}

	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

