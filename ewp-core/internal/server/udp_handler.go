package server

import (
	"bytes"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"ewp-core/protocol/ewp"
)

// UDP 转发处理器 (服务端)
// 实现 Full-Cone NAT，支持 P2P/游戏/语音

var (
	udpSessionManager = ewp.NewUDPSessionManager()
	udpBufferPool     = sync.Pool{
		New: func() interface{} {
			return make([]byte, 65536)
		},
	}
)

// HandleUDPStream 处理 UDP 流 (通过 TCP 隧道)
// reader: 从客户端读取 UDP 包
// writer: 向客户端写入 UDP 响应
func HandleUDPStream(reader io.Reader, writer io.Writer, done chan struct{}) {
	defer close(done)

	for {
		// 解码 UDP 包
		pkt, err := ewp.DecodeUDPPacket(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("❌ UDP decode error: %v", err)
			}
			return
		}

		// 处理 UDP 包
		go handleUDPPacket(pkt, writer)
	}
}

// handleUDPPacket 处理单个 UDP 包
func handleUDPPacket(pkt *ewp.UDPPacket, writer io.Writer) {
	// 获取或创建会话
	session, _ := udpSessionManager.GetOrCreate(pkt.GlobalID)

	session.Lock()
	defer session.Unlock()

	// 处理状态
	switch pkt.Status {
	case ewp.UDPStatusNew:
		if pkt.Target == nil {
			log.Printf("❌ UDP New packet without target")
			return
		}
		session.LastTarget = pkt.Target

		// 创建到目标的 UDP 连接
		if session.RemoteConn == nil {
			conn, err := net.DialUDP("udp", nil, pkt.Target)
			if err != nil {
				log.Printf("❌ UDP dial error: %v", err)
				return
			}
			session.RemoteConn = conn

			// 启动接收协程
			go receiveUDPResponses(session, writer)
		}

		log.Printf("📦 UDP New: %s (GlobalID: %x)", pkt.Target, pkt.GlobalID[:4])

	case ewp.UDPStatusKeep:
		// 更新目标地址（如果提供）
		if pkt.Target != nil {
			session.LastTarget = pkt.Target
		}

		// 如果连接不存在，需要重新建立
		if session.RemoteConn == nil && session.LastTarget != nil {
			conn, err := net.DialUDP("udp", nil, session.LastTarget)
			if err != nil {
				log.Printf("❌ UDP dial error: %v", err)
				return
			}
			session.RemoteConn = conn
			go receiveUDPResponses(session, writer)
		}

	case ewp.UDPStatusEnd:
		// 关闭会话
		udpSessionManager.Remove(pkt.GlobalID)
		log.Printf("📦 UDP End: GlobalID %x", pkt.GlobalID[:4])
		return
	}

	// 发送数据到目标
	if session.RemoteConn != nil && len(pkt.Payload) > 0 {
		_, err := session.RemoteConn.Write(pkt.Payload)
		if err != nil {
			log.Printf("❌ UDP write error: %v", err)
			return
		}
	}
}

// receiveUDPResponses 接收 UDP 响应并发送回客户端
func receiveUDPResponses(session *ewp.UDPSession, writer io.Writer) {
	buf := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(buf)

	for {
		session.Lock()
		conn := session.RemoteConn
		session.Unlock()

		if conn == nil {
			return
		}

		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return
		}

		if n == 0 {
			continue
		}

		// 构建响应包
		respPkt := &ewp.UDPPacket{
			GlobalID: session.GlobalID,
			Status:   ewp.UDPStatusKeep,
			Target:   remoteAddr,
			Payload:  buf[:n],
		}

		// 编码并发送
		data, err := ewp.EncodeUDPPacket(respPkt)
		if err != nil {
			log.Printf("❌ UDP encode error: %v", err)
			continue
		}

		if _, err := writer.Write(data); err != nil {
			log.Printf("❌ UDP response write error: %v", err)
			return
		}
	}
}

// HandleUDPConnection 处理 UDP 模式的连接 (用于 EWP CommandUDP)
func HandleUDPConnection(reader io.Reader, writer io.Writer) {
	done := make(chan struct{})

	// 使用带缓冲的 writer
	bufWriter := &syncWriter{w: writer}

	go HandleUDPStream(reader, bufWriter, done)

	<-done
	log.Printf("✅ UDP connection closed")
}

// syncWriter 线程安全的 writer
type syncWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}

// CleanupUDPSessions 清理所有 UDP 会话
func CleanupUDPSessions() {
	udpSessionManager.Close()
}

// IsUDPTarget 检查目标是否是 UDP 模式标识
func IsUDPTarget(target string) bool {
	return len(target) >= 6 && target[:6] == "udp://"
}

// HandleUDPStreamBidirectional 处理双向 UDP 流
func HandleUDPStreamBidirectional(rw io.ReadWriter) {
	done := make(chan struct{})
	
	// 创建缓冲读取器
	bufReader := &bytes.Buffer{}
	
	// 启动读取协程
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := rw.Read(buf)
			if err != nil {
				close(done)
				return
			}
			bufReader.Write(buf[:n])
		}
	}()

	// 处理 UDP 流
	HandleUDPStream(bufReader, rw, done)
}
