package server

import (
	"io"
	"net"
	"sync"
	"time"

	"ewp-core/protocol/ewp"
	log "ewp-core/log"
)

// UDP 转发处理器 (服务端)
// 实现 Full-Cone NAT，支持 P2P/游戏/语音

const udpIdleTimeout = 5 * time.Minute

var udpBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 65536)
	},
}

// udpHandler 封装单个客户端连接的 UDP 会话管理器。
// 每次调用 HandleUDPConnection 时创建新实例，彻底消除跨连接会话污染。
type udpHandler struct {
	mgr *ewp.UDPSessionManager
}

func newUDPHandler() *udpHandler {
	return &udpHandler{mgr: ewp.NewUDPSessionManager()}
}

// handleStream 阻塞式地从 reader 解码 UDP 包并分发处理。
// 返回时关闭 done channel。
func (h *udpHandler) handleStream(reader io.Reader, writer io.Writer, done chan struct{}) {
	defer close(done)

	for {
		pkt, err := ewp.DecodeUDPPacket(reader)
		if err != nil {
			if err != io.EOF {
				log.Warn("UDP decode error: %v", err)
			}
			return
		}
		go h.handlePacket(pkt, writer)
	}
}

// handlePacket 处理单个 UDP 包（在 goroutine 中调用）。
func (h *udpHandler) handlePacket(pkt *ewp.UDPPacket, writer io.Writer) {
	session, _ := h.mgr.GetOrCreate(pkt.GlobalID)

	session.Lock()
	defer session.Unlock()

	switch pkt.Status {
	case ewp.UDPStatusNew:
		if pkt.Target == nil {
			log.Warn("UDP new packet without target")
			return
		}
		session.LastTarget = pkt.Target

		if session.RemoteConn == nil {
			conn, err := net.DialUDP("udp", nil, pkt.Target)
			if err != nil {
				log.Warn("UDP dial error: %v", err)
				return
			}
			session.RemoteConn = conn
			go h.receiveResponses(session, writer)
		}

		log.Debug("UDP new session: %s (GlobalID: %x)", pkt.Target, pkt.GlobalID[:4])

	case ewp.UDPStatusKeep:
		if pkt.Target != nil {
			session.LastTarget = pkt.Target
		}
		if session.RemoteConn == nil && session.LastTarget != nil {
			conn, err := net.DialUDP("udp", nil, session.LastTarget)
			if err != nil {
				log.Warn("UDP dial error: %v", err)
				return
			}
			session.RemoteConn = conn
			go h.receiveResponses(session, writer)
		}

	case ewp.UDPStatusEnd:
		h.mgr.Remove(pkt.GlobalID)
		log.Debug("UDP session ended (GlobalID: %x)", pkt.GlobalID[:4])
		return
	}

	if session.RemoteConn != nil && len(pkt.Payload) > 0 {
		if _, err := session.RemoteConn.Write(pkt.Payload); err != nil {
			log.Warn("UDP write error: %v", err)
			return
		}
		h.mgr.Touch(pkt.GlobalID)
	}
}

// receiveResponses 接收远端 UDP 响应并转发给客户端。
func (h *udpHandler) receiveResponses(session *ewp.UDPSession, writer io.Writer) {
	buf := udpBufferPool.Get().([]byte)
	defer udpBufferPool.Put(buf)

	const readDeadline = 30 * time.Second

	for {
		session.Lock()
		conn := session.RemoteConn
		lastActive := session.LastActive
		session.Unlock()

		if conn == nil {
			return
		}

		if !lastActive.IsZero() && time.Since(lastActive) > udpIdleTimeout {
			h.mgr.Remove(session.GlobalID)
			return
		}

		conn.SetReadDeadline(time.Now().Add(readDeadline))
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

		h.mgr.Touch(session.GlobalID)

		respPkt := &ewp.UDPPacket{
			GlobalID: session.GlobalID,
			Status:   ewp.UDPStatusKeep,
			Target:   remoteAddr,
			Payload:  buf[:n],
		}

		data, err := ewp.EncodeUDPPacket(respPkt)
		if err != nil {
			log.Warn("UDP encode error: %v", err)
			continue
		}

		if _, err := writer.Write(data); err != nil {
			log.Warn("UDP response write error: %v", err)
			return
		}
	}
}

// HandleUDPConnection 处理 UDP 模式的连接 (用于 EWP CommandUDP)。
// 每次调用创建独立的会话管理器，彻底隔离不同客户端连接的 UDP 状态。
func HandleUDPConnection(reader io.Reader, writer io.Writer) {
	h := newUDPHandler()
	done := make(chan struct{})
	sw := &syncWriter{w: writer}

	go h.handleStream(reader, sw, done)

	cleanupTicker := time.NewTicker(1 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-done:
			h.mgr.Close()
			log.Info("UDP connection closed")
			return
		case <-cleanupTicker.C:
			h.mgr.CloseIdle(udpIdleTimeout)
		}
	}
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


