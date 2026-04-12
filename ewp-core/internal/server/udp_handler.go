package server

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	log "ewp-core/log"
	"ewp-core/protocol/ewp"
)

// UDP 转发处理器 (服务端)
// 实现 Full-Cone NAT，支持 P2P/游戏/语音

const (
	udpIdleTimeout   = 5 * time.Minute
	udpIncomingDepth = 64  // per-session 入包队列深度（有界，防 OOM）
	udpWriteDepth    = 256 // 回包写入队列深度
)

var udpBufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 65536)
		return &b
	},
}

// incomingPkt 是派发给 session worker 的入站包。
// target 为本次发送的目标地址（Full-Cone NAT 允许 Keep 包更换目标）。
type incomingPkt struct {
	target  *net.UDPAddr
	payload []byte
}

// udpSession 管理单个 UDP 会话的所有状态。
// conn 是 ListenUDP 非连接 socket，任意远端均可向其发包（Full-Cone NAT）。
// conn 在创建后不可变，因此 receiveResponses 可以无锁读取。
// lastActiveNs 用 atomic 访问，避免 worker / receiver 双写竞争。
type udpSession struct {
	globalID     [8]byte
	conn         *net.UDPConn    // 建立后不变（ListenUDP 非连接 socket）
	initTarget   *net.UDPAddr    // 初始目标，dispatch 只写（单 goroutine 安全）
	lastActiveNs int64           // atomic UnixNano
	incoming     chan incomingPkt // 有界入包队列
	closeOnce    sync.Once
}

func (s *udpSession) updateActive() {
	atomic.StoreInt64(&s.lastActiveNs, time.Now().UnixNano())
}

func (s *udpSession) idleSince() time.Duration {
	ns := atomic.LoadInt64(&s.lastActiveNs)
	if ns == 0 {
		return 0
	}
	return time.Duration(time.Now().UnixNano() - ns)
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		close(s.incoming)
		if s.conn != nil {
			s.conn.Close()
		}
	})
}

// udpHandler 管理单个客户端连接的全部 UDP 会话。
type udpHandler struct {
	mu       sync.Mutex
	sessions map[[8]byte]*udpSession
	writer   *chanWriter
}

func newUDPHandler(w io.Writer) *udpHandler {
	return &udpHandler{
		sessions: make(map[[8]byte]*udpSession),
		writer:   newChanWriter(w),
	}
}

func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
	h.mu.Lock()
	s, exists := h.sessions[globalID]
	if !exists {
		s = &udpSession{
			globalID: globalID,
			incoming: make(chan incomingPkt, udpIncomingDepth),
		}
		h.sessions[globalID] = s
	}
	h.mu.Unlock()
	return s, !exists
}

func (h *udpHandler) remove(globalID [8]byte) {
	h.mu.Lock()
	s, ok := h.sessions[globalID]
	if ok {
		delete(h.sessions, globalID)
	}
	h.mu.Unlock()
	if ok {
		s.close()
	}
}

func (h *udpHandler) closeAll() {
	h.mu.Lock()
	sessions := make([]*udpSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		sessions = append(sessions, s)
	}
	h.sessions = make(map[[8]byte]*udpSession)
	h.mu.Unlock()

	for _, s := range sessions {
		s.close()
	}
}

func (h *udpHandler) closeIdle(timeout time.Duration) {
	h.mu.Lock()
	var idle []*udpSession
	for id, s := range h.sessions {
		if s.idleSince() > timeout {
			idle = append(idle, s)
			delete(h.sessions, id)
		}
	}
	h.mu.Unlock()
	for _, s := range idle {
		s.close()
	}
}

// handleStream 阻塞式解码入站 UDP 包并派发，退出时关闭 done。
func (h *udpHandler) handleStream(reader io.Reader, done chan struct{}) {
	defer close(done)
	for {
		pkt, err := ewp.DecodeUDPPacket(reader)
		if err != nil {
			if err != io.EOF {
				log.Warn("UDP decode error: %v", err)
			}
			return
		}
		log.V("[Server UDP] Decoded: GlobalID=%x Status=%d Target=%v PayloadLen=%d", 
			pkt.GlobalID[:4], pkt.Status, pkt.Target, len(pkt.Payload))
		h.dispatch(pkt)
	}
}

// dispatch 路由单个包到对应 session（无额外 goroutine，O(1)）。
func (h *udpHandler) dispatch(pkt *ewp.UDPPacket) {
	if pkt.Status == ewp.UDPStatusEnd {
		h.remove(pkt.GlobalID)
		log.Debug("UDP session ended (GlobalID: %x)", pkt.GlobalID[:4])
		return
	}

	s, created := h.getOrCreate(pkt.GlobalID)

	if created {
		// 新 session：必须是 New 状态且带目标地址
		if pkt.Status != ewp.UDPStatusNew || pkt.Target == nil {
			h.remove(pkt.GlobalID)
			return
		}
		// ListenUDP（非连接 socket）：服务器绑定随机本地端口。
		// 任意远端均可向该端口发包 → 真正的 Full-Cone NAT。
		// （DialUDP 是 connected socket，内核仅接受 pkt.Target 来源的回包，
		//  导致 P2P / WebRTC ICE / 负载均衡场景下回包被内核过滤丢弃。）
		// 根据目标地址类型选择合适的网络协议：IPv4或IPv6
		network := "udp4"
		if pkt.Target.IP.To4() == nil {
			network = "udp6"
		}
		conn, err := net.ListenUDP(network, &net.UDPAddr{})
		if err != nil {
			log.Warn("UDP listen error: %v", err)
			h.remove(pkt.GlobalID)
			return
		}
		s.conn = conn
		s.initTarget = pkt.Target
		s.updateActive()
		log.Debug("UDP new session: %s (GlobalID: %x)", pkt.Target, pkt.GlobalID[:4])
		go h.sessionWorker(s)
	} else if s.conn == nil {
		return
	}

	if len(pkt.Payload) == 0 {
		return
	}

	// 每个入站包携带目标地址：Keep 包允许更换目标（多候选地址 ICE/STUN 场景）。
	target := s.initTarget
	if pkt.Target != nil {
		target = pkt.Target
		s.initTarget = pkt.Target // 单 goroutine 写，安全
	}

	// safeSend: 非阻塞投递，recover 防止 closeIdle/sessionWorker 并发关闭
	// s.incoming 导致 send-on-closed-channel panic。
	safeSend(s.incoming, incomingPkt{target: target, payload: pkt.Payload})
}

// safeSend 向 ch 非阻塞投递，忽略队列满和 closed channel 两种情况。
func safeSend(ch chan incomingPkt, pkt incomingPkt) {
	defer func() { recover() }()
	select {
	case ch <- pkt:
	default:
		log.V("[UDP] session queue full, dropping packet")
	}
}

// sessionWorker 是每个 session 的单一出站 goroutine，串行写 UDP 消除锁竞争。
// 同时启动 receiveResponses，两者共享同一 conn（不可变）。
func (h *udpHandler) sessionWorker(s *udpSession) {
	go h.receiveResponses(s) // receiver 在 conn.Close() 时退出

	for pkt := range s.incoming {
		if pkt.target == nil {
			continue
		}
		// WriteTo 明确指定目标地址（非连接 socket 必须）。
		// 允许每个包发往不同目标（ICE 多候选地址检查）。
		if _, err := s.conn.WriteTo(pkt.payload, pkt.target); err != nil {
			log.Warn("UDP write error for %s: %v", pkt.target, err)
			// Don't return/remove session on write error - just continue
			// The session will timeout eventually if target is unreachable
			continue
		}
		s.updateActive()
	}
}

// receiveResponses 接收远端 UDP 响应并转发给客户端。
// conn 引用在 session 创建时固定，无需加锁。
func (h *udpHandler) receiveResponses(s *udpSession) {
	bufp := udpBufferPool.Get().(*[]byte)
	buf := *bufp
	defer udpBufferPool.Put(bufp)

	const readDeadline = 30 * time.Second
	conn := s.conn // 不可变，安全无锁读取

	for {
		if s.idleSince() > udpIdleTimeout {
			h.remove(s.globalID)
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
		s.updateActive()

		respPkt := &ewp.UDPPacket{
			GlobalID: s.globalID,
			Status:   ewp.UDPStatusKeep,
			Target:   remoteAddr,
			Payload:  buf[:n],
		}

		data, err := ewp.EncodeUDPPacket(respPkt)
		if err != nil {
			log.Warn("UDP encode error: %v", err)
			continue
		}

		if err := h.writer.write(data); err != nil {
			log.Warn("UDP response write failed: %v, session may be disconnected", err)
			// Don't return here - continue processing other responses
			// The session will eventually timeout and be cleaned up
			continue
		}
	}
}

// HandleUDPConnection 处理 UDP 模式连接，每次调用独立隔离所有状态。
func HandleUDPConnection(reader io.Reader, writer io.Writer) {
	h := newUDPHandler(writer)
	done := make(chan struct{})

	go h.handleStream(reader, done)

	cleanupTicker := time.NewTicker(1 * time.Minute)
	defer cleanupTicker.Stop()

	for {
		select {
		case <-done:
			h.closeAll()
			h.writer.close()
			log.Info("UDP connection closed")
			return
		case <-cleanupTicker.C:
			h.closeIdle(udpIdleTimeout)
		}
	}
}

// chanWriter 用单 goroutine 序列化所有回包写入，替代 mutex syncWriter。
// 各 session 的 receiveResponses goroutine 并发投递到 channel，
// 写入 goroutine 顺序消费，彻底消除锁竞争。
type chanWriter struct {
	ch        chan []byte
	w         io.Writer
	closeOnce sync.Once
	wg        sync.WaitGroup
	lastErr   unsafe.Pointer // *error, atomic
}

func newChanWriter(w io.Writer) *chanWriter {
	cw := &chanWriter{
		ch: make(chan []byte, udpWriteDepth),
		w:  w,
	}
	cw.wg.Add(1)
	go cw.loop()
	return cw
}

func (cw *chanWriter) loop() {
	defer cw.wg.Done()
	for data := range cw.ch {
		if _, err := cw.w.Write(data); err != nil {
			errPtr := err
			atomic.StorePointer(&cw.lastErr, unsafe.Pointer(&errPtr))
			// Writer is broken: drain remaining items to unblock write() callers
			// and allow close() to complete. No further Write calls.
			for range cw.ch {
			}
			return
		}
	}
}

func (cw *chanWriter) write(data []byte) (writeErr error) {
	if p := atomic.LoadPointer(&cw.lastErr); p != nil {
		return *(*error)(p)
	}
	// Recover from send-on-closed-channel panic that can occur if close()
	// races with a receiveResponses goroutine that is still writing.
	defer func() {
		if r := recover(); r != nil {
			writeErr = io.ErrClosedPipe
		}
	}()
	cw.ch <- data
	return nil
}

func (cw *chanWriter) close() {
	cw.closeOnce.Do(func() {
		close(cw.ch)
		cw.wg.Wait()
	})
}
