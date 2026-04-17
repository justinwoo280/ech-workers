package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	log "ewp-core/log"
	"ewp-core/protocol/ewp"
)

// dnsResolveTimeout caps synchronous and async DNS lookups so a slow or
// malicious resolver cannot block the handleStream goroutine indefinitely.
const dnsResolveTimeout = 2 * time.Second

// UDP 转发处理器 (服务端)
// 实现 Full-Cone NAT，支持 P2P/游戏/语音

const (
	udpIdleTimeout   = 5 * time.Minute
	udpIncomingDepth = 64  // per-session 入包队列深度（有界，防 OOM）
	udpWriteDepth    = 256 // 回包写入队列深度

	// maxUDPSessionsPerConn is the per-connection session cap.
	// A single authenticated client cannot open more than this many concurrent
	// UDP sessions; the oldest idle session is evicted when the cap is hit.
	// This prevents fd/goroutine exhaustion via GlobalID flooding. (P1-3)
	maxUDPSessionsPerConn = 500
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
	conn         *net.UDPConn     // 建立后不变（ListenUDP 非连接 socket）
	initTarget   *net.UDPAddr     // 初始目标，dispatch 只写（单 goroutine 安全）
	lastActiveNs int64            // atomic UnixNano
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
	mu              sync.Mutex
	sessions        map[[8]byte]*udpSession
	writer          *chanWriter
	handshakeTarget string // 握手时客户端提供的目标地址 (domain:port 或 ip:port)
}

func newUDPHandler(w io.Writer, handshakeTarget string) *udpHandler {
	return &udpHandler{
		sessions:        make(map[[8]byte]*udpSession),
		writer:          newChanWriter(w),
		handshakeTarget: handshakeTarget,
	}
}

func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
	h.mu.Lock()
	s, exists := h.sessions[globalID]
	if !exists {
		// P1-3: enforce per-connection session cap.
		if len(h.sessions) >= maxUDPSessionsPerConn {
			h.evictOldestIdle_locked()
		}
		s = &udpSession{
			globalID: globalID,
			incoming: make(chan incomingPkt, udpIncomingDepth),
		}
		h.sessions[globalID] = s
	}
	h.mu.Unlock()
	return s, !exists
}

// evictOldestIdle_locked removes the session with the longest idle time.
// Must be called with h.mu held.
func (h *udpHandler) evictOldestIdle_locked() {
	var (
		oldestID   [8]byte
		oldestIdle time.Duration
		found      bool
	)
	for id, s := range h.sessions {
		if idle := s.idleSince(); idle > oldestIdle {
			oldestIdle = idle
			oldestID = id
			found = true
		}
	}
	if found {
		s := h.sessions[oldestID]
		delete(h.sessions, oldestID)
		go s.close() // close outside the lock to avoid deadlock
		log.V("[UDP] session cap reached (%d), evicted oldest idle session (idle=%s)",
			maxUDPSessionsPerConn, oldestIdle.Round(time.Second))
	}
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
		// 新 session：必须是 New 状态
		if pkt.Status != ewp.UDPStatusNew {
			h.remove(pkt.GlobalID)
			return
		}

		// 确定目标地址，按优先级：
		//   1. 帧内 IP 地址 (pkt.Target)           → 直接使用，无需 DNS
		//   2. 帧内域名 (pkt.TargetHost)            → 异步 DNS（P0-4）
		//   3. 握手阶段的 handshakeTarget（兜底）   → 异步 DNS（P0-4）
		target := pkt.Target

		if target == nil && (pkt.TargetHost != "" || h.handshakeTarget != "") {
			// P0-4: DNS resolution is async — we must NOT block the handleStream
			// goroutine.  A slow or unresolvable name (e.g. attack with random
			// domains) would otherwise stall all subsequent packets on this
			// connection for up to the OS DNS timeout (5 s by default).
			//
			// Strategy:
			//   1. Session was already created by getOrCreate() above (conn == nil).
			//   2. We spawn a goroutine that resolves DNS with a hard 2 s deadline.
			//   3. On success  → creates the UDP socket, starts sessionWorker,
			//      forwards the initial payload.
			//   4. On failure  → removes the session (client gets no response,
			//      which is the same observable behaviour as before).
			//   5. Subsequent packets that arrive while DNS is in-flight hit the
			//      `else if s.conn == nil { return }` branch below and are dropped
			//      (acceptable: they will be retransmitted by the application).

			var resolveHost string
			var resolvePort int

			if pkt.TargetHost != "" {
				resolveHost = pkt.TargetHost
				resolvePort = int(pkt.TargetPort)
			} else {
				host, portStr, err := net.SplitHostPort(h.handshakeTarget)
				if err != nil {
					log.Warn("UDP parse handshake target %q: %v", h.handshakeTarget, err)
					h.remove(pkt.GlobalID)
					return
				}
				resolveHost = host
				fmt.Sscanf(portStr, "%d", &resolvePort)
			}

			// Capture values needed inside the goroutine.
			globalID := pkt.GlobalID
			payload := append([]byte(nil), pkt.Payload...)
			capturedS := s

			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
				defer cancel()

				addrs, err := net.DefaultResolver.LookupIPAddr(ctx, resolveHost)
				if err != nil || len(addrs) == 0 {
					log.Warn("UDP async resolve %q: %v", resolveHost, err)
					h.remove(globalID)
					return
				}
				resolved := &net.UDPAddr{IP: addrs[0].IP, Port: resolvePort}

				// Re-acquire the lock to check the session is still alive and to
				// initialise the UDP socket atomically.
				h.mu.Lock()
				curr, exists := h.sessions[globalID]
				if !exists || curr != capturedS {
					// Session was removed (e.g. UDPStatusEnd arrived) during resolution.
					h.mu.Unlock()
					return
				}

				network := "udp4"
				if resolved.IP.To4() == nil {
					network = "udp6"
				}
				conn, listenErr := net.ListenUDP(network, &net.UDPAddr{})
				if listenErr != nil {
					h.mu.Unlock()
					log.Warn("UDP listen error: %v", listenErr)
					h.remove(globalID)
					return
				}
				capturedS.conn = conn
				capturedS.initTarget = resolved
				capturedS.updateActive()
				h.mu.Unlock()

				log.Debug("UDP async resolved %q -> %s (GlobalID: %x)", resolveHost, resolved, globalID[:4])
				go h.sessionWorker(capturedS)

				if len(payload) > 0 {
					safeSend(capturedS.incoming, incomingPkt{target: resolved, payload: payload})
				}
			}()
			return // Return immediately — do not block the reader goroutine.
		}

		if target == nil {
			log.Warn("UDP new session without target (GlobalID: %x)", pkt.GlobalID[:4])
			h.remove(pkt.GlobalID)
			return
		}

		// IP target: create session synchronously (no DNS needed).
		network := "udp4"
		if target.IP.To4() == nil {
			network = "udp6"
		}
		conn, err := net.ListenUDP(network, &net.UDPAddr{})
		if err != nil {
			log.Warn("UDP listen error: %v", err)
			h.remove(pkt.GlobalID)
			return
		}
		s.conn = conn
		s.initTarget = target
		s.updateActive()
		log.Debug("UDP new session: %s (GlobalID: %x)", target, pkt.GlobalID[:4])
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
	} else if pkt.TargetHost != "" {
		// Keep 包携带域名 target，解析后更新。
		// P0-4: enforce a short timeout so a bad domain cannot stall this goroutine.
		ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, pkt.TargetHost)
		cancel()
		if err == nil && len(addrs) > 0 {
			resolved := &net.UDPAddr{IP: addrs[0].IP, Port: int(pkt.TargetPort)}
			target = resolved
			s.initTarget = resolved
		}
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
// handshakeTarget 是握手阶段客户端提供的目标地址（domain:port 或 ip:port），
// 当 UDP 帧中未携带目标 IP 时（域名场景），服务端使用此地址进行 DNS 解析。
func HandleUDPConnection(reader io.Reader, writer io.Writer, handshakeTarget string) {
	h := newUDPHandler(writer, handshakeTarget)
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
