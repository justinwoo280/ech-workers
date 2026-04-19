package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	commpool "ewp-core/common/bufferpool"
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

// udpSession 管理单个 UDP 会话的所有状态。
// conn 是 ListenUDP 非连接 socket，任意远端均可向其发包（Full-Cone NAT）。
// conn 在创建后不可变，因此 receiveResponses 可以无锁读取。
// lastActiveNs 用 atomic 访问，避免并发写竞争。
// P2-UDP-OPT: 移除 incoming channel，直接调用 conn.WriteTo（线程安全）
type udpSession struct {
	globalID     [8]byte
	conn         *net.UDPConn                // 建立后不变（ListenUDP 非连接 socket）
	initTarget   atomic.Pointer[net.UDPAddr] // Bug-B: 使用 atomic.Pointer 避免竞态
	lastActiveNs int64                       // atomic UnixNano
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
		if s.conn != nil {
			s.conn.Close()
		}
	})
}

// udpHandler 管理单个客户端连接的全部 UDP 会话。
// P2-UDP-OPT: 使用 sync.Map 实现无锁读取（99% 的包是现有会话）
type udpHandler struct {
	sessions        sync.Map // map[[8]byte]*udpSession
	sessionCount    atomic.Int32
	writer          *chanWriter
	handshakeTarget string // 握手时客户端提供的目标地址 (domain:port 或 ip:port)
}

func newUDPHandler(w io.Writer, handshakeTarget string) *udpHandler {
	return &udpHandler{
		writer:          newChanWriter(w),
		handshakeTarget: handshakeTarget,
	}
}

func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
	// P2-UDP-OPT: 快速路径 - 无锁读取（99% 的包）
	if val, ok := h.sessions.Load(globalID); ok {
		return val.(*udpSession), false
	}

	// 慢速路径：创建新会话
	// 检查会话上限
	if h.sessionCount.Load() >= maxUDPSessionsPerConn {
		h.evictOldestIdle()
	}

	s := &udpSession{
		globalID: globalID,
	}

	// 原子插入（如果不存在）
	actual, loaded := h.sessions.LoadOrStore(globalID, s)
	if loaded {
		// 另一个 goroutine 先创建了，使用它的
		return actual.(*udpSession), false
	}

	// 我们创建了它
	h.sessionCount.Add(1)
	return s, true
}

// evictOldestIdle removes the session with the longest idle time.
// P2-UDP-OPT: 使用 sync.Map.Range 遍历
func (h *udpHandler) evictOldestIdle() {
	var (
		oldestKey  [8]byte
		oldestIdle time.Duration
		found      bool
	)

	h.sessions.Range(func(key, value interface{}) bool {
		id := key.([8]byte)
		s := value.(*udpSession)
		if idle := s.idleSince(); idle > oldestIdle {
			oldestIdle = idle
			oldestKey = id
			found = true
		}
		return true
	})

	if found {
		if val, loaded := h.sessions.LoadAndDelete(oldestKey); loaded {
			h.sessionCount.Add(-1)
			s := val.(*udpSession)
			s.close()
			log.V("[UDP] session cap reached (%d), evicted oldest idle session (idle=%s)",
				maxUDPSessionsPerConn, oldestIdle.Round(time.Second))
		}
	}
}

func (h *udpHandler) remove(globalID [8]byte) {
	if val, loaded := h.sessions.LoadAndDelete(globalID); loaded {
		h.sessionCount.Add(-1)
		s := val.(*udpSession)
		s.close()
	}
}

func (h *udpHandler) closeAll() {
	var sessions []*udpSession
	h.sessions.Range(func(key, value interface{}) bool {
		sessions = append(sessions, value.(*udpSession))
		return true
	})

	// 清空 map
	h.sessions.Range(func(key, value interface{}) bool {
		h.sessions.Delete(key)
		return true
	})
	h.sessionCount.Store(0)

	// 关闭所有会话
	for _, s := range sessions {
		s.close()
	}
}

func (h *udpHandler) closeIdle(timeout time.Duration) {
	var idle [][2]interface{} // [globalID, *udpSession]
	h.sessions.Range(func(key, value interface{}) bool {
		s := value.(*udpSession)
		if s.idleSince() > timeout {
			idle = append(idle, [2]interface{}{key, s})
		}
		return true
	})

	for _, pair := range idle {
		if _, loaded := h.sessions.LoadAndDelete(pair[0]); loaded {
			h.sessionCount.Add(-1)
			pair[1].(*udpSession).close()
		}
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

// dispatch 路由单个包到对应 session。
// P3-UDP-OPT: 直接调用 conn.WriteTo（线程安全），移除 channel 和 worker goroutine
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

				// 检查会话是否仍然存在
				val, exists := h.sessions.Load(globalID)
				if !exists || val.(*udpSession) != capturedS {
					// Session was removed (e.g. UDPStatusEnd arrived) during resolution.
					return
				}

				network := "udp4"
				if resolved.IP.To4() == nil {
					network = "udp6"
				}
				conn, listenErr := net.ListenUDP(network, &net.UDPAddr{})
				if listenErr != nil {
					log.Warn("UDP listen error: %v", listenErr)
					h.remove(globalID)
					return
				}
				capturedS.conn = conn
				capturedS.initTarget.Store(resolved)
				capturedS.updateActive()

				log.Debug("UDP async resolved %q -> %s (GlobalID: %x)", resolveHost, resolved, globalID[:4])
				
				// P3-UDP-OPT: 仅启动接收器，无 worker
				go h.receiveResponses(capturedS)

				// P3-UDP-OPT: 直接写入 UDP socket（线程安全）
				if len(payload) > 0 && resolved != nil {
					if _, err := capturedS.conn.WriteTo(payload, resolved); err != nil {
						log.Warn("UDP write error for %s: %v", resolved, err)
					} else {
						capturedS.updateActive()
					}
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
		s.initTarget.Store(target)
		s.updateActive()
		log.Debug("UDP new session: %s (GlobalID: %x)", target, pkt.GlobalID[:4])
		
		// P3-UDP-OPT: 仅启动接收器，无 worker
		go h.receiveResponses(s)
	} else if s.conn == nil {
		return
	}

	if len(pkt.Payload) == 0 {
		return
	}

	// 每个入站包携带目标地址：Keep 包允许更换目标（多候选地址 ICE/STUN 场景）。
	target := s.initTarget.Load()
	if pkt.Target != nil {
		target = pkt.Target
		s.initTarget.Store(pkt.Target)
	} else if pkt.TargetHost != "" {
		// Keep 包携带域名 target，解析后更新。
		// P0-4: enforce a short timeout so a bad domain cannot stall this goroutine.
		ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, pkt.TargetHost)
		cancel()
		if err == nil && len(addrs) > 0 {
			resolved := &net.UDPAddr{IP: addrs[0].IP, Port: int(pkt.TargetPort)}
			target = resolved
			s.initTarget.Store(resolved)
		}
	}

	// P3-UDP-OPT: 直接写入 UDP socket（线程安全，无需 channel）
	if target != nil {
		if _, err := s.conn.WriteTo(pkt.Payload, target); err != nil {
			log.Warn("UDP write error for %s: %v", target, err)
			// Don't remove session on write error - it will timeout eventually
		} else {
			s.updateActive()
		}
	}
}

// receiveResponses 接收远端 UDP 响应并转发给客户端。
// conn 引用在 session 创建时固定，无需加锁。
func (h *udpHandler) receiveResponses(s *udpSession) {
	bufp := udpBufferPool.Get().(*[]byte)
	buf := *bufp
	defer udpBufferPool.Put(bufp)

	// P1-UDP-OPT: 使用池化写缓冲区实现零分配热路径
	writeBuf := commpool.GetLarge()
	defer commpool.PutLarge(writeBuf)

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

		// P1-UDP-OPT: 使用 AppendUDPAddrFrame 和池化缓冲区（零分配）
		writeBuf = writeBuf[:0] // 重置缓冲区长度
		addr, ok := netip.AddrFromSlice(remoteAddr.IP)
		if !ok {
			log.Warn("UDP invalid remote IP: %v", remoteAddr.IP)
			continue
		}
		addrPort := netip.AddrPortFrom(addr, uint16(remoteAddr.Port))
		writeBuf = ewp.AppendUDPAddrFrame(
			writeBuf,
			s.globalID,
			ewp.UDPStatusKeep,
			addrPort,
			buf[:n],
		)

		if err := h.writer.write(writeBuf); err != nil {
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
	closed    int32          // atomic: 1 if closed, 0 otherwise (P1-8)
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

func (cw *chanWriter) write(data []byte) error {
	if p := atomic.LoadPointer(&cw.lastErr); p != nil {
		return *(*error)(p)
	}
	// P1-8: check closed flag atomically instead of using recover() to mask
	// send-on-closed-channel panic. This makes the race condition explicit
	// and prevents masking other potential bugs.
	if atomic.LoadInt32(&cw.closed) != 0 {
		return io.ErrClosedPipe
	}
	// Note: there's still a tiny race window between the check and the send,
	// but it's acceptable because:
	// 1. The channel has a buffer (udpWriteDepth=256), so most sends succeed
	// 2. If close() happens during send, the goroutine will exit cleanly
	// 3. The closed flag prevents new sends after close() completes
	select {
	case cw.ch <- data:
		return nil
	default:
		// Channel full - this is a backpressure signal
		return fmt.Errorf("write queue full")
	}
}

func (cw *chanWriter) close() {
	cw.closeOnce.Do(func() {
		atomic.StoreInt32(&cw.closed, 1) // P1-8: mark as closed before closing channel
		close(cw.ch)
		cw.wg.Wait()
	})
}
