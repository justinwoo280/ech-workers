# EWP UDP Data Path Performance Optimization Plan

## Executive Summary

This document outlines a comprehensive optimization strategy for the UDP data path in EWP, targeting three critical performance bottlenecks:
1. High memory allocation (GC pressure) in hot paths
2. Server-side map lock contention
3. Unnecessary channel & goroutine overhead

## Current Performance Analysis

### 1. Memory Allocation Bottlenecks (High Priority)

#### Server - Outbound Path (`receiveResponses`)
**Location**: `ewp-core/internal/server/udp_handler.go:289-320`

**Current Implementation**:
```go
respPkt := &ewp.UDPPacket{
    GlobalID: s.globalID,
    Status:   ewp.UDPStatusKeep,
    Target:   remoteAddr,
    Payload:  buf[:n],
}
data, err := ewp.EncodeUDPPacket(respPkt)
```

**Problem**: 
- `EncodeUDPPacket` allocates a new slice: `out := make([]byte, totalLen)` for every packet
- Struct allocation for `&ewp.UDPPacket{}`
- In high-throughput scenarios (e.g., video streaming, gaming), this creates thousands of allocations per second

#### Server - Inbound Path (`DecodeUDPPacket`)
**Location**: `ewp-core/protocol/ewp/udp.go:147-230`

**Current Implementation**:
```go
pkt := &UDPPacket{}
// ...
pkt.Payload = make([]byte, payloadLen)
copy(pkt.Payload, frameBuf[offset:offset+payloadLen])
```

**Problem**:
- New `*UDPPacket` pointer allocation per packet
- Payload slice allocation even though we have a pooled frame buffer

#### Client - Outbound Path (All Transports)
**Location**: `ewp-core/transport/websocket/conn.go:373-395` (and similar in grpc, xhttp, h3grpc)

**Current Implementation**:
```go
buf := make([]byte, 0, totalCap)
buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, target.Addr, data)
return c.Write(buf)
```

**Problem**:
- Every `WriteUDP` call allocates a new buffer
- `AppendUDPAddrFrame` exists but operates on freshly allocated slices
- No buffer pooling despite having `bufferpool.GetLarge()` available

### 2. Server-Side Lock Contention (High Priority)

**Location**: `ewp-core/internal/server/udp_handler.go:100-118`

**Current Implementation**:
```go
func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
    h.mu.Lock()  // Full lock on every packet!
    s, exists := h.sessions[globalID]
    if !exists {
        // ... create session
        h.sessions[globalID] = s
    }
    h.mu.Unlock()
    return s, !exists
}
```

**Problem**:
- Every incoming UDP packet from the tunnel calls `dispatch()` → `getOrCreate()`
- Full `sync.Mutex` lock serializes all packet processing
- In high-traffic scenarios (BitTorrent, QUIC, multiplayer games), this becomes a severe bottleneck
- Modern servers have many CPU cores, but this lock prevents parallel processing

**Impact**: Artificial throughput cap and increased latency due to thread contention

### 3. Channel & Goroutine Overhead (Medium Priority)

**Location**: `ewp-core/internal/server/udp_handler.go:254-268`

**Current Implementation**:
```go
// sessionWorker is per-session goroutine
func (h *udpHandler) sessionWorker(s *udpSession) {
    go h.receiveResponses(s)
    
    for pkt := range s.incoming {  // Channel read
        if pkt.target == nil {
            continue
        }
        if _, err := s.conn.WriteTo(pkt.payload, pkt.target); err != nil {
            // ...
        }
        s.updateActive()
    }
}
```

**Problem**:
- `handleStream` reads packet → places in `s.incoming` channel → `sessionWorker` wakes up → writes to UDP socket
- Channel synchronization forces context switches and adds latency
- `net.UDPConn.WriteTo` is thread-safe in Go (OS-level UDP socket supports concurrent writes)
- The channel and goroutine are unnecessary overhead for a simple write operation

**Impact**: Increased per-packet latency (microseconds per packet add up) and CPU context switching overhead

## Optimization Strategy

### Phase 1: Zero-Allocation Hot Path (Priority: Critical)

#### 1.1 Server Outbound Path Optimization

**Goal**: Eliminate allocations in `receiveResponses` by using buffer pools

**Implementation**:

```go
// In receiveResponses (udp_handler.go)
func (h *udpHandler) receiveResponses(s *udpSession) {
    readBufp := udpBufferPool.Get().(*[]byte)
    readBuf := *readBufp
    defer udpBufferPool.Put(readBufp)
    
    // NEW: Get write buffer from pool
    writeBuf := commpool.GetLarge()
    defer commpool.PutLarge(writeBuf)

    for {
        // ... existing idle check and read logic ...
        
        n, remoteAddr, err := conn.ReadFromUDP(readBuf)
        if err != nil { /* ... */ }
        
        s.updateActive()

        // NEW: Use AppendUDPAddrFrame with pooled buffer (zero-allocation)
        writeBuf = writeBuf[:0]  // Reset buffer
        addrPort := netip.AddrPortFrom(
            netip.AddrFromSlice(remoteAddr.IP),
            uint16(remoteAddr.Port),
        )
        writeBuf = ewp.AppendUDPAddrFrame(
            writeBuf, 
            s.globalID, 
            ewp.UDPStatusKeep, 
            addrPort, 
            readBuf[:n],
        )

        if err := h.writer.write(writeBuf); err != nil {
            // ... error handling ...
        }
    }
}
```

**Benefits**:
- Zero allocations per packet in hot path
- Reuses same buffer for all packets in the session lifetime
- `AppendUDPAddrFrame` already exists and is zero-allocation when given a pooled buffer

**Note**: `chanWriter.write()` needs to copy the data before returning since we reuse the buffer

#### 1.2 Client Outbound Path Optimization

**Goal**: Eliminate allocations in all transport `WriteUDP` implementations

**Implementation** (example for websocket, apply to all transports):

```go
// In transport/websocket/conn.go
type Conn struct {
    // ... existing fields ...
    udpWriteBuf []byte  // Reusable buffer for WriteUDP (per-connection)
    udpWriteMu  sync.Mutex  // Protect udpWriteBuf
}

func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
    c.udpWriteMu.Lock()
    defer c.udpWriteMu.Unlock()
    
    if c.useTrojan {
        return c.writeTrojanUDP(target, data)
    }

    // Ensure buffer has enough capacity
    requiredCap := 2 + 8 + 1 + 1 + 19 + 2 + len(data)  // Max size (IPv6)
    if cap(c.udpWriteBuf) < requiredCap {
        c.udpWriteBuf = make([]byte, 0, requiredCap)
    }
    
    c.udpWriteBuf = c.udpWriteBuf[:0]  // Reset length
    
    if target.Domain != "" {
        c.udpWriteBuf = ewp.AppendUDPDomainFrame(
            c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep, 
            target.Domain, target.Port, data,
        )
    } else {
        c.udpWriteBuf = ewp.AppendUDPAddrFrame(
            c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep, 
            target.Addr, data,
        )
    }
    
    return c.Write(c.udpWriteBuf)
}
```

**Benefits**:
- Zero allocations per packet after first call
- Per-connection buffer (not global pool) avoids contention
- Mutex only protects buffer reuse, not the actual network write

**Alternative Approach** (if per-connection buffer is not desired):

```go
func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
    buf := commpool.GetLarge()
    defer commpool.PutLarge(buf)
    
    buf = buf[:0]
    if target.Domain != "" {
        buf = ewp.AppendUDPDomainFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, 
                                       target.Domain, target.Port, data)
    } else {
        buf = ewp.AppendUDPAddrFrame(buf, c.udpGlobalID, ewp.UDPStatusKeep, 
                                     target.Addr, data)
    }
    
    return c.Write(buf)
}
```

**Trade-offs**:
- Per-connection buffer: Better performance, slightly more memory per connection
- Pool-based: Slightly more contention on pool, but lower memory footprint

**Recommendation**: Use per-connection buffer for UDP (high packet rate justifies the memory)

#### 1.3 Server Inbound Path Optimization

**Current State**: Already partially optimized
- Frame buffer comes from `udpFramePool` ✓
- But still allocates `*UDPPacket` struct and payload slice

**Optimization Options**:

**Option A**: Keep current design (acceptable)
- The allocation happens once per packet, but the packet is short-lived
- Most GC pressure comes from the outbound path (responses)
- Focus optimization efforts on outbound path first

**Option B**: Add zero-copy decode path (future enhancement)
- Add `DecodeUDPPacketInPlace` that returns views into the frame buffer
- Requires careful lifetime management to avoid use-after-free
- More complex, defer to Phase 2 if needed

### Phase 2: Eliminate Lock Contention (Priority: High)

#### 2.1 Convert to sync.Map

**Goal**: Replace `sync.Mutex + map` with `sync.Map` for lock-free reads

**Implementation**:

```go
type udpHandler struct {
    sessions        sync.Map  // map[[8]byte]*udpSession
    sessionCount    atomic.Int32  // Track count for cap enforcement
    writer          *chanWriter
    handshakeTarget string
}

func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
    // Fast path: lock-free read
    if val, ok := h.sessions.Load(globalID); ok {
        return val.(*udpSession), false
    }
    
    // Slow path: create new session
    // Check session cap before creating
    if h.sessionCount.Load() >= maxUDPSessionsPerConn {
        h.evictOldestIdle()
    }
    
    s := &udpSession{
        globalID: globalID,
        incoming: make(chan incomingPkt, udpIncomingDepth),
    }
    
    actual, loaded := h.sessions.LoadOrStore(globalID, s)
    if loaded {
        // Another goroutine created it first
        return actual.(*udpSession), false
    }
    
    h.sessionCount.Add(1)
    return s, true
}

func (h *udpHandler) remove(globalID [8]byte) {
    if val, loaded := h.sessions.LoadAndDelete(globalID); loaded {
        h.sessionCount.Add(-1)
        s := val.(*udpSession)
        s.close()
    }
}
```

**Benefits**:
- Lock-free reads for existing sessions (99% of packets in steady state)
- Only contention on session creation (rare)
- Scales linearly with CPU cores

**Considerations**:
- `evictOldestIdle()` needs to iterate all sessions (use `Range`)
- Slightly more complex than mutex, but well worth it for hot path

#### 2.2 Alternative: RWMutex Fast Path

**Goal**: If `sync.Map` complexity is undesired, use `RWMutex` for read-heavy workload

**Implementation**:

```go
func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
    // Fast path: read lock
    h.mu.RLock()
    s, exists := h.sessions[globalID]
    h.mu.RUnlock()
    
    if exists {
        return s, false
    }
    
    // Slow path: write lock for creation
    h.mu.Lock()
    defer h.mu.Unlock()
    
    // Double-check after acquiring write lock
    if s, exists := h.sessions[globalID]; exists {
        return s, false
    }
    
    // Check cap and create
    if len(h.sessions) >= maxUDPSessionsPerConn {
        h.evictOldestIdle_locked()
    }
    
    s = &udpSession{
        globalID: globalID,
        incoming: make(chan incomingPkt, udpIncomingDepth),
    }
    h.sessions[globalID] = s
    return s, true
}
```

**Benefits**:
- Simpler than `sync.Map`
- Still provides significant improvement over full lock
- Multiple readers can proceed in parallel

**Trade-offs**:
- Not as fast as `sync.Map` for read-heavy workloads
- Still has some contention on the read lock

**Recommendation**: Use `sync.Map` for maximum performance, or `RWMutex` for simplicity

### Phase 3: Eliminate Channel Overhead (Priority: Medium)

#### 3.1 Direct WriteTo from handleStream

**Goal**: Remove `sessionWorker` goroutine and `incoming` channel, write directly to UDP socket

**Current Flow**:
```
handleStream → decode packet → s.incoming channel → sessionWorker → conn.WriteTo
```

**Optimized Flow**:
```
handleStream → decode packet → conn.WriteTo (direct)
```

**Implementation**:

```go
// Remove sessionWorker entirely

type udpSession struct {
    globalID     [8]byte
    conn         *net.UDPConn
    initTarget   atomic.Pointer[net.UDPAddr]
    lastActiveNs int64
    closeOnce    sync.Once
    // REMOVED: incoming chan incomingPkt
}

func (h *udpHandler) dispatch(pkt *ewp.UDPPacket) {
    if pkt.Status == ewp.UDPStatusEnd {
        h.remove(pkt.GlobalID)
        return
    }

    s, created := h.getOrCreate(pkt.GlobalID)

    if created {
        // ... existing session creation logic ...
        // REMOVED: go h.sessionWorker(s)
        go h.receiveResponses(s)  // Only start receiver
    } else if s.conn == nil {
        return
    }

    if len(pkt.Payload) == 0 {
        return
    }

    // Determine target address
    target := s.initTarget.Load()
    if pkt.Target != nil {
        target = pkt.Target
        s.initTarget.Store(pkt.Target)
    } else if pkt.TargetHost != "" {
        // ... DNS resolution logic ...
    }

    // NEW: Write directly to UDP socket (thread-safe)
    if target != nil {
        if _, err := s.conn.WriteTo(pkt.Payload, target); err != nil {
            log.Warn("UDP write error for %s: %v", target, err)
        }
        s.updateActive()
    }
}
```

**Benefits**:
- Eliminates channel allocation and synchronization overhead
- Reduces per-packet latency (no context switch to worker goroutine)
- Reduces goroutine count (one per session → one per two sessions, since only receiver remains)
- Simpler code (fewer moving parts)

**Safety Analysis**:
- `net.UDPConn.WriteTo` is thread-safe in Go
- Multiple goroutines can call `WriteTo` on the same `*net.UDPConn` concurrently
- The OS network stack handles concurrent writes to the same UDP socket FD
- No data corruption or race conditions

**Considerations**:
- `handleStream` becomes slightly more blocking (writes directly instead of queuing)
- In practice, UDP writes are non-blocking at the OS level (they just queue in kernel buffer)
- If kernel buffer is full, write returns error immediately (no blocking)
- This is acceptable behavior for UDP (lossy protocol)

**Async DNS Handling**:
The async DNS resolution for new sessions (P0-4 fix) needs adjustment:

```go
if created && target == nil && (pkt.TargetHost != "" || h.handshakeTarget != "") {
    // Capture values for async goroutine
    globalID := pkt.GlobalID
    payload := append([]byte(nil), pkt.Payload...)
    capturedS := s
    
    go func() {
        // ... DNS resolution logic ...
        
        // After successful resolution and socket creation:
        if len(payload) > 0 && resolved != nil {
            capturedS.conn.WriteTo(payload, resolved)
            capturedS.updateActive()
        }
    }()
    return
}
```

No channel needed - just write directly after DNS completes.

## Implementation Roadmap

### Stage 1: Low-Risk Quick Wins (Week 1)

**Tasks**:
1. Implement client-side `WriteUDP` buffer pooling (all transports)
   - Files: `transport/websocket/conn.go`, `transport/grpc/conn.go`, `transport/xhttp/*.go`, `transport/h3grpc/conn.go`
   - Add per-connection `udpWriteBuf` field
   - Modify `WriteUDP` to reuse buffer
   
2. Implement server-side `receiveResponses` buffer pooling
   - File: `internal/server/udp_handler.go`
   - Use `commpool.GetLarge()` for write buffer
   - Use `AppendUDPAddrFrame` with pooled buffer

**Testing**:
- Unit tests: Verify correctness with various packet sizes
- Benchmark: Measure allocation reduction with `go test -bench . -benchmem`
- Integration: Test with real UDP traffic (DNS, QUIC, gaming)

**Expected Impact**:
- 80-90% reduction in allocations per packet
- 20-30% reduction in GC pause time
- Minimal risk (buffer pooling is well-understood pattern)

### Stage 2: Lock Contention Fix (Week 2)

**Tasks**:
1. Convert `udpHandler.sessions` to `sync.Map`
   - File: `internal/server/udp_handler.go`
   - Refactor `getOrCreate`, `remove`, `closeAll`, `closeIdle`
   - Add `sessionCount` atomic counter for cap enforcement
   
2. Update `evictOldestIdle` to use `Range`

**Testing**:
- Stress test: Multiple concurrent connections with high packet rate
- Benchmark: Compare throughput before/after with multiple CPU cores
- Verify session cap enforcement still works

**Expected Impact**:
- 2-5x throughput improvement on multi-core systems
- Near-linear scaling with CPU cores
- Reduced tail latency under load

**Risk**: Medium (sync.Map has different semantics than mutex+map)

### Stage 3: Channel Elimination (Week 3)

**Tasks**:
1. Remove `sessionWorker` and `incoming` channel
   - File: `internal/server/udp_handler.go`
   - Modify `dispatch` to call `conn.WriteTo` directly
   - Update async DNS path to write directly
   - Remove `incomingPkt` struct and `safeSend` function

2. Update session struct
   - Remove `incoming chan incomingPkt` field
   - Keep only `receiveResponses` goroutine per session

**Testing**:
- Functional: Verify UDP sessions still work correctly
- Latency: Measure per-packet latency improvement
- Stress: High packet rate with many concurrent sessions
- Edge cases: Session creation race conditions, DNS resolution

**Expected Impact**:
- 10-20% reduction in per-packet latency
- 50% reduction in goroutines (one per session instead of two)
- Simpler code (fewer synchronization primitives)

**Risk**: Low-Medium (direct writes are simpler, but need to verify no blocking issues)

## Performance Metrics & Validation

### Benchmarking Strategy

**Micro-benchmarks** (per-packet operations):
```go
func BenchmarkUDPEncodeWrite(b *testing.B) {
    // Measure allocation and time for encode+write path
}

func BenchmarkUDPSessionLookup(b *testing.B) {
    // Measure session map lookup performance
}
```

**Integration benchmarks** (end-to-end):
- UDP echo server: Measure round-trip latency
- Bulk transfer: Measure throughput (packets/sec, MB/s)
- Concurrent sessions: Measure scalability with N sessions

**Real-world testing**:
- DNS queries: Measure response time
- QUIC connections: Measure HTTP/3 performance
- Gaming traffic: Measure jitter and packet loss
- BitTorrent: Measure DHT query performance

### Success Criteria

**Phase 1 (Zero-Allocation)**:
- ✓ Allocations per packet: < 1 (measured with `-benchmem`)
- ✓ GC pause time: 20-30% reduction
- ✓ No functional regressions

**Phase 2 (Lock-Free)**:
- ✓ Throughput scaling: Near-linear with CPU cores (up to 8 cores)
- ✓ Lock contention: < 1% of CPU time (measured with pprof)
- ✓ Session cap enforcement: Still works correctly

**Phase 3 (Channel Elimination)**:
- ✓ Per-packet latency: 10-20% reduction (p50, p99)
- ✓ Goroutine count: 50% reduction per session
- ✓ No blocking issues under load

## Risk Mitigation

### Rollback Strategy
- Each phase is independently deployable
- Feature flag for new optimizations (if needed)
- Keep old code path available for A/B testing

### Compatibility
- All optimizations are internal implementation changes
- No protocol changes
- No API changes
- Fully backward compatible

### Testing Coverage
- Unit tests for each optimization
- Integration tests with real UDP traffic
- Stress tests with high packet rates
- Regression tests for edge cases

## Alternative Approaches Considered

### 1. io_uring (Linux-specific)
**Pros**: Maximum performance on Linux
**Cons**: Platform-specific, complex, not available on Windows/macOS
**Decision**: Defer to future (Phase 4) if needed

### 2. User-space UDP stack (e.g., netstack)
**Pros**: Full control over packet processing
**Cons**: Very complex, reinvents the wheel, OS kernel is already optimized
**Decision**: Not worth the complexity

### 3. Batch processing (read/write multiple packets at once)
**Pros**: Amortizes syscall overhead
**Cons**: Increases latency, complex API changes
**Decision**: Consider for Phase 4 if needed

## Code Examples

### Example 1: Optimized Server receiveResponses

```go
func (h *udpHandler) receiveResponses(s *udpSession) {
    // Read buffer from existing pool
    readBufp := udpBufferPool.Get().(*[]byte)
    readBuf := *readBufp
    defer udpBufferPool.Put(readBufp)
    
    // NEW: Write buffer from common pool (zero-allocation hot path)
    writeBuf := commpool.GetLarge()
    defer commpool.PutLarge(writeBuf)

    const readDeadline = 30 * time.Second
    conn := s.conn

    for {
        if s.idleSince() > udpIdleTimeout {
            h.remove(s.globalID)
            return
        }

        conn.SetReadDeadline(time.Now().Add(readDeadline))
        n, remoteAddr, err := conn.ReadFromUDP(readBuf)
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

        // NEW: Zero-allocation frame encoding
        writeBuf = writeBuf[:0]  // Reset buffer length
        addrPort := netip.AddrPortFrom(
            netip.AddrFromSlice(remoteAddr.IP),
            uint16(remoteAddr.Port),
        )
        writeBuf = ewp.AppendUDPAddrFrame(
            writeBuf,
            s.globalID,
            ewp.UDPStatusKeep,
            addrPort,
            readBuf[:n],
        )

        if err := h.writer.write(writeBuf); err != nil {
            log.Warn("UDP response write failed: %v", err)
            continue
        }
    }
}
```

**Key Changes**:
- Added `writeBuf := commpool.GetLarge()` for frame encoding
- Use `AppendUDPAddrFrame` instead of `EncodeUDPPacket`
- Convert `*net.UDPAddr` to `netip.AddrPort` (zero-allocation type)
- Reuse `writeBuf` for all packets (reset with `[:0]`)

### Example 2: Optimized Client WriteUDP (WebSocket)

```go
type Conn struct {
    // ... existing fields ...
    udpWriteBuf []byte
    udpWriteMu  sync.Mutex
}

func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
    c.udpWriteMu.Lock()
    defer c.udpWriteMu.Unlock()
    
    if c.useTrojan {
        return c.writeTrojanUDPPooled(target, data)
    }

    // Calculate required capacity (max for IPv6)
    requiredCap := 2 + 8 + 1 + 1 + 19 + 2 + len(data)
    if target.Domain != "" {
        requiredCap = 2 + 8 + 1 + 1 + (1 + 1 + len(target.Domain) + 2) + 2 + len(data)
    }
    
    // Grow buffer if needed (rare, only on first call or large packet)
    if cap(c.udpWriteBuf) < requiredCap {
        c.udpWriteBuf = make([]byte, 0, requiredCap)
    }
    
    // Reset buffer and append frame
    c.udpWriteBuf = c.udpWriteBuf[:0]
    
    if target.Domain != "" {
        c.udpWriteBuf = ewp.AppendUDPDomainFrame(
            c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep,
            target.Domain, target.Port, data,
        )
    } else {
        c.udpWriteBuf = ewp.AppendUDPAddrFrame(
            c.udpWriteBuf, c.udpGlobalID, ewp.UDPStatusKeep,
            target.Addr, data,
        )
    }
    
    return c.Write(c.udpWriteBuf)
}

func (c *Conn) writeTrojanUDPPooled(target transport.Endpoint, data []byte) error {
    // Similar optimization for Trojan protocol
    // ... (reuse c.udpWriteBuf)
}
```

**Key Changes**:
- Added `udpWriteBuf` field to `Conn` struct
- Added `udpWriteMu` to protect buffer (only one write at a time per connection)
- Grow buffer only if needed (amortized allocation)
- Reuse buffer for all packets on this connection

### Example 3: Lock-Free Session Lookup with sync.Map

```go
type udpHandler struct {
    sessions        sync.Map  // map[[8]byte]*udpSession
    sessionCount    atomic.Int32
    writer          *chanWriter
    handshakeTarget string
}

func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
    // Fast path: lock-free read (99% of packets)
    if val, ok := h.sessions.Load(globalID); ok {
        return val.(*udpSession), false
    }
    
    // Slow path: create new session
    // Check session cap
    if h.sessionCount.Load() >= maxUDPSessionsPerConn {
        h.evictOldestIdle()
    }
    
    s := &udpSession{
        globalID: globalID,
    }
    
    // Atomic insert-if-absent
    actual, loaded := h.sessions.LoadOrStore(globalID, s)
    if loaded {
        // Another goroutine created it first, use theirs
        return actual.(*udpSession), false
    }
    
    // We created it
    h.sessionCount.Add(1)
    return s, true
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
    
    // Clear map
    h.sessions.Range(func(key, value interface{}) bool {
        h.sessions.Delete(key)
        return true
    })
    h.sessionCount.Store(0)
    
    // Close all sessions
    for _, s := range sessions {
        s.close()
    }
}

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
            log.V("[UDP] evicted oldest idle session (idle=%s)", oldestIdle.Round(time.Second))
        }
    }
}
```

**Key Changes**:
- Replaced `sync.Mutex + map` with `sync.Map`
- Added `sessionCount atomic.Int32` for O(1) count tracking
- `getOrCreate` uses lock-free `Load` for fast path
- `LoadOrStore` handles race conditions atomically
- `Range` used for iteration (closeAll, evictOldestIdle)

### Example 4: Direct WriteTo (No Channel)

```go
type udpSession struct {
    globalID     [8]byte
    conn         *net.UDPConn
    initTarget   atomic.Pointer[net.UDPAddr]
    lastActiveNs int64
    closeOnce    sync.Once
    // REMOVED: incoming chan incomingPkt
}

func (h *udpHandler) dispatch(pkt *ewp.UDPPacket) {
    if pkt.Status == ewp.UDPStatusEnd {
        h.remove(pkt.GlobalID)
        log.Debug("UDP session ended (GlobalID: %x)", pkt.GlobalID[:4])
        return
    }

    s, created := h.getOrCreate(pkt.GlobalID)

    if created {
        if pkt.Status != ewp.UDPStatusNew {
            h.remove(pkt.GlobalID)
            return
        }

        // ... existing session creation logic ...
        // (DNS resolution, socket creation, etc.)
        
        // CHANGED: Only start receiver, no worker
        go h.receiveResponses(s)
    } else if s.conn == nil {
        return
    }

    if len(pkt.Payload) == 0 {
        return
    }

    // Determine target address
    target := s.initTarget.Load()
    if pkt.Target != nil {
        target = pkt.Target
        s.initTarget.Store(pkt.Target)
    } else if pkt.TargetHost != "" {
        // Inline DNS resolution with timeout
        ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
        addrs, err := net.DefaultResolver.LookupIPAddr(ctx, pkt.TargetHost)
        cancel()
        if err == nil && len(addrs) > 0 {
            resolved := &net.UDPAddr{IP: addrs[0].IP, Port: int(pkt.TargetPort)}
            target = resolved
            s.initTarget.Store(resolved)
        }
    }

    // NEW: Direct write to UDP socket (thread-safe, no channel)
    if target != nil {
        if _, err := s.conn.WriteTo(pkt.Payload, target); err != nil {
            log.Warn("UDP write error for %s: %v", target, err)
            // Don't remove session on write error - it will timeout eventually
        } else {
            s.updateActive()
        }
    }
}

// REMOVED: sessionWorker function entirely
```

**Key Changes**:
- Removed `incoming chan incomingPkt` from `udpSession`
- Removed `sessionWorker` goroutine
- `dispatch` calls `conn.WriteTo` directly
- Only `receiveResponses` goroutine remains per session
- Simpler, faster, less memory

## Monitoring & Observability

### Key Metrics to Track

**Performance Metrics**:
- Packets per second (inbound/outbound)
- Bytes per second (throughput)
- Per-packet latency (p50, p95, p99)
- Active UDP sessions count
- Session creation/destruction rate

**Resource Metrics**:
- Heap allocations per second
- GC pause time (p50, p99)
- Goroutine count
- CPU usage (user/system)
- Lock contention time (via pprof)

**Error Metrics**:
- UDP write errors
- Session evictions (cap reached)
- DNS resolution failures
- Dropped packets (queue full)

### Profiling Tools

**CPU Profiling**:
```bash
go test -cpuprofile=cpu.prof -bench .
go tool pprof cpu.prof
```

**Memory Profiling**:
```bash
go test -memprofile=mem.prof -bench .
go tool pprof mem.prof
```

**Allocation Profiling**:
```bash
go test -bench . -benchmem
# Look for "allocs/op" metric
```

**Lock Contention**:
```bash
go test -mutexprofile=mutex.prof -bench .
go tool pprof mutex.prof
```

## Conclusion

This optimization plan addresses the three major performance bottlenecks in the EWP UDP data path:

1. **Zero-Allocation Hot Path**: Eliminates 80-90% of allocations by using buffer pools
2. **Lock-Free Session Lookup**: Enables multi-core scaling with `sync.Map`
3. **Direct WriteTo**: Reduces latency by eliminating channel overhead

The optimizations are:
- **Backward compatible**: No protocol or API changes
- **Incrementally deployable**: Each phase is independent
- **Low risk**: Well-understood patterns with comprehensive testing
- **High impact**: Expected 2-5x throughput improvement and 20-30% latency reduction

Implementation can proceed in three stages over 3 weeks, with each stage delivering measurable improvements.

---

**Document Version**: 1.0  
**Date**: 2026-04-19  
**Author**: Performance Analysis Team  
**Status**: Ready for Implementation
