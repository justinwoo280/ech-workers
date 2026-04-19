# EWP UDP 数据路径性能优化方案

## 概述

本文档针对 EWP UDP 数据路径的三个关键性能瓶颈提出全面的优化策略：
1. 热路径中的高内存分配（GC 压力）
2. 服务端 map 锁竞争
3. 不必要的 channel 和 goroutine 开销

## 当前性能问题分析

### 问题 1: 内存分配瓶颈（高优先级）

#### 服务端出站路径 (`receiveResponses`)
**位置**: `ewp-core/internal/server/udp_handler.go:289-320`

**问题**:
- `EncodeUDPPacket` 每个包都分配新切片: `out := make([]byte, totalLen)`
- 结构体分配: `&ewp.UDPPacket{}`
- 高吞吐场景（视频流、游戏）每秒产生数千次分配

#### 服务端入站路径 (`DecodeUDPPacket`)
**位置**: `ewp-core/protocol/ewp/udp.go:147-230`

**问题**:
- 每个包分配新的 `*UDPPacket` 指针
- Payload 切片分配，即使已有池化的帧缓冲区

#### 客户端出站路径（所有传输层）
**位置**: `ewp-core/transport/websocket/conn.go:373-395`（其他传输层类似）

**问题**:
- 每次 `WriteUDP` 调用都分配新缓冲区
- 没有使用已有的 `bufferpool.GetLarge()`

### 问题 2: 服务端锁竞争（高优先级）

**位置**: `ewp-core/internal/server/udp_handler.go:100-118`

**当前实现**:
```go
func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
    h.mu.Lock()  // 每个包都要全锁！
    s, exists := h.sessions[globalID]
    // ...
    h.mu.Unlock()
}
```

**问题**:
- 每个入站 UDP 包都调用 `dispatch()` → `getOrCreate()`
- 完全的 `sync.Mutex` 锁串行化所有包处理
- 高流量场景（BT、QUIC、多人游戏）成为严重瓶颈
- 无法利用多核 CPU 并行处理

**影响**: 人为限制吞吐量上限，增加延迟

### 问题 3: Channel 和 Goroutine 开销（中优先级）

**位置**: `ewp-core/internal/server/udp_handler.go:254-268`

**当前实现**:
```go
func (h *udpHandler) sessionWorker(s *udpSession) {
    go h.receiveResponses(s)
    
    for pkt := range s.incoming {  // Channel 读取
        if _, err := s.conn.WriteTo(pkt.payload, pkt.target); err != nil {
            // ...
        }
    }
}
```

**问题**:
- `handleStream` 读包 → 放入 `s.incoming` channel → `sessionWorker` 唤醒 → 写 UDP socket
- Channel 同步强制上下文切换，增加延迟
- `net.UDPConn.WriteTo` 在 Go 中是线程安全的（OS 级 UDP socket 支持并发写）
- Channel 和 goroutine 是不必要的开销

**影响**: 增加每包延迟（微秒级累积）和 CPU 上下文切换开销

## 优化策略

### 阶段 1: 零分配热路径（优先级：关键）

#### 1.1 服务端出站路径优化

**目标**: 通过缓冲池消除 `receiveResponses` 中的分配

**实现方案**:
```go
func (h *udpHandler) receiveResponses(s *udpSession) {
    readBufp := udpBufferPool.Get().(*[]byte)
    readBuf := *readBufp
    defer udpBufferPool.Put(readBufp)
    
    // 新增：从池获取写缓冲区（零分配热路径）
    writeBuf := commpool.GetLarge()
    defer commpool.PutLarge(writeBuf)

    for {
        // ... 现有的空闲检查和读取逻辑 ...
        
        n, remoteAddr, err := conn.ReadFromUDP(readBuf)
        if err != nil { /* ... */ }
        
        s.updateActive()

        // 新增：使用池化缓冲区的零分配帧编码
        writeBuf = writeBuf[:0]  // 重置缓冲区
        addrPort := netip.AddrPortFrom(
            netip.AddrFromSlice(remoteAddr.IP),
            uint16(remoteAddr.Port),
        )
        writeBuf = ewp.AppendUDPAddrFrame(
            writeBuf, s.globalID, ewp.UDPStatusKeep, 
            addrPort, readBuf[:n],
        )

        if err := h.writer.write(writeBuf); err != nil {
            // ... 错误处理 ...
        }
    }
}
```

**优势**:
- 热路径零分配
- 会话生命周期内重用同一缓冲区
- `AppendUDPAddrFrame` 已存在且在给定池化缓冲区时零分配

#### 1.2 客户端出站路径优化

**目标**: 消除所有传输层 `WriteUDP` 实现中的分配

**实现方案**（以 websocket 为例，应用于所有传输层）:
```go
type Conn struct {
    // ... 现有字段 ...
    udpWriteBuf []byte      // WriteUDP 可重用缓冲区（每连接）
    udpWriteMu  sync.Mutex  // 保护 udpWriteBuf
}

func (c *Conn) WriteUDP(target transport.Endpoint, data []byte) error {
    c.udpWriteMu.Lock()
    defer c.udpWriteMu.Unlock()
    
    if c.useTrojan {
        return c.writeTrojanUDP(target, data)
    }

    // 确保缓冲区有足够容量
    requiredCap := 2 + 8 + 1 + 1 + 19 + 2 + len(data)  // 最大尺寸（IPv6）
    if cap(c.udpWriteBuf) < requiredCap {
        c.udpWriteBuf = make([]byte, 0, requiredCap)
    }
    
    c.udpWriteBuf = c.udpWriteBuf[:0]  // 重置长度
    
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

**优势**:
- 首次调用后零分配
- 每连接缓冲区（非全局池）避免竞争
- Mutex 仅保护缓冲区重用，不保护实际网络写入

### 阶段 2: 消除锁竞争（优先级：高）

#### 2.1 转换为 sync.Map

**目标**: 用 `sync.Map` 替换 `sync.Mutex + map` 实现无锁读取

**实现方案**:
```go
type udpHandler struct {
    sessions        sync.Map  // map[[8]byte]*udpSession
    sessionCount    atomic.Int32  // 跟踪计数以强制上限
    writer          *chanWriter
    handshakeTarget string
}

func (h *udpHandler) getOrCreate(globalID [8]byte) (*udpSession, bool) {
    // 快速路径：无锁读取
    if val, ok := h.sessions.Load(globalID); ok {
        return val.(*udpSession), false
    }
    
    // 慢速路径：创建新会话
    if h.sessionCount.Load() >= maxUDPSessionsPerConn {
        h.evictOldestIdle()
    }
    
    s := &udpSession{
        globalID: globalID,
    }
    
    actual, loaded := h.sessions.LoadOrStore(globalID, s)
    if loaded {
        return actual.(*udpSession), false
    }
    
    h.sessionCount.Add(1)
    return s, true
}
```

**优势**:
- 现有会话的无锁读取（稳态下 99% 的包）
- 仅在会话创建时竞争（罕见）
- 随 CPU 核心数线性扩展

### 阶段 3: 消除 Channel 开销（优先级：中）

#### 3.1 从 handleStream 直接 WriteTo

**目标**: 移除 `sessionWorker` goroutine 和 `incoming` channel，直接写入 UDP socket

**当前流程**:
```
handleStream → 解码包 → s.incoming channel → sessionWorker → conn.WriteTo
```

**优化后流程**:
```
handleStream → 解码包 → conn.WriteTo（直接）
```

**实现方案**:
```go
// 完全移除 sessionWorker

type udpSession struct {
    globalID     [8]byte
    conn         *net.UDPConn
    initTarget   atomic.Pointer[net.UDPAddr]
    lastActiveNs int64
    closeOnce    sync.Once
    // 移除: incoming chan incomingPkt
}

func (h *udpHandler) dispatch(pkt *ewp.UDPPacket) {
    // ... 现有的会话创建逻辑 ...
    
    if created {
        // 移除: go h.sessionWorker(s)
        go h.receiveResponses(s)  // 仅启动接收器
    }

    // ... 确定目标地址 ...

    // 新增：直接写入 UDP socket（线程安全）
    if target != nil {
        if _, err := s.conn.WriteTo(pkt.Payload, target); err != nil {
            log.Warn("UDP write error for %s: %v", target, err)
        }
        s.updateActive()
    }
}
```

**优势**:
- 消除 channel 分配和同步开销
- 减少每包延迟（无上下文切换到 worker goroutine）
- 减少 goroutine 数量（每会话一个而非两个）
- 代码更简单（更少的同步原语）

**安全性分析**:
- `net.UDPConn.WriteTo` 在 Go 中是线程安全的
- 多个 goroutine 可以并发调用同一 `*net.UDPConn` 的 `WriteTo`
- OS 网络栈处理同一 UDP socket FD 的并发写入
- 无数据损坏或竞态条件

## 实施路线图

### 第 1 阶段：低风险快速收益（第 1 周）

**任务**:
1. 实现客户端 `WriteUDP` 缓冲池化（所有传输层）
2. 实现服务端 `receiveResponses` 缓冲池化

**预期影响**:
- 每包分配减少 80-90%
- GC 暂停时间减少 20-30%
- 风险最小（缓冲池化是成熟模式）

### 第 2 阶段：锁竞争修复（第 2 周）

**任务**:
1. 将 `udpHandler.sessions` 转换为 `sync.Map`
2. 更新 `evictOldestIdle` 使用 `Range`

**预期影响**:
- 多核系统吞吐量提升 2-5 倍
- 随 CPU 核心数近线性扩展
- 负载下尾延迟降低

**风险**: 中等（sync.Map 语义与 mutex+map 不同）

### 第 3 阶段：Channel 消除（第 3 周）

**任务**:
1. 移除 `sessionWorker` 和 `incoming` channel
2. 修改 `dispatch` 直接调用 `conn.WriteTo`

**预期影响**:
- 每包延迟减少 10-20%
- Goroutine 数量减少 50%（每会话一个而非两个）
- 代码更简单

**风险**: 低-中等（直接写入更简单，但需验证无阻塞问题）

## 性能指标与验证

### 基准测试策略

**微基准测试**（每包操作）:
```go
func BenchmarkUDPEncodeWrite(b *testing.B) {
    // 测量编码+写入路径的分配和时间
}

func BenchmarkUDPSessionLookup(b *testing.B) {
    // 测量会话 map 查找性能
}
```

**集成基准测试**（端到端）:
- UDP echo 服务器：测量往返延迟
- 批量传输：测量吞吐量（包/秒，MB/秒）
- 并发会话：测量 N 个会话的可扩展性

**真实场景测试**:
- DNS 查询：测量响应时间
- QUIC 连接：测量 HTTP/3 性能
- 游戏流量：测量抖动和丢包
- BitTorrent：测量 DHT 查询性能

### 成功标准

**阶段 1（零分配）**:
- ✓ 每包分配：< 1（用 `-benchmem` 测量）
- ✓ GC 暂停时间：减少 20-30%
- ✓ 无功能回归

**阶段 2（无锁）**:
- ✓ 吞吐量扩展：随 CPU 核心数近线性（最多 8 核）
- ✓ 锁竞争：< 1% CPU 时间（用 pprof 测量）
- ✓ 会话上限强制：仍正常工作

**阶段 3（Channel 消除）**:
- ✓ 每包延迟：减少 10-20%（p50、p99）
- ✓ Goroutine 数量：每会话减少 50%
- ✓ 负载下无阻塞问题

## 风险缓解

### 回滚策略
- 每个阶段独立可部署
- 新优化的功能标志（如需要）
- 保留旧代码路径用于 A/B 测试

### 兼容性
- 所有优化都是内部实现变更
- 无协议变更
- 无 API 变更
- 完全向后兼容

### 测试覆盖
- 每个优化的单元测试
- 真实 UDP 流量的集成测试
- 高包速率的压力测试
- 边缘情况的回归测试

## 监控与可观测性

### 关键指标跟踪

**性能指标**:
- 每秒包数（入站/出站）
- 每秒字节数（吞吐量）
- 每包延迟（p50、p95、p99）
- 活跃 UDP 会话数
- 会话创建/销毁速率

**资源指标**:
- 每秒堆分配
- GC 暂停时间（p50、p99）
- Goroutine 数量
- CPU 使用率（用户/系统）
- 锁竞争时间（通过 pprof）

**错误指标**:
- UDP 写入错误
- 会话驱逐（达到上限）
- DNS 解析失败
- 丢弃的包（队列满）

## 结论

本优化方案解决了 EWP UDP 数据路径的三个主要性能瓶颈：

1. **零分配热路径**: 通过使用缓冲池消除 80-90% 的分配
2. **无锁会话查找**: 通过 `sync.Map` 实现多核扩展
3. **直接 WriteTo**: 通过消除 channel 开销减少延迟

这些优化：
- **向后兼容**: 无协议或 API 变更
- **增量部署**: 每个阶段独立
- **低风险**: 成熟模式，全面测试
- **高影响**: 预期吞吐量提升 2-5 倍，延迟减少 20-30%

实施可在 3 周内分三个阶段进行，每个阶段都能带来可测量的改进。

---

**文档版本**: 1.0  
**日期**: 2026-04-19  
**作者**: 性能分析团队  
**状态**: 准备实施

## 附录：详细代码示例

完整的代码示例和实现细节请参考英文版文档：
`ewp-core/doc/UDP_PERFORMANCE_OPTIMIZATION_PLAN.md`
