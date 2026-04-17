---
id: "136a4710-5e80-42aa-9edf-8f9378889956"
title: "P0-3: Vision FlowReader Direct-Copy Switch Bug / Vision FlowReader 错误读取 Writer 状态字段"
assignee: ""
status: 0
createdAt: "2026-04-17T11:17:47.852Z"
updatedAt: "2026-04-17T11:18:06.904Z"
type: ticket
---

# P0-3: Vision FlowReader Direct-Copy Switch Bug / Vision FlowReader 错误读取 Writer 状态字段

## 🔴 Severity / 优先级

**P0 — Critical (Data Plane Bug)** | Sprint 2 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/ewp/flow.go (FlowReader.Read)
- file:ewp-core/protocol/ewp/flow_state.go (FlowState 字段定义)
- file:ewp-core/protocol/ewp/flow_writer.go

## 🎯 Description / 漏洞描述与影响

Vision XTLS 零拷贝直传依赖**双向独立**的开关:写端检测 TLS App Data 后通知对端切换并自身切换;读端在收到 command=2 时自身切换。

**当前 Bug**: FlowReader 检查 `ShouldDirectCopy` 时读的是 **Writer 字段** 而非 Reader 字段,导致 FlowReader 永远不会进入读端直传模式,直到本端 FlowWriter 也触发了写端切换。后果:

1. TLS App Data 持续被 unpadding 解析(性能损失,对短帧敏感)
2. 协议状态机理论上在某些场景下识别失败

## 💥 Reproduction / 复现条件

1. 客户端发起对外 TLS 握手(经 Vision Flow 通道)
2. 服务端响应 TLS Server Hello + ChangeCipherSpec
3. 用 pprof 观察 FlowReader 路径热点 — 持续在 unpadding 解析逻辑内
4. 对比 Xray 实现:同等场景下 FlowReader 已切换为零拷贝直传

## 🔧 Fix / 修复方案

为 `FlowState` 增加 `ShouldDirectCopyRead(isUplink bool)` 方法,或在 FlowReader 中直接读取正确的 Inbound/Outbound Reader 字段。

```go
// 示意
func (s *FlowState) ShouldDirectCopyRead() bool {
    return atomic.LoadInt32(&s.readerDirectCopy) == 1
}
```

参考 Xray 上游实现的双向状态分离。

## ✅ Acceptance Criteria / 验收标准

FlowReader 与 FlowWriter 的 direct-copy 开关相互独立接收到 command=2 (FlowCommandDirect) 时,FlowReader 立即切换为零拷贝FlowWriter 切换不影响 FlowReader 状态新增单元测试覆盖"仅读端切换""仅写端切换""双向切换"三种场景

## 🧪 Verification / 验证方法

- **单元测试**: 修改 `protocol/ewp/flow_test.go`,构造 mock 流,断言 direct-copy 后续 Read 走零拷贝路径(可通过插桩计数)
- **基准测试**: `BenchmarkFlowReader` 在 direct-copy 后吞吐应显著提升
- **e2e**: 用 wireshark 抓 TLS,观察 padding 仅出现在握手阶段而非 App Data

## 🔗 Dependencies / 依赖关系

- 与 `P1-13` (XtlsFilterTls 滤波缓冲) 和 `P1-14` (counter 双向独立) 同模块,建议按顺序修复
- `Bug-G` (FlowReader state==nil leftover) 同模块,可一并审视

## ⚠️ Regression Risk / 回归风险

**高**: Vision 是核心数据面,修改后需:

- 大量 e2e 流量回放测试(HTTP/HTTPS/WebSocket/QUIC over Vision)
- 与 Xray 服务端互操作测试(若适用)
- 性能回归基准对比
