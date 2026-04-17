---
id: "82f425b1-1308-4296-ad9f-0e707220faa5"
title: "P2-17: gVisor WritePackets BufferPool / gVisor 写包用 bufferpool"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:05.673Z"
updatedAt: "2026-04-17T11:27:09.618Z"
type: ticket
---

# P2-17: gVisor WritePackets BufferPool / gVisor 写包用 bufferpool

## 🟡 Severity / 优先级

**P2 — Low (Performance)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/tun/gvisor/endpoint.go `WritePackets` 每包 make+copy

## 🎯 Description / 漏洞描述与影响

性能损失,GC 压力大。

## 🔧 Fix / 修复方案

用 `common/bufferpool`:

```go
buf := bufferpool.GetSmall(); defer bufferpool.PutSmall(buf)
```

## ✅ Acceptance Criteria / 验收标准

WritePackets 使用 bufferpool基准测试 GC 次数减少

## 🧪 Verification / 验证方法

- **基准测试**: 修复前后对比

## 🔗 Dependencies / 依赖关系

- 与 `P2-6` (bufferpool 校验) 协同

## ⚠️ Regression Risk / 回归风险

**低**
