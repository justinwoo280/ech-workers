---
id: "61b52bd8-f88a-43a4-8f0b-5d7c59a9e6ac"
title: "P2-40: UUID[:] Cross-Goroutine Lifetime / UUID slice 跨 goroutine 拷贝"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:59.930Z"
updatedAt: "2026-04-17T11:29:04.210Z"
type: ticket
---

# P2-40: UUID[:] Cross-Goroutine Lifetime / UUID slice 跨 goroutine 拷贝

## 🟡 Severity / 优先级

**P2 — Low (Memory Lifetime)** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/internal/server/protocol_ewp.go `req.UUID[:]` 暴露给 FlowState

## 🎯 Description / 漏洞描述与影响

内存生命周期跨 goroutine,理论上 req 被 GC 后 FlowState 持有的 slice 仍引用,但 GC 安全。属防御深度。

## 🔧 Fix / 修复方案

拷贝一份:

```go
uuid := append([]byte(nil), req.UUID[:]...)
flowState.SetUUID(uuid)
```

## ✅ Acceptance Criteria / 验收标准

跨 goroutine 传递 slice 时显式拷贝注释说明所有权

## 🧪 Verification / 验证方法

- **代码审查**

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
