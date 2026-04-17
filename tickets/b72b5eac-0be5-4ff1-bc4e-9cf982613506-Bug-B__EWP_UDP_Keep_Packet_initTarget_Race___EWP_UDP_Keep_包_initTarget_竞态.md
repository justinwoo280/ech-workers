---
id: "b72b5eac-0be5-4ff1-bc4e-9cf982613506"
title: "Bug-B: EWP UDP Keep Packet initTarget Race / EWP UDP Keep 包 initTarget 竞态"
assignee: ""
status: 0
createdAt: "2026-04-17T11:29:14.644Z"
updatedAt: "2026-04-17T11:29:21.543Z"
type: ticket
---

# Bug-B: EWP UDP Keep Packet initTarget Race / EWP UDP Keep 包 initTarget 竞态

## 🔵 Severity / 优先级

**Bug — Low (Theoretical Race)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/internal/server/udp_handler.go `dispatch` line 246

## 🎯 Description / 漏洞描述与影响

Keep 包带 target 时重写 `s.initTarget`,但写入无锁。注释说"单 goroutine 写,安全",但 cleanup goroutine 也访问。理论上 pointer 撕裂(Go 对 pointer 是 atomic-sized,但安全边界依赖 GC,**理论上的 race**)。

## 💥 Reproduction / 复现条件

- 极罕见:cleanup goroutine 与 dispatch 同时访问 initTarget,GC 移动期间撕裂

## 🔧 Fix / 修复方案

用 `atomic.Pointer[Address]` 或加 RWMutex:

```go
var initTarget atomic.Pointer[Address]
initTarget.Store(&addr)
```

## ✅ Acceptance Criteria / 验收标准

initTarget 使用 atomic.Pointer 或 RWMutexrace detector 通过

## 🧪 Verification / 验证方法

- **race detector**: `go test -race ./internal/server/...`

## 🔗 Dependencies / 依赖关系

- 与 `P0-4` (UDP DNS 异步化) 同模块,可一并修复

## ⚠️ Regression Risk / 回归风险

**低**
