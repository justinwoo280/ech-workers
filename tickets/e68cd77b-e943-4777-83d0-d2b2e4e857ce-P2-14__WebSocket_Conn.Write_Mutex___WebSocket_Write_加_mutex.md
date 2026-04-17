---
id: "e68cd77b-e943-4777-83d0-d2b2e4e857ce"
title: "P2-14: WebSocket Conn.Write Mutex / WebSocket Write 加 mutex"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:49.743Z"
updatedAt: "2026-04-17T11:26:54.031Z"
type: ticket
---

# P2-14: WebSocket Conn.Write Mutex / WebSocket Write 加 mutex

## 🟡 Severity / 优先级

**P2 — Medium (Race)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/transport/websocket/conn.go `Write` 与 ping goroutine 并发写 socket

## 🎯 Description / 漏洞描述与影响

gws 文档要求显式同步(无压测崩溃证据,但理论存在 race)。

## 🔧 Fix / 修复方案

```go
type Conn struct { writeMu sync.Mutex; ... }
func (c *Conn) Write(p []byte) {
    c.writeMu.Lock(); defer c.writeMu.Unlock()
    c.gws.WriteMessage(...)
}
```

## ✅ Acceptance Criteria / 验收标准

Write 与 ping 写互斥race detector 通过

## 🧪 Verification / 验证方法

- **race**: `go test -race ./transport/websocket/...`

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**低**: mutex 略影响吞吐,可忽略
