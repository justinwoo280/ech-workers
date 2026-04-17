---
id: "657c7e29-592e-462a-8609-1ffaf5742f4b"
title: "P2-21: XHTTP SessionID Use crypto/rand / XHTTP SessionID 用 crypto/rand"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:23.353Z"
updatedAt: "2026-04-17T11:27:27.494Z"
type: ticket
---

# P2-21: XHTTP SessionID Use crypto/rand / XHTTP SessionID 用 crypto/rand

## 🟡 Severity / 优先级

**P2 — Medium (Predictable)** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/transport/xhttp/stream_down.go `generateSessionID` 用 UnixNano

## 🎯 Description / 漏洞描述与影响

sessionID 可预测,攻击者可猜测/竞态创建合法用户的 sessionID。

## 🔧 Fix / 修复方案

用 `crypto/rand`:

```go
var b [16]byte; rand.Read(b[:])
return hex.EncodeToString(b[:])
```

## ✅ Acceptance Criteria / 验收标准

sessionID 不可预测长度足够(≥128 bit)

## 🧪 Verification / 验证方法

- **单元测试**: 1000 个 sessionID 无碰撞

## 🔗 Dependencies / 依赖关系

- 与 `P0-7` (XHTTP Session Limit) 配套

## ⚠️ Regression Risk / 回归风险

**极低**
