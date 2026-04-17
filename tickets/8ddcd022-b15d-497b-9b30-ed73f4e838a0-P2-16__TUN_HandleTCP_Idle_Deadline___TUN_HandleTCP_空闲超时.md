---
id: "8ddcd022-b15d-497b-9b30-ed73f4e838a0"
title: "P2-16: TUN HandleTCP Idle Deadline / TUN HandleTCP 空闲超时"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:58.970Z"
updatedAt: "2026-04-17T11:27:04.916Z"
type: ticket
---

# P2-16: TUN HandleTCP Idle Deadline / TUN HandleTCP 空闲超时

## 🟡 Severity / 优先级

**P2 — Medium (Half-Open)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/tun/handler.go `HandleTCP` 双向无 read deadline

## 🎯 Description / 漏洞描述与影响

**半开 TCP 连接永驻**,占用 fd 与内存。

## 💥 Reproduction / 复现条件

1. TUN 模式下大量短连接,部分对端崩溃未发 FIN
2. 半开连接累积,fd 耗尽

## 🔧 Fix / 修复方案

加 Idle deadline:

```go
conn.SetReadDeadline(time.Now().Add(idleTimeout))
// 收到数据后刷新 deadline
```

## ✅ Acceptance Criteria / 验收标准

HandleTCP 有空闲超时(默认 5min)超时后关闭 conn 释放 fd配置可调

## 🧪 Verification / 验证方法

- **单元测试**: 注入半开连接,断言超时关闭
- **长跑**: TUN 模式 24h fd 数稳定

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**中**: 长连接(SSH/WebSocket)可能误杀,需 keepalive 配合
