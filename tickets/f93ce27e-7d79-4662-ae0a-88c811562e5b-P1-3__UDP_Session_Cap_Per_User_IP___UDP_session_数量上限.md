---
id: "f93ce27e-7d79-4662-ae0a-88c811562e5b"
title: "P1-3: UDP Session Cap Per User/IP / UDP session 数量上限"
assignee: ""
status: 0
createdAt: "2026-04-17T11:20:53.829Z"
updatedAt: "2026-04-17T11:21:04.565Z"
type: ticket
---

# P1-3: UDP Session Cap Per User/IP / UDP session 数量上限

## 🟠 Severity / 优先级

**P1 — High (FD/Goroutine Exhaustion)** | Sprint 3 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/internal/server/udp_handler.go `udpHandler.sessions`
- file:ewp-core/protocol/ewp/udp.go `UDPSessionManager`

## 🎯 Description / 漏洞描述与影响

已认证客户端可创建无限 UDP session(每个 GlobalID),消耗服务端 fd 与 goroutine。`closeIdle(5min)` 周期回收,但攻击者**周期内即可制造数十万 session**。

## 💥 Reproduction / 复现条件

1. 客户端用单一 UUID 在 5min 内创建 100k 个不同 GlobalID
2. 每个 session 占用 1 socket + 1 goroutine
3. 服务端 fd 耗尽,新连接被拒绝

## 🔧 Fix / 修复方案

per-connection 与 per-IP 上限(如各 200),达到后:

- 拒绝新 session,或
- LRU 淘汰最旧空闲 session

```go
if len(h.sessions) >= maxPerConn { evictOldestIdle() }
```

## ✅ Acceptance Criteria / 验收标准

udpHandler 与 UDPSessionManager 均有上限超限时返回明确错误帧给客户端LRU 淘汰只针对真正空闲(无近期流量)的 session配置可调,有 metric 暴露当前数量

## 🧪 Verification / 验证方法

- **单元测试**: 创建 N+1 session,断言旧 session 被淘汰且 fd 释放
- **DoS 测试**: 100k session 攻击,服务端 RSS/fd 稳定
- **正功能**: 普通客户端(< 100 session)无影响

## 🔗 Dependencies / 依赖关系

- 与 `P0-7` (XHTTP Session Limit) 是同类机制,可抽象统一接口
- 与 `P0-4` (UDP DNS 异步化) 协同 — pending session 也要计数

## ⚠️ Regression Risk / 回归风险

**低-中**: 上限设置过低可能影响游戏类大量 UDP 连接的应用。需:

- 默认值要保守
- 提供配置项与文档
