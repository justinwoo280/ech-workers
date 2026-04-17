---
id: "76bc780f-c07f-4785-81f3-884c8472c398"
title: "P0-7: XHTTP Session Limit + LRU / XHTTP Session 数量限制与淘汰"
assignee: ""
status: 0
createdAt: "2026-04-17T11:18:55.141Z"
updatedAt: "2026-04-17T11:19:09.661Z"
type: ticket
---

# P0-7: XHTTP Session Limit + LRU / XHTTP Session 数量限制与淘汰

## 🔴 Severity / 优先级

**P0 — Critical (DoS / FD Exhaustion)** | Sprint 3 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/xhttp_handler.go `xhttpSessions sync.Map`

## 🎯 Description / 漏洞描述与影响

一个已认证用户可通过不断变换 sessionID 创建无穷会话(每 session 一个 goroutine + remote conn + uploadQueue),直至**服务端耗尽 fd 或 OOM**。当前 `sync.Map` 无任何上限,无 TTL,无 LRU。

## 💥 Reproduction / 复现条件

1. 攻击者(已认证)发起 N 个 XHTTP 握手,每次 sessionID 不同
2. 每个 session 占用: 1 goroutine + 1 远端 socket + uploadQueue
3. N → 数十万,fd 耗尽,服务端 `accept: too many open files`

## 🔧 Fix / 修复方案

- **每用户(UUID)session 上限**(如 100)
- **每 IP 上限**(如 50)
- **LRU 淘汰**: 超出时关闭最旧的 session
- **空闲 TTL**(如 5 min)

```go
// 示意
if cap.PerUser(uuid) >= maxPerUser { evictOldest(uuid) }
```

可用 `golang.org/x/sync/singleflight` + `hashicorp/golang-lru` 现成库。

## ✅ Acceptance Criteria / 验收标准

xhttpSessions 不再无界,有 per-user/per-IP/total 三层上限超出上限触发 LRU 淘汰,被淘汰的 session 资源(goroutine、conn、buffer)正确清理配置可调,默认值文档化配套 metrics(session 总数、淘汰计数)

## 🧪 Verification / 验证方法

- **单元测试**: 模拟创建 N+1 session,断言旧 session 被淘汰且 fd 释放
- **压力测试**: 100k session 创建尝试,服务端稳定运行
- **goroutine 泄漏**: 每次淘汰后用 pprof 确认 goroutine 数稳定

## 🔗 Dependencies / 依赖关系

- 与 `P1-3` (UDP session cap) 是同类机制,可抽象统一接口
- 与 `P0-6` 配合实现完整的 XHTTP DoS 防御

## ⚠️ Regression Risk / 回归风险

**中**: LRU 淘汰可能误杀活跃 session(如长轮询 download)。需:

- TTL 仅基于真实空闲时间,不基于创建时间
- 给客户端明确的 session 失效错误码,以便重连
