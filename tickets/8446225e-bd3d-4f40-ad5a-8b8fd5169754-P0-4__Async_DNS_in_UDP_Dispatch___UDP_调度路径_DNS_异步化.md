---
id: "8446225e-bd3d-4f40-ad5a-8b8fd5169754"
title: "P0-4: Async DNS in UDP Dispatch / UDP 调度路径 DNS 异步化"
assignee: ""
status: 0
createdAt: "2026-04-17T11:18:07.677Z"
updatedAt: "2026-04-17T11:18:24.666Z"
type: ticket
---

# P0-4: Async DNS in UDP Dispatch / UDP 调度路径 DNS 异步化

## 🔴 Severity / 优先级

**P0 — Critical (DoS + Performance)** | Sprint 2 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/internal/server/udp_handler.go `dispatch` line 184-189, line 248-253
- file:ewp-core/internal/server/trojan_udp_handler.go `handleStream` line 90

## 🎯 Description / 漏洞描述与影响

`net.LookupIP(pkt.TargetHost)` / `net.ResolveUDPAddr` **直接在 handleStream goroutine 中同步调用**,期间该 TCP 连接的所有后续 UDP 包都阻塞。

后果:

- 单客户端 P50 延迟受系统 DNS 影响,慢 DNS(5s 超时)直接卡死隧道
- **DoS**: 攻击者构造大量 `UDPStatusNew` + 不可解析域名,服务端 goroutine 长时间阻塞

## 💥 Reproduction / 复现条件

1. 客户端用 EWP 协议发起 UDP session
2. TargetHost 为 `<random>.invalid.example.com`
3. 系统 DNS 解析超时 5s
4. 同一连接其他 UDP session 全部阻塞
5. 重复 N 次 → 服务端 N 个 goroutine 卡住

## 🔧 Fix / 修复方案

**异步 DNS**: 解析放到后台 goroutine,先返回 `pending` session,等解析完成再创建出站 socket;或预先用 DoH client 解析。

```go
// 示意
go func() {
    addr, err := resolver.Resolve(ctx, host)
    sessionMu.Lock(); session.target = addr; ...
}()
```

带超时上限(如 2s),失败时关闭 session 并返回错误帧。

## ✅ Acceptance Criteria / 验收标准

dispatch / handleStream 中无同步 net.LookupIP / net.ResolveUDPAddr 调用DNS 解析超时上限可配置(默认 2s)解析中的 session 处于 pending 状态,UDP 包先入队不丢解析失败时返回明确错误,关闭 session同一 TCP 连接上其他 session 不受单 session DNS 阻塞影响

## 🧪 Verification / 验证方法

- **单元测试**: 注入慢 resolver(sleep 3s),断言其他 session 不受影响
- **DoS 验证**: 用 100 个不可解析域名同时发起 session,服务端 goroutine 数应有上限,CPU 与延迟稳定
- **正功能**: 普通域名解析后包正常转发

## 🔗 Dependencies / 依赖关系

- 与 `P1-3` (UDP session cap) 协同 — 异步化后更需要 cap 控制 pending 队列
- 与 `P1-11` (Trojan UDP resolve failure 包丢失) 同模块,可一并修复

## ⚠️ Regression Risk / 回归风险

**中**: 异步化改变了 session 生命周期,需:

- 仔细处理 pending 状态下 UDP 包的入队/弃用
- 与 cleanup goroutine 的并发安全
- 测试 IPv4/IPv6 双栈场景
