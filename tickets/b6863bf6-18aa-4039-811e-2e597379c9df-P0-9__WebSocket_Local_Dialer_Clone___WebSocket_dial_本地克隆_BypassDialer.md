---
id: "b6863bf6-18aa-4039-811e-2e597379c9df"
title: "P0-9: WebSocket Local Dialer Clone / WebSocket dial 本地克隆 BypassDialer"
assignee: ""
status: 0
createdAt: "2026-04-17T11:19:26.509Z"
updatedAt: "2026-04-17T11:19:39.624Z"
type: ticket
---

# P0-9: WebSocket Local Dialer Clone / WebSocket dial 本地克隆 BypassDialer

## 🔴 Severity / 优先级

**P0 — Critical (Data Race)** | Sprint 2 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/transport/websocket/transport.go `dial` line 158-163
- `t.bypassCfg.TCPDialer.Timeout = 10 * time.Second`

## 🎯 Description / 漏洞描述与影响

`bypassCfg` 来自 `tun.Setup` 注入,**所有 transport 实例共享同一 ****`*net.Dialer`**。多个并发 `dial` 同时写 `Timeout` 字段:

- **数据竞态**(go race detector 必报)
- `Timeout` 全局生效会污染其他模块(如 ECH manager 的 dialer)

## 💥 Reproduction / 复现条件

1. 多个 WebSocket transport 并发 Dial
2. `go test -race` 立即报 `WRITE/WRITE` 或 `WRITE/READ` race on `Timeout` 字段
3. ECH manager 的 dialer 突然有了 10s timeout(本应是默认或更短)

## 🔧 Fix / 修复方案

每次 `Dial` 局部克隆 dialer,或仅在 NewTransport 时设置一次。

```go
// 示意
localDialer := *t.bypassCfg.TCPDialer  // 值拷贝
localDialer.Timeout = 10 * time.Second
conn, err := localDialer.DialContext(ctx, "tcp", addr)
```

## ✅ Acceptance Criteria / 验收标准

WebSocket dial 不再修改共享 bypassCfg 字段所有需要不同 timeout 的地方使用本地副本go test -race ./transport/... 无新 race 警告审视其他 transport (gRPC/H3/XHTTP) 是否有同类问题

## 🧪 Verification / 验证方法

- **race detector**: 100 并发 Dial + 同时其他模块用 ECH dialer
- **单元测试**: 断言 Dial 后 `bypassCfg.TCPDialer.Timeout` 字段未变
- **e2e**: 长跑 1h 监控 ECH 模块的 dial timeout 行为是否稳定

## 🔗 Dependencies / 依赖关系

- 与 `P0-8` (TLS Config 克隆) 是同 sprint 的并发安全修复,可一并 review

## ⚠️ Regression Risk / 回归风险

**低**: 局部克隆的开销可忽略。需:

- 检查 grpc/h3grpc/xhttp transport 是否有类似模式
- 检查 `bypass.BypassDialer` 内部其他字段(KeepAlive、Resolver)是否被修改
