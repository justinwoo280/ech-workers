---
id: "1ba74c7f-471c-47eb-92de-04da5695afd0"
title: "P1-4: TunnelDNSResolver Connection Pool / TunnelDNSResolver 连接池"
assignee: ""
status: 0
createdAt: "2026-04-17T11:21:04.990Z"
updatedAt: "2026-04-17T11:21:15.632Z"
type: ticket
---

# P1-4: TunnelDNSResolver Connection Pool / TunnelDNSResolver 连接池

## 🟠 Severity / 优先级

**P1 — High (Performance)** | Sprint 3 | 工作量: 1.5 天

## 📍 Location / 精确位置

- file:ewp-core/dns/tunnel_resolver.go `serialQuery` 持有 `queryMu` 整个 HTTP 请求生命周期

## 🎯 Description / 漏洞描述与影响

HTTP/1.1 单连接 + 一次只能一个请求 → 高并发场景下 DNS 解析延迟随并发**线性增长**。TUN 模式下浏览器同时打开 50 个 tab 时严重劣化。

## 💥 Reproduction / 复现条件

1. TUN 模式启用
2. 浏览器同时打开 50 个新域名页面
3. 每个域名解析平均 100ms,串行 → 5s 完成最后一个
4. 用户感知"网络变慢"

## 🔧 Fix / 修复方案

- **连接池**: N 个 tunnel + DoH 连接,round-robin
- 或升级为 **HTTP/2 over tunnel** 利用多路复用

```go
// 示意:简单连接池
pool := newPool(8) // 8 条连接
conn := pool.Acquire(); defer pool.Release(conn)
return conn.Query(ctx, name)
```

## ✅ Acceptance Criteria / 验收标准

DNS 解析支持 N 路并发(默认 8)50 并发解析 P99 < 单查询的 1.5 倍池中失败连接自动剔除配置可调

## 🧪 Verification / 验证方法

- **基准测试**: `BenchmarkResolveParallel-50` 对比修复前后吞吐
- **e2e**: TUN 模式下浏览器多 tab 加载时间显著改善
- **长跑**: 24h 池中连接数稳定

## 🔗 Dependencies / 依赖关系

- **触发** `P1-16` (TXID 验证) — 多路复用后必须验证 TXID
- 与 `P1-5` (cache 上限) 配合

## ⚠️ Regression Risk / 回归风险

**中**: 连接池的复杂度增加 bug 面。需:

- 仔细处理 TUN 模式与 bypass 模式的连接复用边界
- 失败连接的快速剔除
