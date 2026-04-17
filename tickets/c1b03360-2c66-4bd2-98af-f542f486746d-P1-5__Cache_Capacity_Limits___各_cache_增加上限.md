---
id: "c1b03360-2c66-4bd2-98af-f542f486746d"
title: "P1-5: Cache Capacity Limits / 各 cache 增加上限"
assignee: ""
status: 0
createdAt: "2026-04-17T11:21:16.012Z"
updatedAt: "2026-04-17T11:21:25.619Z"
type: ticket
---

# P1-5: Cache Capacity Limits / 各 cache 增加上限

## 🟠 Severity / 优先级

**P1 — High (Memory Leak)** | Sprint 3 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/dns/tunnel_resolver.go `r.cache sync.Map`
- file:ewp-core/transport/grpc/transport.go `grpcConnPool`

## 🎯 Description / 漏洞描述与影响

长时间运行积累不限大小。grpcConnPool 中失败的连接不会被清理(`shutdown / TransientFailure` 状态才会替换)。

## 💥 Reproduction / 复现条件

1. 长跑 7 天
2. DNS 缓存累积数十万条目(尤其 fakeip 场景)
3. grpcConnPool 残留多次失败的 ClientConn
4. RSS 持续增长

## 🔧 Fix / 修复方案

设置容量上限 + LRU,引入后台清理 goroutine:

```go
cache := lru.New(maxEntries) // 如 hashicorp/golang-lru
go cleanupLoop(ctx, cache, 10*time.Minute)
```

## ✅ Acceptance Criteria / 验收标准

DNS cache 与 grpcConnPool 均有 entry 数上限LRU 淘汰策略后台 goroutine 周期清理过期/失败条目配置项 + metric 暴露当前 cache 利用率

## 🧪 Verification / 验证方法

- **长跑**: 7 天监控 RSS 与 cache size
- **单元测试**: 注入 N+1 条目,断言旧条目被淘汰
- **失败连接清理**: 模拟 ClientConn 持续失败,验证池中数量稳定

## 🔗 Dependencies / 依赖关系

- 与 `P1-4` (DNS 连接池) 同 sprint
- 与 `P1-10` (gRPC Pool 清理) 是相邻模块,可一并修复

## ⚠️ Regression Risk / 回归风险

**低**: 主要是新增容量管理,不改语义
