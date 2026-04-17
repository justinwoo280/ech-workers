---
id: "d5376793-3caa-4717-a5f2-1ef3f73a6be3"
title: "P1-10: gRPC Pool Cleanup / gRPC ClientConn 池清理"
assignee: ""
status: 0
createdAt: "2026-04-17T11:22:06.333Z"
updatedAt: "2026-04-17T11:22:15.247Z"
type: ticket
---

# P1-10: gRPC Pool Cleanup / gRPC ClientConn 池清理

## 🟠 Severity / 优先级

**P1 — High (Connection Leak)** | Sprint 3 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/transport/grpc/transport.go `grpcConnPool` 全局 map

## 🎯 Description / 漏洞描述与影响

- `Transport.Close()` 不存在
- 失败的 ClientConn 留在池中(只在下次 Dial 才检查 state)
- 多 outbound 切换或重连后,池**只增不减**

## 💥 Reproduction / 复现条件

1. 频繁切换 outbound 节点
2. 老的 ClientConn 进入 IDLE/SHUTDOWN 但不被清理
3. 池大小持续增长

## 🔧 Fix / 修复方案

- 添加 `Transport.Close()` 接口
- 连接引用计数
- 后台 goroutine 周期检查 state,清理 SHUTDOWN/TransientFailure

```go
// 示意
func (t *Transport) Close() error {
    t.poolMu.Lock(); defer t.poolMu.Unlock()
    for k, c := range t.pool { c.Close(); delete(t.pool, k) }
}
```

## ✅ Acceptance Criteria / 验收标准

Transport.Close() 实现并被上层调用池有引用计数,无人引用且失败时自动剔除周期 cleanup goroutine长跑下池大小稳定

## 🧪 Verification / 验证方法

- **单元测试**: 100 次切换 outbound,断言池大小有上限
- **goroutine 泄漏**: 每次 Close 后 grpc 内部 goroutine 释放
- **手工验证**: 长跑 24h 监控池大小

## 🔗 Dependencies / 依赖关系

- 与 `P1-5` (cache 上限) 是同类资源治理

## ⚠️ Regression Risk / 回归风险

**中**: ClientConn 复用语义改变,需仔细测试:

- 多 outbound 切换的连接复用率
- Close 后再 Dial 自动恢复
