---
id: "8f290655-91d7-444e-b967-52145b102ce0"
title: "P0-8: Clone TLS Config to Avoid ECH Race / TLS Config 克隆避免 ECH 更新竞态"
assignee: ""
status: 0
createdAt: "2026-04-17T11:19:10.803Z"
updatedAt: "2026-04-17T11:19:25.825Z"
type: ticket
---

# P0-8: Clone TLS Config to Avoid ECH Race / TLS Config 克隆避免 ECH 更新竞态

## 🔴 Severity / 优先级

**P0 — Critical (Concurrency)** | Sprint 2 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/common/tls/config.go `STDConfig.TLSConfig` 直接返回 `c.config`,**未克隆**
- file:ewp-core/common/tls/ech.go `UpdateFromRetry` 修改 `EncryptedClientHelloConfigList`

## 🎯 Description / 漏洞描述与影响

- 同一 Transport 的多个并发 `Dial()` 共享同一 `*tls.Config`
- 当 ECH 被服务端拒绝并通过 `UpdateFromRetry` 更新 `EncryptedClientHelloConfigList` 时,**正在握手中的连接会读到部分更新的字段**
- **Go 文档明确要求 tls.Config 不可在使用中修改**

## 💥 Reproduction / 复现条件

1. 100 个并发 Dial 同时进行
2. 中途服务端发送 ECH retry config
3. UpdateFromRetry 修改 config 的 EncryptedClientHelloConfigList
4. 部分握手中的连接可能 panic / 用半新半旧的 ECH config 失败

## 🔧 Fix / 修复方案

- `TLSConfig()` 返回 `c.config.Clone()`
- ECH manager 持有独立 config,Dial 时 Clone

```go
// 示意
func (c *STDConfig) TLSConfig() *tls.Config {
    cfg := c.config.Clone()
    cfg.EncryptedClientHelloConfigList = c.echMgr.Current()
    return cfg
}
```

## ✅ Acceptance Criteria / 验收标准

TLSConfig() 始终返回 Clone,而非共享引用ECH config 更新通过原子方式快照,不影响进行中的 Dial用 -race 运行所有 transport 测试无 data race 警告文档注释说明 TLS Config 的不可变约束

## 🧪 Verification / 验证方法

- **race detector**: `go test -race ./common/tls/... ./transport/...`
- **并发测试**: 1000 并发 Dial + 持续 ECH update,无 panic 无 race
- **e2e**: ECH retry 场景下连接成功率不下降

## 🔗 Dependencies / 依赖关系

- 与 `P0-9` (WebSocket BypassDialer 共享) 是同类共享可变状态问题,Sprint 2 配套修复
- `P1-12` (统一 ECH 错误检测) 是相关项

## ⚠️ Regression Risk / 回归风险

**低-中**: Clone 增加少量内存分配(微秒级)。需:

- benchmark Dial 性能不退化超过 5%
- 验证 SessionTicket / KeyLogWriter 等共享字段在 Clone 后行为正确
