---
id: "94b6b82c-12ec-4719-a5ea-a11bf873fb04"
title: "P2-6: Bufferpool Origin Validation / Bufferpool 来源校验"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:04.515Z"
updatedAt: "2026-04-17T11:26:12.627Z"
type: ticket
---

# P2-6: Bufferpool Origin Validation / Bufferpool 来源校验

## 🟡 Severity / 优先级

**P2 — Low (Defensive)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/common/bufferpool/pool.go `PutLarge` 等

## 🎯 Description / 漏洞描述与影响

不验证 buf 是否原本来自 pool,**外部 buffer 被混入** → 后续 Get 拿到不预期 size 的 buffer,可能越界。

## 💥 Reproduction / 复现条件

- 代码 bug 把外部 slice 误传入 PutLarge → 池被污染

## 🔧 Fix / 修复方案

加 magic 字段或 sync.Pool with type assertion:

```go
type pooledBuf struct { magic uint64; data []byte }
if b.magic != poolMagic { panic("foreign buffer in pool") }
```

## ✅ Acceptance Criteria / 验收标准

Put 时校验 buffer 是 pool 创建的校验失败 panic 或 log

## 🧪 Verification / 验证方法

- **单元测试**: 注入外部 buffer,断言被拒

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**低**
