---
id: "bc39db56-371f-4cea-a601-9bd19977b92a"
title: "P2-8: IsNormalCloseError Use errors.Is / IsNormalCloseError 改用 errors.Is"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:18.029Z"
updatedAt: "2026-04-17T11:26:22.711Z"
type: ticket
---

# P2-8: IsNormalCloseError Use errors.Is / IsNormalCloseError 改用 errors.Is

## 🟡 Severity / 优先级

**P2 — Low (Maintainability)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/proxy.go `IsNormalCloseError`

## 🎯 Description / 漏洞描述与影响

用字符串匹配错误,Go 标准库错误文案变化时失效。

## 💥 Reproduction / 复现条件

- Go 版本升级,`io.EOF` 文案变化(理论上),IsNormalCloseError 失效

## 🔧 Fix / 修复方案

用 `errors.Is + 标准 net errors`:

```go
if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) { return true }
```

## ✅ Acceptance Criteria / 验收标准

移除字符串匹配,使用 errors.Is单元测试覆盖各种关闭错误

## 🧪 Verification / 验证方法

- **单元测试**: 注入各种关闭错误,断言识别

## 🔗 Dependencies / 依赖关系

- 与 `P1-12` (ECH errors.As) 是同类改进

## ⚠️ Regression Risk / 回归风险

**低**
