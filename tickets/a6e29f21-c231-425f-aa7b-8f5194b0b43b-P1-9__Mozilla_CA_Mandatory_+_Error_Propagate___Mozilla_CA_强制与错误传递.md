---
id: "a6e29f21-c231-425f-aa7b-8f5194b0b43b"
title: "P1-9: Mozilla CA Mandatory + Error Propagate / Mozilla CA 强制与错误传递"
assignee: ""
status: 0
createdAt: "2026-04-17T11:21:54.012Z"
updatedAt: "2026-04-17T11:22:05.951Z"
type: ticket
---

# P1-9: Mozilla CA Mandatory + Error Propagate / Mozilla CA 强制与错误传递

## 🟠 Severity / 优先级

**P1 — High (Silent Trust)** | Sprint 4 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/common/tls/config.go `NewSTDConfig` line 41-43
- 当前: `} else { roots, _ = x509.SystemCertPool() }`

## 🎯 Description / 漏洞描述与影响

`SystemCertPool()` 错误被忽略。某些受限系统(如 Android minSdk 26 但 user CA 被禁用)可能返回 `nil`,导致后续校验失败 / **静默信任所有证书**(取决于 tls 实现)。

## 💥 Reproduction / 复现条件

1. 在 user CA 被禁用的设备上,`SystemCertPool()` 返回 (nil, error)
2. 错误被 `_` 丢弃
3. roots = nil → tls.Config.RootCAs = nil → 走系统默认验证(行为依赖 Go 版本)
4. 中间人证书可能不被检测

## 🔧 Fix / 修复方案

错误必须返回失败;Mobile 默认强制 useMozillaCA:

```go
roots, err := x509.SystemCertPool()
if err != nil || roots == nil { return nil, fmt.Errorf("no CA: %w", err) }
```

Mobile 配置默认 `useMozillaCA = true`。

## ✅ Acceptance Criteria / 验收标准

NewSTDConfig 不忽略 SystemCertPool() 错误roots 为 nil 时显式返回构造失败Mobile 端配置默认 useMozillaCA = true文档说明嵌入的 Mozilla CA 更新策略

## 🧪 Verification / 验证方法

- **单元测试**: mock SystemCertPool 返回 error,断言 NewSTDConfig 失败
- **手工验证**: 在受限 Android 设备上启动,无明确错误前不应能建立 TLS

## 🔗 Dependencies / 依赖关系

- 与 `P0-12` (DoH 严格模式) 是同 Sprint 的信任链强化

## ⚠️ Regression Risk / 回归风险

**中**: 部分用户系统 CA 异常时,从"静默允许"变"明确失败"。需:

- 嵌入 Mozilla CA 作为兜底
- 文档化错误信息引导用户
