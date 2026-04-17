---
id: "bc3e96a2-f026-4e19-8bff-399d93e7733b"
title: "P1-12: Unified ECH Error Detection (errors.As) / 统一 ECH 错误检测"
assignee: ""
status: 0
createdAt: "2026-04-17T11:22:24.940Z"
updatedAt: "2026-04-17T11:22:35.089Z"
type: ticket
---

# P1-12: Unified ECH Error Detection (errors.As) / 统一 ECH 错误检测

## 🟠 Severity / 优先级

**P1 — High (Brittle Error Matching)** | Sprint 3 | 工作量: 0.5 天

## 📍 Location / 精确位置

- WS / gRPC / H3 三处都有相似逻辑,字符串匹配 `"ECH"`
- file:ewp-core/transport/websocket/transport.go
- file:ewp-core/transport/grpc/transport.go
- file:ewp-core/transport/h3grpc/transport.go (已正确使用 errors.As)

## 🎯 Description / 漏洞描述与影响

依赖错误字符串脆弱;若 Go 版本变更错误文案,**ECH 自动恢复失效**,客户端无法触发 retry。

## 💥 Reproduction / 复现条件

1. 升级 Go 版本,标准库 ECH 错误文案变更(如从 "ECH rejected" → "encrypted client hello rejected")
2. 字符串匹配失效
3. ECH retry config 不被处理,所有 ECH 连接失败

## 🔧 Fix / 修复方案

统一使用 `errors.As(&tls.ECHRejectionError{})`(已在 H3 实现):

```go
var rej *tls.ECHRejectionError
if errors.As(err, &rej) {
    echMgr.UpdateFromRetry(rej.RetryConfigList)
    return retry()
}
```

WS/gRPC 用 interface 反射回退(若 ECHRejectionError 不可访问)。

## ✅ Acceptance Criteria / 验收标准

三处 transport 统一使用 errors.As,而非字符串匹配抽象一个 helper 函数 isECHRejection(err) (*ECHRejection, bool)Go 版本升级后行为依然正确

## 🧪 Verification / 验证方法

- **单元测试**: mock 返回 `*tls.ECHRejectionError`,断言三处 transport 都正确触发 retry
- **e2e**: ECH 配置过期场景下三种 transport 均能自动恢复

## 🔗 Dependencies / 依赖关系

- 与 `P0-8` (TLS Config 克隆) 协同

## ⚠️ Regression Risk / 回归风险

**低**
