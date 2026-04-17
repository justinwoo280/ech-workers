---
id: "80a6efb7-95c9-47d7-8147-22bf156753c6"
title: "P1-24: Server TLS MinVersion = 1.3 / 服务端最小 TLS 版本提升"
assignee: ""
status: 0
createdAt: "2026-04-17T11:24:29.239Z"
updatedAt: "2026-04-17T11:24:39.174Z"
type: ticket
---

# P1-24: Server TLS MinVersion = 1.3 / 服务端最小 TLS 版本提升

## 🟠 Severity / 优先级

**P1 — High (Downgrade)** | Sprint 1 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/config_mode.go line 221: `MinVersion: tls.VersionTLS12`

## 🎯 Description / 漏洞描述与影响

- 与项目宣称的"TLS 1.3 + ECH"不符
- TLS 1.2 不支持 ECH
- 中间人可降级到 TLS 1.2 → 暴露 SNI

## 💥 Reproduction / 复现条件

1. 中间人在 ClientHello 中过滤 TLS 1.3 cipher
2. 服务端接受 TLS 1.2 协商
3. ECH 失效,SNI 明文暴露

## 🔧 Fix / 修复方案

改为 TLS 1.3:

```go
MinVersion: tls.VersionTLS13,
```

## ✅ Acceptance Criteria / 验收标准

服务端 TLS 配置 MinVersion = TLS 1.3拒绝 TLS 1.2 客户端连接客户端配置同样建议 TLS 1.3文档明确 ECH 需 TLS 1.3

## 🧪 Verification / 验证方法

- **单元测试**: 模拟 TLS 1.2 客户端,断言握手失败
- **手工验证**: `openssl s_client -tls1_2` 失败,`-tls1_3` 成功

## 🔗 Dependencies / 依赖关系

- 与 `P0-12` (DoH 严格模式) 是配套强化

## ⚠️ Regression Risk / 回归风险

**低-中**: 部分老客户端不支持 TLS 1.3,但本项目本身要求 ECH,客户端必须支持
