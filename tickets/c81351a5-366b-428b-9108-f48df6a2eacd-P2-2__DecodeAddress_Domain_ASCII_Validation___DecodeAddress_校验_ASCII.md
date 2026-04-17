---
id: "c81351a5-366b-428b-9108-f48df6a2eacd"
title: "P2-2: DecodeAddress Domain ASCII Validation / DecodeAddress 校验 ASCII"
assignee: ""
status: 0
createdAt: "2026-04-17T11:25:42.602Z"
updatedAt: "2026-04-17T11:25:48.746Z"
type: ticket
---

# P2-2: DecodeAddress Domain ASCII Validation / DecodeAddress 校验 ASCII

## 🟡 Severity / 优先级

**P2 — Medium (Log Injection)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/ewp/address.go `DecodeAddress` Domain 类型

## 🎯 Description / 漏洞描述与影响

不校验 host 是否含 `\0`/控制字符 → **日志注入风险**,攻击者可在域名字段注入换行 / ANSI 转义伪造日志。

## 💥 Reproduction / 复现条件

1. 攻击者构造域名 `example.com\nFAKE LOG ENTRY`
2. 服务端 log 此域名时,日志被插入伪条目

## 🔧 Fix / 修复方案

加 ASCII 可打印校验:

```go
if !isPrintableASCIIOrIDN(domain) { return errInvalidDomain }
```

## ✅ Acceptance Criteria / 验收标准

DecodeAddress 拒绝含控制字符的 domain单元测试覆盖

## 🧪 Verification / 验证方法

- **单元测试**: 注入 `\n` `\0` `\x1b[31m`,断言被拒

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**低**: 需测试 IDN 域名兼容
