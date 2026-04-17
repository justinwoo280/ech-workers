---
id: "f875204f-6ffb-4dec-925d-f73f347fe047"
title: "P2-15: XHTTP isIPAddress IPv6 Brackets / XHTTP IPv6 括号处理"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:54.813Z"
updatedAt: "2026-04-17T11:26:58.212Z"
type: ticket
---

# P2-15: XHTTP isIPAddress IPv6 Brackets / XHTTP IPv6 括号处理

## 🟡 Severity / 优先级

**P2 — Low** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/transport/xhttp/transport.go `isIPAddress` 对 `[::1]` 返回 false

## 🎯 Description / 漏洞描述与影响

触发不必要 DNS 查询(IPv6 字面量被当 hostname 解析)。

## 🔧 Fix / 修复方案

先 strip brackets:

```go
host := strings.Trim(addr, "[]")
return net.ParseIP(host) != nil
```

## ✅ Acceptance Criteria / 验收标准

[::1] 被识别为 IP,不查 DNS

## 🧪 Verification / 验证方法

- **单元测试**: 各种 IPv6 字面量

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
