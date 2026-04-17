---
id: "8d7e65a2-c1cb-4979-aa37-90c227adfa8d"
title: "P2-22: XHTTP xmux Use math/rand / XHTTP xmux 选择用 math/rand"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:27.716Z"
updatedAt: "2026-04-17T11:27:30.919Z"
type: ticket
---

# P2-22: XHTTP xmux Use math/rand / XHTTP xmux 选择用 math/rand

## 🟡 Severity / 优先级

**P2 — Low (Performance)** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/transport/xhttp/xmux.go 用 crypto/rand 选 client

## 🎯 Description / 漏洞描述与影响

crypto/rand 是杀鸡用牛刀(选连接不需密码学随机)。

## 🔧 Fix / 修复方案

math/rand 即可:

```go
return clients[rand.Intn(len(clients))]
```

## ✅ Acceptance Criteria / 验收标准

xmux 选择使用 math/rand性能改善

## 🧪 Verification / 验证方法

- **基准测试**

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
