---
id: "20dd15b3-9ba6-4858-93eb-b4d440c65201"
title: "P2-20: XHTTP StreamOne Header Constants / XHTTP 头大小抽常量"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:18.727Z"
updatedAt: "2026-04-17T11:27:22.973Z"
type: ticket
---

# P2-20: XHTTP StreamOne Header Constants / XHTTP 头大小抽常量

## 🟡 Severity / 优先级

**P2 — Low (Maintainability)** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/xhttp_handler.go `xhttpStreamOneHandler` Trojan EWP 头大小用魔数 `KeyLength+2+1+1+2+2`

## 🎯 Description / 漏洞描述与影响

易错,新增字段时容易忘记更新。

## 🔧 Fix / 修复方案

抽常量:

```go
const ewpStreamOneHeaderSize = KeyLength + 2 + 1 + 1 + 2 + 2
```

或定义结构体让编译器算大小。

## ✅ Acceptance Criteria / 验收标准

魔数被命名常量替代注释说明字段构成

## 🧪 Verification / 验证方法

- **代码审查**

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
