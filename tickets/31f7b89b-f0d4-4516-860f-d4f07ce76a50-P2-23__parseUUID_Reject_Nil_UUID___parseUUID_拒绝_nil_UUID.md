---
id: "31f7b89b-f0d4-4516-860f-d4f07ce76a50"
title: "P2-23: parseUUID Reject Nil UUID / parseUUID 拒绝 nil UUID"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:31.665Z"
updatedAt: "2026-04-17T11:27:35.098Z"
type: ticket
---

# P2-23: parseUUID Reject Nil UUID / parseUUID 拒绝 nil UUID

## 🟡 Severity / 优先级

**P2 — Medium** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/option/legacy.go `parseUUID` 接受 nil UUID `00000000-...`

## 🎯 Description / 漏洞描述与影响

弱凭证不被发现 — 用户配置了全零 UUID,启动成功但安全性为零。

## 🔧 Fix / 修复方案

校验非零:

```go
if isNilUUID(u) { return errNilUUID }
```

## ✅ Acceptance Criteria / 验收标准

全零 UUID 被拒绝单元测试覆盖

## 🧪 Verification / 验证方法

- **单元测试**

## 🔗 Dependencies / 依赖关系

- 与 `P0-1` 配套

## ⚠️ Regression Risk / 回归风险

**极低**
