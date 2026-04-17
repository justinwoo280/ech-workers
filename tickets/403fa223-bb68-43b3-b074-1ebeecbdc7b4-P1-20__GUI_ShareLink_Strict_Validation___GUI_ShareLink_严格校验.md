---
id: "403fa223-bb68-43b3-b074-1ebeecbdc7b4"
title: "P1-20: GUI ShareLink Strict Validation / GUI ShareLink 严格校验"
assignee: ""
status: 0
createdAt: "2026-04-17T11:23:48.632Z"
updatedAt: "2026-04-17T11:23:58.910Z"
type: ticket
---

# P1-20: GUI ShareLink Strict Validation / GUI ShareLink 严格校验

## 🟠 Severity / 优先级

**P1 — High (Crash + UX)** | Sprint 4 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-gui/src/ShareLink.cpp `parseLink`

## 🎯 Description / 漏洞描述与影响

- UUID 不校验长度/格式
- 端口超界不校验
- domain 含特殊字符直接接受
- → 导入恶意剪贴板内容可创建畸形节点,后续保存/编辑时崩溃,或被 Core 拒绝但用户不知所以

## 💥 Reproduction / 复现条件

1. 攻击者构造 `ewp://invalid-uuid@host:99999/?...` 链接放入剪贴板
2. 用户导入 → 节点入库,UUID 字段是 "invalid-uuid"
3. 启动连接 → Core 报错"invalid UUID",但 UI 不明确

## 🔧 Fix / 修复方案

严格校验,无效字段 → 返回 invalid,**不入库**:

```cpp
if (!isValidUUID(uuid)) return ShareLink::Invalid("UUID 格式错误");
if (port < 1 || port > 65535) return ShareLink::Invalid("端口越界");
```

## ✅ Acceptance Criteria / 验收标准

UUID 严格校验为 RFC 4122 格式端口在 1-65535domain/host 严格 ASCII / IDN 校验失败时给用户明确错误提示单元测试覆盖各种畸形链接

## 🧪 Verification / 验证方法

- **单元测试**: `parseLink` 注入 20+ 种畸形,断言均返回 Invalid 且不抛异常
- **手工验证**: 导入畸形链接弹出明确错误对话框

## 🔗 Dependencies / 依赖关系

- 与 `P1-21` (导入确认) 是同 sprint 的 GUI UX 强化

## ⚠️ Regression Risk / 回归风险

**低**
