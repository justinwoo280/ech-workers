---
id: "0c1e5cd8-1cf4-4850-b260-aeb53f99815b"
title: "P2-34: GUI System Proxy Save Original State / GUI 系统代理保留原始状态"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:24.777Z"
updatedAt: "2026-04-17T11:28:31.301Z"
type: ticket
---

# P2-34: GUI System Proxy Save Original State / GUI 系统代理保留原始状态

## 🟡 Severity / 优先级

**P2 — Medium (User Settings Loss)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-gui/src/SystemProxy.cpp `disable` 无视 enable 失败状态强制 disable

## 🎯 Description / 漏洞描述与影响

**改回原系统设置丢失**。如用户原本有公司代理设置,启用 GUI 代理失败后 disable 时把公司代理也清掉。

## 🔧 Fix / 修复方案

保存原 PROXY_ENABLE / PROXY_SERVER / PROXY_OVERRIDE 状态,disable 时恢复:

```cpp
// enable 前
QSettings::value("ProxyServer", originalProxy);
// disable 时
QSettings::setValue("ProxyServer", originalProxy);
```

## ✅ Acceptance Criteria / 验收标准

enable 前保存所有相关注册表/设置项disable 时恢复测试公司代理场景

## 🧪 Verification / 验证方法

- **手工验证**: 设置公司代理后启用/禁用 GUI 代理,公司代理保留

## 🔗 Dependencies / 依赖关系

- 与 `P1-19` (PAC 覆盖) 同模块

## ⚠️ Regression Risk / 回归风险

**低**
