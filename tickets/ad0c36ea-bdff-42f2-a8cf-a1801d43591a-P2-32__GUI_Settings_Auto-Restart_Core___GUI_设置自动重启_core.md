---
id: "ad0c36ea-bdff-42f2-a8cf-a1801d43591a"
title: "P2-32: GUI Settings Auto-Restart Core / GUI 设置自动重启 core"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:16.119Z"
updatedAt: "2026-04-17T11:28:19.841Z"
type: ticket
---

# P2-32: GUI Settings Auto-Restart Core / GUI 设置自动重启 core

## 🟡 Severity / 优先级

**P2 — Low (UX)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-gui/src/MainWindow.cpp `onShowSettings` 不重启 core 应用新设置

## 🎯 Description / 漏洞描述与影响

配置改变不生效,用户疑惑。

## 🔧 Fix / 修复方案

- 提示重启 / 自动重启
- 或检测哪些设置改变,选择性重启

## ✅ Acceptance Criteria / 验收标准

设置保存后提示是否重启用户确认后无缝重启 core重连成功

## 🧪 Verification / 验证方法

- **手工验证**

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**低**
