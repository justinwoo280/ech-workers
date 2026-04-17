---
id: "3b1d1d33-b869-4c30-a38c-ae717166f347"
title: "P2-30: Android QUERY_ALL_PACKAGES On-Demand / Android 按需查询应用列表"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:05.266Z"
updatedAt: "2026-04-17T11:28:10.606Z"
type: ticket
---

# P2-30: Android QUERY_ALL_PACKAGES On-Demand / Android 按需查询应用列表

## 🟡 Severity / 优先级

**P2 — Medium (Play Store Policy)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-android/app/src/main/java/com/echworkers/android/data/AppRepository.kt `QUERY_ALL_PACKAGES` 权限

## 🎯 Description / 漏洞描述与影响

Play Store 政策要求该权限**严格说明使用场景**,否则审核拒绝。

## 🔧 Fix / 修复方案

- 改为按需查询(用 `<queries>` Manifest 元素声明特定包名)
- 仅"分应用代理"功能页面使用 packageManager.getInstalledApplications

## ✅ Acceptance Criteria / 验收标准

Manifest 移除 QUERY_ALL_PACKAGES分应用代理功能仍正常工作Play Store 政策合规说明

## 🧪 Verification / 验证方法

- **手工验证**: 分应用代理功能页面正常显示已安装应用
- **Play Console**: pre-launch report 无权限警告

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**中**: 部分场景可能查不到应用,需测试
