---
id: "abdaf19d-d7a0-4f08-9e65-846fca585acf"
title: "P2-29: Android monitorVPN 5-10s Interval / Android VPN 监控间隔放宽"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:01.439Z"
updatedAt: "2026-04-17T11:28:04.860Z"
type: ticket
---

# P2-29: Android monitorVPN 5-10s Interval / Android VPN 监控间隔放宽

## 🟡 Severity / 优先级

**P2 — Low (Battery)** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-android/app/src/main/java/com/echworkers/android/service/EWPVpnService.kt `monitorVPN` 每 2s 查询一次 stats

## 🎯 Description / 漏洞描述与影响

2s 频率电池消耗大。

## 🔧 Fix / 修复方案

改为 5-10s,UI 更新可单独配置。

## ✅ Acceptance Criteria / 验收标准

监控间隔 ≥5s用户体感不下降

## 🧪 Verification / 验证方法

- **电池测试**: Android Battery Historian 对比

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
