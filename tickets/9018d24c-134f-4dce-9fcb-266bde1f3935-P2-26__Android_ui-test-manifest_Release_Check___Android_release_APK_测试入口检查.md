---
id: "9018d24c-134f-4dce-9fcb-266bde1f3935"
title: "P2-26: Android ui-test-manifest Release Check / Android release APK 测试入口检查"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:45.093Z"
updatedAt: "2026-04-17T11:27:50.048Z"
type: ticket
---

# P2-26: Android ui-test-manifest Release Check / Android release APK 测试入口检查

## 🟡 Severity / 优先级

**P2 — Medium (Attack Surface)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-android/app/build.gradle.kts `debugImplementation ui-test-manifest`

## 🎯 Description / 漏洞描述与影响

debugImplementation 应仅用于 debug,但需验证 release APK 是否真无测试入口。

## 🔧 Fix / 修复方案

- 检查 release APK 用 `apkanalyzer` 确认无 ui-test-manifest 类
- 如有,移到 `androidTestImplementation`

```kotlin
androidTestImplementation("androidx.compose.ui:ui-test-manifest:...")
```

## ✅ Acceptance Criteria / 验收标准

release APK 不含 ui-test-manifestCI 加入 APK 检查 step

## 🧪 Verification / 验证方法

- **APK 分析**: `apkanalyzer dex packages release.apk | grep test`

## 🔗 Dependencies / 依赖关系

- 与 `P2-27` (Proguard) 同模块

## ⚠️ Regression Risk / 回归风险

**低**
