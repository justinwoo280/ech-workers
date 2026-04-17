---
id: "a8fad8c4-675f-407c-9607-06e45b9f35b8"
title: "P2-27: Android Proguard Specific Methods / Android Proguard 规则精化"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:50.798Z"
updatedAt: "2026-04-17T11:27:56.053Z"
type: ticket
---

# P2-27: Android Proguard Specific Methods / Android Proguard 规则精化

## 🟡 Severity / 优先级

**P2 — Low (Reverse Engineering)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-android/app/proguard-rules.pro `-keep @Serializable class * {*;}` 全保留

## 🎯 Description / 漏洞描述与影响

通配 keep 让反混淆几乎失效,所有 Serializable 类的内部字段名都暴露。

## 🔧 Fix / 修复方案

改为 `<init>` 与具体方法:

```
-keep @Serializable class * {
    <init>(...);
    *** Companion;
    public static *** Companion();
}
```

## ✅ Acceptance Criteria / 验收标准

Proguard 规则更精确APK 中 Serializable 类字段名仍混淆kotlinx.serialization 仍正常工作

## 🧪 Verification / 验证方法

- **APK 反编译**: 检查混淆程度
- **e2e**: 应用功能正常

## 🔗 Dependencies / 依赖关系

- 与 `P2-26` 同模块

## ⚠️ Regression Risk / 回归风险

**中**: Proguard 规则错误可能导致序列化崩溃,需大量 e2e 测试
