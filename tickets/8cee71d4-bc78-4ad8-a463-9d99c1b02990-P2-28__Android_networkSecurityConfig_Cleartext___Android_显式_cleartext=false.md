---
id: "8cee71d4-bc78-4ad8-a463-9d99c1b02990"
title: "P2-28: Android networkSecurityConfig Cleartext / Android 显式 cleartext=false"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:56.436Z"
updatedAt: "2026-04-17T11:28:00.618Z"
type: ticket
---

# P2-28: Android networkSecurityConfig Cleartext / Android 显式 cleartext=false

## 🟡 Severity / 优先级

**P2 — Low (Defensive)** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-android/app/src/main/AndroidManifest.xml

## 🎯 Description / 漏洞描述与影响

默认 28+ 是 false 但显式更安全(防止后续意外开启)。

## 🔧 Fix / 修复方案

加 networkSecurityConfig:

```xml
<application android:networkSecurityConfig="@xml/network_security_config" ...>

<network-security-config><base-config cleartextTrafficPermitted="false"/></network-security-config>
```

## ✅ Acceptance Criteria / 验收标准

显式禁止 cleartext单元测试或 lint 验证

## 🧪 Verification / 验证方法

- **lint**: Android Lint 报告通过

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**极低**
