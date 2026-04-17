---
id: "d4be3194-c0fd-42fa-a7a9-64211d35c1e7"
title: "P2-35: CI Gradle Wrapper Validation / CI 加 Gradle Wrapper 校验"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:32.143Z"
updatedAt: "2026-04-17T11:28:35.755Z"
type: ticket
---

# P2-35: CI Gradle Wrapper Validation / CI 加 Gradle Wrapper 校验

## 🟡 Severity / 优先级

**P2 — Medium (Supply Chain)** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:.github/workflows/build-android-apk.yml `gradle-version: '8.5'`

## 🎯 Description / 漏洞描述与影响

与 Android Gradle Plugin 兼容性未固定,CI 不稳定。Wrapper 文件未校验易被供应链攻击。

## 🔧 Fix / 修复方案

加 wrapper 校验:

```yaml
- uses: gradle/wrapper-validation-action@v1
```

## ✅ Acceptance Criteria / 验收标准

CI 加入 wrapper-validation stepgradle-version 固定具体小版本

## 🧪 Verification / 验证方法

- **CI 运行**: 通过即可

## 🔗 Dependencies / 依赖关系

- 与 `P2-36`、`P2-37` 同 sprint

## ⚠️ Regression Risk / 回归风险

**极低**
