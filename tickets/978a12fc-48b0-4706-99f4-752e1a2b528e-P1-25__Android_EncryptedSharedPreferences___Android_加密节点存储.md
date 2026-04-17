---
id: "978a12fc-48b0-4706-99f4-752e1a2b528e"
title: "P1-25: Android EncryptedSharedPreferences / Android 加密节点存储"
assignee: ""
status: 0
createdAt: "2026-04-17T11:24:39.322Z"
updatedAt: "2026-04-17T11:24:46.795Z"
type: ticket
---

# P1-25: Android EncryptedSharedPreferences / Android 加密节点存储

## 🟠 Severity / 优先级

**P1 — High (At-Rest Credential)** | Sprint 4 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-android/app/src/main/java/com/echworkers/android/data/NodeRepository.kt

## 🎯 Description / 漏洞描述与影响

配合 P0-10 是双重风险。即使关闭 backup,**root 设备/恶意 backup 工具仍可读取 ****`/data/data/com.echworkers.android/shared_prefs/nodes.xml`**** 明文**。

## 💥 Reproduction / 复现条件

1. root 设备
2. `cat /data/data/com.echworkers.android/shared_prefs/nodes.xml` → 明文 UUID/密码

## 🔧 Fix / 修复方案

迁移 `androidx.security:security-crypto`:

```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(KeyScheme.AES256_GCM).build()
val sp = EncryptedSharedPreferences.create(context, "nodes", masterKey, ...)
```

提供旧数据迁移逻辑,迁移成功后删除旧文件。

## ✅ Acceptance Criteria / 验收标准

NodeRepository 使用 EncryptedSharedPreferences旧数据自动迁移到加密存储迁移完成后删除明文 prefs单元测试覆盖加密/解密往返

## 🧪 Verification / 验证方法

- **手工验证**: root 设备 cat prefs xml,内容应为加密 base64,无可读 UUID
- **单元测试**: store/load 节点,断言数据一致

## 🔗 Dependencies / 依赖关系

- 与 `P0-10` (allowBackup=false) 是双重防御
- **被** `P1-18` (Intent NodeId) 依赖

## ⚠️ Regression Risk / 回归风险

**中**:

- 加密 prefs 在某些设备(KeyStore 异常)可能失败
- 需 fallback 策略与错误处理
- 应用首次升级需要数据迁移测试
