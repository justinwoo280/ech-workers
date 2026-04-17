---
id: "2d6efd76-be42-4511-b93f-ffc4da1461c7"
title: "P1-18: Intent Pass NodeId, Not Full JSON / Intent 改传 nodeId"
assignee: ""
status: 0
createdAt: "2026-04-17T11:23:28.046Z"
updatedAt: "2026-04-17T11:23:38.270Z"
type: ticket
---

# P1-18: Intent Pass NodeId, Not Full JSON / Intent 改传 nodeId

## 🟠 Severity / 优先级

**P1 — High (Credential Leak via Intent)** | Sprint 4 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-android/app/src/main/java/com/echworkers/android/data/VpnRepository.kt `connect` line 60-65

## 🎯 Description / 漏洞描述与影响

- 虽 Intent 显式 component 路由,无第三方接收
- 但若设备开启 ADB,`adb shell dumpsys activity intents` 可看到 extras
- Android 13+ 对前台服务 Intent 有 logging
- → 凭证可能在系统日志/调试输出中泄露

## 💥 Reproduction / 复现条件

1. 用户启用开发者选项 ADB
2. 调试或日志收集时,`dumpsys activity intents` 输出 Intent extras
3. UUID/Trojan 密码出现在日志中

## 🔧 Fix / 修复方案

节点 JSON 改为传 nodeId,EWPVpnService 再从 SharedPrefs 读取(配合 P0-10 + P1-25 的加密):

```kotlin
intent.putExtra("nodeId", node.id)
// EWPVpnService 内部:
val node = NodeRepository.getById(intent.getIntExtra("nodeId", -1))
```

## ✅ Acceptance Criteria / 验收标准

Intent 不再携带 UUID/密码字段EWPVpnService 启动时从加密 SharedPrefs 读取节点dumpsys 验证 Intent extras 不含敏感信息

## 🧪 Verification / 验证方法

- **手工验证**: `adb shell dumpsys activity intents | grep -i uuid` 无结果
- **单元测试**: VpnRepository.connect 后 Intent extras 仅含 nodeId

## 🔗 Dependencies / 依赖关系

- **依赖** `P0-10` (allowBackup=false) 与 `P1-25` (EncryptedSharedPreferences)

## ⚠️ Regression Risk / 回归风险

**低**
