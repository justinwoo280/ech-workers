---
id: "ca9face4-f877-49d2-ad9b-f8385dcb1ab3"
title: "P0-10: Android allowBackup=false + Backup Rules / Android 关闭 ADB 备份"
assignee: ""
status: 0
createdAt: "2026-04-17T11:19:40.388Z"
updatedAt: "2026-04-17T11:19:56.750Z"
type: ticket
---

# P0-10: Android allowBackup=false + Backup Rules / Android 关闭 ADB 备份

## 🔴 Severity / 优先级

**P0 — Critical (Credential Leak)** | Sprint 1 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-android/app/src/main/AndroidManifest.xml line 11

## 🎯 Description / 漏洞描述与影响

`adb backup -f x.ab com.echworkers.android` 即可拖出 `nodes_json` SharedPreferences,其中包含 **所有节点的 UUID 和 Trojan 密码明文**。**无需 root**。

`NodeRepository` 用普通 SharedPreferences 存储,未使用 EncryptedSharedPreferences(见 P1-25)。

## 💥 Reproduction / 复现条件

1. 用户手机连接电脑(USB 调试可关,但 backup 默认开)
2. 攻击者 `adb backup -f leak.ab com.echworkers.android`
3. `dd if=leak.ab of=leak.tar bs=24 skip=1` + `tar xf leak.tar`
4. `cat apps/com.echworkers.android/sp/nodes.xml` → 看到所有 UUID 明文

## 🔧 Fix / 修复方案

- 设置 `android:allowBackup="false"`
- 或提供 `backup_rules.xml` / `data_extraction_rules.xml` 显式排除节点存储

```xml
<application android:allowBackup="false" ...>
```

如需保留部分备份能力(如界面设置):

```xml
<application android:dataExtractionRules="@xml/backup_rules" ...>

<full-backup-content><exclude domain="sharedpref" path="nodes.xml"/></full-backup-content>
```

## ✅ Acceptance Criteria / 验收标准

AndroidManifest.xml 中 android:allowBackup="false" 或定义 dataExtractionRules验证 adb backup 后产物中不含节点凭证release build 与 debug build 行为一致对 Android 12+ 的 dataExtractionRules 也明确排除

## 🧪 Verification / 验证方法

- **手工验证**: `adb backup -f test.ab com.echworkers.android` → unpack 后 grep UUID 字段应无结果
- **单元测试**: Manifest 解析断言 allowBackup=false
- **回归**: 应用主功能不受影响

## 🔗 Dependencies / 依赖关系

- 必须在 `P1-18` (Intent 改传 nodeId) 之前
- 与 `P1-25` (EncryptedSharedPreferences) 是双重防御,应一并实施

## ⚠️ Regression Risk / 回归风险

**低**: 用户从此无法用 adb 备份/恢复节点配置。需:

- 提供应用内"导出/导入节点"功能(可加密导出)
- Release Notes 说明此变更
