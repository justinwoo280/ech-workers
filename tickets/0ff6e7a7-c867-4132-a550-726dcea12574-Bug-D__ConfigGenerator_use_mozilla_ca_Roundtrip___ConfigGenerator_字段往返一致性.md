---
id: "0ff6e7a7-c867-4132-a550-726dcea12574"
title: "Bug-D: ConfigGenerator use_mozilla_ca Roundtrip / ConfigGenerator 字段往返一致性"
assignee: ""
status: 0
createdAt: "2026-04-17T11:29:31.652Z"
updatedAt: "2026-04-17T11:29:44.215Z"
type: ticket
---

# Bug-D: ConfigGenerator use_mozilla_ca Roundtrip / ConfigGenerator 字段往返一致性

## 🔵 Severity / 优先级

**Bug — Low** | Sprint 5 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-gui/src/ConfigGenerator.cpp `generateTLS` line 212: `tls["use_mozilla_ca"] = node.useMozillaCA`
- file:ewp-gui/src/EWPNode.h line 61: `bool useMozillaCA = true` ✅ 字段存在

## 🎯 Description / 漏洞描述与影响

**已验证**: `EWPNode.h` 中确实有 `useMozillaCA` 字段(line 61),Bug-D 原报告"未读 EWPNode.h"的疑虑可消除。

但仍需确保:

1. 序列化默认值 `true` 与 Mobile/Client 一致
2. 旧版 nodes.json 不含此字段时反序列化 fallback 正确(line 119: `obj["useMozillaCA"].toBool(true)`)
3. Core 配置 schema 接受 `use_mozilla_ca` 字段名(snake_case)

## 💥 Reproduction / 复现条件

- 旧版本 nodes.json 升级后,字段缺失 → 默认 true → 与 Mobile 行为一致 ✅(已正确)
- 可能不一致点:Core 配置可能期望 `useMozillaCA` (camelCase) 而非 `use_mozilla_ca`

## 🔧 Fix / 修复方案

- 确认 Core 配置 schema 字段名(snake vs camel)
- 加单元测试验证 GUI → Core 配置往返一致性

```cpp
// 验证 generateConfig() 输出可被 Core 正确解析
QJsonDocument out = generator.generate(node);
QVERIFY(coreConfigParser.parse(out).useMozillaCA == node.useMozillaCA);
```

## ✅ Acceptance Criteria / 验收标准

验证字段名与 Core 一致加单元测试验证 GUI 配置 → Core 解析往返文档化字段名约定

## 🧪 Verification / 验证方法

- **e2e**: GUI 启动 core,断言 ECH/CA 行为符合预期

## 🔗 Dependencies / 依赖关系

- 与 `P1-9` (Mozilla CA mandatory) 同链路

## ⚠️ Regression Risk / 回归风险

**低**
