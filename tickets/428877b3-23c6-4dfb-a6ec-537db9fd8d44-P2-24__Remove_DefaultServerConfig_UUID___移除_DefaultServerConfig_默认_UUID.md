---
id: "428877b3-23c6-4dfb-a6ec-537db9fd8d44"
title: "P2-24: Remove DefaultServerConfig UUID / 移除 DefaultServerConfig 默认 UUID"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:35.496Z"
updatedAt: "2026-04-17T11:27:38.950Z"
type: ticket
---

# P2-24: Remove DefaultServerConfig UUID / 移除 DefaultServerConfig 默认 UUID

## 🟡 Severity / 优先级

**P2 — Medium (Same Class as P0-1)** | Sprint 1 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/option/server_config.go `DefaultServerConfig`

## 🎯 Description / 漏洞描述与影响

同 P0-1 但低优先,可一并去除以保持一致性。

## 🔧 Fix / 修复方案

UUID 字段默认空,加载时校验。

## ✅ Acceptance Criteria / 验收标准

DefaultServerConfig.UUID = ""与 P0-1 同时修复

## 🧪 Verification / 验证方法

- 同 P0-1

## 🔗 Dependencies / 依赖关系

- 与 `P0-1` 一并修复

## ⚠️ Regression Risk / 回归风险

**低**
