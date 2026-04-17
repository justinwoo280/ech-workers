---
id: "13f420ce-1663-4ab2-9856-07b15a450467"
title: "P2-18: h3grpc_web ClientIP Unification / h3grpc_web 统一使用 getClientIP"
assignee: ""
status: 0
createdAt: "2026-04-17T11:27:09.961Z"
updatedAt: "2026-04-17T11:27:13.844Z"
type: ticket
---

# P2-18: h3grpc_web ClientIP Unification / h3grpc_web 统一使用 getClientIP

## 🟡 Severity / 优先级

**P2 — Medium (Same as P0-2)** | Sprint 1 | 工作量: 0.1 天

## 📍 Location / 精确位置

- file:ewp-core/internal/server/h3grpc_web.go `clientIP := r.RemoteAddr`

## 🎯 Description / 漏洞描述与影响

同 P0-2 反面,CDN 后 IP 错误识别。

## 🔧 Fix / 修复方案

修 P0-2 后统一使用 `getClientIP(r)`。

## ✅ Acceptance Criteria / 验收标准

使用 getClientIP与 wsHandler 一致

## 🧪 Verification / 验证方法

- 同 P1-23

## 🔗 Dependencies / 依赖关系

- **必须** `P0-2` 先完成
- 与 `P1-23` 同 sprint

## ⚠️ Regression Risk / 回归风险

**低**
