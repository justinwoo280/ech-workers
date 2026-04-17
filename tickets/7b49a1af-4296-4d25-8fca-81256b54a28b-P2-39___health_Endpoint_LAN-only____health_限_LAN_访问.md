---
id: "7b49a1af-4296-4d25-8fca-81256b54a28b"
title: "P2-39: /health Endpoint LAN-only / /health 限 LAN 访问"
assignee: ""
status: 0
createdAt: "2026-04-17T11:28:54.589Z"
updatedAt: "2026-04-17T11:28:59.155Z"
type: ticket
---

# P2-39: /health Endpoint LAN-only / /health 限 LAN 访问

## 🟡 Severity / 优先级

**P2 — Low (Info Disclosure)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/main.go `healthHandler` `/health` 无认证

## 🎯 Description / 漏洞描述与影响

暴露服务存在 — 攻击者可通过 /health 200 OK 确认这是 ECH Workers 服务。

## 🔧 Fix / 修复方案

可改为 192.168/* / 10.x 限制,或要求 token:

```go
if !isLocalNetwork(r.RemoteAddr) { http.NotFound(w, r); return }
```

## ✅ Acceptance Criteria / 验收标准

/health 仅 LAN 可访问公网访问返回 404

## 🧪 Verification / 验证方法

- **手工验证**: 公网 curl /health 返回 404,LAN 返回 200

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**低**: 部分 monitoring 工具走公网,需配置例外
