---
id: "933e8773-2d10-4717-8c5c-c860d88c1175"
title: "P1-23: wsHandler ClientIP Unification / wsHandler 统一使用 getClientIP"
assignee: ""
status: 0
createdAt: "2026-04-17T11:24:20.021Z"
updatedAt: "2026-04-17T11:24:28.492Z"
type: ticket
---

# P1-23: wsHandler ClientIP Unification / wsHandler 统一使用 getClientIP

## 🟠 Severity / 优先级

**P1 — High (Rate Limit Bypass)** | Sprint 1 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/ws_handler.go line 72

## 🎯 Description / 漏洞描述与影响

当前用 `r.RemoteAddr` 而非 `getClientIP(r)`,与其他 handler 不一致。在 CDN 后所有 WS 请求都被同一 edge IP 限流(本质是 P0-2 反面)。

## 💥 Reproduction / 复现条件

1. 部署在 Cloudflare 后
2. 所有 WS 请求 RemoteAddr 都是 CF edge
3. 单一恶意客户端触发限流后,**所有合法用户被一并封禁**

## 🔧 Fix / 修复方案

统一用 `getClientIP(r)`,**前提是先修复 P0-2**(可信代理白名单):

```go
clientIP := getClientIP(r)
limiter.Allow(clientIP)
```

## ✅ Acceptance Criteria / 验收标准

wsHandler 使用 getClientIP(r)CDN 后正确识别真实客户端 IP直连场景使用 RemoteAddr

## 🧪 Verification / 验证方法

- **集成测试**: CDN 后场景,正确识别 XFF
- **直连测试**: 直连场景,XFF 被忽略

## 🔗 Dependencies / 依赖关系

- **必须** `P0-2` (trusted proxies) 先完成
- 同时考虑 `P2-18` (h3grpc_web 同问题)

## ⚠️ Regression Risk / 回归风险

**低**(在 P0-2 正确的前提下)
