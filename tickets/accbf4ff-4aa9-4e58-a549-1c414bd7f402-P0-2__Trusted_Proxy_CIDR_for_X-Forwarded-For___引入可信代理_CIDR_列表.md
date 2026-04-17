---
id: "accbf4ff-4aa9-4e58-a549-1c414bd7f402"
title: "P0-2: Trusted Proxy CIDR for X-Forwarded-For / 引入可信代理 CIDR 列表"
assignee: ""
status: 0
createdAt: "2026-04-17T11:17:30.961Z"
updatedAt: "2026-04-17T11:17:47.047Z"
type: ticket
---

# P0-2: Trusted Proxy CIDR for X-Forwarded-For / 引入可信代理 CIDR 列表

## 🔴 Severity / 优先级

**P0 — Critical** | Sprint 1 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/server/main.go `getClientIP` line 154-171

## 🎯 Description / 漏洞描述与影响

`getClientIP` 无条件信任 `X-Forwarded-For` / `CF-Connecting-IP` 头,而 `RateLimiter.Allow(clientIP)` 与失败封禁均使用此 IP。攻击者可:

1. 伪造不同的 XFF 头 → 真实攻击 IP **永远不被封禁**(限流机制完全失效)
2. 伪造无辜 IP → **放大攻击,封禁正常用户**

## 💥 Reproduction / 复现条件

1. 直连(非 CDN 后)发送 HTTP 请求,头部携带 `X-Forwarded-For: <随机IP>`
2. 重复发送大量握手失败请求,每次换 XFF
3. 观察服务端永远不触发限流,真实源 IP 不在封禁列表

## 🔧 Fix / 修复方案

引入 `trusted_proxies` CIDR 列表,**只在源 IP 命中可信 CDN 段时才解析 XFF 头**;否则用 `r.RemoteAddr`。

```go
// 示意
if isTrusted(realRemote, trustedCIDRs) { return parseXFFLast(r) }
return realRemote
```

可信 CIDR 配置项:

- 默认 Cloudflare 官方 IP 段(可定时刷新 API)
- 用户自定义白名单

## ✅ Acceptance Criteria / 验收标准

配置中新增 trusted_proxies: []string 字段(CIDR 列表)getClientIP 仅当 r.RemoteAddr 命中 trusted CIDR 时才查 XFF/CF-Connecting-IP直连场景使用 r.RemoteAddr,XFF 被忽略默认配置内置 Cloudflare 官方 IP 段(可禁用)文档说明 CDN 部署需要正确配置该字段

## 🧪 Verification / 验证方法

- **单元测试**: 三组用例 — 不可信源伪造 XFF / 可信源正确解析 / 多级 XFF 取最右一个不可信
- **集成测试**: 直连发送伪 XFF,观察限流以 RemoteAddr 触发
- **手工验证**: `curl -H "X-Forwarded-For: 1.2.3.4"` 直连后,`/health` 等端点限流计数应基于真实源

## 🔗 Dependencies / 依赖关系

- **阻塞** `P1-23` (wsHandler IP) 与 `P2-18` (h3grpc_web IP) — 两者将统一使用此函数

## ⚠️ Regression Risk / 回归风险

**中**: CDN 后部署若未配置 trusted_proxies,所有用户被识别为同一 edge IP → 全部限流。

- 必须有明确的部署迁移指南
- 默认值需包含 Cloudflare CIDR 兜底
