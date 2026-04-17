---
id: "57ce28b5-4a62-4e2c-83ab-7de8fa94fb8c"
title: "P1-15: Bypass Resolver Default DoT/DoH / Bypass Resolver 默认加密 DNS"
assignee: ""
status: 0
createdAt: "2026-04-17T11:22:57.716Z"
updatedAt: "2026-04-17T11:23:08.671Z"
type: ticket
---

# P1-15: Bypass Resolver Default DoT/DoH / Bypass Resolver 默认加密 DNS

## 🟠 Severity / 优先级

**P1 — High (DNS Plaintext Leak)** | Sprint 4 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/transport/resolver.go `NewBypassResolver` line 36 (默认 `8.8.8.8:53`)

## 🎯 Description / 漏洞描述与影响

VPN 启动后,bypass dialer 走物理网卡,发送的是 **未加密 DNS over UDP/TCP**,运营商可看见所有节点域名 — **完全暴露代理服务器域名**。

## 💥 Reproduction / 复现条件

1. 启动 VPN,服务器域名为 `proxy.example.com`
2. bypass dialer 走 `8.8.8.8:53` 明文 DNS 查询 `proxy.example.com`
3. 运营商抓包看到查询日志
4. **代理域名暴露,可被针对性封锁**

## 🔧 Fix / 修复方案

默认改为 DoT(853)或 DoH,或允许用户配置:

```go
// 示意
defaultBypassDNS = "https://1.1.1.1/dns-query" // DoH
// 或
defaultBypassDNS = "tls://1.1.1.1:853"          // DoT
```

## ✅ Acceptance Criteria / 验收标准

BypassResolver 默认使用 DoH/DoT配置项允许用户切换抓包验证查询不再明文与 P0-12 共用同一 DoH 实现

## 🧪 Verification / 验证方法

- **抓包验证**: tcpdump 物理网卡,无 53/UDP 明文 DNS
- **单元测试**: BypassResolver 正确使用 DoH client

## 🔗 Dependencies / 依赖关系

- 与 `P0-12` (DoH 多源) 紧密相关,应配套实施
- 与 `P1-9` (Mozilla CA) 同 Sprint

## ⚠️ Regression Risk / 回归风险

**中**: DoH/DoT 在某些 NAT/防火墙后可能不通,需:

- 提供 fallback 与诊断工具
- 默认值需考虑国内/海外差异
