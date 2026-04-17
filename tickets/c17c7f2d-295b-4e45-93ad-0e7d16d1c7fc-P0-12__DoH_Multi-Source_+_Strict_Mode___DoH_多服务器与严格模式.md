---
id: "c17c7f2d-295b-4e45-93ad-0e7d16d1c7fc"
title: "P0-12: DoH Multi-Source + Strict Mode / DoH 多服务器与严格模式"
assignee: ""
status: 0
createdAt: "2026-04-17T11:20:09.758Z"
updatedAt: "2026-04-17T11:20:25.482Z"
type: ticket
---

# P0-12: DoH Multi-Source + Strict Mode / DoH 多服务器与严格模式

## 🔴 Severity / 优先级

**P0 — Critical (SNI Leak Fallback)** | Sprint 4 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/cmd/client/main.go line 107: `https://223.5.5.5/dns-query`
- file:ewp-core/ewpmobile/vpn_manager.go line 164
- file:ewp-core/common/tls/ech.go (FallbackOnError 行为)

## 🎯 Description / 漏洞描述与影响

- DoH 服务器 IP 写死 (`223.5.5.5`)
- TLS 证书校验依赖系统 CA(IP 直连,SNI 是 IP)
- 若 IP 被 GFW 劫持(SNI 阻断/TCP 重置),ECH bootstrap 失败
- 客户端**回退到普通 TLS 暴露 SNI**(若 `FallbackOnError=true`)

## 💥 Reproduction / 复现条件

1. GFW 阻断 `223.5.5.5:443` (TCP RST)
2. 客户端 ECH bootstrap 失败
3. FallbackOnError=true → 用明文 SNI 直接握手
4. SNI = 真实代理域名 → 立即被识别

## 🔧 Fix / 修复方案

- DoH 服务器**列表化**(默认含 alidns/cloudflare/quad9/google),自动竞速选最快
- ECH bootstrap 失败在严格模式下应**拒绝连接**,而非回退
- 可配置 `dns_servers: [...]` 与 `ech_strict: true`

```go
// 示意
servers := []string{"https://223.5.5.5/dns-query", "https://1.1.1.1/dns-query", ...}
ip := racer.FastestSuccessful(servers, ctx)
```

## ✅ Acceptance Criteria / 验收标准

DoH 服务器配置改为列表,默认包含 ≥3 个不同 ASN 的服务器启动时并行竞速,选最快可用新增 ech_strict_mode 配置,默认 true严格模式下 ECH bootstrap 失败 → 直接报错,不回退明文文档说明各模式的安全权衡

## 🧪 Verification / 验证方法

- **单元测试**: mock DoH 服务器,模拟首选失败 → 自动 failover
- **e2e**: 阻断 223.5.5.5,客户端仍能解析(走 cloudflare)
- **抓包**: 严格模式下,bootstrap 失败时不发出明文 SNI 请求

## 🔗 Dependencies / 依赖关系

- 与 `P1-15` (Bypass DNS plaintext) 配套修复,统一 DoH 默认值
- 与 `P1-9` (Mozilla CA mandatory) 紧密相关

## ⚠️ Regression Risk / 回归风险

**中**: 严格模式可能在国内网络环境下导致部分用户连不上。需:

- 提供"宽松模式"开关(默认严格)
- 文档清楚说明国内/海外推荐配置
