---
id: "cdf0a0ea-d448-4c0a-a587-910111b2bad0"
title: "P1-27: BypassResolver probeBestIP Fingerprint / BypassResolver 探测指纹"
assignee: ""
status: 0
createdAt: "2026-04-17T11:24:58.132Z"
updatedAt: "2026-04-17T11:25:05.653Z"
type: ticket
---

# P1-27: BypassResolver probeBestIP Fingerprint / BypassResolver 探测指纹

## 🟠 Severity / 优先级

**P1 — High (Fingerprintable Behavior)** | Sprint 5 | 工作量: 0.5 天

## 📍 Location / 精确位置

- file:ewp-core/transport/resolver.go `probeBestIP`

## 🎯 Description / 漏洞描述与影响

每解析一次目标,建多个临时 TCP — 留下指纹("固定模式探测多个 IP 然后只保留 1 个"),易被 DPI 识别为代理客户端行为;同时占用对端 TCP 半开连接。

## 💥 Reproduction / 复现条件

1. DPI 设备观察客户端流量
2. 看到固定 N 个 IP 的 SYN/RST 模式
3. 标记为"代理客户端"

## 🔧 Fix / 修复方案

- 简化为 ICMP / 单 IP fast path
- 或缓存更长时间(降低探测频率)

```go
// 示意
if cached := cache.Get(domain); cached.fresh() { return cached.ip }
ip := probeICMPOrSingle(domain)
```

## ✅ Acceptance Criteria / 验收标准

probeBestIP 减少并发探测数量缓存有效期延长(如 1h)抓包指纹不再固定

## 🧪 Verification / 验证方法

- **抓包对比**: 修复前后 SYN 包数量
- **单元测试**: 多次解析同域名应命中缓存

## 🔗 Dependencies / 依赖关系

- 无强依赖

## ⚠️ Regression Risk / 回归风险

**低-中**: 探测策略变化可能影响最优 IP 选择
