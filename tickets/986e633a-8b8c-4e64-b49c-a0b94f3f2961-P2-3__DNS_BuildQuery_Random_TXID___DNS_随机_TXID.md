---
id: "986e633a-8b8c-4e64-b49c-a0b94f3f2961"
title: "P2-3: DNS BuildQuery Random TXID / DNS 随机 TXID"
assignee: ""
status: 0
createdAt: "2026-04-17T11:25:49.200Z"
updatedAt: "2026-04-17T11:25:54.133Z"
type: ticket
---

# P2-3: DNS BuildQuery Random TXID / DNS 随机 TXID

## 🟡 Severity / 优先级

**P2 — Medium (Fingerprint)** | Sprint 5 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/dns/query.go `BuildQuery` 硬编码 TXID `0x0001`

## 🎯 Description / 漏洞描述与影响

DPI 易识别 — 所有 DNS 查询 TXID 都是 0x0001 是非常显著的指纹。

## 💥 Reproduction / 复现条件

1. DPI 抓 DNS 流量
2. 所有查询 TXID = 1 → 立即识别本客户端

## 🔧 Fix / 修复方案

用 `crypto/rand`:

```go
binary.BigEndian.PutUint16(txid[:], uint16(rand.Intn(65535)+1))
```

## ✅ Acceptance Criteria / 验收标准

BuildQuery TXID 随机配合 P1-16 校验响应 TXID

## 🧪 Verification / 验证方法

- **抓包验证**: TXID 分布均匀

## 🔗 Dependencies / 依赖关系

- 与 `P1-16` (TXID 校验) 协同

## ⚠️ Regression Risk / 回归风险

**极低**
