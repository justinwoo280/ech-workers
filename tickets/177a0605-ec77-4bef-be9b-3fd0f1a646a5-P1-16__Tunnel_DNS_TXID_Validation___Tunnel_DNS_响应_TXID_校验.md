---
id: "177a0605-ec77-4bef-be9b-3fd0f1a646a5"
title: "P1-16: Tunnel DNS TXID Validation / Tunnel DNS 响应 TXID 校验"
assignee: ""
status: 0
createdAt: "2026-04-17T11:23:09.575Z"
updatedAt: "2026-04-17T11:23:17.243Z"
type: ticket
---

# P1-16: Tunnel DNS TXID Validation / Tunnel DNS 响应 TXID 校验

## 🟠 Severity / 优先级

**P1 — High (Cache Poisoning Risk)** | Sprint 3 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/dns/tunnel_resolver.go
- file:ewp-core/dns/doh.go `ParseResponse`

## 🎯 Description / 漏洞描述与影响

`ParseResponse` 不校验响应的 TXID 是否匹配请求 TXID。HTTP/1.1 单连接 serial 模式下不会出问题,但若改为 HTTP/2 多路复用(P1-4),**响应可能被错配**。

## 💥 Reproduction / 复现条件

1. 修复 P1-4 后,DNS 走 HTTP/2 多路复用
2. 同时发送多个 DNS 查询
3. 响应顺序不保证
4. ParseResponse 不验证 TXID → 可能解析错对应的响应

## 🔧 Fix / 修复方案

- 验证 TXID,或文档化 HTTP/1.1 假设
- 推荐验证:

```go
if resp.TxID != req.TxID { return errTxIDMismatch }
```

## ✅ Acceptance Criteria / 验收标准

ParseResponse 接受预期 TXID 参数,不匹配返回错误调用方传入请求 TXID 进行校验单元测试覆盖 mismatch 场景

## 🧪 Verification / 验证方法

- **单元测试**: 注入响应 TXID 与请求不匹配,断言报错

## 🔗 Dependencies / 依赖关系

- **触发**于 `P1-4` (DNS 连接池) — 多路复用必须有此校验

## ⚠️ Regression Risk / 回归风险

**低**
