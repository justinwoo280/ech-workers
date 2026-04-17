---
id: "b8fd0635-7dfc-4edb-a088-6f3e42170762"
title: "P2-4: DNS Compression Pointer Robustness / DNS 压缩指针鲁棒性"
assignee: ""
status: 0
createdAt: "2026-04-17T11:25:54.514Z"
updatedAt: "2026-04-17T11:25:59.132Z"
type: ticket
---

# P2-4: DNS Compression Pointer Robustness / DNS 压缩指针鲁棒性

## 🟡 Severity / 优先级

**P2 — Low** | Sprint 5 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/dns/response.go `ParseResponse` 压缩指针解析逻辑不全

## 🎯 Description / 漏洞描述与影响

部分非典型 DNS 响应解析失败(嵌套压缩、特殊指针)。

## 💥 Reproduction / 复现条件

- 部分上游 DNS 服务器返回嵌套压缩响应,解析失败

## 🔧 Fix / 修复方案

用成熟 DNS 库(`miekg/dns`)或重写,正确处理 RFC 1035 压缩。

## ✅ Acceptance Criteria / 验收标准

通过 DNS 解析 fuzz 测试兼容主流 DNS 服务器响应

## 🧪 Verification / 验证方法

- **fuzz 测试**: `go test -fuzz=FuzzParseResponse`

## 🔗 Dependencies / 依赖关系

- 无

## ⚠️ Regression Risk / 回归风险

**中**: 替换 DNS 解析库需大量回归
