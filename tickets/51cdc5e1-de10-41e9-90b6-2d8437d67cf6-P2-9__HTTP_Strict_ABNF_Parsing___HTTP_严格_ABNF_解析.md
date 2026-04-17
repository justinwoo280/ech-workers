---
id: "51cdc5e1-de10-41e9-90b6-2d8437d67cf6"
title: "P2-9: HTTP Strict ABNF Parsing / HTTP 严格 ABNF 解析"
assignee: ""
status: 0
createdAt: "2026-04-17T11:26:23.150Z"
updatedAt: "2026-04-17T11:26:29.618Z"
type: ticket
---

# P2-9: HTTP Strict ABNF Parsing / HTTP 严格 ABNF 解析

## 🟡 Severity / 优先级

**P2 — Medium (HTTP Smuggling)** | Sprint 5 | 工作量: 1 天

## 📍 Location / 精确位置

- file:ewp-core/protocol/http/server.go

## 🎯 Description / 漏洞描述与影响

HTTP 请求行用 `strings.Fields` 接受任意空白(tab、多空格)→ 潜在 **HTTP smuggling** 攻击向量。

## 💥 Reproduction / 复现条件

1. 攻击者发送 `GET\t/\tHTTP/1.1` (含 tab)
2. 本代理与上游对此解析不一致
3. 可能造成 request smuggling

## 🔧 Fix / 修复方案

严格按 ABNF 解析(只接受单个 SP):

```go
parts := strings.SplitN(line, " ", 3)
if len(parts) != 3 { return errMalformed }
```

## ✅ Acceptance Criteria / 验收标准

严格只接受 RFC 7230 定义的请求行格式拒绝 tab / 多空格fuzz 测试覆盖

## 🧪 Verification / 验证方法

- **fuzz**: `go test -fuzz=FuzzRequestLine`
- **回归**: 主流客户端(curl/Chrome)不受影响

## 🔗 Dependencies / 依赖关系

- 与 `P0-5` (HTTP body 截断) 同文件

## ⚠️ Regression Risk / 回归风险

**低**
