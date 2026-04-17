---
id: "3cdfcabd-9ccb-4054-8301-f070b6aaa16b"
title: "P1-11: Trojan UDP Resolve Failure → Close Session / Trojan UDP 解析失败包丢失修复"
assignee: ""
status: 0
createdAt: "2026-04-17T11:22:16.101Z"
updatedAt: "2026-04-17T11:22:24.208Z"
type: ticket
---

# P1-11: Trojan UDP Resolve Failure → Close Session / Trojan UDP 解析失败包丢失修复

## 🟠 Severity / 优先级

**P1 — High (Silent Data Loss)** | Sprint 2 | 工作量: 0.25 天

## 📍 Location / 精确位置

- file:ewp-core/internal/server/trojan_udp_handler.go `handleStream` line 91-94

## 🎯 Description / 漏洞描述与影响

`net.ResolveUDPAddr` 失败仅 `continue`,该包 payload **永久丢失但 session 仍存活**,客户端无任何错误反馈。

## 💥 Reproduction / 复现条件

1. Trojan UDP session,客户端发送目标 = `invalid.tld`
2. 服务端 ResolveUDPAddr 失败,silently continue
3. 客户端等不到响应,但也无 error 帧
4. 客户端最终超时,但已无谓地等待数秒

## 🔧 Fix / 修复方案

返回 EWP/Trojan 错误帧或关闭 session:

```go
// 示意
addr, err := net.ResolveUDPAddr(...)
if err != nil {
    sendErrorResponse(stream, err); closeSession(); return
}
```

## ✅ Acceptance Criteria / 验收标准

解析失败时给客户端发明确错误响应或关闭 session 让客户端立即知晓不再 silent continue

## 🧪 Verification / 验证方法

- **单元测试**: 注入解析失败,断言客户端收到错误或 session 关闭
- **e2e**: Trojan 客户端发送非法目标,得到明确错误反馈

## 🔗 Dependencies / 依赖关系

- 与 `P0-4` (UDP DNS 异步化) 同模块,可一并修复

## ⚠️ Regression Risk / 回归风险

**低**
